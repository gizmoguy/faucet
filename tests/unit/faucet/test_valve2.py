#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import namedtuple
from functools import partial

import hashlib
import cProfile
import io
import ipaddress
import logging
import os
import pstats
import shutil
import socket
import tempfile
import time
import unittest

from ryu.controller import dpset
from ryu.controller.ofp_event import EventOFPMsgBase
from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, icmpv6, ipv4, ipv6, lldp, slow, packet, vlan
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from prometheus_client import CollectorRegistry

from beka.route import RouteAddition, RouteRemoval
from beka.ip import IPAddress, IPPrefix

from faucet import faucet
from faucet import faucet_bgp
from faucet import faucet_dot1x
from faucet import faucet_experimental_api
from faucet import faucet_experimental_event
from faucet import faucet_metrics
from faucet import valves_manager
from faucet import valve_of
from faucet import valve_packet
from faucet import valve_util
from faucet.valve import TfmValve

from fakeoftable import FakeOFTable


FAUCET_MAC = '0e:00:00:00:00:01'


# TODO: fix fake OF table implementation for in_port filtering
# (ie. do not output to in_port)
BASE_DP1_CONFIG = """
        dp_id: 1
        egress_pipeline: True
        ignore_learn_ins: 100
        ofchannel_log: '/dev/null'
        packetin_pps: 99
        lldp_beacon:
            send_interval: 1
            max_per_interval: 1
"""

DP1_CONFIG = """
        combinatorial_port_flood: True
""" + BASE_DP1_CONFIG

IDLE_DP1_CONFIG = """
        use_idle_timeout: True
""" + DP1_CONFIG

GROUP_DP1_CONFIG = """
        group_table: True
        combinatorial_port_flood: False
""" + BASE_DP1_CONFIG

CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                loop_protect: True
                receive_lldp: True
                max_hosts: 1
                hairpin: True
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
                loop_protect: True
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]

    s2:
        hardware: 'Open vSwitch'
        dp_id: 0xdeadbeef
        interfaces:
            p1:
                number: 1
                native_vlan: v100
    s3:
        hardware: 'Open vSwitch'
        combinatorial_port_flood: True
        dp_id: 0x3
        stack:
            priority: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v300
            p2:
                number: 2
                native_vlan: v300
            p3:
                number: 3
                native_vlan: v300
            p4:
                number: 4
                native_vlan: v300
            5:
                description: p5
                stack:
                    dp: s4
                    port: 5
    s4:
        hardware: 'Open vSwitch'
        dp_id: 0x4
        interfaces:
            p1:
                number: 1
                native_vlan: v300
            p2:
                number: 2
                native_vlan: v300
            p3:
                number: 3
                native_vlan: v300
            p4:
                number: 4
                native_vlan: v300
            5:
                description: p5
                number: 5
                stack:
                    dp: s3
                    port: 5
routers:
    router1:
        vlans: [v100, v200]
vlans:
    v100:
        vid: 0x100
        targeted_gw_resolution: True
        faucet_vips: ['10.0.0.254/24']
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
            - route:
                ip_dst: 10.99.98.0/24
                ip_gw: 10.0.0.99
    v200:
        vid: 0x200
        faucet_vips: ['fc00::1:254/112', 'fe80::1:254/64']
        routes:
            - route:
                ip_dst: 'fc00::10:0/112'
                ip_gw: 'fc00::1:1'
            - route:
                ip_dst: 'fc00::20:0/112'
                ip_gw: 'fc00::1:99'
    v300:
        vid: 0x300
    v400:
        vid: 0x400
""" % DP1_CONFIG


def build_pkt(pkt):
    """Build and return a packet and eth type from a dict."""

    def serialize(layers):
        """Concatenate packet layers and serialize."""
        result = packet.Packet()
        for layer in reversed(layers):
            result.add_protocol(layer)
        result.serialize()
        return result

    layers = []
    assert 'eth_dst' in pkt and 'eth_src' in pkt
    ethertype = None
    if 'arp_source_ip' in pkt and 'arp_target_ip' in pkt:
        ethertype = ether.ETH_TYPE_ARP
        arp_code = pkt.get('arp_code', arp.ARP_REQUEST)
        layers.append(arp.arp(
            src_ip=pkt['arp_source_ip'], dst_ip=pkt['arp_target_ip'], opcode=arp_code))
    elif 'ipv6_src' in pkt and 'ipv6_dst' in pkt:
        ethertype = ether.ETH_TYPE_IPV6
        if 'router_solicit_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_ROUTER_SOLICIT))
        elif 'neighbor_advert_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_ADVERT,
                data=icmpv6.nd_neighbor(
                    dst=pkt['neighbor_advert_ip'],
                    option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
        elif 'neighbor_solicit_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_SOLICIT,
                data=icmpv6.nd_neighbor(
                    dst=pkt['neighbor_solicit_ip'],
                    option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
        elif 'echo_request_data' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ICMPV6_ECHO_REQUEST,
                data=icmpv6.echo(id_=1, seq=1, data=pkt['echo_request_data'])))
        layers.append(ipv6.ipv6(
            src=pkt['ipv6_src'],
            dst=pkt['ipv6_dst'],
            nxt=inet.IPPROTO_ICMPV6))
    elif 'ipv4_src' in pkt and 'ipv4_dst' in pkt:
        ethertype = ether.ETH_TYPE_IP
        proto = inet.IPPROTO_IP
        if 'echo_request_data' in pkt:
            echo = icmp.echo(id_=1, seq=1, data=pkt['echo_request_data'])
            layers.append(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST, data=echo))
            proto = inet.IPPROTO_ICMP
        net = ipv4.ipv4(src=pkt['ipv4_src'], dst=pkt['ipv4_dst'], proto=proto)
        layers.append(net)
    elif 'actor_system' in pkt and 'partner_system' in pkt:
        ethertype = ether.ETH_TYPE_SLOW
        layers.append(slow.lacp(
            version=1,
            actor_system=pkt['actor_system'],
            actor_port=1,
            partner_system=pkt['partner_system'],
            partner_port=1,
            actor_key=1,
            partner_key=1,
            actor_system_priority=65535,
            partner_system_priority=1,
            actor_port_priority=255,
            partner_port_priority=255,
            actor_state_defaulted=0,
            partner_state_defaulted=0,
            actor_state_expired=0,
            partner_state_expired=0,
            actor_state_timeout=1,
            partner_state_timeout=1,
            actor_state_collecting=1,
            partner_state_collecting=1,
            actor_state_distributing=1,
            partner_state_distributing=1,
            actor_state_aggregation=1,
            partner_state_aggregation=1,
            actor_state_synchronization=1,
            partner_state_synchronization=1,
            actor_state_activity=0,
            partner_state_activity=0))
    elif 'chassis_id' in pkt and 'port_id' in pkt:
        ethertype = ether.ETH_TYPE_LLDP
        return valve_packet.lldp_beacon(
            pkt['eth_src'], pkt['chassis_id'], str(pkt['port_id']), 1,
            org_tlvs=pkt.get('org_tlvs', None),
            system_name=pkt.get('system_name', None))
    assert ethertype is not None, pkt
    if 'vid' in pkt:
        tpid = ether.ETH_TYPE_8021Q
        layers.append(vlan.vlan(vid=pkt['vid'], ethertype=ethertype))
    else:
        tpid = ethertype
    eth = ethernet.ethernet(
        dst=pkt['eth_dst'],
        src=pkt['eth_src'],
        ethertype=tpid)
    layers.append(eth)
    result = serialize(layers)
    return result


class ValveTestBases:
    """Insulate test base classes from unittest so we can reuse base clases."""


    class ValveTestSmall(unittest.TestCase): # pytype: disable=module-attr
        """Base class for all Valve unit tests."""

        DP = 's1'
        DP_ID = 1
        NUM_PORTS = 5
        NUM_TABLES = 10
        P1_V100_MAC = '00:00:00:01:00:01'
        P2_V200_MAC = '00:00:00:02:00:02'
        P3_V200_MAC = '00:00:00:02:00:03'
        P1_V300_MAC = '00:00:00:03:00:01'
        UNKNOWN_MAC = '00:00:00:04:00:04'
        V100 = 0x100|ofp.OFPVID_PRESENT
        V200 = 0x200|ofp.OFPVID_PRESENT
        V300 = 0x300|ofp.OFPVID_PRESENT
        LOGNAME = 'faucet'
        ICMP_PAYLOAD = bytes('A'*8, encoding='UTF-8')

        def __init__(self, *args, **kwargs):
            self.dot1x = None
            self.last_flows_to_dp = {}
            self.valve = None
            self.valves_manager = None
            self.metrics = None
            self.bgp = None
            self.table = None
            self.logger = None
            self.tmpdir = None
            self.faucet_event_sock = None
            self.registry = None
            self.sock = None
            self.notifier = None
            self.config_file = None
            super(ValveTestBases.ValveTestSmall, self).__init__(*args, **kwargs)

        def setup_valve(self, config):
            """Set up test DP with config."""
            self.tmpdir = tempfile.mkdtemp()
            self.config_file = os.path.join(self.tmpdir, 'valve_unit.yaml')
            self.faucet_event_sock = os.path.join(self.tmpdir, 'event.sock')
            self.table = FakeOFTable(self.NUM_TABLES)
            logfile = os.path.join(self.tmpdir, 'faucet.log')
            self.logger = valve_util.get_logger(self.LOGNAME, logfile, logging.DEBUG, 0)
            self.registry = CollectorRegistry()
            self.metrics = faucet_metrics.FaucetMetrics(reg=self.registry) # pylint: disable=unexpected-keyword-arg
            # TODO: verify events
            self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
                self.faucet_event_sock, self.metrics, self.logger)
            self.bgp = faucet_bgp.FaucetBgp(
                self.logger, logfile, self.metrics, self.send_flows_to_dp_by_id)
            self.dot1x = faucet_dot1x.FaucetDot1x(
                self.logger, self.metrics, self.send_flows_to_dp_by_id)
            self.valves_manager = valves_manager.ValvesManager(
                self.LOGNAME, self.logger, self.metrics, self.notifier,
                self.bgp, self.dot1x, self.send_flows_to_dp_by_id)
            self.last_flows_to_dp[self.DP_ID] = []
            self.notifier.start()
            self.update_config(config, reload_expected=False)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.faucet_event_sock)
            self.connect_dp()

        def teardown_valve(self):
            """Tear down test DP."""
            self.bgp.shutdown_bgp_speakers()
            valve_util.close_logger(self.logger)
            for valve in list(self.valves_manager.valves.values()):
                valve.close_logs()
            self.sock.close()
            shutil.rmtree(self.tmpdir)

        def tearDown(self):
            self.teardown_valve()

        @staticmethod
        def profile(func, sortby='cumulative', amount=20, count=1):
            """Convenience method to profile a function call."""
            prof = cProfile.Profile()
            prof.enable()
            for _ in range(count):
                func()
            prof.disable()
            prof_stream = io.StringIO()
            prof_stats = pstats.Stats(prof, stream=prof_stream).sort_stats(sortby)
            prof_stats.print_stats(amount)
            print(prof_stream.getvalue())

        def get_prom(self, var, labels=None):
            """Return a Prometheus variable value."""
            if labels is None:
                labels = {}
            labels.update({
                'dp_name': self.DP,
                'dp_id': '0x%x' % self.DP_ID})
            val = self.registry.get_sample_value(var, labels)
            if val is None:
                val = 0
            return val

        def prom_inc(self, func, var, labels=None, inc_expected=True):
            """Check Prometheus variable increments by 1 after calling a function."""
            before = self.get_prom(var, labels)
            func()
            after = self.get_prom(var, labels)
            msg = '%s %s before %f after %f' % (var, labels, before, after)
            if inc_expected:
                self.assertEqual(before + 1, after, msg=msg)
            else:
                self.assertEqual(before, after, msg=msg)

        def send_flows_to_dp_by_id(self, valve, flows):
            """Callback for ValvesManager to simulate sending flows to DP."""
            valve = self.valves_manager.valves[self.DP_ID]
            prepared_flows = valve.prepare_send_flows(flows)
            self.last_flows_to_dp[valve.dp.dp_id] = prepared_flows

        def update_config(self, config, reload_type='cold', reload_expected=True):
            """Update FAUCET config with config as text."""
            before_dp_status = int(self.get_prom('dp_status'))
            print("self.assertFalse(self.valves_manager.config_watcher.files_changed())")
            self.assertFalse(self.valves_manager.config_watcher.files_changed())
            existing_config = os.path.exists(self.config_file)

            if existing_config:
                with open(self.config_file) as config_file:
                    print("OLD HASH: %s" % hashlib.sha256(config_file.read().encode('utf-8')).hexdigest())

            with open(self.config_file, 'w') as config_file:
                config_file.write(config)
            if existing_config:
                with open(self.config_file) as config_file:
                    print("NEW HASH: %s" % hashlib.sha256(config_file.read().encode('utf-8')).hexdigest())
                print("self.assertTrue(self.valves_manager.config_watcher.files_changed())")
                self.assertTrue(self.valves_manager.config_watcher.files_changed())
            self.last_flows_to_dp[self.DP_ID] = []
            var = 'faucet_config_reload_%s_total' % reload_type
            self.prom_inc(
                partial(self.valves_manager.request_reload_configs,
                        time.time(), self.config_file), var=var, inc_expected=reload_expected)
            self.valve = self.valves_manager.valves[self.DP_ID]
            if self.DP_ID in self.last_flows_to_dp:
                reload_ofmsgs = self.last_flows_to_dp[self.DP_ID]
                self.table.apply_ofmsgs(reload_ofmsgs)
            self.assertEqual(before_dp_status, int(self.get_prom('dp_status')))

        def connect_dp(self):
            """Call DP connect and set all ports to up."""
            self.assertEqual(0, int(self.get_prom('dp_status')))
            discovered_up_ports = [port_no for port_no in range(1, self.NUM_PORTS + 1)]
            self.table.apply_ofmsgs(
                self.valve.switch_features(None) +
                self.valve.datapath_connect(time.time(), discovered_up_ports))
            self.assertEqual(1, int(self.get_prom('dp_status')))
            for port_no in discovered_up_ports:
                if port_no in self.valve.dp.ports:
                    self.set_port_up(port_no)
            self.assertTrue(self.valve.dp.to_conf())

        def port_labels(self, port_no):
            port = self.valve.dp.ports[port_no]
            return {'port': port.name, 'port_description': port.description}

        def port_expected_status(self, port_no, exp_status):
            if port_no not in self.valve.dp.ports:
                return
            labels = self.port_labels(port_no)
            status = int(self.get_prom('port_status', labels=labels))
            self.assertEqual(
                status, exp_status,
                msg='status %u != expected %u for port %s' % (
                    status, exp_status, labels))

        def set_port_down(self, port_no):
            """Set port status of port to down."""
            self.table.apply_ofmsgs(self.valve.port_status_handler(
                port_no, ofp.OFPPR_DELETE, ofp.OFPPS_LINK_DOWN))
            self.port_expected_status(port_no, 0)

        def set_port_up(self, port_no):
            """Set port status of port to up."""
            self.table.apply_ofmsgs(self.valve.port_status_handler(
                port_no, ofp.OFPPR_ADD, 0))
            self.port_expected_status(port_no, 1)

        def flap_port(self, port_no):
            """Flap op status on a port."""
            self.set_port_down(port_no)
            self.set_port_up(port_no)

        @staticmethod
        def packet_outs_from_flows(flows):
            """Return flows that are packetout actions."""
            return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPPacketOut)]

        def learn_hosts(self):
            """Learn some hosts."""
            # TODO: verify learn caching.
            for _ in range(2):
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.UNKNOWN_MAC,
                    'ipv4_src': '10.0.0.1',
                    'ipv4_dst': '10.0.0.2'})
                # TODO: verify host learning banned
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.UNKNOWN_MAC,
                    'eth_dst': self.P1_V100_MAC,
                    'ipv4_src': '10.0.0.2',
                    'ipv4_dst': '10.0.0.1'})
                self.rcv_packet(2, 0x200, {
                    'eth_src': self.P2_V200_MAC,
                    'eth_dst': self.P3_V200_MAC,
                    'ipv4_src': '10.0.0.2',
                    'ipv4_dst': '10.0.0.3',
                    'vid': 0x200})
                self.rcv_packet(3, 0x200, {
                    'eth_src': self.P3_V200_MAC,
                    'eth_dst': self.P2_V200_MAC,
                    'ipv4_src': '10.0.0.3',
                    'ipv4_dst': '10.0.0.4',
                    'vid': 0x200})

        def verify_expiry(self):
            """Verify FIB resolution attempts expire."""
            now = time.time()
            for _ in range(self.valve.dp.max_host_fib_retry_count + 1):
                now += (self.valve.dp.timeout * 2)
                self.valve.state_expire(now, None)
                self.valve.resolve_gateways(now, None)
            # TODO: verify state expired

        def verify_flooding(self, matches):
            """Verify flooding for a packet, depending on the DP implementation."""

            combinatorial_port_flood = self.valve.dp.combinatorial_port_flood
            if self.valve.dp.group_table:
                combinatorial_port_flood = False

            def _verify_flood_to_port(match, port, valve_vlan, port_number=None):
                if valve_vlan.port_is_tagged(port):
                    vid = valve_vlan.vid|ofp.OFPVID_PRESENT
                else:
                    vid = 0
                if port_number is None:
                    port_number = port.number
                return self.table.is_output(match, port=port_number, vid=vid)

            for match in matches:
                in_port_number = match['in_port']
                in_port = self.valve.dp.ports[in_port_number]

                if ('vlan_vid' in match and
                        match['vlan_vid'] & ofp.OFPVID_PRESENT is not 0):
                    valve_vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
                else:
                    valve_vlan = in_port.native_vlan

                all_ports = {
                    port for port in self.valve.dp.ports.values() if port.running()}
                remaining_ports = all_ports - {
                    port for port in valve_vlan.get_ports() if port.running}

                hairpin_output = _verify_flood_to_port(
                    match, in_port, valve_vlan, ofp.OFPP_IN_PORT)
                self.assertEqual(
                    in_port.hairpin, hairpin_output,
                    msg='hairpin flooding incorrect (expected %s got %s)' % (
                        in_port.hairpin, hairpin_output))

                # Packet must be flooded to all ports on the VLAN.
                if not self.valve.dp.stack or 'priority' in self.valve.dp.stack:
                    for port in valve_vlan.get_ports():
                        output = _verify_flood_to_port(match, port, valve_vlan)
                        if port == in_port:
                            self.assertNotEqual(
                                output, combinatorial_port_flood,
                                msg=('flooding to in_port (%s) not '
                                     'compatible with flood mode (%s)') % (
                                         output, combinatorial_port_flood))
                            continue
                        self.assertTrue(
                            output,
                            msg=('%s with unknown eth_dst not flooded'
                                 ' on VLAN %u to port %u' % (
                                     match, valve_vlan.vid, port.number)))

                # Packet must not be flooded to ports not on the VLAN.
                for port in remaining_ports:
                    if port.stack:
                        self.assertTrue(
                            self.table.is_output(match, port=port.number),
                            msg=('Unknown eth_dst not flooded to stack port %s' % port))
                    elif not port.mirror:
                        self.assertFalse(
                            self.table.is_output(match, port=port.number),
                            msg=('Unknown eth_dst flooded to non-VLAN/stack/mirror %s' % port))

        def rcv_packet(self, port, vid, match):
            """Simulate control plane receiving a packet on a port/VID."""
            pkt = build_pkt(match)
            vlan_pkt = pkt
            # TODO: VLAN packet submitted to packet in always has VID
            # Fake OF switch implementation should do this by applying actions.
            if vid and vid not in match:
                vlan_match = match
                vlan_match['vid'] = vid
                vlan_pkt = build_pkt(match)
            msg = namedtuple(
                'null_msg',
                ('match', 'in_port', 'data', 'total_len', 'cookie', 'reason'))(
                    {'in_port': port}, port, vlan_pkt.data, len(vlan_pkt.data),
                    self.valve.dp.cookie, valve_of.ofp.OFPR_ACTION)
            self.last_flows_to_dp[self.DP_ID] = []
            now = time.time()
            self.prom_inc(
                partial(self.valves_manager.valve_packet_in, now, self.valve, msg),
                'of_packet_ins_total')
            rcv_packet_ofmsgs = self.last_flows_to_dp[self.DP_ID]
            self.table.apply_ofmsgs(rcv_packet_ofmsgs)
            for valve_service in (
                    'resolve_gateways', 'advertise', 'fast_advertise', 'state_expire'):
                self.valves_manager.valve_flow_services(
                    now, valve_service)
            self.valves_manager.update_metrics(now)
            return rcv_packet_ofmsgs


class ValveChangeACLTestCase(ValveTestBases.ValveTestSmall):
    """Test changes to ACL on a port."""

    CONFIG = """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_a
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    SAME_CONTENT_CONFIG = """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_b
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    DIFF_CONTENT_CONFIG = """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_diff_c
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_change_port_acl(self):
        """Test port ACL can be changed."""
        print("self.update_config(self.SAME_CONTENT_CONFIG, reload_type='warm')")
        self.update_config(self.SAME_CONTENT_CONFIG, reload_type='warm')
        print("self.update_config(self.DIFF_CONTENT_CONFIG, reload_type='warm')")
        self.update_config(self.DIFF_CONTENT_CONFIG, reload_type='warm')


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
