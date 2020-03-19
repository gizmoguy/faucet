"""Implement gauge API."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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

import copy
import yaml
from faucet import config_parser_util


class GaugeAPI:
    """An API for interacting with Gauge."""

    def __init__(self, *_args, **_kwargs):
        self.gauge = None

    def is_registered(self):
        """Return True if registered and ready to serve API requests."""
        return self.gauge is not None

    def _register(self, gauge):
        """Register with Gauge RyuApp."""
        if self.gauge is None:
            self.gauge = gauge

    def dump_all(self):
        """Capture all state we can."""
        if self.gauge is not None:
            # Setup a flat file db
            #   dbs:
            #     ft_file:
            #       type: 'text'
            #       compress: True
            #       path: 'flow_tables'
            #
            # Launch one of every watcher with our gzip file store
            #   port_state  {'text': GaugePortStateLogger}
            #   port_stats  {'text': GaugePortStatsLogger}
            #   flow_table  {'text': GaugeFlowTableLogger}
            #   meter_stats {'text': GaugeMeterStatsLogger}
            #
            # Trigger all watchers
            #
            # Somehow decide when we have collected everything (one-time watchers?)
            #
            # Tear down all the new watchers
            db_name = '__dump_all'
            dump_all_path = '/tmp/dump_all/'

            self.old_conf, _ = config_parser_util.read_config(self.gauge.config_file, self.gauge.logname)

            conf = copy.deepcopy(self.old_conf)
            print(conf)

            if 'dbs' not in conf:
                conf['dbs'] = {}
            if 'watchers' not in conf:
                conf['watchers'] = {}

            conf['dbs'][db_name + '_flow_table'] = {
                    'type': 'text',
                    'compress': True,
                    'path': dump_all_path + '/flow_table'
                    }

            # TODO: Try to create directory here

            for watcher in ['port_state', 'port_stats', 'flow_table', 'meter_stats']:
                conf['dbs'][db_name + '_' + watcher] = {
                        'type': 'text',
                        'compress': True,
                        'file': dump_all_path + '/' + watcher + '.json.gz'
                        }
                watcher_name = '__dump_all_{}'.format(watcher)
                conf['watchers'][watcher_name] = {
                        'type': watcher,
                        'all_dps': True,
                        'db': db_name + '_' + watcher
                        }

            print(conf)

            # Write new config
            with open(self.gauge.config_file, 'w') as config_file:
                yaml.dump(conf, config_file, default_flow_style=False)

            with open(self.gauge.config_file, 'r') as f:
                print(f.read())

            self.gauge._load_config()

            for dpid, watchers in self.gauge.watchers.items():
                print('* %s' % dpid)
                for dpid_watchers in watchers.values():
                    for watcher in dpid_watchers:
                        if watcher.conf.db == db_name:
                            if watcher.conf.type != 'port_state':
                                print('** triggering %s' % watcher)
                                watcher.send_req()

            import time
            time.sleep(100)

            # Restore old config
            with open(self.gauge.config_file, 'w') as config_file:
                yaml.dump(self.old_conf, config_file, default_flow_style=False)

            self.gauge._load_config()

            return {}
        return None
