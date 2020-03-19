"""Implement gauge wsgi application."""

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

from ryu.app.wsgi import ControllerBase, route
from webob import Response
import json


class GaugeWSGIApp(ControllerBase):
    """An WSGI app for Gauge's API."""

    def __init__(self, req, link, data, **config):
        super(GaugeWSGIApp, self).__init__(req, link, data, **config)
        self.gauge_api = data['gauge_api']

    @route('dump_state', '/dump_state', methods=['GET'])
    def dump_state(self, req, **kwargs):
        if self.gauge_api.dump_all():
            return Response(content_type='application/json', json_body={"status": "200"})
        else:
            return Response(content_type='application/json', json_body={"status": "403"})
