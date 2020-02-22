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

    def trigger_watchers(self):
        """Get the current running config of Gauge as a python dictionary."""
        if self.gauge is not None:
            for watcher in self.gauge.watchers:
                watcher.send_req()
            return {}
        return None
