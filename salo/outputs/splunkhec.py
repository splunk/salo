#!/usr/bin/env python3

#  Copyright 2021 Splunk Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import asyncio
import os
from typing import Dict

from aiohec import SplunkHEC

from salo import Sessions
from salo.outputs import SaloOutput


class SplunkOutput(SaloOutput):
    def __init__(self, config: Dict) -> None:
        super().__init__(config)
        self.host = os.getenv("SPLUNK_HOST") or ""
        self.token = os.getenv("SPLUNK_TOKEN") or ""

    def save(self, sessions: Sessions) -> None:
        asyncio.run(self._save(sessions))

    async def _save(self, sessions: Sessions) -> None:
        async with SplunkHEC(splunk_host=self.host, token=self.token) as hec:
            for session in sessions.generate():
                event_config = None
                event_type = str(type(session)).split("'")[1]
                for k in self.config.keys():
                    if event_type.startswith(k):
                        event_config = self.config.get(k)
                    if event_config:
                        output = event_config.get("outputs", {}).get("splunk")
                        if output:
                            index = output.get("index")
                            sourcetype = output.get("sourcetype")
                            source = output.get("source")
                            await hec.add_event(
                                session.generate(),
                                index=index,
                                source=source,
                                sourcetype=sourcetype,
                            )
                        else:
                            print(
                                f"[!] No Splunk output configurtion for {event_type}. Event NOT saved!"
                            )
