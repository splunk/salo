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

from pathlib import Path

from salo import Sessions
from salo.outputs import SaloOutput


class LocalFileOutput(SaloOutput):
    def save(self, sessions: Sessions) -> None:
        for session in sessions.generate():
            event_config = None
            event_type = str(type(session)).split("'")[1]
            for k in self.config.keys():
                if event_type.startswith(k):
                    event_config = self.config.get(k)
            if event_config:
                output = event_config.get("outputs", {}).get("file")
                if output:
                    try:
                        path = Path(output.get("path"))
                    except TypeError:
                        print(f"Required path was not provided for {event_type}")
                        continue
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open(mode="a") as f:
                        f.write(session.generate())
                else:
                    print(
                        f"[!] Invalid file output configurtion for {event_type}. Event NOT saved!"
                    )
            else:
                print(f"[!] No output configuration for {event_type}! Event NOT saved.")
