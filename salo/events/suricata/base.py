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

from datetime import datetime
from typing import Dict, Optional

from pydantic import Field, IPvAnyAddress, validator

from salo import SaloEventModel, fake


class SuricataModel(SaloEventModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    flow_id: Optional[int] = None
    pcap_cnt: Optional[int] = None
    event_type: Optional[str] = None
    src_ip: Optional[IPvAnyAddress] = Field(default_factory=fake.ipv4_private)
    src_port: Optional[int] = None
    dest_ip: Optional[IPvAnyAddress] = Field(default_factory=fake.ipv4_public)
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    packet: Optional[str] = None
    packet_info: Optional[Dict] = None
    tx_id: Optional[int] = None
    app_proto: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: f"{v.isoformat()}"}

    @validator("src_port", pre=True, always=True)
    def set_src_port(cls, v):
        return v or fake.port_number(is_dynamic=True)

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or fake.port_number(is_system=True)

    def generate(self, by_alias: bool = True, exclude_none: bool = True):
        return self.json(by_alias=by_alias, exclude_none=exclude_none)
