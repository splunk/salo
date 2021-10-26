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

from typing import List, Optional

from pydantic import Field, validator

from salo import fake

from .base import ZeekModel


class RDPModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/protocols/rdp/main.zeek.html#type-RDP::Info",
        "https://docs.zeek.org/en/master/logs/rdp.html",
    ]
    cookie: str = Field(default_factory=fake.lexify)
    result: str = Field(default="encrypted")
    security_protocol: str = Field(default="HYBRID")
    client_channels: Optional[List[str]] = None
    keyboard_layour: Optional[str] = None
    client_build: Optional[str] = None
    client_name: Optional[str] = None
    client_dig_product_id: Optional[str] = None
    desktop_width: Optional[int] = None
    desktop_height: Optional[int] = None
    requested_color_depth: Optional[str] = None
    cert_type: Optional[str] = None
    cert_count: int = Field(default=0)
    cert_permanent: Optional[bool] = None
    encryption_level: Optional[str] = None
    encryption_method: Optional[str] = None
    ssl: Optional[bool] = None

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or 3389
