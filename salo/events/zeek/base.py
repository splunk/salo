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
import random
import string
from typing import Optional

from pydantic import Field, IPvAnyAddress, validator

from salo import SaloEventModel, fake


def random_uid() -> str:
    return "C" + "".join(random.choices(string.ascii_letters + string.digits, k=17))


def random_fuid() -> str:
    return "F" + "".join(random.choices(string.ascii_letters + string.digits, k=17))


class ZeekModel(SaloEventModel):
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Log event timestamp",
    )
    uid: Optional[str] = Field(
        default_factory=random_uid, title="uid", description="Zeek unique ID"
    )
    src_ip: Optional[IPvAnyAddress] = Field(
        default_factory=fake.ipv4_private,
        description="Source ip address of connection",
    )
    src_port: Optional[int] = Field(
        default=None,
        description="Source port of the connection",
    )
    dest_ip: Optional[IPvAnyAddress] = Field(
        default_factory=fake.ipv4_public,
        description="Destination ip address of connection",
    )
    dest_port: Optional[int] = Field(
        default=None,
        description="Destination port of the connection",
    )

    class Config:
        json_encoders = {datetime: lambda v: f"{v.isoformat()}Z"}
        fields = {
            "timestamp": "ts",
            "src_ip": "id.orig_h",
            "src_port": "id.orig_p",
            "dest_ip": "id.resp_h",
            "dest_port": "id.resp_p",
        }

    @validator("src_port", pre=True, always=True)
    def set_src_port(cls, v):
        return v or fake.port_number(is_dynamic=True)

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or fake.port_number(is_system=True)

    def generate(self, by_alias: bool = True, exclude_none: bool = True):
        return self.json(by_alias=by_alias, exclude_none=exclude_none)
