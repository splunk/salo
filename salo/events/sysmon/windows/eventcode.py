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
from inspect import currentframe, getframeinfo
from pathlib import Path
import random
from typing import Optional
from uuid import UUID, uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import Field, IPvAnyAddress, validator

from salo import SaloEventModel
from salo import fake


class EventCodeModel(SaloEventModel):
    _template: str = str()
    timestamp: datetime = Field(default_factory=datetime.now)

    class Config:
        json_encoders = {datetime: lambda v: f"{v.isoformat()}"}
        fields = {
            "src_ip": "SourceIp",
            "src_port": "SourcePort",
            "dest_ip": "DestinationIp",
            "dest_port": "DestinationPort",
            "timestamp": "SystemTime",
            "protocol": "Protocol",
        }

    @validator("UtcTime", pre=False, always=True, check_fields=False)
    def set_utctime(cls, v, *, values):
        return v or values.get("timestamp")

    @validator("SourceIsIpv6", pre=True, always=True, check_fields=False)
    def set_source_is_ipv6(cls, v, *, values):
        src_ip = values.get("src_ip")
        if src_ip and not v:
            return (lambda: src_ip.version == 6)()
        return v

    @validator("DestinationIsIpv6", pre=False, always=True, check_fields=False)
    def set_destination_is_ipv6(cls, v, *, values):
        dest_ip = values.get("dest_ip")
        if dest_ip and not v:
            return (lambda: dest_ip.version == 6)()
        return v

    def generate(self, by_alias: bool = True, exclude_none: bool = True):
        filename = getframeinfo(currentframe()).filename
        parent = Path(filename).resolve().parent
        template = parent.joinpath(self._template)
        env = Environment(
            loader=FileSystemLoader(parent),
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=select_autoescape(default_for_string=True, default=True),
        )
        return env.get_template(template.name).render(
            self.dict(by_alias=by_alias, exclude_none=exclude_none)
        )


class EventCode3Model(EventCodeModel):
    _template: str = "eventcode3.jinja2"
    Version: int = Field(default=5)
    Level: int = Field(default=4)
    Task: int = Field(default=3)
    Opcode: int = Field(default=0)
    Keywords: str = "0x8000000000000000"
    EventRecordID: int = Field(default_factory=fake.pyint)
    ProcessID: int = Field(default_factory=fake.pyint)
    ThreadID: int = Field(default_factory=fake.pyint)
    Computer: str = Field(default_factory=fake.hostname)
    UserID: str = Field(default="S-1-5-18")
    UtcTime: datetime = Field(default_factory=datetime.now)
    ProcessGuid: UUID = Field(default_factory=uuid4)
    ProcessId: int = Field(default_factory=fake.pyint)
    Image: Optional[str] = None
    User: Optional[str] = None
    protocol: Optional[str] = None
    Initiated: bool = Field(default_factory=fake.pybool)
    src_ip: IPvAnyAddress = Field(default_factory=fake.ipv4_private)
    SourceIsIpv6: bool = Field(default=False)
    SourceHostname: str = Field(default_factory=fake.hostname)
    src_port: Optional[str] = None
    SourcePortName: str = Field(default="-")
    dest_ip: IPvAnyAddress = Field(default_factory=fake.ipv4_public)
    DestinationIsIpv6: bool = Field(default=False)
    DestinationHostname: str = Field(default="-")
    dest_port: Optional[str] = None
    DestinationPortName: str = Field(default="-")

    @validator("Image", pre=True, always=True)
    def set_Image(cls, v):
        return v or f"C:{fake.file_path(extension='exe')}".replace("/", "\\")

    @validator("User", pre=True, always=True)
    def set_User(cls, v):
        return v or f"{fake.domain_word().upper()}\\{fake.user_name()}"

    @validator("protocol", pre=True, always=True)
    def set_protocol(cls, v):
        return v or random.choice(["tcp", "udp"])

    @validator("src_port", pre=True, always=True)
    def set_src_port(cls, v):
        return v or fake.port_number(is_dynamic=True)

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or fake.port_number(is_system=True)
