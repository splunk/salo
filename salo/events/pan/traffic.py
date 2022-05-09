#!/usr/bin/env python3

#  Copyright 2022 Splunk Inc.
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

import json
from datetime import datetime, timedelta
from ipaddress import IPv4Address
import random
import string
from typing import Optional

from pydantic import Field, IPvAnyAddress, validator

from salo import SaloEventModel, fake

SYSLOG_FIELDS = [
    "future_use1",
    "receive_time",
    "serial_number",
    "log_type",
    "log_subtype",
    "version",
    "generated_time",
    "src_ip",
    "dest_ip",
    "src_translated_ip",
    "dest_translated_ip",
    "rule",
    "src_user",
    "dest_user",
    "app",
    "vsys",
    "src_zone",
    "dest_zone",
    "src_interface",
    "dest_interface",
    "log_forwarding_profile",
    "future_use3",
    "session_id",
    "repeat_count",
    "src_port",
    "dest_port",
    "src_translated_port",
    "dest_translated_port",
    "session_flags",
    "transport",
    "action",
    "bytes",
    "bytes_out",
    "bytes_in",
    "packets",
    "start_time",
    "duration",
    "http_category",
    "future_use4",
    "sequence_number",
    "action_flags",
    "src_location",
    "dest_location",
    "future_use5",
    "packets_out",
    "packets_in",
    "session_end_reason",
    "devicegroup_level1",
    "devicegroup_level2",
    "devicegroup_level3",
    "devicegroup_level4",
    "vsys_name",
    "dvc_name",
    "action_source",
    "src_vm",
    "dest_vm",
    "tunnel_id",
    "tunnel_monitor_tag",
    "tunnel_session_id",
    "tunnel_start_time",
    "tunnel_type",
]


class PANTrafficModel(SaloEventModel):
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Log event timestamp"
    )
    receive_time: Optional[datetime] = None
    serial_number: Optional[str] = None
    log_type: str = Field(default="TRAFFIC")
    log_subtype: Optional[str] = None
    version: str = Field(default="10.0")
    generated_time: Optional[datetime] = None
    src_ip: Optional[IPvAnyAddress] = Field(
        default_factory=fake.ipv4_public,
        description="Source ip address of connection",
    )
    dest_ip: Optional[IPvAnyAddress] = Field(
        default_factory=fake.ipv4_public,
        description="Destination ip address of connection",
    )
    src_translated_ip: Optional[IPvAnyAddress] = Field(default=IPv4Address("0.0.0.0"))
    dest_translated_ip: Optional[IPvAnyAddress] = Field(default=IPv4Address("0.0.0.0"))
    rule: Optional[str] = None
    src_user: Optional[str] = None
    dest_user: str = Field(default="")
    app: str = Field(default_factory=fake.user_name)
    vsys: str = Field(default="vsys1")
    src_zone: Optional[str] = None
    dest_zone: Optional[str] = None
    src_interface: str = Field(default="")
    dest_interface: str = Field(default="")
    log_forwarding_profile: Optional[str] = None
    future_use3: str = Field(default="")
    session_id: int = Field(default_factory=fake.pyint)
    repeat_count: int = Field(default=1)
    src_port: Optional[int] = Field(
        default=None,
        description="Source port of the connection",
    )
    dest_port: Optional[int] = Field(
        default=None,
        description="Destination port of the connection",
    )
    src_translated_port: int = Field(default=0)
    dest_translated_port: int = Field(default=0)
    session_flags: int = Field(default_factory=fake.pyint)
    proto: Optional[str] = None
    action: Optional[str] = None
    bytes_out: int = Field(default_factory=fake.pyint)
    bytes_in: int = Field(default_factory=fake.pyint)
    bytes: Optional[int] = None
    duration: int = Field(default_factory=fake.pyint)
    http_category: str = Field(default="any")
    future_use4: str = Field(default="")
    start_time: Optional[datetime] = None
    sequence_number: int = Field(default_factory=fake.pyint)
    action_flags: Optional[str] = None
    src_location: str = Field(default_factory=fake.country_code)
    dest_location: str = Field(default_factory=fake.country_code)
    future_use5: str = Field(default="")
    packets_out: int = Field(default_factory=fake.pyint)
    packets_in: int = Field(default_factory=fake.pyint)
    packets: Optional[str] = None
    session_end_reason: str = Field(default="Unknown")
    devicegroup_level1: int = Field(default=0)
    devicegroup_level2: int = Field(default=0)
    devicegroup_level3: int = Field(default=0)
    devicegroup_level4: int = Field(default=0)
    vsys_name: str = Field(default="")
    dvc_name: Optional[str] = None
    action_source: str = Field(default="Unknown")
    src_vm: str = Field(default="")
    dest_vm: str = Field(default="")
    tunnel_id: int = Field(default=0)
    tunnel_monitor_tag: str = Field(default="")
    tunnel_session_id: int = Field(default=0)
    tunnel_start_time: Optional[datetime] = None
    tunnel_type: Optional[str] = None
    future_use1: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: f"{v.strftime('%Y/%m/%d %H:%M:%S')}"}
        fields = {
            "timestamp": "generated_time",
            "proto": "transport",
        }

    @validator("serial_number", pre=True, always=True)
    def set_serial_number(cls, v):
        return v or "".join(random.choices(string.digits, k=15))

    @validator("src_port", pre=True, always=True)
    def set_src_port(cls, v):
        return v or fake.port_number(is_dynamic=True)

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or fake.port_number(is_system=True)

    @validator("log_subtype", pre=True, always=True)
    def set_log_subtype(cls, v):
        return v or random.choice(["start", "end", "deny", "drop", "vulnerability"])

    @validator("rule", pre=True, always=True)
    def set_rule(cls, v):
        return v or fake.catch_phrase().replace(" ", "-")

    @validator("src_user", pre=True, always=True)
    def set_src_user(cls, v):
        return v or f"{fake.domain_word()}/{fake.user_name()}"

    @validator("src_zone", pre=True, always=True)
    def set_src_zone(cls, v):
        return v or fake.catch_phrase().replace(" ", "-")

    @validator("dest_zone", pre=True, always=True)
    def set_dest_zone(cls, v):
        return v or fake.catch_phrase().replace(" ", "-")

    @validator("log_forwarding_profile", pre=True, always=True)
    def set_log_forwarding_profile(cls, v):
        return v or fake.pystr_format(string_format="??-logger")

    @validator("proto", pre=True, always=True)
    def set_proto(cls, v):
        if v:
            return v
        elif fake.boolean(chance_of_getting_true=80):
            return "tcp"
        elif fake.boolean(chance_of_getting_true=90):
            return "udp"
        else:
            return "icmp"

    @validator("action", pre=True, always=True)
    def set_action(cls, v, *, values):
        subtype = values.get("log_subtype")
        action_map = {
            "start": "allow",
            "end": "allow",
            "deny": "deny",
            "drop": "deny",
            "vulnerablity": "alert",
        }
        return v or action_map.get("subtype", "allow")

    @validator("bytes", pre=True, always=True)
    def set_bytes(cls, v, *, values):
        return v or values.get("bytes_in", 0) + values.get("bytes_out", 0)

    @validator("packets", pre=True, always=True)
    def set_packets(cls, v, *, values):
        return v or values.get("packets_in", 0) + values.get("packets_out", 0)

    @validator("action_flags", pre=True, always=True)
    def set_action_flags(cls, v):
        return v or f"-{''.join(random.choices(string.digits, k=15))}"

    @validator("dvc_name", pre=True, always=True)
    def set_dvc_name(cls, v):
        return v or fake.pystr_format(string_format="PA-??")

    @validator("receive_time", pre=True, always=True)
    def set_receive_time(cls, v, *, values):
        return v or values.get("timestamp")

    @validator("start_time", pre=True, always=True)
    def set_start_time(cls, v, *, values):
        return v or (
            values.get("timestamp") - timedelta(seconds=values.get("duration"))
        )

    @validator("tunnel_start_time", pre=True, always=True)
    def set_tunnel_start_time(cls, v, *, values):
        return v or (
            values.get("timestamp") - timedelta(seconds=values.get("duration"))
        )

    @validator("tunnel_type", pre=True, always=True)
    def set_tunnel_type(cls, v):
        return v or fake.pystr_format(string_format="???-??-???")

    @validator("future_use1", pre=True, always=True)
    def set_future_use1(cls, v, *, values):
        return (
            v
            or f'{values.get("timestamp").strftime("%b %m %H:%M:%S")} {fake.hostname()} {fake.pyint(max_value=999)} <{fake.pyint(max_value=200)}>1 {values.get("timestamp").isoformat()} {fake.hostname()} {fake.hostname()} - {fake.hostname()} - 1'
        )

    def generate(self, by_alias: bool = True, exclude_none: bool = True):
        results = json.loads(self.json(by_alias=by_alias, exclude_none=exclude_none))
        return f"{','.join([str(results[k]) for k in SYSLOG_FIELDS])}"
        #  return self.json(by_alias=by_alias, exclude_none=exclude_none)
