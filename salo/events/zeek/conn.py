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

import random
from typing import List, Optional

from pydantic import Field, root_validator, validator

from salo import fake

from .base import ZeekModel

CONN_STATES = [
    "S0",
    "S1",
    "S2",
    "S3",
    "SF",
    "REJ",
    "RSTO",
    "RSTR",
    "RSTOS0",
    "RSTRH",
    "SH",
    "SHR",
    "OTH",
]

HISTORIES = [
    "D",
    "Dd",
    "S",
    "ShADTadtFf",
    "ShADTadtFfR",
    "ShADTadtFfRR",
    "ShADTadtR",
    "ShADTadtTFf",
    "ShADTadtfF",
    "ShADTadtfFr",
    "ShADTadtfR",
    "ShADTadttTFf",
    "ShADTadttfFr",
    "ShR",
]

SERVICES = {
    "tcp": {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "dns": 53,
        "http": 80,
        "ntp": 123,
        "http,ssl": 443,
        "smtp,ssl": 587,
    },
    "udp": {"dns": 53, "ntp": 123},
}


class ConnModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info",
        "https://docs.zeek.org/en/master/logs/conn.html",
    ]
    proto: str = Field(...)
    service: str = Field(...)
    duration: Optional[float] = None
    orig_bytes: int = Field(default_factory=fake.pyint)
    resp_bytes: int = Field(default_factory=fake.pyint)
    conn_state: Optional[str] = None
    local_orig: Optional[bool] = None
    local_resp: Optional[bool] = None
    missed_bytes: int = Field(default_factory=fake.pyint)
    history: Optional[str] = None
    orig_pkts: int = Field(default_factory=fake.pyint)
    orig_ip_bytes: int = Field(default_factory=fake.pyint)
    resp_pkts: int = Field(default_factory=fake.pyint)
    resp_ip_bytes: int = Field(default_factory=fake.pyint)
    tunnel_parents: Optional[str] = None
    orig_l2_addr: Optional[str] = None
    resp_l2_addr: Optional[str] = None
    vlan: Optional[int] = None
    inner_vlan: Optional[int] = None
    speculative_service: Optional[str] = None

    @validator("duration", pre=True, always=True)
    def set_duration(cls, v):
        return v or fake.pydecimal(right_digits=14, positive=True)

    @validator("conn_state", pre=True, always=True)
    def set_conn_state(cls, v):
        return v or random.choice(CONN_STATES)

    @validator("history", pre=True, always=True)
    def set_history(cls, v):
        return v or random.choice(HISTORIES)

    @root_validator(pre=True)
    def ports_protocols(cls, values):
        values["proto"] = values.get("proto", random.choice(list(SERVICES.keys())))
        values["service"] = values.get(
            "service", random.choice(list(SERVICES[values["proto"]].keys()))
        )
        values["dest_port"] = values.get(
            "dest_port", SERVICES[values["proto"]][values["service"]]
        )
        return values
