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
import base64
from ipaddress import IPv4Network
from typing import List, Literal, Optional, Union

from pydantic import Field, validator

from salo import SaloStencilModel, fake

REGIONS = ["eu-west-1", "us-west-2", "us-east-1", "us-east-2"]

PHASES = {
    "kill": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
        "20.140.0.0/15",
        "96.31.172.0/24",
        "131.228.12.0/22",
        "144.86.226.0/24",
    ],
    "beacon": [
        "8.18.144.0/23",
        "87.238.80.0/21",
        "87.238.80.0/21",
        "71.152.53.0/24",
    ],
    "preactivation": [
        "18.130.0.0/16",
        "99.79.0.0/16",
        "184.72.0.0/15",
    ],
}


class SunBurstDNSQuery(SaloStencilModel):
    sunburst_phase: Literal["kill", "beacon", "preactivation"] = Field(default="beacon")
    dns_query: Optional[str]
    dest_port: int = Field(default=53)
    dns_rcode: int = Field(default=0)
    dns_rcode_name: str = Field(default="NOERROR")
    dns_qtype: int = Field(default=1)
    dns_qtype_name: str = Field(default="A")
    dns_rdata: Optional[Union[str, List[str]]] = None
    proto: str = Field(default="udp")
    service: str = Field(default="dns")

    @validator("dns_query", pre=True, always=True)
    def set_dns_query(cls, v):
        if not v:
            region = random.choice(REGIONS)
            encoded_str = base64.b32encode(
                fake.pystr(min_chars=15, max_chars=15).encode()
            )
            domain = (
                f"{encoded_str.decode().lower()}.appsync-api.{region}.avsvmcloud.com"
            )
            return domain
        return v

    @validator("dns_rdata", pre=True, always=True)
    def set_dns_rdata(cls, v, *, values):
        if not v:
            phase = values.get("sunburst_phase")
            netblock = IPv4Network(random.choice(PHASES[phase]))
            ip = str(netblock[random.randint(0, netblock.num_addresses)])
            return ip
        return v
