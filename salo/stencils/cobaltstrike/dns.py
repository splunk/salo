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

from base64 import b64encode
import random
from typing import List, Optional

from pydantic import Field, validator

from salo import SaloStencilModel, fake

DOMAINS = [
    "c2.dns.getbobspizza.com",
]


class CobaltStrikeDNSC2(SaloStencilModel):
    dns_query: Optional[str]
    dns_version: int = Field(default=2)
    dns_rcode: int = Field(default=0)
    dns_rcode_name: str = Field(default="NOERROR")
    dns_qtype: int = Field(default=16)
    dns_qtype_name: str = Field(default="TXT")
    dns_rdata: Optional[List[str]]
    dns_ttl: Optional[List[int]] = None
    dns_qa: bool = Field(default=True)
    dns_rd: bool = Field(default=True)
    dns_ra: bool = Field(default=True)
    dns_type: str = Field(default="answer")
    proto: str = Field(default="udp")
    service: str = Field(default="dns")
    dest_port: int = Field(default=53)

    @validator("dns_query", pre=True, always=True)
    def set_dns_query(cls, v):
        random_str = fake.pystr_format(
            string_format="######??#.#?#?#???", letters="abcdef"
        )
        return v or f"api.{random_str}.{random.choice(DOMAINS)}"

    @validator("dns_rdata", pre=True, always=True)
    def set_dns_rdata(cls, v):
        return v or [
            b64encode(fake.binary(length=fake.pyint(min_value=100, max_value=200)))
        ]
