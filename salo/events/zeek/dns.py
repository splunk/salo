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

from salo import fake
import random
from typing import List, Optional, Union

from pydantic import Field, validator, root_validator

from .base import ZeekModel

MAX_TRANS_ID = 65535
MAX_RTT = 2
MAX_TTL = 28800

Q_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "*",
}

Q_CLASSES = {1: "C_INTERNET"}

RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}


class DNSModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info",
        "https://docs.zeek.org/en/master/logs/dns.html",
    ]
    proto: Optional[str] = None
    dns_id: Optional[int] = None
    dns_rtt: Optional[float] = None
    dns_query: str = Field(default_factory=fake.hostname)
    dns_qclass: int
    dns_qclass_name: str
    dns_qtype: int
    dns_qtype_name: str
    dns_rcode: int
    dns_rcode_name: str
    dns_aa: Optional[bool] = None
    dns_tc: Optional[bool] = None
    dns_rd: Optional[bool] = None
    dns_ra: Optional[bool] = None
    dns_z: int = Field(default=0)
    dns_rdata: Optional[Union[str, List[str]]] = None
    dns_ttl: Optional[Union[int, List[int]]] = None
    dns_rejected: Optional[bool] = None
    dns_auth: Optional[List[str]] = None
    dns_addl: Optional[List[str]] = None
    dns_original_query: Optional[str] = None

    class Config:
        fields = {
            "dns_id": "trans_id",
            "dns_rtt": "rtt",
            "dns_query": "query",
            "dns_aa": "AA",
            "dns_tc": "TC",
            "dns_rd": "RD",
            "dns_ra": "RA",
            "dns_z": "Z",
            "dns_qclass": "qclass",
            "dns_qclass_name": "qclass_name",
            "dns_rcode": "rcode",
            "dns_rcode_name": "rcode_name",
            "dns_qtype": "qtype",
            "dns_qtype_name": "qtype_name",
            "dns_ttl": "TTLs",
            "dns_rdata": "answers",
            "dns_rejected": "rejected",
            "dns_auth": "auth",
            "dns_addl": "addl",
            "dns_original_query": "original_query"
        }

    @validator("dest_port", pre=True, always=True, check_fields=False)
    def set_dest_port(cls, v):
        return v or 53

    @validator("proto", pre=True, always=True)
    def set_proto(cls, v):
        return v or random.choice(["tcp", "udp"])

    @validator("dns_id", pre=True, always=True)
    def set_dns_id(cls, v):
        return v or fake.pyint(max_value=MAX_TRANS_ID)

    @validator("dns_rtt", pre=True, always=True)
    def set_dns_rtt(cls, v):
        return v or fake.pydecimal(right_digits=14, positive=True, max_value=MAX_RTT)

    @validator("dns_aa", pre=True, always=True)
    def set_dns_aa(cls, v):
        return v or fake.boolean(chance_of_getting_true=90)

    @validator("dns_tc", pre=True, always=True)
    def set_dns_tc(cls, v):
        return v or fake.boolean(chance_of_getting_true=1)

    @validator("dns_rd", pre=True, always=True)
    def set_rd(cls, v):
        return v or fake.boolean(chance_of_getting_true=10)

    @validator("dns_ra", pre=True, always=True)
    def set_ra(cls, v):
        return v or fake.boolean(chance_of_getting_true=10)

    @validator("dns_rejected", pre=True, always=True)
    def set_dns_rejected(cls, v):
        return v or fake.boolean(chance_of_getting_true=1)

    @validator("dns_rdata", pre=True, always=True)
    def set_dns_rdata(cls, v):
        if isinstance(v, str):
            return [v]
        return v

    @validator("dns_ttl", pre=True, always=True)
    def set_dns_ttl(cls, v, *, values):
        if isinstance(v, int):
            return [v]
        elif values.get('dns_rdata'):
            return [
                fake.pyint(max_value=MAX_TTL) for _ in range(len(values["dns_rdata"]))
            ]
        else:
            return v

    @root_validator(pre=True)
    def set_values(cls, values) -> None:
        values["dns_qclass"] = values.get("dns_qclass", random.choice(list(Q_CLASSES.keys())))
        values["dns_qclass_name"] = values.get("dns_qclass_name", Q_CLASSES[values["dns_qclass"]])
        values["dns_qtype"] = values.get("dns_qtype", random.choice(list(Q_TYPES.keys())))
        values["dns_qtype_name"] = values.get("dns_qtype_name", Q_TYPES[values["dns_qtype"]])
        values["dns_rcode"] = values.get("dns_rcode", random.choice(list(RCODES.keys())))
        values["dns_rcode_name"] = values.get("dns_rcode_name", RCODES[values["dns_rcode"]])
        if values["dns_rcode"] == 0 and not values.get("dns_rdata"):
            answers = []
            if values["dns_qtype"] in (1, 2):
                answers = [fake.ipv4_public() for _ in range(fake.pyint(max_value=10))]
            elif values["dns_qtype"] == 15:
                answers = [
                    f"mx.{fake.domain_name()}" for _ in range(fake.pyint(max_value=4))
                ]
            elif values["dns_qtype"] == 28:
                answers = [fake.ipv6() for _ in range(fake.pyint(max_value=10))]
            values["dns_rdata"] = answers
        return values
