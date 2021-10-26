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

from itertools import zip_longest
from typing import Dict, List, Optional, Union

from pydantic import Field, root_validator, validator

from salo import SaloEventModel, fake

from .base import SuricataModel

MAX_DNS_ID = 65535
MAX_TTL = 28800


class DNSModelFull(SaloEventModel):
    dns_type: Optional[str] = Field(defaults="query")
    dns_id: Optional[int] = None
    dns_version: Optional[str] = None
    dns_qr: Optional[bool] = None
    dns_aa: Optional[bool] = None
    dns_tc: Optional[bool] = None
    dns_rd: Optional[bool] = None
    dns_ra: Optional[bool] = None
    dns_rcode_name: Optional[str] = None
    dns_query: Optional[str] = None
    dns_qtype_name: Optional[str] = None
    dns_rdata: Optional[Union[str, List[str]]] = None
    dns_ttl: Optional[Union[List[int], int]] = None
    dns_answers: Optional[List[Dict]] = None
    dns_grouped: Optional[Dict[str, List]] = None

    class Config:
        fields = {
            "dns_type": "type",
            "dns_id": "id",
            "dns_version": "version",
            "dns_qr": "qr",
            "dns_aa": "aa",
            "dns_tc": "tc",
            "dns_rd": "rd",
            "dns_ra": "ra",
            "dns_rcode_name": "rcode",
            "dns_query": "rrname",
            "dns_qtype_name": "rrtype",
            "dns_rdata": "rdata",
            "dns_ttl": "ttl",
            "dns_answers": "answers",
            "dns_grouped": "grouped",
        }

    @validator("dns_id", pre=True, always=True)
    def set_dns_id(cls, v):
        return v or fake.pyint(max_value=MAX_DNS_ID)

    @validator("dns_qr", pre=True, always=True)
    def set_dns_qr(cls, v):
        return v or fake.boolean(chance_of_getting_true=90)

    @validator("dns_aa", pre=True, always=True)
    def set_aa(cls, v):
        return v or fake.boolean(chance_of_getting_true=90)

    @validator("dns_tc", pre=True, always=True)
    def set_tc(cls, v):
        return v or fake.boolean(chance_of_getting_true=1)

    @validator("dns_rd", pre=True, always=True)
    def set_rd(cls, v):
        return v or fake.boolean(chance_of_getting_true=10)

    @validator("dns_ra", pre=True, always=True)
    def set_ra(cls, v):
        return v or fake.boolean(chance_of_getting_true=10)

    @root_validator(pre=True)
    def set_values(cls, values):
        if not "dns_answers" in values:
            answers = []
            if values.get("dns_type") == "answer":
                responses = values.get("dns_rdata", [])
                ttls = values.get("dns_ttl", [])
                if isinstance(responses, str):
                    responses = [responses]
                if isinstance(ttls, int):
                    ttls = [ttls]
                for response, ttl in zip_longest(responses, ttls):
                    answer = {
                        "rrname": values.get("dns_query", fake.hostname()),
                        "rrtype": values.get("dns_qtype_name", "CNAME"),
                        "ttl": ttl or fake.pyint(max_value=MAX_TTL),
                        "rdata": response,
                    }
                    answers.append(answer)
                values["dns_answers"] = answers
                # Ensure these are None so they don't show up in results
                values["dns_rdata"] = None
                values["dns_ttl"] = None
        return values


class DNSModel(SuricataModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/logs/dns.html",
    ]
    event_type: str = Field(default="dns")
    dest_port: int = Field(default=53)
    dns: Optional[Union[DNSModelFull, Dict]] = None

    @root_validator(pre=True)
    def set_values(cls, values):
        values["dns"] = DNSModelFull(**values)
        return values

    def get_options(self, *args, **kwargs) -> Dict:
        data: Dict = super().dict(*args, **kwargs)
        new_data: Dict = data.copy()
        new_data.update(data.pop("dns"))
        answers: List[Dict] = new_data.get("dns_answers", [])
        if answers:
            new_data["dns_query"] = new_data.get("dns_query", answers[0].get("rrname"))
            new_data["dns_qtype_name"] = new_data.get(
                "dns_qtype_name", answers[0].get("rrtype")
            )
            new_data["dns_ttl"] = new_data.get("dns_ttl", answers[0].get("ttl"))
            new_data["dns_rdata"] = new_data.get("dns_rdata", answers[0].get("rdata"))
        return new_data
