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
from typing import List, Optional

from pydantic import Field, root_validator, validator

from .base import ZeekModel, random_fuid, random_uid


class FilesModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/frameworks/files/main.zeek.html#type-Files::Info",
        "https://docs.zeek.org/en/master/logs/files.html",
    ]
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    fuid: str = Field(default_factory=random_fuid)
    tx_hosts: Optional[List[str]] = None
    rx_hosts: Optional[List[str]] = None
    conn_uids: Optional[List[str]] = None
    source: str = Field(default="HTTP")
    depth: Optional[int] = None
    analyzers: Optional[List[str]] = None
    mime_type: str = Field(default_factory=fake.mime_type)
    duration: Optional[float] = None
    is_orig: Optional[bool] = None
    seen_bytes: Optional[int] = None
    total_bytes: Optional[int] = None
    missing_bytes: int = Field(default=0)
    overflow_bytes: int = Field(default=0)
    timedout: Optional[bool] = None
    parent_fuid: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    extracted: Optional[str] = None
    extracted_cutoff: Optional[bool] = None
    extract_size: Optional[int] = None

    @root_validator(pre=True)
    def set_fields(cls, values):
        values["tx_hosts"] = values.get(
            "tx_hosts", [values.get("dest_ip", fake.ipv4())]
        )
        values["rx_hosts"] = values.get("rx_hosts", [values.get("src_ip", fake.ipv4())])
        values["conn_uids"] = values.get("conn_uids", [values.get("uid", random_uid())])
        values["fuid"] = values.get("fuid", random_fuid())
        values["source"] = values.get("source", "HTTP")
        values["extracted"] = f"{values['source']}-{values['fuid']}.exe"
        values["total_bytes"] = values.get("total_bytes", fake.pyint())
        if fake.boolean(chance_of_getting_true=95):
            values["seen_bytes"] = values["total_bytes"]
        elif fake.boolean(chance_of_getting_true=50):
            values["seen_bytes"] = fake.pyint(max_value=values["total_bytes"] / 2)
        else:
            values["seen_bytes"] = values["total_bytes"] - fake.pyint(
                max_value=values["total_bytes"]
            )
        if values["total_bytes"] > values["seen_bytes"]:
            values["missing_bytes"] = abs(values["total_bytes"] - values["seen_bytes"])
        if values["total_bytes"] < values["seen_bytes"]:
            values["overflow_bytes"] = abs(values["total_bytes"] - values["seen_bytes"])
        return values

    @validator("depth", pre=True, always=True)
    def set_depth(cls, v):
        return v or fake.pyint(min_value=0, max_value=2)

    @validator("duration", pre=True, always=True)
    def set_duration(cls, v):
        return v or fake.pydecimal(positive=True)

    @validator("is_orig", pre=True, always=True)
    def set_is_orig(cls, v):
        return v or fake.boolean(chance_of_getting_true=20)

    @validator("timedout", pre=True, always=True)
    def set_timedout(cls, v):
        return v or fake.boolean(chance_of_getting_true=2)

    @validator("extracted_cutoff", pre=True, always=True)
    def set_extracted_cutoff(cls, v):
        return v or fake.boolean(chance_of_getting_true=1)

    @validator(
        "uid", "src_ip", "src_port", "dest_ip", "dest_port", pre=True, always=True
    )
    def set_conn_info(cls, v):
        return None
