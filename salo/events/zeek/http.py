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

from .base import ZeekModel, random_fuid


MAX_FUIDS = 2
HTTP_VERSIONS = ["1.0", "1.1"]
METHODS = ["GET", "POST"]
STATUSES = {
    200: "OK",
    204: "No Content",
    301: "Moved Permanently",
    301: "Redirect",
    302: "Moved Temporarily",
    400: "Bad request",
    401: "Unauthorized",
    404: "Not Found",
    503: "Service Unavailable",
}


class HTTPModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info",
        "https://docs.zeek.org/en/master/logs/http.html",
    ]
    trans_depth: int = fake.pyint(max_value=10)
    http_method: str = Field(default_factory=fake.http_method)
    http_hostname: str = Field(default_factory=fake.domain_name)
    http_uri: str = Field(default_factory=fake.file_path)
    http_referrer: Optional[str] = None
    http_version: Optional[str] = None
    http_user_agent: str = Field(default_factory=fake.user_agent)
    http_origin: Optional[str] = None
    http_request_body_len: int = Field(default_factory=fake.pyint)
    http_response_body_len: int = Field(default_factory=fake.pyint)
    http_status_code: int
    http_status_msg: str
    http_info_code: Optional[int] = None
    http_info_msg: Optional[str] = None
    http_tags: Optional[List] = Field(default_factory=list)
    http_username: Optional[str] = None
    http_password: Optional[str] = None
    http_proxied: Optional[List[str]] = None
    orig_fuids: Optional[List[str]] = None
    orig_filenames: Optional[List[str]] = None
    orig_mime_types: Optional[List[str]] = None
    resp_fuids: Optional[List[str]] = None
    resp_filenames: Optional[List[str]] = None
    resp_mime_types: Optional[List[str]] = None
    http_client_header_names: Optional[List[str]] = None
    http_server_header_names: Optional[List[str]] = None
    http_cookie_vars: Optional[List[str]] = None
    http_uri_vars: Optional[List[str]] = None

    class Config:
        fields = {
            "http_method": "method",
            "http_hostname": "host",
            "http_uri": "uri",
            "http_length": "length",
            "http_status_code": "status",
            "http_referrer": "referrer",
            "http_version": "version",
            "http_user_agent": "user_agent",
            "http_origin": "origin",
            "http_request_body_len": "request_body_len",
            "http_response_body_len": "response_body_len",
            "http_status_code": "status_code",
            "http_status_msg": "status_msg",
            "http_info_code": "info_code",
            "http_info_msg": "info_msg",
            "http_tags": "tags",
            "http_username": "username",
            "http_password": "password",
            "http_proxied": "proxied",
            "http_client_header_names": "client_header_names",
            "http_server_header_names": "server_header_names",
            "http_cookie": "cookie_vars",
            "http_uri_vars": "uri_vars",
        }

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or 80

    @validator("http_version", pre=True, always=True)
    def set_http_version(cls, v):
        if v:
            v = v.lstrip("HTTP/")
        return v or random.choice(HTTP_VERSIONS)

    @root_validator(pre=True)
    def set_values(cls, values):
        values["http_status_code"] = values.get(
            "http_status_code", random.choice(list(STATUSES.keys()))
        )
        values["http_status_msg"] = values.get(
            "http_status_msg", STATUSES[values["http_status_code"]]
        )
        if (
            fake.boolean(chance_of_getting_true=20)
            and values["http_status_code"] == 200
        ):
            values["resp_fuids"] = [
                random_fuid() for _ in range(fake.pyint(max_value=MAX_FUIDS))
            ]
            values["resp_mime_types"] = [
                fake.mime_type() for _ in range(len(values["resp_fuids"]))
            ]
        return values
