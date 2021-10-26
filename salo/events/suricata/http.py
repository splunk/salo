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
from typing import Dict, List, Optional, Union

from pydantic import Field, root_validator, validator

from salo import SaloEventModel, fake

from .base import SuricataModel


MAX_FUIDS = 2
HTTP_VERSIONS = ["HTTP/1.0", "HTTP/1.1"]
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


class HTTPModelFull(SaloEventModel):
    http_port: Optional[int] = None
    http_hostname: str = Field(default_factory=fake.domain_name)
    http_uri: str = Field(default_factory=fake.file_path)
    http_user_agent: str = Field(default_factory=fake.user_agent)
    http_content_type: str = Field(default_factory=fake.mime_type)
    http_cookie: Optional[str] = None
    http_length: int = Field(default_factory=fake.pyint)
    http_status_code: Optional[int] = None
    http_version: Optional[str] = None
    http_method: str = Field(default_factory=fake.http_method)
    http_referrer: Optional[str] = None
    http_request_headers: Optional[List[Dict]] = None
    http_response_headers: Optional[List[Dict]] = None

    class Config:
        fields = {
            "http_hostname": "hostname",
            "http_uri": "url",
            "http_cookie": "cookie",
            "http_length": "length",
            "http_status_code": "status",
            "http_version": "protocol",
            "http_referrer": "http_refer",
        }

    @validator("http_version", pre=True, always=True)
    def set_http_version(cls, v):
        if v:
            if not v.startswith("HTTP/"):
                v = "HTTP/" + v
        return v or random.choice(HTTP_VERSIONS)

    @validator("http_status_code", pre=True, always=True)
    def set_http_status_code(cls, v):
        return v or random.choice(list(STATUSES.keys()))


class HTTPModel(SuricataModel):
    _refs: List[str] = [
        "https://suricata.readthedocs.io/en/suricata-6.0.0/output/eve/eve-json-format.html#event-type-http"
    ]
    event_type: str = Field(default="http")
    dest_port: int = Field(default=80)
    http: Optional[Union[HTTPModelFull, Dict]] = None

    @root_validator(pre=True)
    def set_values(cls, values):
        values["http"] = HTTPModelFull(**values)
        return values

    def get_options(self, *args, **kwargs):
        data = super().dict(*args, **kwargs)
        new_data = data.copy()
        new_data.update(data.pop("http"))
        return new_data
