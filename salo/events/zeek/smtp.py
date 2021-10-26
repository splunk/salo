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
from typing import List, Optional

from pydantic import Field, IPvAnyAddress, root_validator, validator

from salo import fake

from .base import ZeekModel, random_fuid


MAX_FUIDS = 5
MAX_RCPT = 5
MAX_CC = 10


class SMTPModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/protocols/smtp/main.zeek.html#type-SMTP::Info",
        "https://docs.zeek.org/en/master/logs/smtp.html",
    ]
    dest_port: Optional[int] = Field(default=25)
    smtp_trans_depth: Optional[int] = None
    smtp_helo: str = Field(default_factory=fake.hostname)
    smtp_mailfrom: str
    smtp_rcptto: List[str]
    timestamp: datetime = Field(default_factory=datetime.now)
    smtp_from: str
    smtp_to: List[str]
    smtp_cc: Optional[List[str]] = None
    smtp_reply_to: Optional[str] = None
    smtp_msg_id: Optional[str] = None
    smtp_in_reply_to: Optional[str] = None
    smtp_subject: str = Field(default_factory=fake.text)
    smtp_x_originating_ip: Optional[str] = None
    smtp_first_received: Optional[str] = None
    smtp_second_received: Optional[str] = None
    smtp_last_reply: Optional[str] = None
    smtp_path: Optional[List[IPvAnyAddress]] = None
    smtp_user_agent: str = Field(default_factory=fake.user_agent)
    smtp_tls: Optional[bool] = None
    smtp_process_received_from: Optional[bool] = None
    smtp_has_client_activity: Optional[bool] = None
    smtp_process_smtp_headers: Optional[bool] = None
    smtp_entity_count: Optional[int] = None
    fuids: Optional[List[str]] = None
    smtp_is_webmail: Optional[bool] = None

    class Config:
        fields = {
            "smtp_trans_depth": "trans_depth",
            "smtp_helo": "helo",
            "smtp_mailfrom": "mailfrom",
            "smtp_rcptto": "rcptto",
            "timestamp": "data",
            "smtp_from": "from",
            "smtp_to": "to",
            "smtp_cc": "cc",
            "smtp_reply_to": "reply_to",
            "smtp_msg_id": "msg_id",
            "smtp_in_reply_to": "in_reply_to",
            "smtp_subject": "subject",
            "smtp_x_originating_ip": "x_originating_ip",
            "smtp_first_received": "first_received",
            "smtp_second_received": "second_received",
            "smtp_last_reply": "last_reply",
            "smtp_path": "path",
            "smtp_user_agent": "user_agent",
            "smtp_tls": "tls",
            "smtp_process_received_from": "process_received_from",
            "smtp_has_client_activity": "has_client_activity",
            "smtp_process_smtp_headers": "process_smtp_headers",
            "smtp_entity_count": "entity_count",
            "smtp_is_webmail": "is_webmail",
        }

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or 25

    @validator("smtp_msg_id", pre=True, always=True)
    def set_smtp_msg_id(cls, v):
        return v or f"<{fake.hexify()}${fake.lexify()}${fake.hexify()}@{fake.tld()}>"

    @validator("smtp_trans_depth", pre=True, always=True)
    def set_smtp_trans_depth(cls, v):
        return v or fake.pyint(max_value=5)

    @validator("smtp_path", pre=True, always=True)
    def set_smtp_path(cls, v, *, values):
        src = values.get("src_ip", fake.ipv4())
        dest = values.get("dest_ip", fake.ipv4())
        path = [dest, src]
        return v or path

    @validator("smtp_tls", pre=True, always=True)
    def set_smtp_tls(cls, v):
        return v or fake.boolean(chance_of_getting_true=50)

    @validator("fuids", pre=True, always=True)
    def set_fuids(cls, v):
        fuids = None
        if fake.boolean(chance_of_getting_true=20):
            fuids = [random_fuid() for _ in range(fake.pyint(max_value=MAX_FUIDS))]
        return v or fuids

    @validator("smtp_is_webmail", pre=True, always=True)
    def set_is_webmail(cls, v):
        if fake.boolean(chance_of_getting_true=60):
            is_webmail = fake.boolean(chance_of_getting_true=80)
        else:
            is_webmail = None
        return v or is_webmail

    @root_validator(pre=True)
    def set_values(cls, values) -> None:
        values["smtp_mailfrom"] = values.get("smtp_mailfrom", fake.email())
        values["smtp_rcptto"] = values.get(
            "smtp_rcptto", [fake.email() for _ in range(MAX_RCPT)]
        )
        values["smtp_from"] = values.get(
            "smtp_from", f'"{fake.name()}" <{values["smtp_mailfrom"]}>'
        )
        values["smtp_to"] = values.get(
            "smtp_to", [f'"{fake.name()}" <{e}>' for e in values["smtp_rcptto"]]
        )
        if "smtp_cc" not in values:
            if fake.boolean(chance_of_getting_true=50):
                values["smtp_cc"] = [
                    f'"{fake.name()}" <{fake.email()}>' for _ in range(MAX_CC)
                ]
        return values
