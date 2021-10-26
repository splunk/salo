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
from datetime import datetime
import random
from typing import Optional

from pydantic import BaseModel, Field, validator

from salo import SaloEventModel, fake


class ActorLocationModel(BaseModel):
    country_code: str = Field(default_factory=fake.country_code)


class GitHubAuditModel(SaloEventModel):
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Log event timestamp",
    )
    github_document_id: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: int(v.timestamp())}
        fields = {
            "timestamp": "@timestamp",
            "github_action": "action",
            "github_active": "active",
            "github_actor": "actor",
            "github_actor_location": "actor_location",
            "github_business": "business",
            "github_config": "config",
            "github_config_was": "config_was",
            "github_created_at": "created_at",
            "github_document_id": "_document_id",
            "github_events": "events",
            "github_events_were": "events_were",
            "github_hook_id": "hook_id",
            "github_name": "name",
            "github_org": "org",
            "github_repo": "repo",
            "github_repository": "repository",
            "github_repository_public": "repository_public",
            "github_team": "team",
            "github_transport_protocol": "transport_protocol",
            "github_transport_protocol_name": "transport_protocol_name",
            "github_user": "user",
            "github_visibility": "visibility",
        }

    @validator("github_document_id", pre=True, always=True)
    def set_github_document_id(cls, v):
        return v or b64encode(fake.binary(length=12))

    @validator(
        "github_created_at", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_created_at(cls, v, *, values):
        return v or values.get("timestamp")

    @validator(
        "github_org", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_org(cls, v):
        return v or fake.domain_word()

    @validator(
        "github_business", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_business(cls, v):
        return v or fake.company()

    @validator(
        "github_actor", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_actor(cls, v):
        return v or fake.user_name()

    @validator(
        "github_user", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_user(cls, v):
        return v or fake.user_name()

    @validator(
        "github_name", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_name(cls, v):
        return v or fake.company()

    @validator(
        "github_hook_id", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_hook_id(cls, v):
        return v or random.randint(111111111, 999999999)

    @validator(
        "github_repo", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_repo(cls, v, *, values):
        org = values.get("github_org", fake.domain_word())
        repo = v or "_".join(fake.words(nb=random.randint(1,4)))
        return f"{org}/{repo}"

    @validator(
        "github_repository", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_repository(cls, v, *, values):
        return v or values.get(
            "github_repo", f"{fake.domain_word()}/{fake.domain_word()}"
        )

    @validator(
        "github_visibility", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_visibility(cls, v):
        return v or random.choice(["internal", "private", "public"])

    @validator(
        "github_team", pre=True, always=True, check_fields=False, allow_reuse=True
    )
    def set_github_team(cls, v, *, values):
        org = values.get("github_org", fake.domain_word())
        team = v or fake.domain_word()
        return f"{org}/{team}"

    def generate(self, by_alias: bool = True, exclude_none: bool = True):
        return self.json(by_alias=by_alias, exclude_none=exclude_none)
