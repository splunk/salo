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

from pydantic import BaseModel, AnyHttpUrl, Field, validator

from salo import fake

from .base import ActorLocationModel, GitHubAuditModel


class ConfigModel(BaseModel):
    content_type: str = Field(default="json")
    insecure_ssl: str = Field(default="0")
    url: AnyHttpUrl = Field(default_factory=fake.url)


class HookModel(GitHubAuditModel):
    github_org: Optional[str] = None
    github_created_at: Optional[datetime] = None
    github_active: bool = Field(default=True)
    github_actor: Optional[str] = None
    github_hook_id: Optional[int] = None
    github_name: str = Field(default="webhook")
    github_actor_location: ActorLocationModel = Field(
        default_factory=ActorLocationModel
    )
    github_config: ConfigModel = Field(default_factory=ConfigModel)
    github_events: List[str] = Field(default=["*"])


class Create(HookModel):
    github_action: str = Field(default="hook.create")
    github_repo: Optional[str] = None


class ConfigChanged(HookModel):
    github_action: str = Field(default="hook.config_changed")
    github_config_was: Optional[ConfigModel] = None

    @validator("github_config_was", pre=True, always=True)
    def set_github_config_was(cls, v, *, values):
        return v or values.get("github_config_was", ConfigModel())


class EventsChanged(HookModel):
    github_action: str = Field(default="hook.events_changed")
    github_events_were: Optional[List[str]] = None

    @validator("github_events_were", pre=True, always=True)
    def set_github_events_were(cls, v, *, values):
        return v or values.get("github_events_were", ["*"])
