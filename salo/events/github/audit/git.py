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

from typing import Literal, Optional

from pydantic import Field

from salo import fake

from .base import ActorLocationModel, GitHubAuditModel


class GitModel(GitHubAuditModel):
    github_actor: Optional[str] = None
    github_business: Optional[str] = None
    github_org: Optional[str] = None
    github_repo: Optional[str] = None
    github_actor_location: ActorLocationModel = Field(
        default_factory=ActorLocationModel
    )
    github_repository: Optional[str] = None
    github_repository_public: bool = Field(default_factory=fake.pybool)
    github_transport_protocol_name: Literal["http", "ssh"] = Field(default="http")
    github_transport_protocol: int = Field(default=1)


class Push(GitModel):
    github_action: str = Field(default="git.push")


class Clone(GitModel):
    github_action: str = Field(default="git.clone")


class Fetch(GitModel):
    github_action: str = Field(default="git.fetch")
