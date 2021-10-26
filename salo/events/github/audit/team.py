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
from typing import Optional

from pydantic import Field

from .base import ActorLocationModel, GitHubAuditModel


class TeamModel(GitHubAuditModel):
    github_actor: Optional[str] = None
    github_org: Optional[str] = None
    github_team: Optional[str] = None
    github_created_at: Optional[datetime] = None
    github_actor_location: ActorLocationModel = Field(
        default_factory=ActorLocationModel
    )


class AddMember(TeamModel):
    github_action: str = Field(default="team.add_member")
    github_user: Optional[str] = None


class Create(TeamModel):
    github_action: str = Field(default="team.create")
