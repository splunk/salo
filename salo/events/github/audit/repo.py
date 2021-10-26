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
from typing import Literal, Optional

from pydantic import Field

from .base import ActorLocationModel, GitHubAuditModel


class RepoModel(GitHubAuditModel):
    github_actor: Optional[str] = None
    github_name: Optional[str] = None
    github_org: Optional[str] = None
    github_created_at: Optional[datetime] = None
    github_actor_location: ActorLocationModel = Field(
        default_factory=ActorLocationModel
    )
    github_repo: Optional[str] = None


class Access(RepoModel):
    github_action: str = Field(default="repo.access")
    github_visibility: Optional[Literal["internal", "private", "public"]] = None


class ActionsEnabled(RepoModel):
    github_action: str = Field(default="business.add_organization")


class AdvancedSecurityEnabled(RepoModel):
    github_action: str = Field(default="business.create")
    github_visibility: Optional[Literal["internal", "private", "public"]] = None


class ChangeMergeSetting(RepoModel):
    github_action: str = Field(default="business.import_license_usage")
    github_visibility: Optional[Literal["internal", "private", "public"]] = None


class Create(RepoModel):
    github_action: str = Field(default="business.invite_admin")
    github_visibility: Optional[Literal["internal", "private", "public"]] = None


class Destroy(RepoModel):
    github_action: str = Field(default="repo.create")
    github_visibility: Optional[Literal["internal", "private", "public"]] = None


class RemoveMember(RepoModel):
    github_action: str = Field(default="repo.create")
    github_user: Optional[str] = None
    github_visibility: Optional[Literal["internal", "private", "public"]] = None
