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

from datetime import datetime, timedelta
import random
from typing import Optional, Union

from croniter import croniter
from dateutil import parser as parser


class Cadence:
    DEFAULT_CADENCE = "*/1 * * * * *"

    def __init__(
        self,
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
        jitter_max: Optional[int] = None,
        jitter_min: Optional[int] = None,
        cadence: Optional[str] = None,
    ) -> None:
        """
        Timestamp cadance class

        Ensures somewhat random timestamps based on a cron-like configuration

        """
        if start and isinstance(start, str):
            start = parser.parse(start)
        self.start = start or datetime.now()
        if end and isinstance(end, str):
            end = parser.parse(end)
        self.end = end
        self.jitter_min = jitter_min if jitter_min is not None else 0
        self.jitter_max = jitter_max if jitter_max is not None else 0
        self.cadence_str = cadence or self.DEFAULT_CADENCE
        self.cadence = croniter(self.cadence_str, self.start)

    def next(self) -> datetime:
        """
        Get next timestamp in cadence

        """
        return self.jitter(self.cadence.get_next(datetime))

    def current(self) -> datetime:
        """
        Get the current timestmapp in cadence

        """
        return self.cadence.get_current()

    def jitter(self, current: datetime) -> datetime:
        """
        Introduce random jitter to timestamp ensuring delta is not precise

        """
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        next = current + timedelta(seconds=jitter)
        self.set_current(next)
        return next

    def set_current(self, current: Union[str, datetime]) -> None:
        """
        Set the current timestamp to a new value

        """
        current = self.parse_time(current)
        self.cadence.set_current(current)

    def parse_time(self, dt: Union[str, datetime]) -> datetime:
        """
        Parse a value to ensure it is a datetime object
        """
        if isinstance(dt, str):
            dt: datetime = parser.parse(dt)
        return dt

    def update_cadence(
        self,
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
        jitter_min: Optional[int] = None,
        jitter_max: Optional[int] = None,
        cadence: Optional[str] = None,
    ) -> None:
        """
        Update cadence of timestamps

        """
        start = self.parse_time(start or self.current())
        if jitter_min is not None:
            self.jitter_min = jitter_min
        if jitter_max is not None:
            self.jitter_max = jitter_max
        self.cadence = croniter(cadence or self.cadence_str, start)
