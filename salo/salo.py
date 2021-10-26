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

import importlib
import os
from pathlib import Path
import random
import sys
from typing import Any, Dict, Generator, List, Optional, Union

from faker import Factory
from pydantic.error_wrappers import ValidationError
from pydantic.main import ModelMetaclass
import yaml

from salo.cadence import Cadence
from salo.events import SaloEventModel
from salo.stencils import SaloStencilModel


"""

    ..  _framework:


"""

SALO_PATH = os.getenv("SALO_PATH")
if SALO_PATH:
    sys.path.append(SALO_PATH)

# Create a fake factory for Salo Event objects
fake = Factory.create()


class Session:
    def __init__(
        self,
        model: Dict,
        cadence: Cadence,
        defaults: Dict,
        saved_values: Optional[Dict] = None,
    ) -> None:
        """
        Salo class to spawn Event objects and ensure event attributes are synchronized

        """
        self.spawns: List[Union[SaloEventModel, SaloStencilModel]] = []
        self.cadence = cadence
        self.saved_values = saved_values or {}
        self.spawn(model, defaults)

    def spawn(self, model: Dict, options: Dict) -> None:
        """
        Iterate over event objects in recipe, generate Event objects, and spawn
        additional child Event objects.

        """
        for repeat in range(model.get("repeat", 1)):
            event = Event(model, self, options)
            if event.event and event.should_run:
                self.spawns.append(event.event)
                for spawn in event.spawns:
                    self.spawn(model=spawn, options=event.options.copy())

    def __repr__(self):
        return f"Session({self.spawns})"

    def generate(self, with_stencils: bool = False) -> Generator:
        """
        Iterate over Event objects for this Session

        """
        for spawn in self.spawns:
            if isinstance(spawn, SaloStencilModel) and with_stencils == False:
                continue
            yield spawn

    def __len__(self):
        return len(self.spawns)


class Sessions:
    def __init__(
        self,
        config: str,
        outputs: Optional[List] = None,
        output_config: Optional[str] = None,
    ) -> None:
        """
        Salo class for collecting and managing Session objects

        """
        self.config = self.load_config(Path(config))
        self.sessions: List[Session] = []
        self.defaults: Dict = self.config.get("options", {})
        self.scenario: Optional[str] = self.config.get("scenario", None)
        self.cadence = Cadence(**self.config.get("time", {}))
        self.saved_values: Dict = {}
        self.output_config = (
            self.load_config(Path(output_config)) if output_config else {}
        )
        self.outputs = outputs or []

        for model in self.config.get("sessions", []):
            self.create_session(model)

    def load_config(self, config: Path) -> Dict:
        """
        Load Salo configuration file for recipe or output

        """
        with config.open() as f:
            return yaml.safe_load(f)

    def create_session(self, model: Dict) -> None:
        """
        Create a new Session object for this collection of Sessions
        """
        session = Session(model, self.cadence, self.defaults.copy(), self.saved_values)
        self.saved_values.update(session.saved_values)
        self.sessions.append(session)

    def generate(self, with_stencils: bool = False) -> Generator:
        """
        Iterate over Event objects for each Session object

        """
        for session in self.sessions:
            for spawn in session.spawns:
                if isinstance(spawn, SaloStencilModel) and with_stencils == False:
                    continue
                yield spawn

    def save(self) -> None:
        """
        Pass all Sessions to outputs for saving/post-processing

        """
        for output in self.outputs:
            out = output(self.output_config)
            out.save(self)

    def __repr__(self):
        return f"Sessions({self.sessions})"

    def __len__(self):
        return sum(len(s) for s in self.sessions)


class Event:
    def __init__(
        self, model: Dict, session: Session, options: Dict, exclude_none: bool = True
    ) -> None:
        """
        Salo Event object for generating individual log events

        """

        self.module: ModelMetaclass = self._load_model(model["event"])
        self.save_values: Dict = model.get("save_values") or {}
        self.options: Dict = options.copy()
        self.model_options: Dict = model.get("options") or {}
        self.session: Session = session
        self.time: Dict = model.get("time") or {}
        self.spawns: List[Dict] = model.get("spawns") or []
        self.should_run: bool = fake.boolean(
            chance_of_getting_true=model.get("likelihood", 100)
        )
        self.exclude_none = exclude_none
        self.event: Optional[Union[SaloEventModel, SaloStencilModel]] = None

        if self.should_run:
            self.run()

    def run(self) -> None:
        """
        Create log event

        """
        self.set_options()
        try:
            self.event: Union[SaloEventModel, SaloStencilModel] = self.module(
                **self.options
            )
        except ValidationError as e:
            print(e)
            print(f"  Options: {self.options}")
            return
        # NOTE: In some cases (such as with suricata models), it may be needed to handle
        #       the model options differently, such as nested dict()'s. If so, we will
        #       need a method get_options(), which is essentially a wrapper for `dict()`.
        #       Otherwise, just jump the model as a normal `dict()`.
        if hasattr(self.event, "get_options"):
            event_options = self.event.get_options(
                by_alias=False, exclude_none=self.exclude_none
            ).copy()
        else:
            event_options = self.event.dict(
                by_alias=False, exclude_none=self.exclude_none
            ).copy()
        self.options.update(event_options)
        self.update_saved_values(self.event)

    def update_cadence(self) -> None:
        """
        Update the cadence and timestamp for this Event

        """
        # timestamp precedence:
        #  1) time: start
        #  2) options: timestamp
        #  3) parent model timestamp
        #  4) datetime.now()
        if "timestamp" in self.options and not "start" in self.time:
            self.time["start"] = self.options["timestamp"]
        if self.time:
            self.session.cadence.update_cadence(**self.time)
        self.options["timestamp"] = self.session.cadence.next()

    def update_saved_values(
        self, event: Union[SaloStencilModel, SaloEventModel]
    ) -> None:
        """
        Ensure saved_values are updated if defined in the recipe

        """
        for k, v in self.save_values.items():
            if hasattr(event, v):
                self.session.saved_values[k] = getattr(event, v)

    def get_saved_value(
        self, key: str, index: Optional[int] = None, is_random: bool = False
    ) -> Any:
        """
        Set the value of an attribute for the event if a saved_value exists and is defined

        """
        value = self.session.saved_values.get(key)
        if isinstance(value, list):
            if is_random:
                return random.choice(value)
            elif index is not None:
                if index >= len(value):
                    raise Exception(f"'{key}' has no index of '{index}'")
                else:
                    return value[index]
        return value

    def set_options(self) -> None:
        """
        Set Event options

        """
        new_options = self.model_options.copy()
        for k, v in new_options.items():
            if isinstance(v, str):
                if v.startswith("$"):
                    values = v.lstrip("$").split(".")
                    saved_key = values.pop(0)
                    if saved_key in self.session.saved_values:
                        if values:
                            opt = values.pop()
                            if opt == "random":
                                self.model_options[k] = self.get_saved_value(
                                    key=saved_key, is_random=True
                                )
                            else:
                                self.model_options[k] = self.get_saved_value(
                                    key=saved_key, index=int(opt)
                                )
                        else:
                            self.model_options[k] = self.get_saved_value(key=saved_key)
        self.options.update(self.model_options)
        self.update_cadence()

    def save_value(self, key: str, value: str) -> None:
        """
        Update Session object with values if a saved_value is defined

        """
        self.session.saved_values[key] = value

    def _load_model(self, model_path: str) -> ModelMetaclass:
        """
        Import model object defined in recipe

        """
        try:
            module_name, event_name = model_path.rsplit(".", 1)
            module = importlib.import_module(module_name)
            return getattr(module, event_name)
        except (AttributeError, ModuleNotFoundError) as err:
            print(f"Failed to load model {model_path}")
            print(err)
            exit()
