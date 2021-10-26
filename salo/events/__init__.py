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

"""

    ..  _SaloEventModel:

    Overview
    ********

    Events are specific schemas that represent the contruct of a logged event. Event generation is very
    dynamic and flexible, allowing for nearly any logged event to be easily generated once a `SaloEventModel`
    has been created. Once a `SaloEventModel` is created, logged events can easily be customized via a
    recipe or, for more advanced use cases, by leveraging `Stencils`. SALO comes with several `Events` out of
    the box, with more being developed and shared regularly. 

    `SaloEventModel` leverages `pydantic <https://pydantic-docs.helpmanual.io/>`_ for modeling to ensure strict data validation and 
    type checking. If creating a new `SaloEventModel`, it is recommended to have a minimal understanding of ``pydantic``, though 
    being an expert is not a  requirement.

    Model Fields
    ************

    In order to ensure ``SaloEventModel`` classes can pass along their values to other ``SaloEventModel`` and ``SaloStencilModel`` objects, SALO
    heavily relies on ``pydantic`` ``Field`` aliases. For example, ``Zeek`` represents the source ip address as ``id.orig_h``, while
    ``suricata`` represents it as ``src_ip``. To accomodate the multitude of variations across log schemas, ``pydantic`` ``Field`` aliases
    are used to define common ``Field`` names across models.  

    Example
    *******

    `Events` must be a subclass of the ``SaloEventModel`` class. Let's explore a simple example of a ``SaloEventModel``.

    In this example, we will create a ``SaloEventModel`` that produces a simple log output. Our example log event will
    be in JSON:

    .. code-block:: json


        {"source": "test", "src_ip": "1.1.1.1"}


    Let's build our example event model in ``salo/events/example.py``::


        from pydantic import Field, IPvAnyAddress

        from salo import SaloEventModel

        class ExampleModel(SaloEventModel):
            source: str = Field(default="test")
            src_ip: IPvAnyAddress = Field(default="1.1.1.1")

            def generate(self, by_alias: bool = True, exclude_none: bool = True):
                return self.json(by_alias=by_alias, exclude_none=exclude_none)


    .. note:: The ``generate`` method must exist. In this case, we are returning a JSON result. However, any output can be
             returned to include raw text or XML. In some cases, it may be more useful to generate results using a templating
             language, such as `Jinja2 <https://jinja2docs.readthedocs.io/en/stable/>`_.

    Now, we  can simple create a new recipe in ``example.yaml``:

    .. code-block:: yaml


        sessions:
          - event: salo.events.example.ExampleModel

    Once the recipe is executed, ``salogen.py -r example.yaml``, you should see the exact log output we  set out to create:

    .. code-block:: json


        {"source": "test", "src_ip": "1.1.1.1"}


    API
    ***

"""


from typing import Any, Dict

from pydantic import BaseModel


class SaloEventModel(BaseModel):
    class Config:
        allow_population_by_field_name = True
        underscore_attrs_are_private = True
        validate_assignment = True
        allow_reuse = True

        @staticmethod
        def schema_extra(schema: Dict[str, Any], model) -> None:
            if hasattr(model.Config, "fields"):
                config = model.Config.fields
            else:
                config = {}
            for key, prop in schema.get("properties", {}).items():
                if key in config:
                    prop["alias"] = config[key]
                prop.pop("title", None)

    #  TODO: Find a better way to handle schema creation. This method won't
    #        work with nested models. In other words, this won't work and
    #        there doesn't seem to be a good way to ensuring aliases are
    #        mapped properly.
    #  @classmethod
    #  def get_aliases(cls) -> Dict[str, Dict[str, Optional[str]]]:
    #      """ Generate dictionary of attributes, aliases, and descriptions """
    #      schema = cls.schema(by_alias=False)
    #      alias_schema = cls.schema(by_alias=True)
    #      print(cls().dict())
    #      aliases = {}
    #      for schema_results, alias in zip(schema.get('properties', {}).items(), alias_schema.get('properties', {}).keys()):
    #          aliases[schema_results[0]] = {"alias": alias, "description": schema_results[1].get("description")}
    #      return aliases
