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

    ..  _SaloStencilModel:

    Overview
    ********

    Stencils allow for complex programmatic ``SaloEventModel`` generation. By leveraging Stencils, SALO is able to produce
    events that can easily mimic specific characteristics, tactics, and techniques of an attack. For instance, some malware
    may create command and control (C2) beacons over DNS that leverage TXT records with base64 encoded content.
    A `Stencil` can be created that mimics this specific pattern to ensure ``SaloEventModel`` that are generated appear 
    as close to the attack as possible. 

    As with ``SaloEventModel``, a ``SaloStencilModel`` leverages pydantic for modeling. `Stencils` are identical to
    `Events` in nearly every way, except for the fact that `Stencils` will not generate output by default. They are 
    designed to be used as a model to define specific attributes across one or more ``SaloEventModel``.
    
    Model Fields
    ************

    In order to ensure ``SaloStencilModel`` classes can pass along their values to other ``SaloStencilModel`` and ``SaloEventModel`` objects, SALO
    heavily relies on ``pydantic`` ``Field`` aliases. For example, ``Zeek`` represents the source ip address as ``id.orig_h``, while
    ``suricata`` represents it as ``src_ip``. To accomodate the multitude of variations across log schemas, ``pydantic`` ``Field`` aliases
    are used to define common ``Field`` names across models.  

    Example
    *******

    `Stencils` must be a subclass of the ``SaloStencilModel`` class. Let's explore a simple example of a ``SaloStencilModel``.

    In this example, we will create a `stencil` in ``salo/stencils/badactor.py`` for a DNS Query and HTTP GET request::

        import random
        from typing import List, Optional

        from pydantic import Field, validator

        from salo import SaloStencilModel

        class BadActor(SaloStencilModel):
            dns_query: Optional[str]
            dest_port: int = Field(default=53)
            dns_rcode: int = Field(default=0)
            dns_rcode_name: str = Field(default="NOERROR")
            dns_qtype: int = Field(default=1)
            dns_qtype_name: str = Field(default="A")
            dns_rdata: Optional[List[str]]
            http_method: str = Field(default="GET")
            http_uri: str = Field(default="/bin/fast.cgi?user=root")

            @validator("dns_query", pre=True, always=True)
            def set_dns_query(cls, v):
                return v or random.choice(["badsite.com", "totallydoesntexist.io"])

            @validator("dns_rdata", pre=True, always=True)
            def set_dns_rdata(cls, v):
                return v or random.sample(["1.2.3.4", "5.6.7.8"])


    This `stencil` will ensure that each ``SaloEventModel`` that is spawned from this stencil will be assigned the defined
    attributes above if the ``SaloEventModel`` contains the attributes. Once the ``SaloStencilModel`` has been created, the
    `recipe` must be configured to use the stencil:


    .. code-block:: yaml


        sessions:
          - event: salo.stencils.badactor.BadActor
            spawns:
              - event: salo.events.zeek.DNSModel
                spawns:
                  - event: salo.events.zeek.HTTPModel


    .. note:: Spawned `Events` from a `Stencil` are treated as new `Sessions`, and as such, will generate unique random attributes
             if they are not defined. To ensure attributes are inherited, ``SaloEventModel`` `events` must spawn additional `events`.
             If inherited values are not needed, then there is no need for them to be spawned.

    Once executed, two synthentic log events will be generated. One for DNS and another  for the HTTP request. As you can see,
    the defined values in our `stencil` have automatically pre-populated the neccessary fields:

    .. code-block:: json



        {
          "ts": "2021-11-02T11:05:56Z",
          "uid": "CqxewMpzKDwx3V0CqW",
          "id.orig_h": "192.168.88.172",
          "id.orig_p": 54827,
          "id.resp_h": "201.6.38.99",
          "id.resp_p": 53,
          "proto": "tcp",
          "trans_id": 24991,
          "rtt": 1.1869650984929,
          "query": "totallydoesntexist.io",
          "qclass": 1,
          "qclass_name": "C_INTERNET",
          "qtype": 1,
          "qtype_name": "A",
          "rcode": 0,
          "rcode_name": "NOERROR",
          "AA": true,
          "TC": false,
          "RD": false,
          "RA": false,
          "Z": 0,
          "answers": [
            "1.2.3.4"
          ],
          "TTLs": [
            15585
          ],
          "rejected": false
        }
        {
          "ts": "2021-11-02T11:05:57Z",
          "uid": "CqxewMpzKDwx3V0CqW",
          "id.orig_h": "192.168.88.172",
          "id.orig_p": 54827,
          "id.resp_h": "201.6.38.99",
          "id.resp_p": 53,
          "trans_depth": 10,
          "method": "GET",
          "host": "davies-patterson.net",
          "uri": "/bin/fast.cgi?user=root",
          "version": "1.0",
          "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 4.0; Trident/5.1)",
          "request_body_len": 7162,
          "response_body_len": 2689,
          "status_code": 301,
          "status_msg": "Redirect",
          "tags": []
        }


    API
    ***

"""

from pydantic import BaseModel


class SaloStencilModel(BaseModel):
    class Config:
        allow_population_by_field_name = True
        validate_assignment = True
        allow_reuse = True
