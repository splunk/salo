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

    .. _SaloOutputs:


    Overview
    ********

    Outputs are a means to produce and save output from a SALO recipe. One or more can be defined, allowing to save results to multiple
    locations. The current outputs supported are:

        - Console
        - Local File
        - Splunk

    .. note:: If no `output` is defined, generated events will be printed to the console.


    Configuration File
    ******************

    To simplify outputs, it is possible to customize how and where log output is handled. This can be done via a configuration file.
    The configuration for `outputs` is a simple YAML file. Let's take a look at an example from the default ``outputs.yaml`` file.

    The initial key, ``salo.events.suricata``, is the root object that is matched when saving log output. If the ``SaloEventModel``
    class starts with ``salo.events.suricata``, then this configuration will be used to save the output. SALO will iterate over each
    key defined in ``outputs`` and save to the appropriate output object:

    .. code-block:: yaml


        salo.events.suricata:
          outputs:
            file:
              path: suricata/eve.log
            splunk:
              index: salo
              sourcetype: suricata


    It is also possible to match against more specific ``SaloEventModel`` classes. In this case, let's take a look at a ``Zeek`` output
    from the default ``outputs.yaml`` file:

    .. code-block:: yaml


        salo.events.zeek.dns.DNSModel:
          outputs:
            file:
              path: zeek/dns.log
            splunk:
              index: salo
              sourcetype: "bro:dns:json"


    In this instance, the ``SaloEventModel`` match will have to be the full path to ``salo.events.zeek.dns.DNSModel`` in order to be saved.
    This is useful when more specific logs are needed, such as ``dns.log`` or ``http.log``.


    API
    ***

"""

from abc import ABC, abstractmethod
from typing import Dict

from salo import Sessions


class SaloOutput(ABC):

    def __init__(self, config: Dict):
        self.config = config

    @abstractmethod
    def save(self, sessions: Sessions) -> None:
        pass

