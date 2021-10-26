[![Docs](https://img.shields.io/badge/documentation-latest-blue)](https://splunk.github.io/salo)
[![GitHub](https://img.shields.io/github/license/splunk/salo)](https://github.com/splunk/salo/blob/main/LICENSE)
[![python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org)



[![Logo](/docs/src/_static/salo-600x182.png)](#)


## Synthetic Adversarial Log Objects (SALO)

Synthetic Adversarial Log Objects (SALO) is a framework for the generation of log events without the need
for infrastructure or actions to initiate the event that causes a log event. The purpose of this
framework is to allow security practitioners, data scientists, and researchers the ability to create log
events in a simple, repeatable, and randomized way without the overhead of traditional required resources.

Want to learn more? Take a look at the [documentation](https://splunk.github.io/salo).

## Why SALO?

In the past, in order to generate simple network security logs, such as DNS queries for a malicious domain,
it would be required to build one or more servers, as well as a network monitoring solution to capture
events. Additionally, the DNS queries would have to be sent to a resolver with no simple way to construct
custom requests or responses. This process can be time consuming, present technical and financial hurdles,
and be extremely cumbersome or difficult to accomplish. This is especially so for more complex scenarios
that may require highly technical deployments of software, services, and/or cloud native technology. 

SALO seeks to simplify the task of creating and collecting log events from any source that generates
them by constructing models for such events and a simple method for defining attributes and their values.

## Demo
[![Demo](/docs/src/_static/salo-demo.gif)](#)


## Quick Start

Create a new [venv](https://docs.python.org/3/library/venv.html) for SALO:

```bash
$ python3 -m venv ~/.venv/salo
```

Activate the new ``venv`` environment:

```bash
$ source ~/.venv/salo/bin/activate
```

Clone the respository:

```bash
$ git clone https://github.com/splunk/salo
```

Change directories to the newly cloned one:

```bash
$ cd salo
```

Then, install SALO and neccessary requirements:

```bash
$ pip3 install -e .
```

Once installed, you can simply run ``salo``. Multiple example `recipes` can be found in the [examples/recipes/ folder](examples/recipes/):

```bash
$ salo recipe examples/recipes/beacon.yaml
```

For more advanced use cases of SALO, take a look at some [example recipes](examples/recipes/) as well as the [project documentation](https://splunk.github.io/salo).

## Support

This software is released as-is. Splunk provides no warranty and no support on this software.

## License

Copyright 2021 Splunk Inc.
 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
