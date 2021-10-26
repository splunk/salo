.. _installation:

============
Installation
============

Create a new `venv <https://docs.python.org/3/library/venv.html>`_ for SALO::

    $ python3 -m venv ~/.venv/salo


Activate the new ``venv`` environment::

    $ source ~/.venv/salo/bin/activate


.. note:: the path above, ``~/.venv/salo``, can be replaced with your preferred path for ``venv`` environments. 

Clone the respository::

    $ git clone https://github.com/splunk/salo


Change directories to the newly cloned one::

    $ cd salo


Then, install SALO and neccessary requirements::

    $ pip3 install -e .


.. _usage:

=====
Usage
=====

Once installed, you can simply run ``salo``. Multiple example `recipes` can be found in the ``examples/recipes/`` folder::

    $ salo recipe examples/recipes/beacon.yaml


Viewing Event Schema
********************

`Event schemas` define the attributes of a specific log event. When building a `recipe`, it is useful to view an `event schema` in order
to properly define attributes for an event or session:: 


    $ salo schema salo.events.zeek.dns.DNSModel


The results will be displayed, which  will include all schema information for the event, to include attribute names as well as their aliases:

.. code-block:: json 


    {
      "definitions": {
        "DNSModel": {
          "title": "DNSModel",
          "type": "object",
          "properties": {
            "timestamp": {
              "description": "Log event timestamp",
              "type": "string",
              "format": "date-time"
            },
            "uid": {
              "description": "Zeek unique ID",
              "type": "string"
            },
            "src_ip": {
              "description": "Source ip address of connection",
              "type": "string",
              "format": "ipvanyaddress"
            },
            "src_port": {
              "description": "Source port of the connection",
              "type": "integer"
            },
            "dest_ip": {
              "description": "Destination ip address of connection",
              "type": "string",
              "format": "ipvanyaddress"
            },
            "dest_port": {
              "description": "Destination port of the connection",
              "type": "integer"
            },
            "proto": {
              "type": "string"
            },
            "dns_id": {
              "type": "integer",
              "alias": "trans_id"
            },
            "dns_rtt": {
              "type": "number",
              "alias": "rtt"
            },
            "dns_query": {
              "type": "string",
              "alias": "query"
            },
            "dns_qclass": {
              "type": "integer",
              "alias": "qclass"
            },
            "dns_qclass_name": {
              "type": "string",
              "alias": "qclass_name"
            },
            "dns_qtype": {
              "type": "integer",
              "alias": "qtype"
            },
            "dns_qtype_name": {
              "type": "string",
              "alias": "qtype_name"
            },
            "dns_rcode": {
              "type": "integer",
              "alias": "rcode"
            },
            "dns_rcode_name": {
              "type": "string",
              "alias": "rcode_name"
            },
            "dns_aa": {
              "type": "boolean",
              "alias": "AA"
            },
            "dns_tc": {
              "type": "boolean",
              "alias": "TC"
            },
            "dns_rd": {
              "type": "boolean",
              "alias": "RD"
            },
            "dns_ra": {
              "type": "boolean",
              "alias": "RA"
            },
            "dns_z": {
              "default": 0,
              "type": "integer",
              "alias": "Z"
            },
            "dns_rdata": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              ],
              "alias": "answers"
            },
            "dns_ttl": {
              "anyOf": [
                {
                  "type": "integer"
                },
                {
                  "type": "array",
                  "items": {
                    "type": "integer"
                  }
                }
              ],
              "alias": "TTLs"
            },
            "dns_rejected": {
              "type": "boolean",
              "alias": "rejected"
            },
            "dns_auth": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "alias": "auth"
            },
            "dns_addl": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "alias": "addl"
            },
            "dns_original_query": {
              "type": "string",
              "alias": "original_query"
            }
          },
          "required": [
            "dns_qclass",
            "dns_qclass_name",
            "dns_qtype",
            "dns_qtype_name",
            "dns_rcode",
            "dns_rcode_name"
          ]
        }
      }
    }


Result Output
*************

Output from SALO is handled modularly. There are currently three output modules supported:

    - Console
    - File
    - Splunk HTTP Event Collector (HEC)

If no output module is defined, then SALO will default to `Console` output. Default output 
configurations can be defined in the ``output.yaml`` file. This file can also be customized 
to ensure generated event logs are saved in the desired location. 

As an example, configure the output  for ``salo.events.zeek.dns.DNSModel``, we would create:

.. code-block:: yaml


    salo.events.zeek.dns.DNSModel:
      outputs:
        file:
          path: zeek/dns.log
        splunk:
          index: salo
          sourcetype: "bro:dns:json"


This will resule in both the ``file`` and ``splunk`` outputs for the `event model` ``salo.events.zeek.dns.DNSModel``.
In this case, each `Zeek` event model needs to be defined and configured. However, if the desire was to save all `Zeek`
events to one file, it is possible to change the event model definition like so:

.. code-block:: yaml


    salo.events.zeek:
      outputs:
        file:
          path: zeek/zeek.log
        splunk:
          index: salo
          sourcetype: "bro::json"


SALO will match for the beginning values of the event model definition when determining the output configuration to use. By
doing so, it can help to simplify outputs for events that may be less complex. 


.. note:: Multiple outputs can be used simulatenously. Simply use the command line argument for each of the output modules you would like to use.


Console
^^^^^^^

SALO will default to the `Console` output. No further configuration is required.

File
^^^^

Generated event logs can be saved to files on disk for later use. The configuration for `outputs` must be configured for the individual
event, as outlined above. Once configured, simply add the ``--file`` command line argument::

    $ salo recipe examples/recipes/beacon.yaml --file


Splunk
^^^^^^

To save results to Splunk, an HTTP Event Collector (HEC) must be configured and enabled. Please refer to the Splunk documentation on how to 
`set up and use HTTP Event Collector in Splunk Web <https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector>`_.

Once a Splunk HEC endpoint is enabled and a token has been generated, some environment variables must be set::

    export SPLUNK_HOST="127.0.0.1"
    export SPLUNK_TOKEN="YOUR_TOKEN_HERE"

Now, you're all set to insert event logs directly into Splunk::

    $ salo recipe examples/recipes/beacon.yaml --splunk

