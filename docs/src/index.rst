.. SALO documentation master file, created by
   sphinx-quickstart on Mon Nov  1 13:42:45 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: https://splunk.github.io/salo/src/_static/salo-600x182.png
   :target: https://github.com/splunk/salo

==================
SALO Documentation
==================

Synthetic Adversarial Log Objects (SALO) is a framework for the generation of log events without the need
for infrastructure or actions to initiate the event that causes a log event. The purpose of this
framework is to allow security practitioners, data scientists, and researchers the ability to create log
events in a simple, repeatable, and randomized way without the overhead of traditional required resources.


Why SALO?
*********

In the past, in order to generate simple network security logs, such as DNS queries for a malicious domain,
it would be required to build one or more servers, as well as a network monitoring solution to capture
events. Additionally, the DNS queries would have to be sent to a resolver with no simple way to construct
custom requests or responses. This process can be time consuming, present technical and financial hurdles,
and be extremely cumbersome or difficult to accomplish. This is especially so for more complex scenarios
that may require highly technical deployments of software, services, and/or cloud native technology. 

SALO seeks to simplify the task of creating and collecting log events from any source that generates
them by constructing models for such events and a simple method for defining attributes and their values.


Quick Start
***********

Create a new `venv <https://docs.python.org/3/library/venv.html>`_ for SALO::


    $ python3 -m venv ~/.venv/salo

Activate the new ``venv`` environment::


    $ source ~/.venv/salo/bin/activate


Clone the respository::


    $ git clone https://github.com/splunk/salo


Change directories to the newly cloned one::


    $ cd salo


Then, install SALO and neccessary requirements::


    $ pip3 install -e .


Once installed, you can simply run ``salo``. Multiple example `recipes` can be found in the ``examples/recipes/`` folder::


    $ salo recipe examples/recipes/beacon.yaml



Example Scenario
****************


Let's suppose we want to generate a simple log event from Zeek in the form of a DNS query. We can create
a new `recipe` in a file called ``dns.yaml``:


.. code-block:: yaml


    sessions:
        - event: salo.events.zeek.DNSModel


Now, we can run ``salo`` with this `recipe`, to produce::


    $ salo recipe dns.yaml | jq


Which will produce something similar to:

.. code-block:: json


    {
      "ts": "2021-11-01T13:21:14Z",
      "uid": "C8Fk5zpofVMzoBhn8D",
      "id.orig_h": "172.16.190.191",
      "id.orig_p": 49914,
      "id.resp_h": "209.39.178.20",
      "id.resp_p": 53,
      "proto": "tcp",
      "trans_id": 53305,
      "rtt": 1.49349329260705,
      "query": "web-44.howell-vaughn.com",
      "qclass": 1,
      "qclass_name": "C_INTERNET",
      "qtype": 5,
      "qtype_name": "CNAME",
      "rcode": 0,
      "rcode_name": "NOERROR",
      "AA": true,
      "TC": false,
      "RD": false,
      "RA": false,
      "Z": 0,
      "answers": [],
      "rejected": false
    }


We can see here that SALO generated a new log event just as Zeek would, but without the need for any 
additional resources or software. All of the data in the event are generated automatically without the
need to specifically define any values. SALO allows for every value to be customized within the
`recipe`, making the log generation extremely powerful and flexible. For instance, we can define the
`query` value by making a small change to the above `recipe`:

.. code-block:: yaml


    sessions:
        - event: salo.events.zeek.DNSModel
          options:
            dns_query: deftsecurity.com


Now, if we run the same command, we can see that `query` will have a value of `deftsecurity.com`:

.. code-block:: json


    {
      "ts": "2021-11-01T13:27:51Z",
      "uid": "CG76aJw9ds4wE4oxEM",
      "id.orig_h": "10.133.26.158",
      "id.orig_p": 57670,
      "id.resp_h": "110.189.62.162",
      "id.resp_p": 53,
      "proto": "tcp",
      "trans_id": 29972,
      "rtt": 1.5927651649765,
      "query": "deftsecurity.com",
      "qclass": 1,
      "qclass_name": "C_INTERNET",
      "qtype": 2,
      "qtype_name": "NS",
      "rcode": 2,
      "rcode_name": "SERVFAIL",
      "AA": true,
      "TC": false,
      "RD": false,
      "RA": false,
      "Z": 0,
      "rejected": false
    }


We can even go one step further, and chain this log event with another, such as a Zeek Connection
log event. In this case, we'll add the ``spawns`` configuration option to our example:

.. code-block:: yaml


    sessions:
      - event: salo.events.zeek.DNSModel
        options:
          dns_query: deftsecurity.com
        spawns:
          - event: salo.events.zeek.ConnModel


Now we can see two log events have been generated. One for the DNS query, and another corresponding
log event for the connection, which automatically have overlapping values:

.. code-block:: json



    {
      "ts": "2021-11-01T14:05:08Z",
      "uid": "CmTvCVkHFJD2gXo0LV",
      "id.orig_h": "192.168.155.219",
      "id.orig_p": 60387,
      "id.resp_h": "206.23.9.82",
      "id.resp_p": 53,
      "proto": "udp",
      "trans_id": 39899,
      "rtt": 0.60784220271283,
      "query": "deftsecurity.com",
      "qclass": 1,
      "qclass_name": "C_INTERNET",
      "qtype": 2,
      "qtype_name": "NS",
      "rcode": 3,
      "rcode_name": "NXDOMAIN",
      "AA": true,
      "TC": false,
      "RD": true,
      "RA": false,
      "Z": 0,
      "rejected": false
    }
    {
      "ts": "2021-11-01T14:05:09Z",
      "uid": "CmTvCVkHFJD2gXo0LV",
      "id.orig_h": "192.168.155.219",
      "id.orig_p": 60387,
      "id.resp_h": "206.23.9.82",
      "id.resp_p": 53,
      "proto": "udp",
      "service": "dns",
      "duration": 4.88802234168719,
      "orig_bytes": 7002,
      "resp_bytes": 5235,
      "conn_state": "RSTR",
      "missed_bytes": 164,
      "history": "ShADTadtfFr",
      "orig_pkts": 9028,
      "orig_ip_bytes": 8946,
      "resp_pkts": 9241,
      "resp_ip_bytes": 4615
    }


For more advanced use cases of SALO, take a look at some example `recipes <examples/recipes/>`_.

----------------------------------------------------------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   gettingstarted
   recipes
   faq 

.. toctree::
   :maxdepth: 2
   :caption: Development Guide

   events
   stencils
   outputs
   framework
   autoapi/index

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
