.. _recipes:

=======
Recipes
=======

SALO `recipes` are a configuration file that define a log generation scenario. With recipes, it is possible to tell SALO what log events
to generate, what their values should be, the order logged events should be in, and many other customizations. They enable SALO to generate
highly flexible and repeatable synthetic log objects in a simple way. There are multiple configuration options available -- let's explore them here.

    
Configuration Options
*********************

Root Options
------------

Root options may only be defined at the `root` of the recipe. Meaning, they may not be used within an `event`. If they are defined elsewhere, they will
simply be ignored.

`sessions`
++++++++++

`sessions` is a list of `event` configuration options. Each item, or session, in the list of sessions will be treated independently of other sessions. 
Each ``event`` in a session will pass along their own attributes to ``spawns`` defined.:

.. code-block:: yaml


    sessions:
      # First session
      - event: salo.event.zeek.ConnModel
        spawns:
          # Attributes from the parent event, ConnModel,  will be passed to each spawned event
          - event: salo.event.zeek.DNSModel
      # Second session
      - event: salo.event.zeek.ConnModel
        spawns:
          - event: salo.event.zeek.HTTPModel


Global Options
--------------

Global options may be used at the `root` of the `recipe`, or on a per-event basis. If defined at the `root` of the recipe, they will be the default values
for all `event` configurations in each session within the recipe.

.. note:: All global options can be defined on a per ``event`` basis.


`options`
+++++++++

``options`` can be used to define the values of a ``SaloEventModel`` or ``SaloStencilModel`` attribute. For example, if the ``src_ip`` for all events in 
a recipe should be ``1.2.3.4``, we can define it like so:

.. code-block:: yaml


    options:
      src_ip: 1.2.3.4


.. note:: ``options`` will be inherited from any and all parent ``event`` objects in the same `session`. Additionally, ``options`` defined within an ``event``
          will override any parent ``options`` defined.

time
++++

The ``time`` configuration option is used to define multiple attributes of the timestamp for an ``event``. Several options are available, to include the 
`start` time, `jitter`, and the cadence of ``event`` timestamps. All options below may be used in concert with each other.


start
^^^^^

``start`` is the ``datetime`` value an ``event`` must start at:

.. code-block:: yaml


    time:
      start: 2021-12-25T01:00:00.000000


jitter_min
^^^^^^^^^^

``jitter_min`` is the minimum amount of `jitter` in seconds to introduce into the timestamp:

.. code-block:: yaml


    time:
      jitter_min: 600

jitter_max
^^^^^^^^^^

``jitter_max`` is the maximum amount of `jitter` in seconds to introduce into the timestamp:

.. code-block:: yaml


    time:
      jitter_max: 3600

cadence
^^^^^^^

``cadence`` is a crontab-style configuration option to define the delta between an ``event``. The format for cadence is identical to a crontab configuration,
except that second repetition is supported.::

    second  minute  hour  day  month year


For example, to define a cadence of one event per second:

.. code-block:: yaml


    time:
      cadence: "*/1 * * * * *"


Or, only at 3am on the first of the month:


.. code-block:: yaml


    time:
      cadence: "* * 03 01 * *"



Event Options
-------------

An ``event`` is a subsection of the ``sessions`` option. Each top-level event in ``sessions`` is considered it's own session.

event
+++++

An ``event`` may be a ``SaloEventModel`` or ``SaloStencilModel`` object path. The value must be a python importable library:


.. code-block:: yaml


    sessions:
      - event: salo.events.suricata.DNSModel


.. note:: For custom events, the ``SALO_PATH`` environment variable may be set to include this in the import search path. (i.e., ``export SALO_PATH "/path/to/my/events"``)


If it is a ``SaloStencilModel``, it will only be used for defining the attributes for  ``spawns``. It will not generate any output itself. `Stencils` are designed to 
generate complex programmatic log scenarios which would be otherwise impossible to do with just a `recipe`:

.. code-block:: yaml


    sessions:
      - event: salo.stencils.sunburst.SunBurstDNSQuery
        spawns:
          - event: salo.events.zeek.DNSModel
          - event: salo.events.suricata.DNSModel


If it is a ``SaloEventModel``, it will produce output in the form of a log object:

.. code-block:: yaml


    sessions:
      - event: salo.events.zeek.ConnModel


spawns
++++++

``spawns`` are children of an ``event`` and are recursively chained together. All ``spawns`` of an ``event`` will inherit the parents attribute values.
If the attributes are a member of the `spawned` ``event``, they will be defined. Otherwise, they will be simply ignored and passed along to any additional 
child ``spawns``:

.. code-block:: yaml


    sessions:
      - event: salo.events.zeek.ConnModel
        spawns:
          - event: salo.events.zeek.DNSModel
      - event: salo.events.zeek.ConnModel
        spawns:
          - event: salo.events.zeek.SMTPModel


repeat
++++++

Repeat the ``event``, and all ``spawns``, the number of times that are defined:

.. code-block:: yaml


    sessions:
      - event: salo.events.suricata.DNSModel
        repeat: 100


save_values
+++++++++++

Save the values from the ``event`` as a variable for use in a later ``event`` or ``session``:

.. code-block:: yaml


    sessions:
      - event: salo.events.suricata.DNSModel
        save_values:
          first_dns_query: dns_query
        options:
          dns_query: totallybadsite.com
      - event: salo.event.suricata.HTTPModel
        options:
          http_hostname: $first_dns_query


This example will save the value of ``dns_query`` from the first ``event`` into the variable ``$first_dns_query``. It is then accessed and used to define
the value of ``http_hostname`` in the second ``event``, resulting in the ``http_hostname`` value being ``totallybadsite.com``.

Additionally, if the value is a list, the resulting value can be of a specific index or random. Let's take a look at using a specific index value first:

.. code-block:: yaml


    sessions:
      - event: salo.events.suricata.DNSModel
        save_values:
          first_dns_query: dns_query
          first_dns_rdata: dns_rdata
        options:
          dns_query: totallybadsite.com
          dns_rdata:
            - 1.2.3.4
            - 5.6.7.8
      - event: salo.event.suricata.HTTPModel
        options:
          http_hostname: $first_dns_query
          dest_ip: $first_dns_rdata.0


This will work exactly the same as the previous example above, but will also define the ``dest_ip`` as the value at index ``0``, or ``1.2.3.4``.

If the value of ``dest_ip`` could be any of the values defined in ``dns_rdata``, then we could leverage the ``random`` option:

.. code-block:: yaml


    sessions:
      - event: salo.events.suricata.DNSModel
        save_values:
          first_dns_query: dns_query
          first_dns_rdata: dns_rdata
        options:
          dns_query: totallybadsite.com
          dns_rdata:
            - 1.2.3.4
            - 5.6.7.8
      - event: salo.event.suricata.HTTPModel
        options:
          http_hostname: $first_dns_query
          dest_ip: $first_dns_rdata.random


This allows for an easy and flexible way to define attribute values of an ``event`` within  a different `session`.


likelihood
++++++++++

``likelihood`` will introduce a defined degree of randomness as to whether an ``event`` will be created:

.. code-block:: yaml


    sessions:
      - event: salo.events.zeek.ConnModel
        spawns:
          - event: salo.events.zeek.DNSModel
      - event: salo.events.zeek.ConnModel
        likelihood: 50
        spawns:
          - event: salo.events.zeek.SMTPModel

In the above example,  the first ``event`` and it's ``spawns`` will always produce a log object. However, the second event will only produce a log object
approximately 50% of the time.

