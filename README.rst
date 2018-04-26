Hawk authentication support for Kinto
=====================================

|travis| |master-coverage|

.. |travis| image:: https://travis-ci.org/Kinto/kinto-hawk.svg?branch=master
    :target: https://travis-ci.org/Kinto/kinto-hawk

.. |master-coverage| image::
    https://coveralls.io/repos/Kinto/kinto-hawk/badge.png?branch=master
    :alt: Coverage
    :target: https://coveralls.io/r/Kinto/kinto-hawk

*Kinto-hawk* enables Hawk authentication for *Kinto* based applications.

It adds the Hawk authentication protocol to the Kinto Accounts plugins.

Your users are handled the same way as usual
`Kinto Accounts Users <http://docs.kinto-storage.org/en/stable/api/1.x/accounts.html>`_.

The main benefit of Hawk for Kinto is to prevent replay attacks (very
useful for score games) and to prevent sending the user and password
over the network like with **Basic auth**.

It provides:

* An authentication policy class;
* Integration with *Kinto* cache backend for token verifications;
* Some optional endpoints to perform to grab a new Hawk session.

* `Kinto documentation <http://kinto.readthedocs.io/en/latest/>`_
* `Issue tracker <https://github.com/Kinto/kinto-hawk/issues>`_


Installation
------------

Install the Python package:

::

    pip install kinto-hawk


Include the package in the project configuration:

::

    # Enable plugin.
    kinto.includes = kinto_hawk

And configure authentication policy using `pyramid_multiauth
<https://github.com/mozilla-services/pyramid_multiauth#deployment-settings>`_ formalism:

::

    multiauth.policies = account

    # Enable Hawk authenticated policy and name it account
    multiauth.policy.account.use = kinto_hawk.authentication.HawkAuthenticationPolicy

By default, it will rely on the cache configured in *Kinto*.


Configuration
-------------

As of today, there are no specific configuration for Hawk.


If necessary, override default values for authentication policy:

::

    # multiauth.policy.account.realm = Realm
    # hawk.nonce_ttl_seconds = 60  # A minute
    # hawk.session_ttl_seconds = 2613600  # 2 months since last usage.


How to create a user?
---------------------

You can use the kinto create-user command to create a user:

::

   kinto create-user --ini config/kinto.ini -u admin


Login flow
----------

Once you have a user and you have activated the ``kinto-hawk`` plugin,
you will be able to request an Hawk Session from a new endpoint using
``Basic Auth`` or a previous ``Hawk Session``.

.. note::

   This will only work with an account user. You cannot request an
   Hawk Session for an OAuth authenticated user for instance.


::

    $ http POST https://kinto.dev.mozaws.net/v1/hawk-sessions -v --auth (userID):(password)
    POST /v1/hawk-sessions HTTP/1.1
    Host: kinto.dev.mozaws.net


   HTTP/1.1 201 Created
   Hawk-Session-Token: 47d5616e561443e79d0db605771db46234a984629a6e681059b76657f790583b
