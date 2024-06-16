LDAP
====

Scapy fully implements the LDAPv2 / LDAPv3 messages, in addition to a very basic :class:`~scapy.layers.ldap.LDAP_Client` class.

.. warning::
    *The String Representation of LDAP Search Filters* (RFC2254) is currently **unsupported**.
    This means that you can't use the commonly known LDAP search syntax, and instead have to use the binary format.
    PRs are welcome !

LDAP client usage
-----------------

The general idea when using the :class:`~scapy.layers.ldap.LDAP_Client` class comes down to:

- instantiating the class
- calling :func:`~scapy.layers.ldap.LDAP_Client.connect` with the IP (this is where to specify whether to use SSL or not)
- calling :func:`~scapy.layers.ldap.LDAP_Client.bind` (this is where to specify a SSP if authentication is desired)

The simplest, unauthenticated demo of the client would be something like:

.. code:: pycon

    >>> client = LDAP_Client()
    >>> client.connect("192.168.0.100")
    >>> client.bind(LDAP_BIND_MECHS.NONE)
    >>> client.sr1(LDAP_SearchRequest()).show()
    ┃ Connecting to 192.168.0.100 on port 389...
    └ Connected from ('192.168.0.102', 40228)
    NONE bind succeeded !
    >> LDAP_SearchRequest
    << LDAP_SearchResponseEntry
    ###[ LDAP ]###
    messageID = 0x1 <ASN1_INTEGER[1]>
    \protocolOp\
    |###[ LDAP_SearchResponseEntry ]###
    |  objectName= <ASN1_STRING[b'']>
    |  \attributes\
    |   |###[ LDAP_SearchResponseEntryAttribute ]###
    |   |  type      = <ASN1_STRING[b'domainFunctionality']>
    |   |  \values    \
    |   |   |###[ LDAP_SearchResponseEntryAttributeValue ]###
    |   |   |  value     = <ASN1_STRING[b'7']>
    |   |###[ LDAP_SearchResponseEntryAttribute ]###
    |   |  type      = <ASN1_STRING[b'forestFunctionality']>
    |   |  \values    \
    |   |   |###[ LDAP_SearchResponseEntryAttributeValue ]###
    |   |   |  value     = <ASN1_STRING[b'7']>
    |   |###[ LDAP_SearchResponseEntryAttribute ]###
    |   |  type      = <ASN1_STRING[b'domainControllerFunctionality']>
    |   |  \values    \
    |   |   |###[ LDAP_SearchResponseEntryAttributeValue ]###
    |   |   |  value     = <ASN1_STRING[b'7']>
    [...]

Connecting
~~~~~~~~~~

Let's first instantiate the :class:`~scapy.layers.ldap.LDAP_Client`, and connect to a server over the default port (389):

.. code:: python

    client = LDAP_Client()
    client.connect("192.168.0.100")

It is also possible to use TLS when connecting to the server.

.. code:: python

    client = LDAP_Client()
    client.connect("192.168.0.100", use_ssl=True)

In that case, the default port is 636. This can be changed using the ``port`` attribute.

.. note::
    By default, the server certificate is NOT checked when using this mode, because the server certificate will likely be self-signed.
    To actually use TLS securely, you should pass a ``sslcontext`` as shown below:

.. code:: python

    import ssl
    client = LDAP_Client()
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslcontext.load_verify_locations('path/to/ca.crt')
    client.connect("192.168.0.100", use_ssl=True, sspcontext=sslcontext)

.. note:: If the client is too verbose, you can pass ``verb=False`` when instantiating :class:`~scapy.layers.ldap.LDAP_Client`.

Binding
~~~~~~~

When binding, you must specify a *mechanism type*. This type comes from the :class:`~scapy.layers.ldap.LDAP_BIND_MECHS` enumeration, which contains:

- :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.NONE`: an unauthenticated bind.
- :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SIMPLE`: the simple bind mechanism. Credentials are sent **in plaintext**.
- :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SICILY`: a `Windows specific authentication mechanism specified in [MS-ADTS] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8b9dbfb2-5b6a-497a-a533-7e709cb9a982>`_ that only supports NTLM.
- :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SASL_GSSAPI`: the SASL authentication mechanism, as specified by `RFC 4422 <https://datatracker.ietf.org/doc/html/rfc4422>`_.
- :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SASL_GSS_SPNEGO`: the SPNEGO authentication mechanism, another `Windows specific authentication mechanism specified in [MS-SPNG] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f377a379-c24f-4a0f-a3eb-0d835389e28a>`_.

Depending on the server that you are talking to, some of those mechanisms might not be available. This is most notably the case of :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SICILY` and :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SASL_GSS_SPNEGO` which are mostly Windows-specific.

We'll now go over "how to bind" using each one of those mechanisms:

**NONE (Unauthenticated):**

.. code:: python

    client.bind(LDAP_BIND_MECHS.NONE)

**SIMPLE:**

.. code:: python

    client.bind(
        LDAP_BIND_MECHS.SIMPLE,
        simple_username="Administrator",
        simple_password="Password1!",
    )

**SICILY - NTLM:**

.. code:: python

    ssp = NTLMSSP(UPN="Administrator", PASSWORD="Password1!")
    client.bind(
        LDAP_BIND_MECHS.SICILY,
        ssp=ssp,
    )

**SASL_GSSAPI - Kerberos:**

.. code:: python

    ssp = KerberosSSP(UPN="Administrator@domain.local", PASSWORD="Password1!",
                      SPN="ldap/dc1.domain.local")
    client.bind(
        LDAP_BIND_MECHS.SASL_GSSAPI,
        ssp=ssp,
    )

**SASL_GSS_SPNEGO - NTLM / Kerberos:**

.. code:: python

    ssp = SPNEGOSSP([
        NTLMSSP(UPN="Administrator", PASSWORD="Password1!"),
        KerberosSSP(UPN="Administrator@domain.local", PASSWORD="Password1!",
                    SPN="ldap/dc1.domain.local"),
    ])
    client.bind(
        LDAP_BIND_MECHS.SASL_GSS_SPNEGO,
        ssp=ssp,
    )

Signing / Encryption
~~~~~~~~~~~~~~~~~~~~

Additionally, it is possible to enable signing or encryption of the LDAP data, when LDAPS is NOT in use.
This is done by setting ``sign`` and ``encrypt`` parameters of the :func:`~scapy.layers.ldap.LDAP_Client.bind` function.

There are however a few caveats to note:

- It's not possible to use those flags in ``NONE`` (duh) or ``SIMPLE`` mode.
- When using the :class:`~scapy.layers.ntlm.NTLMSSP` (in :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SICILY` or :attr:`~scapy.layers.ldap.LDAP_BIND_MECHS.SASL_GSS_SPNEGO` mode), it isn't possible to use ``sign`` without ``encrypt``, because Windows doesn't implement it.

Querying
~~~~~~~~

Once the LDAP connection is bound, it becomes possible to perform requests. For instance, to query all the values of the root DSE:

.. code:: python

    client.sr1(LDAP_SearchRequest()).show()

Querying more complicated requests is a bit tedious, as it *currently* requires you to build the Search request yourself.
For instance, this corresponds to querying the DN ``CN=Users,DC=domain,DC=local`` with the filter ``(objectCategory=person)`` and asking for the attributes ``objectClass,name,description,canonicalName``:

.. code:: python

    resp = client.sr1(
        LDAP_SearchRequest(
            filter=LDAP_Filter(
                filter=LDAP_FilterEqual(
                    attributeType=ASN1_STRING(b'objectCategory'),
                    attributeValue=ASN1_STRING(b'person')
                )
            ),
            attributes=[
                LDAP_SearchRequestAttribute(type=ASN1_STRING(b'objectClass')),
                LDAP_SearchRequestAttribute(type=ASN1_STRING(b'name')),
                LDAP_SearchRequestAttribute(type=ASN1_STRING(b'description')),
                LDAP_SearchRequestAttribute(type=ASN1_STRING(b'canonicalName'))
            ],
            baseObject=ASN1_STRING(b'CN=Users,DC=domain,DC=local'),
            scope=ASN1_ENUMERATED(1),
            derefAliases=ASN1_ENUMERATED(0),
            sizeLimit=ASN1_INTEGER(1000),
            timeLimit=ASN1_INTEGER(60),
            attrsOnly=ASN1_BOOLEAN(0)
        )
    )
    resp.show()
