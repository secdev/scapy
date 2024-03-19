GSSAPI
======

Scapy provides access to various `Security Providers <https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture>`_ following the GSSAPI model, but aiming at interacting with the Windows world.

.. note::

    The GSSAPI interfaces are based off the following documentations:
    
        - GSSAPI: `RFC4121 <https://datatracker.ietf.org/doc/html/rfc4121>`_ / `RFC2743 <https://datatracker.ietf.org/doc/html/rfc2743>`_
        - GSSAPI C bindings: `RFC2744 <https://datatracker.ietf.org/doc/html/rfc2744>`_

Usage
-----

.. _ssplist:

The following SSPs are currently provided:

    - :class:`~scapy.layers.ntlm.NTLMSSP`
    - :class:`~scapy.layers.kerberos.KerberosSSP`
    - :class:`~scapy.layers.spnego.SPNEGOSSP`
    - :class:`~scapy.layers.msrpce.msnrpc.NetlogonSSP`

Basically those are classes that implement two functions, trying to micmic the RFCs:

- :func:`~scapy.layers.gssapi.SSP.GSS_Init_sec_context`: called by the client, passing it a ``Context`` and optionally a token
- :func:`~scapy.layers.gssapi.SSP.GSS_Accept_sec_context`: called by the server, passing it a ``Context`` and optionally a token

They both return the updated Context, a token to optionally send to the server/client and a GSSAPI status code.

.. note::

    You can typically use it in :class:`~scapy.layers.smbclient.SMB_Client`, :class:`~scapy.layers.smbserver.SMB_Server`, :class:`~scapy.layers.msrpce.rpcclient.DCERPC_Client` or :class:`~scapy.layers.msrpce.rpcserver.DCERPC_Server`.
    Have a look at `SMB <smb.html>`_ and `DCE/RPC <dcerpc.html>`_ to get examples on how to use it.

Let's implement our own client that uses one of those SSPs.

Client
~~~~~~

.. _ntlm:

First let's create the SSP. We'll take :class:`~scapy.layers.ntlm.NTLMSSP` as an example but the others would work just as well.

.. code:: python

    from scapy.layers.ntlm import *
    clissp = NTLMSSP(
        UPN="Administrator@domain.local",
        PASSWORD="Password1!",
    )

Let's get the first token (in this case, the ntlm negotiate):

.. code:: python

    # We start with a context = None and a val (server answer) = None
    sspcontext, token, status = clissp.GSS_Init_sec_context(None, None)
    # sspcontext will be passed to subsequent calls and stores information
    # regarding this NTLM session, token is the NTLM_NEGOTIATE and status
    # the state of the SSP
    assert status == GSS_S_CONTINUE_NEEDED

Send this token to the server, or use it as required, and get back the server's token.
You can then pass that token as the second parameter of :func:`~scapy.layers.gssapi.SSP.GSS_Init_sec_context`.
To give an example, this is what is done in the LDAP client:

.. code:: python

    # Do we have a token to send to the server?
    while token:
        resp = self.sr1(
            LDAP_BindRequest(
                bind_name=ASN1_STRING(b""),
                authentication=LDAP_Authentication_SaslCredentials(
                    mechanism=ASN1_STRING(b"SPNEGO"),
                    credentials=ASN1_STRING(bytes(token)),
                ),
            )
        )
        sspcontext, token, status = clissp.GSS_Init_sec_context(
            self.sspcontext, GSSAPI_BLOB(resp.protocolOp.serverSaslCreds.val)
        )

.. _spnego:

If you want to use :class:`~scapy.layers.spnego.SPEGOSSP`, you could wrap the SSP as so:

.. code:: python

    from scapy.layers.ntlm import *
    from scapy.layers.spnegossp import SPNEGOSSP
    clissp = SPNEGOSSP(
        [
            NTLMSSP(
                UPN="Administrator@domain.local",
                PASSWORD="Password1!",
            ),
            KerberosSSP(
                UPN="Administrator@domain.local",
                PASSWORD="Password1!",
                SPN="host/dc1.domain.local",
            ),
        ]
    )

You can override the GSS-API ``req_flags`` when calling :func:`~scapy.layers.gssapi.SSP.GSS_Init_sec_context`, using values from :class:`~scapy.layers.gssapi.GSS_C_FLAGS`:

.. code:: python

    sspcontext, token, status = clissp.GSS_Init_sec_context(None, None, req_flags=(
        GSS_C_FLAGS.GSS_C_EXTENDED_ERROR_FLAG |
        GSS_C_FLAGS.GSS_C_MUTUAL_FLAG |
        GSS_C_FLAGS.GSS_C_CONF_FLAG  # Asking for CONFIDENTIALITY
    ))


Server
~~~~~~

Implementing a server is very similar to a client but you'd use :func:`~scapy.layers.gssapi.SSP.GSS_Accept_sec_context` instead.
The client is properly authenticated when `status` is `GSS_S_COMPLETE`.

Let's use :class:`~scapy.layers.ntlm.NTLMSSP` as an example of server-side SSP.

.. code:: python

    from scapy.layers.ntlm import *
    clissp = NTLMSSP(
        IDENTITIES={
            "User1": MD4le("Password1!"),
            "User2": MD4le("Password2!"),
        }
    )

You'll find other examples of how to instantiate a SSP in the docstrings of each SSP. See `the list <#ssplist>`_