NTLM
====

Scapy provides dissection & build methods for NTLM and other Windows mechanisms.

How NTLM works
--------------

NTLM is a legacy method of authentication that uses a `challenge-response mechanism <https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication>`_.
The goal is to:

- verify the identity of the client
- negotiate a common session key between the client and server

.. note::

    We won't get in more details. You can read more in `this article from hackndo <https://en.hackndo.com/ntlm-relay/>`_ to understand how NTLM works.

NTLM in Scapy
-------------

Scapy implements `Security Providers <https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture>`_ trying to stay as close a what you would find in the Windows world.

Basically those are classes that implement two functions:

- ``GSS_Init_sec_context``: called by the client, passing it a ``Context`` and optionally a token
- ``GSS_Accept_sec_context``: called by the server, passing it a ``Context`` and optionally a token

They both return the updated Context, a token to optionally send to the server/client and a GSSAPI status code.

For NTLM, this is implemented in the :class:`~scapy.layers.ntlm.NTLMSSP`.
You can typically use it in :class:`~scapy.layers.smbclient.SMB_Client`, :class:`~scapy.layers.smbserver.SMB_Server`, :class:`~scapy.layers.msrpce.rpcclient.DCERPC_Client` or :class:`~scapy.layers.msrpce.rpcserver.DCERPC_Server`.
Have a look at `SMB <smb.html>`_ and `DCE/RPC <dcerpc.html>`_ to get examples on how to use it.

.. note:: Remember that you can wrap it in a :class:`~scapy.layers.spnego.SPNEGOSSP`
