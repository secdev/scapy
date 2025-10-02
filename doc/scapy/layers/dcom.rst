[MS-DCOM]
=========

DCOM is a mechanism to manipulate COM objects remotely. It is in many ways just an extension over normal DCE/RPC, so understanding DCE/RPC concepts beforehand can be very useful.
Before reading this, have a look at Scapy's `DCE/RPC <dcerpc.html>`_ documentation page.

Terminology
-----------

- In DCOM one instantiates 'classes' to get 'object references'. A class implements one or several 'interfaces', each of which has methods.
- ``CLSID``: the UIID of a **class**, used to instantiate it. This is typically chosen by whoever implements the COM object.
- ``IID``: the UIID of an **interface**, used to request an IPID. This is chosen by whoever defines the COM interface (mostly Microsoft).
- ``IPID``: a UIID that uniquely references an **interface on an object**. This allows to tell DCOM on which object to run the request we send.

There are other IDs such as the OID (a 64bit number that uniquely references each object), and the OXID (a 64bit number that uniquely references each object exporter), but we won't get into the details.

Per the spec, a DCOM client is supposed to keep track of the IPID, OID and OXID ids. In this regard, Scapy abstracts their usage.
On the other hand, the calling application is supposed to know the ``CLSID`` of the class it wishes to instantiate, and the various ``IID`` of the interfaces it wishes to use.

General behavior of a DCOM client
---------------------------------

1. Setup the DCOM client (endpoint, SSP, etc.)
2. Get an object reference: Instantiate a class to get an object reference of the instance (``RemoteCreateInstance``), **OR**, get an object reference towards the class itself (``RemoteGetClassObject``).
3. Acquire the IPID of an interface of the object.
4. Call a method of that interface.
5. Release the reference counts on the interface (delete the IPID).

Step 3 can be done manually through the ``AcquireInterface()`` method, but Scapy will also automatically call it if you try to use an interface that you haven't acquired on an object.

Using the DCOM client
---------------------

General usage
~~~~~~~~~~~~~

1. Setup the DCOM client and connect to the object resolver (which is by default on port 135).

.. code:: python

    from scapy.layers.msrpce.msdcom import DCOM_Client
    from scapy.layers.ntlm import NTLMSSP

    client = DCOM_Client(
        ssp=NTLMSSP(UPN="Administrator@domain.local", PASSWORD="Scapy1111@"),
    )
    client.connect("server1.domain.local")

.. note:: See the examples in `DCE/RPC <dcerpc.html>`_ to connect with SPNEGO/Kerberos.

2. Instantiate a class to get an object reference

.. code:: python

    import uuid
    from scapy.layers.dcerpc import find_com_interface
    from scapy.layers.msrpce.raw.ms_pla import GetDataCollectorSets_Request

    CLSID_TraceSessionCollection = uuid.UUID("03837530-098b-11d8-9414-505054503030")
    # The COM interface must have been compiled by scapy-rpc (midl-to-scapy)
    IDataCollectorSetCollection = find_com_interface("IDataCollectorSetCollection")

    # Get new object reference
    objref = client.RemoteCreateInstance(
        # The CLSID we're instantiating
        clsid=CLSID_TraceSessionCollection,
        iids=[
            # An initial list of interfaces to ask for. There must be at least 1.
            IDataCollectorSetCollection,
        ]
    )

3. Call a method on that object reference

.. code:: python

    result = objref.sr1_req(
        # The request message (here from [MS-PLA])
        pkt=GetDataCollectorSets_Request(
            server=None,
            filter=NDRPointer(
                referent_id=0x72657355,
                value=FLAGGED_WORD_BLOB(
                    cBytes=18,
                    asData=r"session\*".encode("utf-16le"),
                )
            ),
        ),
        # The interface to send it on
        iface=IDataCollectorSetCollection,
    )

4. Release all the requested interfaces on the object reference

.. code:: python

    objref.release()

5. Close the client

.. code:: python

    client.close()


Unmarshalling object references
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some methods return a reference to an object that is created by the remote server. On the network,
those are typically marshalled as a ``MInterfacePointer`` structure. Such a structure can be "unmarshalled" into a local object reference that can be used in Scapy to call methods on that object.

.. code:: python

    # For instance, let's assume we're calling Next() of the IEnumVARIANT
    resp = enum.sr1_req(
        pkt=Next_Request(celt=1),
        iface=IEnumVARIANT,
    )

    # Get the MInterfacePointer value
    value = resp.valueof("rgVar")[0].valueof("_varUnion")
    assert isinstance(value, MInterfacePointer)

    # Unmarshall it and acquire an initial interface on it.
    objref = client.UnmarshallObjectReference(
        value,
        iid=IDataCollectorSet,
    )
