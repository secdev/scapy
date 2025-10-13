.NET Protocols
==============

Scapy implements a few .NET specific protocols. Those protocols are a bit uncommon, but it can be useful to try to understand what's sent by .NET applications, or for more offensive purposes (issues with .NET deserialization for instance).

.NET Remoting
-------------

Implemented under ``ms_nrtp``, you can load it using::

    from scapy.layers.ms_nrtp import *

This supports:

- The .NET remote protocol: ``NRTP*`` classes
- The .NET Binary Formatter: ``NRBF*`` classes

For instance you can try to parse a .NET Remoting payload generated using ysoserial with the ``NRBF()`` to analyse what it's doing.
