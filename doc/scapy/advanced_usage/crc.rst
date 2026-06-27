CRC computation
===============

Scapy provides configurable CRC algorithms in :mod:`scapy.libs.crc`.  Each
variant is a class that can be called on ``bytes`` to obtain an integer
checksum.

Computing a checksum
--------------------

::

    >>> from scapy.libs.crc import CRC_32
    >>> CRC_32(b"123456789")
    3421780262

Built-in variants include :class:`~scapy.libs.crc.CRC_16`,
:class:`~scapy.libs.crc.CRC_32`, :class:`~scapy.libs.crc.CRC_16_CCITT` and
:class:`~scapy.libs.crc.CRC_32_AUTOSAR`.

Custom parameters
-----------------

Use :meth:`~scapy.libs.crc.CRC.from_parameters` or a :class:`~scapy.libs.crc.CRCParam`
object when the polynomial or reflection settings differ from the built-in
classes::

    >>> from scapy.libs.crc import CRC, CRCParam
    >>> params = CRCParam(poly=0x589, size=16, init_crc=0xffff, xor=0xffff,
    ...                   reflect_input=False, reflect_output=False)
    >>> CRC.from_parameters(params, do_not_register=True)(b"test")

Incremental computation
-----------------------

For large or streamed data, use :meth:`~scapy.libs.crc.CRC.create_context` and
``init`` / ``update`` / ``finish``::

    >>> crc = CRC_32.create_context()
    >>> crc.update(b"12345")
    >>> crc.update(b"6789")
    >>> crc.finish()
    3421780262

Finding embedded CRCs
---------------------

When a binary format stores a CRC next to the protected data,
:meth:`~scapy.libs.crc.CRC.search` locates candidate (substring, algorithm)
pairs.  Pass ``only_registry=True`` to restrict the search to registered
classes::

    >>> import struct
    >>> from scapy.libs.crc import CRC, CRC_32
    >>> data = b"payload"
    >>> blob = data + struct.pack("!I", CRC_32(data))
    >>> CRC.search(blob, only_registry=True)
    [((0, 7), 1110206997, CRC_32)]

API reference
-------------

See :mod:`scapy.libs.crc` in the API reference for the full list of classes
and methods.
