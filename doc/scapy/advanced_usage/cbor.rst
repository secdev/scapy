CBOR
====

CBOR (Concise Binary Object Representation) is a binary data format defined
in `RFC 8949 <https://www.rfc-editor.org/rfc/rfc8949.html>`_. Scapy provides
CBOR objects and codecs for individual values, and ``CBOR_Packet`` with
``CBORF_*`` fields for describing packet formats. No external CBOR library
is required.

Encoding and decoding
---------------------

Use ``bytes()`` to encode a CBOR object. ``CBORcodec_Object.dec()`` returns
the decoded object and the remaining bytes. The object's value is in ``.val``::

    >>> from scapy.cbor import CBOR_UNSIGNED_INTEGER, CBORcodec_Object
    >>> encoded = bytes(CBOR_UNSIGNED_INTEGER(42))
    >>> encoded.hex()
    '182a'
    >>> obj, remainder = CBORcodec_Object.dec(encoded)
    >>> obj.val, remainder
    (42, b'')

The codec also encodes Python values, including nested lists and dictionaries::

    >>> CBORcodec_Object.encode_cbor_item([1, "hello", b"data"]).hex()
    '83016568656c6c6f4464617461'

Use ``encode_cbor_item_deterministic()`` for RFC 8949 core-deterministic
encoding, including recursive map-key sorting by encoded bytes. Ordinary
encoding preserves map pair order instead.

Defining packets
----------------

Define a ``CBOR_root`` instead of ``fields_desc``. ``CBORF_ARRAY`` places
fields in a CBOR array. Integer, string, Boolean, and float fields expose
Python values::

    >>> from scapy.cborpacket import CBOR_Packet
    >>> from scapy.cbor import CBORF_ARRAY, CBORF_TEXT_STRING, CBORF_UNSIGNED_INTEGER
    >>> class Message(CBOR_Packet):
    ...     CBOR_root = CBORF_ARRAY(
    ...         CBORF_UNSIGNED_INTEGER("version", 1),
    ...         CBORF_TEXT_STRING("label", ""),
    ...     )
    ...
    >>> pkt = Message(label="hi")
    >>> bytes(pkt).hex()
    '8201626869'
    >>> decoded = Message(bytes(pkt))
    >>> decoded.version, decoded.label
    (1, 'hi')
    >>> decoded.version = 2
    >>> bytes(decoded).hex()
    '8202626869'

Both definite and indefinite arrays can be decoded. Use
``CBORF_ARRAY_INDEFINITE`` to build an indefinite array, or ``CBORF_ITEMS``
to concatenate fields without an array header.

For an array whose elements use the same field or packet decoder, use
``CBORF_ARRAY_OF("values", [],
pkt_cls=CBORF_UNSIGNED_INTEGER)``. ``CBORF_PACKET("child", None,
pkt_cls=Message)`` embeds a packet as one CBOR item;
``CBORF_BYTE_STRING_PACKET`` wraps the packet bytes in a CBOR byte string
instead. ``CBORF_SEMANTIC_TAG(tag_number, field)`` adds a semantic tag to a
field.

Optional fields
---------------

Wrap a field in ``CBORF_optional`` to allow it to be omitted. Missing decoded
fields contain ``None``. Use ``None`` as the default or assign it to omit an
optional field when building.

``CBORF_ANY`` keeps CBOR objects rather than converting them to Python values.
Use ``CBOR_NULL()`` or ``CBOR_UNDEFINED()`` for a present null or undefined
value::

    >>> from scapy.cbor import CBOR_NULL, CBOR_UNDEFINED, CBORF_ANY, CBORF_optional
    >>> class OptionalValue(CBOR_Packet):
    ...     CBOR_root = CBORF_ARRAY(
    ...         CBORF_optional(CBORF_ANY("value", None)),
    ...     )
    ...
    >>> bytes(OptionalValue()).hex()
    '80'
    >>> bytes(OptionalValue(value=None)).hex()
    '80'
    >>> bytes(OptionalValue(value=CBOR_NULL())).hex()
    '81f6'
    >>> bytes(OptionalValue(value=CBOR_UNDEFINED())).hex()
    '81f7'
    >>> OptionalValue(b"\x80").value is None
    True
    >>> isinstance(OptionalValue(b"\x81\xf6").value, CBOR_NULL)
    True

``CBORF_NULL`` and ``CBORF_UNDEFINED`` also retain explicit CBOR objects for
present values. Within Python lists and dictionaries passed to the codec or
``CBORF_ANY``, ``None`` still encodes CBOR null.

Maps
----

``CBORF_MAP`` uses field names as text keys and builds them in encoded-key
order. Unknown members are preserved in ``_cbor_unknown`` when dissecting::

    >>> from scapy.cbor import CBORF_MAP
    >>> class Metadata(CBOR_Packet):
    ...     CBOR_root = CBORF_MAP(
    ...         CBORF_UNSIGNED_INTEGER("b", 1),
    ...         CBORF_UNSIGNED_INTEGER("a", 2),
    ...     )
    ...
    >>> bytes(Metadata()).hex()
    'a2616102616201'

Use distinct ``unknown_field=`` names if a schema contains multiple maps.
For arbitrary map keys, use ``CBOR_MAP`` objects or ``CBORF_ANY`` instead.
``CBOR_MAP.val`` is a ``CBORMapData`` container of ordered pairs: it keeps
keys such as ``1`` and ``True`` distinct. ``cbor_pairs()`` returns the pairs;
``as_dict()`` raises ``ValueError`` if conversion would lose key distinctions
or a key cannot be used in a Python dictionary.

Rebuilding packets
------------------

Decoded packets are rebuilt from their fields when encoded. The schema
determines the container form and map-key order; typed floats use the shortest
exact encoding. Non-preferred input can therefore change even when no field
has been edited. The received input remains available in ``pkt.original``::

    >>> decoded = Message(bytes.fromhex("9f1801626869ff"))
    >>> decoded.version, decoded.label
    (1, 'hi')
    >>> decoded.original.hex()
    '9f1801626869ff'
    >>> bytes(decoded).hex()
    '8201626869'

``CBORF_ANY`` retains its CBOR object values. Individual objects such as
``CBOR_FLOAT`` can preserve their received float encoding until their ``.val``
is assigned. This does not guarantee an exact-byte round trip for the packet.

Invalid data
------------

``dec()`` raises on invalid data. ``safedec()`` returns a
``CBOR_DECODING_ERROR`` object instead::

    >>> from scapy.cbor import CBOR_DECODING_ERROR
    >>> obj, remainder = CBORcodec_Object.safedec(b"\xff")
    >>> isinstance(obj, CBOR_DECODING_ERROR)
    True

See :mod:`scapy.cbor.cborfields` and :mod:`scapy.cbor.cborcodec` for the
field and codec APIs.
