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
fields in a CBOR array; typed fields expose Python values, not CBOR objects::

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

For a homogeneous array, use ``CBORF_ARRAY_OF("values", [],
pkt_cls=CBORF_UNSIGNED_INTEGER)``. ``CBORF_PACKET("child", None,
pkt_cls=Message)`` embeds a packet as one CBOR item;
``CBORF_BYTE_STRING_PACKET`` wraps the packet bytes in a CBOR byte string
instead. ``CBORF_SEMANTIC_TAG(tag_number, field)`` adds a semantic tag to a
field.

Optional fields
---------------

Wrap a field in ``CBORF_optional`` to allow it to be omitted. Missing decoded
fields contain ``CBOR_ABSENT``. For optional typed scalars such as integers,
use ``None`` to omit the field when building.

``CBORF_ANY`` keeps CBOR objects rather than converting them to Python values.
For this field, ``None`` means a present CBOR null, not an omitted item::

    >>> from scapy.cbor import CBOR_ABSENT, CBORF_ANY, CBORF_optional
    >>> class OptionalValue(CBOR_Packet):
    ...     CBOR_root = CBORF_ARRAY(
    ...         CBORF_optional(CBORF_ANY("value", CBOR_ABSENT)),
    ...     )
    ...
    >>> bytes(OptionalValue()).hex()
    '80'
    >>> bytes(OptionalValue(value=None)).hex()
    '81f6'
    >>> OptionalValue(b"\x80").getfieldval("value") is CBOR_ABSENT
    True

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

Invalid data
------------

``dec()`` raises on invalid data. ``safedec()`` returns a
``CBOR_DECODING_ERROR`` object instead::

    >>> from scapy.cbor import CBOR_DECODING_ERROR
    >>> obj, remainder = CBORcodec_Object.safedec(b"\xff")
    >>> isinstance(obj, CBOR_DECODING_ERROR)
    True

Unmodified decoded packets retain their received encoding. Changing fields
rebuilds the affected data; typed floats then use the shortest exact encoding.

See :mod:`scapy.cbor.cborfields` and :mod:`scapy.cbor.cborcodec` for the
field and codec APIs.
