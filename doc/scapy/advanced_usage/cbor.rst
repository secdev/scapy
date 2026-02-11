CBOR
====

What is CBOR?
-------------

.. note::

   This section provides a practical introduction to CBOR from Scapy's perspective. For the complete specification, see RFC 8949.

CBOR (Concise Binary Object Representation) is a data format whose goal is to provide a compact, self-describing binary data interchange format based on the JSON data model. It is defined in RFC 8949 and is designed to be small in code size, reasonably small in message size, and extensible without the need for version negotiation.

CBOR provides basic data types including:

* **Unsigned integers** (major type 0): Non-negative integers
* **Negative integers** (major type 1): Negative integers
* **Byte strings** (major type 2): Raw binary data
* **Text strings** (major type 3): UTF-8 encoded strings
* **Arrays** (major type 4): Ordered sequences of values
* **Maps** (major type 5): Unordered key-value pairs
* **Semantic tags** (major type 6): Tagged values with additional semantics
* **Simple values and floats** (major type 7): Booleans, null, undefined, and floating-point numbers

Each CBOR data item begins with an initial byte that encodes the major type (in the top 3 bits) and additional information (in the low 5 bits). This design allows for compact encoding while maintaining self-describing properties.

Scapy and CBOR
--------------

Scapy provides a complete CBOR encoder and decoder following the same architectural pattern as the ASN.1 implementation. The CBOR engine can encode Python objects to CBOR binary format and decode CBOR data back to Python objects. It has been designed to be RFC 8949 compliant and interoperable with other CBOR implementations.

CBOR engine
^^^^^^^^^^^

Scapy's CBOR engine provides classes to represent CBOR data items. The main components are:

* ``CBOR_MajorTypes``: Defines the 8 major types (0-7) used in CBOR encoding
* ``CBOR_Object``: Base class for all CBOR value objects
* ``CBOR_Codecs``: Registry for encoding/decoding rules

The ``CBOR_MajorTypes`` class defines tags for all major types::

    class CBOR_MajorTypes:
        name = "CBOR_MAJOR_TYPES"
        UNSIGNED_INTEGER = 0
        NEGATIVE_INTEGER = 1
        BYTE_STRING = 2
        TEXT_STRING = 3
        ARRAY = 4
        MAP = 5
        TAG = 6
        SIMPLE_AND_FLOAT = 7

All CBOR objects are represented by Python instances that wrap raw values. They inherit from ``CBOR_Object``::

    class CBOR_UNSIGNED_INTEGER(CBOR_Object):
        tag = CBOR_MajorTypes.UNSIGNED_INTEGER
    
    class CBOR_TEXT_STRING(CBOR_Object):
        tag = CBOR_MajorTypes.TEXT_STRING
    
    class CBOR_ARRAY(CBOR_Object):
        tag = CBOR_MajorTypes.ARRAY

Creating CBOR objects
^^^^^^^^^^^^^^^^^^^^^

CBOR objects can be easily created and composed::

    >>> from scapy.cbor import *
    >>> # Create basic types
    >>> num = CBOR_UNSIGNED_INTEGER(42)
    >>> text = CBOR_TEXT_STRING("Hello, CBOR!")
    >>> data = CBOR_BYTE_STRING(b'\x01\x02\x03')
    >>> 
    >>> # Create collections
    >>> arr = CBOR_ARRAY([CBOR_UNSIGNED_INTEGER(1), 
    ...                    CBOR_UNSIGNED_INTEGER(2),
    ...                    CBOR_TEXT_STRING("three")])
    >>> arr
    <CBOR_ARRAY[[<CBOR_UNSIGNED_INTEGER[1]>, <CBOR_UNSIGNED_INTEGER[2]>, <CBOR_TEXT_STRING['three']>]]>
    >>> 
    >>> # Create maps
    >>> from scapy.cbor.cborcodec import CBORcodec_MAP
    >>> mapping = {"name": "Alice", "age": 30, "active": True}

Encoding and decoding
^^^^^^^^^^^^^^^^^^^^^

CBOR objects are encoded using their ``.enc()`` method. All codecs are referenced in the ``CBOR_Codecs`` object. The default codec is ``CBOR_Codecs.CBOR``::

    >>> num = CBOR_UNSIGNED_INTEGER(42)
    >>> encoded = bytes(num)
    >>> encoded.hex()
    '182a'
    >>> 
    >>> # Decode back
    >>> decoded, remainder = CBOR_Codecs.CBOR.dec(encoded)
    >>> decoded.val
    42
    >>> isinstance(decoded, CBOR_UNSIGNED_INTEGER)
    True

Encoding collections::

    >>> from scapy.cbor.cborcodec import CBORcodec_ARRAY, CBORcodec_MAP
    >>> # Encode an array
    >>> encoded = CBORcodec_ARRAY.enc([1, 2, 3, 4, 5])
    >>> encoded.hex()
    '850102030405'
    >>> 
    >>> # Decode the array
    >>> decoded, _ = CBOR_Codecs.CBOR.dec(encoded)
    >>> [item.val for item in decoded.val]
    [1, 2, 3, 4, 5]
    >>> 
    >>> # Encode a map
    >>> encoded = CBORcodec_MAP.enc({"x": 100, "y": 200})
    >>> decoded, _ = CBOR_Codecs.CBOR.dec(encoded)
    >>> isinstance(decoded, CBOR_MAP)
    True

Working with different types
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

CBOR supports various data types::

    >>> # Booleans
    >>> true_val = CBOR_TRUE()
    >>> false_val = CBOR_FALSE()
    >>> bytes(true_val).hex()
    'f5'
    >>> bytes(false_val).hex()
    'f4'
    >>> 
    >>> # Null and undefined
    >>> null_val = CBOR_NULL()
    >>> undef_val = CBOR_UNDEFINED()
    >>> bytes(null_val).hex()
    'f6'
    >>> bytes(undef_val).hex()
    'f7'
    >>> 
    >>> # Floating point
    >>> float_val = CBOR_FLOAT(3.14159)
    >>> bytes(float_val).hex()
    'fb400921f9f01b866e'
    >>> 
    >>> # Negative integers
    >>> neg = CBOR_NEGATIVE_INTEGER(-100)
    >>> bytes(neg).hex()
    '3863'

Complex structures
^^^^^^^^^^^^^^^^^^

CBOR supports nested structures::

    >>> # Nested arrays
    >>> nested = CBORcodec_ARRAY.enc([1, [2, 3], [4, [5, 6]]])
    >>> decoded, _ = CBOR_Codecs.CBOR.dec(nested)
    >>> isinstance(decoded, CBOR_ARRAY)
    True
    >>> 
    >>> # Complex maps with mixed types
    >>> data = {
    ...     "name": "Bob",
    ...     "age": 25,
    ...     "active": True,
    ...     "tags": ["user", "admin"]
    ... }
    >>> encoded = CBORcodec_MAP.enc(data)
    >>> decoded, _ = CBOR_Codecs.CBOR.dec(encoded)
    >>> len(decoded.val)
    4

Semantic tags
^^^^^^^^^^^^^

CBOR supports semantic tags (major type 6) for providing additional meaning to data items::

    >>> # Tag 1 is for Unix epoch timestamps
    >>> import time
    >>> timestamp = int(time.time())
    >>> tagged = CBOR_SEMANTIC_TAG((1, CBOR_UNSIGNED_INTEGER(timestamp)))
    >>> encoded = bytes(tagged)
    >>> decoded, _ = CBOR_Codecs.CBOR.dec(encoded)
    >>> decoded.val[0]  # Tag number
    1

Interoperability
^^^^^^^^^^^^^^^^

Scapy's CBOR implementation is fully interoperable with other CBOR libraries. The implementation has been tested with the ``cbor2`` Python library to ensure RFC 8949 compliance::

    >>> import cbor2
    >>> # Encode with Scapy, decode with cbor2
    >>> scapy_obj = CBOR_UNSIGNED_INTEGER(12345)
    >>> scapy_encoded = bytes(scapy_obj)
    >>> cbor2.loads(scapy_encoded)
    12345
    >>> 
    >>> # Encode with cbor2, decode with Scapy
    >>> cbor2_encoded = cbor2.dumps([1, "test", True])
    >>> scapy_decoded, _ = CBOR_Codecs.CBOR.dec(cbor2_encoded)
    >>> isinstance(scapy_decoded, CBOR_ARRAY)
    True

Error handling
^^^^^^^^^^^^^^

Scapy provides safe decoding with error handling::

    >>> # Safe decoding returns error objects for invalid data
    >>> invalid_data = b'\xff\xff\xff'
    >>> obj, remainder = CBOR_Codecs.CBOR.safedec(invalid_data)
    >>> isinstance(obj, CBOR_DECODING_ERROR)
    True

