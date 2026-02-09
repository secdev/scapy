# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Codec Implementation - RFC 8949
Following the BER paradigm for ASN.1
"""

import struct
from scapy.compat import chb, orb
from scapy.cbor.cbor import (
    CBORTag,
    CBOR_Codecs,
    CBOR_DECODING_ERROR,
    CBOR_Decoding_Error,
    CBOR_Encoding_Error,
    CBOR_Error,
    CBOR_MajorTypes,
    CBOR_Object,
    _CBOR_ERROR,
)

from typing import (
    Any,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

##################
#  CBOR encoding #
##################


class CBOR_Exception(Exception):
    pass


class CBOR_Codec_Encoding_Error(CBOR_Encoding_Error):
    def __init__(self,
                 msg,  # type: str
                 encoded=None,  # type: Optional[Any]
                 remaining=b""  # type: bytes
                 ):
        # type: (...) -> None
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.encoded = encoded


class CBOR_Codec_Decoding_Error(CBOR_Decoding_Error):
    def __init__(self,
                 msg,  # type: str
                 decoded=None,  # type: Optional[Any]
                 remaining=b""  # type: bytes
                 ):
        # type: (...) -> None
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.decoded = decoded


def CBOR_encode_head(major_type, value):
    # type: (int, int) -> bytes
    """
    Encode CBOR initial byte and additional info.
    Format: 3 bits major type + 5 bits additional info
    """
    if value < 24:
        # Value fits in 5 bits
        return chb((major_type << 5) | value)
    elif value < 256:
        # 1-byte value follows
        return chb((major_type << 5) | 24) + chb(value)
    elif value < 65536:
        # 2-byte value follows
        return chb((major_type << 5) | 25) + struct.pack(">H", value)
    elif value < 4294967296:
        # 4-byte value follows
        return chb((major_type << 5) | 26) + struct.pack(">I", value)
    else:
        # 8-byte value follows
        return chb((major_type << 5) | 27) + struct.pack(">Q", value)


def CBOR_decode_head(s):
    # type: (bytes) -> Tuple[int, int, bytes]
    """
    Decode CBOR initial byte and additional info.
    Returns: (major_type, value, remaining_bytes)
    """
    if not s:
        raise CBOR_Codec_Decoding_Error("Empty CBOR data", remaining=s)
    
    initial_byte = orb(s[0])
    major_type = initial_byte >> 5
    additional_info = initial_byte & 0x1f
    
    if additional_info < 24:
        # Value is in the additional info
        return major_type, additional_info, s[1:]
    elif additional_info == 24:
        # 1-byte value follows
        if len(s) < 2:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 1-byte value", remaining=s)
        return major_type, orb(s[1]), s[2:]
    elif additional_info == 25:
        # 2-byte value follows
        if len(s) < 3:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 2-byte value", remaining=s)
        value = struct.unpack(">H", s[1:3])[0]
        return major_type, value, s[3:]
    elif additional_info == 26:
        # 4-byte value follows
        if len(s) < 5:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 4-byte value", remaining=s)
        value = struct.unpack(">I", s[1:5])[0]
        return major_type, value, s[5:]
    elif additional_info == 27:
        # 8-byte value follows
        if len(s) < 9:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 8-byte value", remaining=s)
        value = struct.unpack(">Q", s[1:9])[0]
        return major_type, value, s[9:]
    else:
        raise CBOR_Codec_Decoding_Error(
            "Invalid additional info: %d" % additional_info, remaining=s)


#    [ CBOR codec classes ]    #


class CBORcodec_metaclass(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[CBORcodec_Object[Any]]
        c = cast('Type[CBORcodec_Object[Any]]',
                 super(CBORcodec_metaclass, cls).__new__(cls, name, bases, dct))
        try:
            c.tag.register(c.codec, c)
        except Exception:
            pass  # Some codecs may not have tags yet
        return c


_K = TypeVar('_K')


class CBORcodec_Object(Generic[_K], metaclass=CBORcodec_metaclass):
    """Base CBOR codec class"""
    codec = CBOR_Codecs.CBOR
    tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    @classmethod
    def cbor_object(cls, val):
        # type: (_K) -> CBOR_Object[_K]
        return cls.tag.cbor_object(val)

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        if not s:
            raise CBOR_Codec_Decoding_Error(
                "%s: Got empty object while expecting tag %r" %
                (cls.__name__, cls.tag), remaining=s
            )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[Any], bytes]
        """Decode CBOR data using automatic dispatch based on major type."""
        return _decode_cbor_item(s, safe=safe)

    @classmethod
    def dec(cls,
            s,  # type: bytes
            context=None,  # type: Optional[Any]
            safe=False,  # type: bool
            ):
        # type: (...) -> Tuple[Union[_CBOR_ERROR, CBOR_Object[_K]], bytes]
        if not safe:
            return cls.do_dec(s, context, safe)
        try:
            return cls.do_dec(s, context, safe)
        except CBOR_Codec_Decoding_Error as e:
            return CBOR_DECODING_ERROR(s, exc=e), b""
        except CBOR_Error as e:
            return CBOR_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,  # type: bytes
                context=None,  # type: Optional[Any]
                ):
        # type: (...) -> Tuple[Union[_CBOR_ERROR, CBOR_Object[_K]], bytes]
        return cls.dec(s, context, safe=True)

    @classmethod
    def enc(cls, s):
        # type: (_K) -> bytes
        raise NotImplementedError("Subclasses must implement enc")


CBOR_Codecs.CBOR.register_stem(CBORcodec_Object)


##########################
#    CBORcodec objects   #
##########################


class CBORcodec_UNSIGNED_INTEGER(CBORcodec_Object[int]):
    """CBOR unsigned integer codec (major type 0)"""
    tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    @classmethod
    def enc(cls, obj):
        # type: (Union[int, CBOR_Object[int]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        i = obj.val if isinstance(obj, CBOR_Object) else obj
        if i < 0:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode negative value as unsigned integer. "
                "Use CBOR_NEGATIVE_INTEGER for negative values.")
        return CBOR_encode_head(0, i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[int], bytes]
        cls.check_string(s)
        major_type, value, remainder = CBOR_decode_head(s)
        if major_type != 0:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 0 (unsigned integer), got %d" % major_type,
                remaining=s)
        return cls.cbor_object(value), remainder


class CBORcodec_NEGATIVE_INTEGER(CBORcodec_Object[int]):
    """CBOR negative integer codec (major type 1)"""
    tag = CBOR_MajorTypes.NEGATIVE_INTEGER

    @classmethod
    def enc(cls, obj):
        # type: (Union[int, CBOR_Object[int]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        i = obj.val if isinstance(obj, CBOR_Object) else obj
        if i >= 0:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode non-negative value as negative integer. "
                "Use CBOR_UNSIGNED_INTEGER for non-negative values.")
        # CBOR negative integer: -1 - n
        return CBOR_encode_head(1, -1 - i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[int], bytes]
        cls.check_string(s)
        major_type, value, remainder = CBOR_decode_head(s)
        if major_type != 1:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 1 (negative integer), got %d" % major_type,
                remaining=s)
        # Decode: -1 - n
        return cls.cbor_object(-1 - value), remainder


class CBORcodec_BYTE_STRING(CBORcodec_Object[bytes]):
    """CBOR byte string codec (major type 2)"""
    tag = CBOR_MajorTypes.BYTE_STRING

    @classmethod
    def enc(cls, obj):
        # type: (Union[bytes, CBOR_Object[bytes]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        data = obj.val if isinstance(obj, CBOR_Object) else obj
        if not isinstance(data, bytes):
            data = bytes(data)
        return CBOR_encode_head(2, len(data)) + data

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[bytes], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 2:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 2 (byte string), got %d" % major_type,
                remaining=s)
        if len(remainder) < length:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for byte string: expected %d, got %d" %
                (length, len(remainder)), remaining=s)
        return cls.cbor_object(remainder[:length]), remainder[length:]


class CBORcodec_TEXT_STRING(CBORcodec_Object[str]):
    """CBOR text string codec (major type 3)"""
    tag = CBOR_MajorTypes.TEXT_STRING

    @classmethod
    def enc(cls, obj):
        # type: (Union[str, CBOR_Object[str]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        text = obj.val if isinstance(obj, CBOR_Object) else obj
        if isinstance(text, str):
            text_bytes = text.encode('utf-8')
        else:
            text_bytes = bytes(text)
        return CBOR_encode_head(3, len(text_bytes)) + text_bytes

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[str], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 3:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 3 (text string), got %d" % major_type,
                remaining=s)
        if len(remainder) < length:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for text string: expected %d, got %d" %
                (length, len(remainder)), remaining=s)
        try:
            text = remainder[:length].decode('utf-8')
        except UnicodeDecodeError as e:
            raise CBOR_Codec_Decoding_Error(
                "Invalid UTF-8 in text string: %s" % str(e), remaining=s)
        return cls.cbor_object(text), remainder[length:]


class CBORcodec_ARRAY(CBORcodec_Object[List[Any]]):
    """CBOR array codec (major type 4)"""
    tag = CBOR_MajorTypes.ARRAY

    @classmethod
    def enc(cls, obj):
        # type: (Union[List[Any], CBOR_Object[List[Any]]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        array = obj.val if isinstance(obj, CBOR_Object) else obj
        result = CBOR_encode_head(4, len(array))
        for item in array:
            result += CBORcodec_Object.encode_cbor_item(item)
        return result

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[List[Any]], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 4:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 4 (array), got %d" % major_type,
                remaining=s)
        
        items = []
        for _ in range(length):
            if not remainder:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough items in array", remaining=s)
            item, remainder = CBORcodec_Object.decode_cbor_item(
                remainder, safe=safe)
            items.append(item)
        
        return cls.cbor_object(items), remainder


class CBORcodec_MAP(CBORcodec_Object[Dict[Any, Any]]):
    """CBOR map codec (major type 5)"""
    tag = CBOR_MajorTypes.MAP

    @classmethod
    def enc(cls, obj):
        # type: (Union[Dict[Any, Any], CBOR_Object[Dict[Any, Any]]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        mapping = obj.val if isinstance(obj, CBOR_Object) else obj
        result = CBOR_encode_head(5, len(mapping))
        for key, value in mapping.items():
            result += CBORcodec_Object.encode_cbor_item(key)
            result += CBORcodec_Object.encode_cbor_item(value)
        return result

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[Dict[Any, Any]], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 5:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 5 (map), got %d" % major_type,
                remaining=s)
        
        mapping = {}
        for _ in range(length):
            if not remainder:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough key-value pairs in map", remaining=s)
            key, remainder = CBORcodec_Object.decode_cbor_item(
                remainder, safe=safe)
            if not remainder:
                raise CBOR_Codec_Decoding_Error(
                    "Map key without value", remaining=s)
            value, remainder = CBORcodec_Object.decode_cbor_item(
                remainder, safe=safe)
            # Convert key to hashable type if it's a CBOR object
            if isinstance(key, CBOR_Object):
                key_val = key.val
            else:
                key_val = key
            mapping[key_val] = value
        
        return cls.cbor_object(mapping), remainder


class CBORcodec_SEMANTIC_TAG(CBORcodec_Object[Tuple[int, Any]]):
    """CBOR semantic tag codec (major type 6)"""
    tag = CBOR_MajorTypes.TAG

    @classmethod
    def enc(cls, obj):
        # type: (Union[Tuple[int, Any], CBOR_Object[Tuple[int, Any]]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        tagged_item = obj.val if isinstance(obj, CBOR_Object) else obj
        tag_num, item = tagged_item
        result = CBOR_encode_head(6, tag_num)
        result += CBORcodec_Object.encode_cbor_item(item)
        return result

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[Tuple[int, Any]], bytes]
        cls.check_string(s)
        major_type, tag_num, remainder = CBOR_decode_head(s)
        if major_type != 6:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 6 (tag), got %d" % major_type,
                remaining=s)
        
        if not remainder:
            raise CBOR_Codec_Decoding_Error(
                "Tag without following item", remaining=s)
        
        item, remainder = CBORcodec_Object.decode_cbor_item(
            remainder, safe=safe)
        return cls.cbor_object((tag_num, item)), remainder


class CBORcodec_SIMPLE_AND_FLOAT(CBORcodec_Object[Union[int, float, bool, None]]):
    """CBOR simple values and floats codec (major type 7)"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    @classmethod
    def enc(cls, obj):
        # type: (Union[int, float, bool, None, CBOR_Object[Any]]) -> bytes
        from scapy.cbor.cbor import (
            CBOR_FALSE, CBOR_TRUE, CBOR_NULL, CBOR_UNDEFINED, CBOR_Object
        )
        
        # Check if obj is a CBOR object instance (for special cases like UNDEFINED)
        if isinstance(obj, CBOR_UNDEFINED):
            return chb(0xf7)  # undefined
        elif isinstance(obj, CBOR_NULL):
            return chb(0xf6)  # null
        elif isinstance(obj, CBOR_TRUE):
            return chb(0xf5)  # true
        elif isinstance(obj, CBOR_FALSE):
            return chb(0xf4)  # false
        elif isinstance(obj, CBOR_Object):
            # For other CBOR objects, use their val attribute
            val = obj.val
        else:
            val = obj
        
        if val is False:
            return chb(0xf4)  # false
        elif val is True:
            return chb(0xf5)  # true
        elif val is None:
            return chb(0xf6)  # null
        elif isinstance(val, float):
            # Encode as double precision (8 bytes)
            return chb(0xfb) + struct.pack(">d", val)
        elif isinstance(val, int) and 0 <= val <= 23:
            # Simple value 0-23
            return CBOR_encode_head(7, val)
        else:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode value as simple/float: %r" % val)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               ):
        # type: (...) -> Tuple[CBOR_Object[Any], bytes]
        from scapy.cbor.cbor import (
            CBOR_FALSE, CBOR_TRUE, CBOR_NULL, CBOR_UNDEFINED,
            CBOR_FLOAT, CBOR_SIMPLE_VALUE
        )
        
        cls.check_string(s)
        
        # For major type 7, we need special handling because additional_info
        # encodes different things (simple values vs float sizes)
        initial_byte = orb(s[0])
        major_type = initial_byte >> 5
        additional_info = initial_byte & 0x1f
        
        if major_type != 7:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 7 (simple/float), got %d" % major_type,
                remaining=s)
        
        # Check for special simple values (encoded directly in additional_info)
        if additional_info == 20:
            return CBOR_FALSE(), s[1:]
        elif additional_info == 21:
            return CBOR_TRUE(), s[1:]
        elif additional_info == 22:
            return CBOR_NULL(), s[1:]
        elif additional_info == 23:
            return CBOR_UNDEFINED(), s[1:]
        elif additional_info == 25:
            # Half precision float (2 bytes) - IEEE 754 binary16
            if len(s) < 3:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for half float", remaining=s)
            half_bytes = s[1:3]
            remainder = s[3:]
            # Convert IEEE 754 binary16 to binary64 (double)
            half_int = struct.unpack(">H", half_bytes)[0]
            sign = (half_int >> 15) & 0x1
            exponent = (half_int >> 10) & 0x1f
            fraction = half_int & 0x3ff
            
            # Handle special cases
            if exponent == 0:
                if fraction == 0:
                    # Zero
                    float_val = -0.0 if sign else 0.0
                else:
                    # Subnormal number
                    float_val = ((-1) ** sign) * (fraction / 1024.0) * (2 ** -14)
            elif exponent == 31:
                if fraction == 0:
                    # Infinity
                    float_val = float('-inf') if sign else float('inf')
                else:
                    # NaN
                    float_val = float('nan')
            else:
                # Normalized number
                float_val = ((-1) ** sign) * (1 + fraction / 1024.0) * (2 ** (exponent - 15))
            
            return CBOR_FLOAT(float_val), remainder
        elif additional_info == 26:
            # Single precision float (4 bytes)
            if len(s) < 5:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for single float", remaining=s)
            float_val = struct.unpack(">f", s[1:5])[0]
            return CBOR_FLOAT(float_val), s[5:]
        elif additional_info == 27:
            # Double precision float (8 bytes)
            if len(s) < 9:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for double float", remaining=s)
            float_val = struct.unpack(">d", s[1:9])[0]
            return CBOR_FLOAT(float_val), s[9:]
        elif additional_info < 24:
            # Simple value 0-23
            return CBOR_SIMPLE_VALUE(additional_info), s[1:]
        else:
            # additional_info 24 means 1-byte simple value follows
            if additional_info == 24:
                if len(s) < 2:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough bytes for simple value", remaining=s)
                return CBOR_SIMPLE_VALUE(orb(s[1])), s[2:]
            else:
                raise CBOR_Codec_Decoding_Error(
                    "Invalid additional info for major type 7: %d" % additional_info,
                    remaining=s)


# Helper methods for encoding/decoding arbitrary CBOR items


def _encode_cbor_item(item):
    # type: (Any) -> bytes
    """Encode a Python value to CBOR bytes"""
    from scapy.cbor.cbor import CBOR_Object
    
    if isinstance(item, CBOR_Object):
        return item.enc()
    elif isinstance(item, bool):
        # Must check bool before int (bool is subclass of int)
        return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
    elif isinstance(item, int):
        if item >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(item)
        else:
            return CBORcodec_NEGATIVE_INTEGER.enc(item)
    elif isinstance(item, bytes):
        return CBORcodec_BYTE_STRING.enc(item)
    elif isinstance(item, str):
        return CBORcodec_TEXT_STRING.enc(item)
    elif isinstance(item, list):
        return CBORcodec_ARRAY.enc(item)
    elif isinstance(item, dict):
        return CBORcodec_MAP.enc(item)
    elif isinstance(item, float):
        return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
    elif item is None:
        return CBORcodec_SIMPLE_AND_FLOAT.enc(None)
    else:
        raise CBOR_Codec_Encoding_Error(
            "Cannot encode type: %s" % type(item))


def _decode_cbor_item(s, safe=False):
    # type: (bytes, bool) -> Tuple[CBOR_Object[Any], bytes]
    """Decode CBOR bytes to a CBOR_Object"""
    if not s:
        raise CBOR_Codec_Decoding_Error("Empty CBOR data", remaining=s)
    
    initial_byte = orb(s[0])
    major_type = initial_byte >> 5
    
    # Dispatch to appropriate codec based on major type
    if major_type == 0:
        return CBORcodec_UNSIGNED_INTEGER.dec(s, safe=safe)
    elif major_type == 1:
        return CBORcodec_NEGATIVE_INTEGER.dec(s, safe=safe)
    elif major_type == 2:
        return CBORcodec_BYTE_STRING.dec(s, safe=safe)
    elif major_type == 3:
        return CBORcodec_TEXT_STRING.dec(s, safe=safe)
    elif major_type == 4:
        return CBORcodec_ARRAY.dec(s, safe=safe)
    elif major_type == 5:
        return CBORcodec_MAP.dec(s, safe=safe)
    elif major_type == 6:
        return CBORcodec_SEMANTIC_TAG.dec(s, safe=safe)
    elif major_type == 7:
        return CBORcodec_SIMPLE_AND_FLOAT.dec(s, safe=safe)
    else:
        raise CBOR_Codec_Decoding_Error(
            "Invalid major type: %d" % major_type, remaining=s)


# Add helper methods to CBORcodec_Object
CBORcodec_Object.encode_cbor_item = staticmethod(_encode_cbor_item)
CBORcodec_Object.decode_cbor_item = staticmethod(_decode_cbor_item)
