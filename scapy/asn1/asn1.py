# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>

"""
ASN.1 (Abstract Syntax Notation One)
"""

import random

from datetime import datetime, timedelta, tzinfo
from scapy.config import conf
from scapy.error import Scapy_Exception, warning
from scapy.volatile import RandField, RandIP, GeneralizedTime
from scapy.utils import Enum_metaclass, EnumElement, binrepr
from scapy.compat import plain_str, bytes_encode, chb, orb

from typing import (
    Any,
    AnyStr,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
    TYPE_CHECKING,
)
from typing import (
    TypeVar,
)

if TYPE_CHECKING:
    from scapy.asn1.ber import BERcodec_Object

try:
    from datetime import timezone
except ImportError:
    # Python 2 compat - don't bother typing it
    class UTC(tzinfo):
        """UTC"""

        def utcoffset(self, dt):  # type: ignore
            return timedelta(0)

        def tzname(self, dt):  # type: ignore
            return "UTC"

        def dst(self, dt):  # type: ignore
            return None

    class timezone(tzinfo):  # type: ignore
        def __init__(self, delta):  # type: ignore
            self.delta = delta

        def utcoffset(self, dt):  # type: ignore
            return self.delta

        def tzname(self, dt):  # type: ignore
            return None

        def dst(self, dt):  # type: ignore
            return None

    timezone.utc = UTC()  # type: ignore


class RandASN1Object(RandField["ASN1_Object[Any]"]):
    def __init__(self, objlist=None):
        # type: (Optional[List[Type[ASN1_Object[Any]]]]) -> None
        if objlist:
            self.objlist = objlist
        else:
            self.objlist = [
                x._asn1_obj
                for x in ASN1_Class_UNIVERSAL.__rdict__.values()  # type: ignore
                if hasattr(x, "_asn1_obj")
            ]
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"  # noqa: E501

    def _fix(self, n=0):
        # type: (int) -> ASN1_Object[Any]
        o = random.choice(self.objlist)
        if issubclass(o, ASN1_INTEGER):
            return o(int(random.gauss(0, 1000)))
        elif issubclass(o, ASN1_IPADDRESS):
            return o(RandIP()._fix())
        elif issubclass(o, ASN1_GENERALIZED_TIME) or issubclass(o, ASN1_UTC_TIME):
            return o(GeneralizedTime()._fix())
        elif issubclass(o, ASN1_STRING):
            z1 = int(random.expovariate(0.05) + 1)
            return o("".join(random.choice(self.chars) for _ in range(z1)))
        elif issubclass(o, ASN1_SEQUENCE) and (n < 10):
            z2 = int(random.expovariate(0.08) + 1)
            return o([self.__class__(objlist=self.objlist)._fix(n + 1)
                      for _ in range(z2)])
        return ASN1_INTEGER(int(random.gauss(0, 1000)))


##############
#    ASN1    #
##############

class ASN1_Error(Scapy_Exception):
    pass


class ASN1_Encoding_Error(ASN1_Error):
    pass


class ASN1_Decoding_Error(ASN1_Error):
    pass


class ASN1_BadTag_Decoding_Error(ASN1_Decoding_Error):
    pass


class ASN1Codec(EnumElement):
    def register_stem(cls, stem):
        # type: (Type[BERcodec_Object[Any]]) -> None
        cls._stem = stem

    def dec(cls, s, context=None):
        # type: (bytes, Optional[Type[ASN1_Class]]) -> ASN1_Object[Any]
        return cls._stem.dec(s, context=context)  # type: ignore

    def safedec(cls, s, context=None):
        # type: (bytes, Optional[Type[ASN1_Class]]) -> ASN1_Object[Any]
        return cls._stem.safedec(s, context=context)  # type: ignore

    def get_stem(cls):
        # type: () -> type
        return cls._stem


class ASN1_Codecs_metaclass(Enum_metaclass):
    element_class = ASN1Codec


class ASN1_Codecs(metaclass=ASN1_Codecs_metaclass):
    BER = cast(ASN1Codec, 1)
    DER = cast(ASN1Codec, 2)
    PER = cast(ASN1Codec, 3)
    CER = cast(ASN1Codec, 4)
    LWER = cast(ASN1Codec, 5)
    BACnet = cast(ASN1Codec, 6)
    OER = cast(ASN1Codec, 7)
    SER = cast(ASN1Codec, 8)
    XER = cast(ASN1Codec, 9)


class ASN1Tag(EnumElement):
    def __init__(self,
                 key,  # type: str
                 value,  # type: int
                 context=None,  # type: Optional[Type[ASN1_Class]]
                 codec=None  # type: Optional[Dict[ASN1Codec, Type[BERcodec_Object[Any]]]]  # noqa: E501
                 ):
        # type: (...) -> None
        EnumElement.__init__(self, key, value)
        # populated by the metaclass
        self.context = context  # type: Type[ASN1_Class]  # type: ignore
        if codec is None:
            codec = {}
        self._codec = codec

    def clone(self):  # not a real deep copy. self.codec is shared
        # type: () -> ASN1Tag
        return self.__class__(self._key, self._value, self.context, self._codec)  # noqa: E501

    def register_asn1_object(self, asn1obj):
        # type: (Type[ASN1_Object[Any]]) -> None
        self._asn1_obj = asn1obj

    def asn1_object(self, val):
        # type: (Any) -> ASN1_Object[Any]
        if hasattr(self, "_asn1_obj"):
            return self._asn1_obj(val)
        raise ASN1_Error("%r does not have any assigned ASN1 object" % self)

    def register(self, codecnum, codec):
        # type: (ASN1Codec, Type[BERcodec_Object[Any]]) -> None
        self._codec[codecnum] = codec

    def get_codec(self, codec):
        # type: (Any) -> Type[BERcodec_Object[Any]]
        try:
            c = self._codec[codec]
        except KeyError:
            raise ASN1_Error("Codec %r not found for tag %r" % (codec, self))
        return c


class ASN1_Class_metaclass(Enum_metaclass):
    element_class = ASN1Tag

    # XXX factorise a bit with Enum_metaclass.__new__()
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[ASN1_Class]
        for b in bases:
            for k, v in b.__dict__.items():
                if k not in dct and isinstance(v, ASN1Tag):
                    dct[k] = v.clone()

        rdict = {}
        for k, v in dct.items():
            if isinstance(v, int):
                v = ASN1Tag(k, v)
                dct[k] = v
                rdict[v] = v
            elif isinstance(v, ASN1Tag):
                rdict[v] = v
        dct["__rdict__"] = rdict

        ncls = cast('Type[ASN1_Class]',
                    type.__new__(cls, name, bases, dct))
        for v in ncls.__dict__.values():
            if isinstance(v, ASN1Tag):
                # overwrite ASN1Tag contexts, even cloned ones
                v.context = ncls
        return ncls


class ASN1_Class(metaclass=ASN1_Class_metaclass):
    pass


class ASN1_Class_UNIVERSAL(ASN1_Class):
    name = "UNIVERSAL"
    # Those casts are made so that MyPy understands what the
    # metaclass does in the background.
    ERROR = cast(ASN1Tag, -3)
    RAW = cast(ASN1Tag, -2)
    NONE = cast(ASN1Tag, -1)
    ANY = cast(ASN1Tag, 0)
    BOOLEAN = cast(ASN1Tag, 1)
    INTEGER = cast(ASN1Tag, 2)
    BIT_STRING = cast(ASN1Tag, 3)
    STRING = cast(ASN1Tag, 4)
    NULL = cast(ASN1Tag, 5)
    OID = cast(ASN1Tag, 6)
    OBJECT_DESCRIPTOR = cast(ASN1Tag, 7)
    EXTERNAL = cast(ASN1Tag, 8)
    REAL = cast(ASN1Tag, 9)
    ENUMERATED = cast(ASN1Tag, 10)
    EMBEDDED_PDF = cast(ASN1Tag, 11)
    UTF8_STRING = cast(ASN1Tag, 12)
    RELATIVE_OID = cast(ASN1Tag, 13)
    SEQUENCE = cast(ASN1Tag, 16 | 0x20)     # constructed encoding
    SET = cast(ASN1Tag, 17 | 0x20)          # constructed encoding
    NUMERIC_STRING = cast(ASN1Tag, 18)
    PRINTABLE_STRING = cast(ASN1Tag, 19)
    T61_STRING = cast(ASN1Tag, 20)          # aka TELETEX_STRING
    VIDEOTEX_STRING = cast(ASN1Tag, 21)
    IA5_STRING = cast(ASN1Tag, 22)
    UTC_TIME = cast(ASN1Tag, 23)
    GENERALIZED_TIME = cast(ASN1Tag, 24)
    GRAPHIC_STRING = cast(ASN1Tag, 25)
    ISO646_STRING = cast(ASN1Tag, 26)       # aka VISIBLE_STRING
    GENERAL_STRING = cast(ASN1Tag, 27)
    UNIVERSAL_STRING = cast(ASN1Tag, 28)
    CHAR_STRING = cast(ASN1Tag, 29)
    BMP_STRING = cast(ASN1Tag, 30)
    IPADDRESS = cast(ASN1Tag, 0 | 0x40)     # application-specific encoding
    COUNTER32 = cast(ASN1Tag, 1 | 0x40)     # application-specific encoding
    COUNTER64 = cast(ASN1Tag, 6 | 0x40)     # application-specific encoding
    GAUGE32 = cast(ASN1Tag, 2 | 0x40)       # application-specific encoding
    TIME_TICKS = cast(ASN1Tag, 3 | 0x40)    # application-specific encoding


class ASN1_Object_metaclass(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[ASN1_Object[Any]]
        c = cast(
            'Type[ASN1_Object[Any]]',
            super(ASN1_Object_metaclass, cls).__new__(cls, name, bases, dct)
        )
        try:
            c.tag.register_asn1_object(c)
        except Exception:
            warning("Error registering %r" % c.tag)
        return c


_K = TypeVar('_K')


class ASN1_Object(Generic[_K], metaclass=ASN1_Object_metaclass):
    tag = ASN1_Class_UNIVERSAL.ANY

    def __init__(self, val):
        # type: (_K) -> None
        self.val = val

    def enc(self, codec):
        # type: (Any) -> bytes
        return self.tag.get_codec(codec).enc(self.val)

    def __repr__(self):
        # type: () -> str
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.val)  # noqa: E501

    def __str__(self):
        # type: () -> str
        return plain_str(self.enc(conf.ASN1_default_codec))

    def __bytes__(self):
        # type: () -> bytes
        return self.enc(conf.ASN1_default_codec)

    def strshow(self, lvl=0):
        # type: (int) -> str
        return ("  " * lvl) + repr(self) + "\n"

    def show(self, lvl=0):
        # type: (int) -> None
        print(self.strshow(lvl))

    def __eq__(self, other):
        # type: (Any) -> bool
        return bool(self.val == other)

    def __lt__(self, other):
        # type: (Any) -> bool
        return bool(self.val < other)

    def __le__(self, other):
        # type: (Any) -> bool
        return bool(self.val <= other)

    def __gt__(self, other):
        # type: (Any) -> bool
        return bool(self.val > other)

    def __ge__(self, other):
        # type: (Any) -> bool
        return bool(self.val >= other)

    def __ne__(self, other):
        # type: (Any) -> bool
        return bool(self.val != other)

    def command(self, json=False):
        # type: (bool) -> Union[Dict[str, str], str]
        if json:
            if isinstance(self.val, bytes):
                val = self.val.decode("utf-8", errors="backslashreplace")
            else:
                val = repr(self.val)
            return {"type": self.__class__.__name__, "value": val}
        else:
            return "%s(%s)" % (self.__class__.__name__, repr(self.val))


#######################
#     ASN1 objects    #
#######################

# on the whole, we order the classes by ASN1_Class_UNIVERSAL tag value

class _ASN1_ERROR(ASN1_Object[Union[bytes, ASN1_Object[Any]]]):
    pass


class ASN1_DECODING_ERROR(_ASN1_ERROR):
    tag = ASN1_Class_UNIVERSAL.ERROR

    def __init__(self, val, exc=None):
        # type: (Union[bytes, ASN1_Object[Any]], Optional[Exception]) -> None
        ASN1_Object.__init__(self, val)
        self.exc = exc

    def __repr__(self):
        # type: () -> str
        return "<%s[%r]{{%r}}>" % (
            self.__dict__.get("name", self.__class__.__name__),
            self.val,
            self.exc and self.exc.args[0] or ""
        )

    def enc(self, codec):
        # type: (Any) -> bytes
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val


class ASN1_force(_ASN1_ERROR):
    tag = ASN1_Class_UNIVERSAL.RAW

    def enc(self, codec):
        # type: (Any) -> bytes
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val


class ASN1_BADTAG(ASN1_force):
    pass


class ASN1_INTEGER(ASN1_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    def __repr__(self):
        # type: () -> str
        h = hex(self.val)
        if h[-1] == "L":
            h = h[:-1]
        # cut at 22 because with leading '0x', x509 serials should be < 23
        if len(h) > 22:
            h = h[:12] + "..." + h[-10:]
        r = repr(self.val)
        if len(r) > 20:
            r = r[:10] + "..." + r[-10:]
        return h + " <%s[%s]>" % (self.__dict__.get("name", self.__class__.__name__), r)  # noqa: E501


class ASN1_BOOLEAN(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN
    # BER: 0 means False, anything else means True

    def __repr__(self):
        # type: () -> str
        return '%s %s' % (not (self.val == 0), ASN1_Object.__repr__(self))


class ASN1_BIT_STRING(ASN1_Object[str]):
    """
     ASN1_BIT_STRING values are bit strings like "011101".
     A zero-bit padded readable string is provided nonetheless,
     which is stored in val_readable
    """
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    def __init__(self, val, readable=False):
        # type: (AnyStr, bool) -> None
        if not readable:
            self.val = cast(str, val)  # type: ignore
        else:
            self.val_readable = cast(bytes, val)  # type: ignore

    def __setattr__(self, name, value):
        # type: (str, Any) -> None
        if name == "val_readable":
            if isinstance(value, (str, bytes)):
                val = "".join(binrepr(orb(x)).zfill(8) for x in value)
            else:
                warning("Invalid val: should be bytes")
                val = "<invalid val_readable>"
            object.__setattr__(self, "val", val)
            object.__setattr__(self, name, bytes_encode(value))
            object.__setattr__(self, "unused_bits", 0)
        elif name == "val":
            value = plain_str(value)
            if isinstance(value, str):
                if any(c for c in value if c not in ["0", "1"]):
                    warning("Invalid operation: 'val' is not a valid bit string.")  # noqa: E501
                    return
                else:
                    if len(value) % 8 == 0:
                        unused_bits = 0
                    else:
                        unused_bits = 8 - (len(value) % 8)
                    padded_value = value + ("0" * unused_bits)
                    bytes_arr = zip(*[iter(padded_value)] * 8)
                    val_readable = b"".join(chb(int("".join(x), 2)) for x in bytes_arr)  # noqa: E501
            else:
                warning("Invalid val: should be str")
                val_readable = b"<invalid val>"
                unused_bits = 0
            object.__setattr__(self, "val_readable", val_readable)
            object.__setattr__(self, name, value)
            object.__setattr__(self, "unused_bits", unused_bits)
        elif name == "unused_bits":
            warning("Invalid operation: unused_bits rewriting "
                    "is not supported.")
        else:
            object.__setattr__(self, name, value)

    def set(self, i, val):
        # type: (int, str) -> None
        """
        Sets bit 'i' to value 'val' (starting from 0)
        """
        val = str(val)
        assert val in ['0', '1']
        if len(self.val) < i:
            self.val += "0" * (i - len(self.val))
        self.val = self.val[:i] + val + self.val[i + 1:]

    def __repr__(self):
        # type: () -> str
        s = self.val_readable
        if len(s) > 16:
            s = s[:10] + b"..." + s[-10:]
        v = self.val
        if len(v) > 20:
            v = v[:10] + "..." + v[-10:]
        return "<%s[%s]=%r (%d unused bit%s)>" % (
            self.__dict__.get("name", self.__class__.__name__),
            v,
            s,
            self.unused_bits,  # type: ignore
            "s" if self.unused_bits > 1 else ""  # type: ignore
        )


class ASN1_STRING(ASN1_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING


class ASN1_NULL(ASN1_Object[None]):
    tag = ASN1_Class_UNIVERSAL.NULL

    def __repr__(self):
        # type: () -> str
        return ASN1_Object.__repr__(self)


class ASN1_OID(ASN1_Object[str]):
    tag = ASN1_Class_UNIVERSAL.OID

    def __init__(self, val):
        # type: (str) -> None
        val = plain_str(val)
        val = conf.mib._oid(val)
        ASN1_Object.__init__(self, val)
        self.oidname = conf.mib._oidname(val)

    def __repr__(self):
        # type: () -> str
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.oidname)  # noqa: E501


class ASN1_ENUMERATED(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED


class ASN1_UTF8_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class ASN1_NUMERIC_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class ASN1_PRINTABLE_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class ASN1_T61_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING


class ASN1_VIDEOTEX_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class ASN1_IA5_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING


class ASN1_GENERAL_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class ASN1_GENERALIZED_TIME(ASN1_STRING):
    """
    Improved version of ASN1_GENERALIZED_TIME, properly handling time zones and
    all string representation formats defined by ASN.1. These are:

    1. Local time only:                        YYYYMMDDHH[MM[SS[.fff]]]
    2. Universal time (UTC time) only:         YYYYMMDDHH[MM[SS[.fff]]]Z
    3. Difference between local and UTC times: YYYYMMDDHH[MM[SS[.fff]]]+-HHMM

    It also handles ASN1_UTC_TIME, which allows:

    1. Universal time (UTC time) only:         YYMMDDHHMM[SS[.fff]]Z
    2. Difference between local and UTC times: YYMMDDHHMM[SS[.fff]]+-HHMM

    Note the differences: Year is only two digits, minutes are not optional and
    there is no milliseconds.
    """
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME
    pretty_time = None

    def __init__(self, val):
        # type: (Union[str, datetime]) -> None
        if isinstance(val, datetime):
            self.__setattr__("datetime", val)
        else:
            super(ASN1_GENERALIZED_TIME, self).__init__(val)

    def __setattr__(self, name, value):
        # type: (str, Any) -> None
        if isinstance(value, bytes):
            value = plain_str(value)

        if name == "val":
            formats = {
                10: "%Y%m%d%H",
                12: "%Y%m%d%H%M",
                14: "%Y%m%d%H%M%S"
            }
            dt = None  # type: Optional[datetime]
            try:
                if value[-1] == "Z":
                    str, ofs = value[:-1], value[-1:]
                elif value[-5] in ("+", "-"):
                    str, ofs = value[:-5], value[-5:]
                elif isinstance(self, ASN1_UTC_TIME):
                    raise ValueError()
                else:
                    str, ofs = value, ""

                if isinstance(self, ASN1_UTC_TIME) and len(str) >= 10:
                    fmt = "%y" + formats[len(str) + 2][2:]
                elif str[-4] == ".":
                    fmt = formats[len(str) - 4] + ".%f"
                else:
                    fmt = formats[len(str)]

                dt = datetime.strptime(str, fmt)
                if ofs == 'Z':
                    dt = dt.replace(tzinfo=timezone.utc)
                elif ofs:
                    sign = -1 if ofs[0] == "-" else 1
                    ofs = datetime.strptime(ofs[1:], "%H%M")
                    delta = timedelta(hours=ofs.hour * sign,
                                      minutes=ofs.minute * sign)
                    dt = dt.replace(tzinfo=timezone(delta))
            except Exception:
                dt = None

            pretty_time = None
            if dt is None:
                _nam = self.tag._asn1_obj.__name__[5:]
                _nam = _nam.lower().replace("_", " ")
                pretty_time = "%s [invalid %s]" % (value, _nam)
            else:
                pretty_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                if dt.microsecond:
                    pretty_time += dt.strftime(".%f")[:4]
                if dt.tzinfo == timezone.utc:
                    pretty_time += dt.strftime(" UTC")
                elif dt.tzinfo is not None:
                    if dt.tzinfo.utcoffset(dt) is not None:
                        pretty_time += dt.strftime(" %z")

            ASN1_STRING.__setattr__(self, "pretty_time", pretty_time)
            ASN1_STRING.__setattr__(self, "datetime", dt)
            ASN1_STRING.__setattr__(self, name, value)
        elif name == "pretty_time":
            print("Invalid operation: pretty_time rewriting is not supported.")
        elif name == "datetime":
            ASN1_STRING.__setattr__(self, name, value)
            if isinstance(value, datetime):
                yfmt = "%y" if isinstance(self, ASN1_UTC_TIME) else "%Y"
                if value.microsecond:
                    str = value.strftime(yfmt + "%m%d%H%M%S.%f")[:-3]
                else:
                    str = value.strftime(yfmt + "%m%d%H%M%S")

                if value.tzinfo == timezone.utc:
                    str = str + "Z"
                else:
                    str = str + value.strftime("%z")  # empty if naive

                ASN1_STRING.__setattr__(self, "val", str)
            else:
                ASN1_STRING.__setattr__(self, "val", None)
        else:
            ASN1_STRING.__setattr__(self, name, value)

    def __repr__(self):
        # type: () -> str
        return "%s %s" % (
            self.pretty_time,
            super(ASN1_GENERALIZED_TIME, self).__repr__()
        )


class ASN1_UTC_TIME(ASN1_GENERALIZED_TIME):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME


class ASN1_ISO646_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class ASN1_UNIVERSAL_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class ASN1_BMP_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING

    def __setattr__(self, name, value):
        # type: (str, Any) -> None
        if name == "val":
            if isinstance(value, str):
                value = value.encode("utf-16be")
            object.__setattr__(self, name, value)
        else:
            object.__setattr__(self, name, value)

    def __repr__(self):
        # type: () -> str
        return "<%s[%r]>" % (
            self.__dict__.get("name", self.__class__.__name__),
            self.val.decode("utf-16be"),  # type: ignore
        )


class ASN1_SEQUENCE(ASN1_Object[List[Any]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    def strshow(self, lvl=0):
        # type: (int) -> str
        s = ("  " * lvl) + ("# %s:" % self.__class__.__name__) + "\n"
        for o in self.val:
            s += o.strshow(lvl=lvl + 1)
        return s


class ASN1_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class ASN1_IPADDRESS(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS


class ASN1_COUNTER32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32


class ASN1_COUNTER64(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER64


class ASN1_GAUGE32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32


class ASN1_TIME_TICKS(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS


conf.ASN1_default_codec = ASN1_Codecs.BER
