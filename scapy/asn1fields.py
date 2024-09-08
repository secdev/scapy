# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>

"""
Classes that implement ASN.1 data structures.
"""

import copy

from functools import reduce

from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_Class,
    ASN1_Class_UNIVERSAL,
    ASN1_Error,
    ASN1_INTEGER,
    ASN1_NULL,
    ASN1_OID,
    ASN1_Object,
    ASN1_STRING,
)
from scapy.asn1.ber import (
    BER_Decoding_Error,
    BER_id_dec,
    BER_tagging_dec,
    BER_tagging_enc,
)
from scapy.base_classes import BasePacket
from scapy.compat import raw
from scapy.volatile import (
    GeneralizedTime,
    RandChoice,
    RandInt,
    RandNum,
    RandOID,
    RandString,
    RandField,
)

from scapy import packet

from typing import (
    Any,
    AnyStr,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from scapy.asn1packet import ASN1_Packet


class ASN1F_badsequence(Exception):
    pass


class ASN1F_element(object):
    pass


##########################
#    Basic ASN1 Field    #
##########################

_I = TypeVar('_I')  # Internal storage
_A = TypeVar('_A')  # ASN.1 object


class ASN1F_field(ASN1F_element, Generic[_I, _A]):
    holds_packets = 0
    islist = 0
    ASN1_tag = ASN1_Class_UNIVERSAL.ANY
    context = ASN1_Class_UNIVERSAL  # type: Type[ASN1_Class]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[_A]
                 context=None,  # type: Optional[Type[ASN1_Class]]
                 implicit_tag=None,  # type: Optional[int]
                 explicit_tag=None,  # type: Optional[int]
                 flexible_tag=False,  # type: Optional[bool]
                 size_len=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        if context is not None:
            self.context = context
        self.name = name
        if default is None:
            self.default = default  # type: Optional[_A]
        elif isinstance(default, ASN1_NULL):
            self.default = default  # type: ignore
        else:
            self.default = self.ASN1_tag.asn1_object(default)  # type: ignore
        self.size_len = size_len
        self.flexible_tag = flexible_tag
        if (implicit_tag is not None) and (explicit_tag is not None):
            err_msg = "field cannot be both implicitly and explicitly tagged"
            raise ASN1_Error(err_msg)
        self.implicit_tag = implicit_tag and int(implicit_tag)
        self.explicit_tag = explicit_tag and int(explicit_tag)
        # network_tag gets useful for ASN1F_CHOICE
        self.network_tag = int(implicit_tag or explicit_tag or self.ASN1_tag)
        self.owners = []  # type: List[Type[ASN1_Packet]]

    def register_owner(self, cls):
        # type: (Type[ASN1_Packet]) -> None
        self.owners.append(cls)

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, _I) -> str
        return repr(x)

    def i2h(self, pkt, x):
        # type: (ASN1_Packet, _I) -> Any
        return x

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[_A, bytes]
        """
        The good thing about safedec is that it may still decode ASN1
        even if there is a mismatch between the expected tag (self.ASN1_tag)
        and the actual tag; the decoded ASN1 object will simply be put
        into an ASN1_BADTAG object. However, safedec prevents the raising of
        exceptions needed for ASN1F_optional processing.
        Thus we use 'flexible_tag', which should be False with ASN1F_optional.

        Regarding other fields, we might need to know whether encoding went
        as expected or not. Noticeably, input methods from cert.py expect
        certain exceptions to be raised. Hence default flexible_tag is False.
        """
        diff_tag, s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                      implicit_tag=self.implicit_tag,
                                      explicit_tag=self.explicit_tag,
                                      safe=self.flexible_tag,
                                      _fname=self.name)
        if diff_tag is not None:
            # this implies that flexible_tag was True
            if self.implicit_tag is not None:
                self.implicit_tag = diff_tag
            elif self.explicit_tag is not None:
                self.explicit_tag = diff_tag
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        if self.flexible_tag:
            return codec.safedec(s, context=self.context)  # type: ignore
        else:
            return codec.dec(s, context=self.context)  # type: ignore

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Union[bytes, _I, _A]) -> bytes
        if x is None:
            return b""
        if isinstance(x, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                x.tag == ASN1_Class_UNIVERSAL.RAW or
                x.tag == ASN1_Class_UNIVERSAL.ERROR or
               self.ASN1_tag == x.tag):
                s = x.enc(pkt.ASN1_codec)
            else:
                raise ASN1_Error("Encoding Error: got %r instead of an %r for field [%s]" % (x, self.ASN1_tag, self.name))  # noqa: E501
        else:
            s = self.ASN1_tag.get_codec(pkt.ASN1_codec).enc(x, size_len=self.size_len)
        return BER_tagging_enc(s,
                               implicit_tag=self.implicit_tag,
                               explicit_tag=self.explicit_tag)

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> _I
        return cast(_I, x)

    def extract_packet(self,
                       cls,  # type: Type[ASN1_Packet]
                       s,  # type: bytes
                       _underlayer=None  # type: Optional[ASN1_Packet]
                       ):
        # type: (...) -> Tuple[ASN1_Packet, bytes]
        try:
            c = cls(s, _underlayer=_underlayer)
        except ASN1F_badsequence:
            c = packet.Raw(s, _underlayer=_underlayer)  # type: ignore
        cpad = c.getlayer(packet.Raw)
        s = b""
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        return self.i2m(pkt, getattr(pkt, self.name))

    def dissect(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> bytes
        v, s = self.m2i(pkt, s)
        self.set_val(pkt, v)
        return s

    def do_copy(self, x):
        # type: (Any) -> Any
        if isinstance(x, list):
            x = x[:]
            for i in range(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
            return x
        if hasattr(x, "copy"):
            return x.copy()
        return x

    def set_val(self, pkt, val):
        # type: (ASN1_Packet, Any) -> None
        setattr(pkt, self.name, val)

    def is_empty(self, pkt):
        # type: (ASN1_Packet) -> bool
        return getattr(pkt, self.name) is None

    def get_fields_list(self):
        # type: () -> List[ASN1F_field[Any, Any]]
        return [self]

    def __str__(self):
        # type: () -> str
        return repr(self)

    def randval(self):
        # type: () -> RandField[_I]
        return cast(RandField[_I], RandInt())

    def copy(self):
        # type: () -> ASN1F_field[_I, _A]
        return copy.copy(self)


############################
#    Simple ASN1 Fields    #
############################

class ASN1F_BOOLEAN(ASN1F_field[bool, ASN1_BOOLEAN]):
    ASN1_tag = ASN1_Class_UNIVERSAL.BOOLEAN

    def randval(self):
        # type: () -> RandChoice
        return RandChoice(True, False)


class ASN1F_INTEGER(ASN1F_field[int, ASN1_INTEGER]):
    ASN1_tag = ASN1_Class_UNIVERSAL.INTEGER

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2**64, 2**64 - 1)


class ASN1F_enum_INTEGER(ASN1F_INTEGER):
    def __init__(self,
                 name,  # type: str
                 default,  # type: ASN1_INTEGER
                 enum,  # type: Dict[int, str]
                 context=None,  # type: Optional[Any]
                 implicit_tag=None,  # type: Optional[Any]
                 explicit_tag=None,  # type: Optional[Any]
                 ):
        # type: (...) -> None
        super(ASN1F_enum_INTEGER, self).__init__(
            name, default, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )
        i2s = self.i2s = {}  # type: Dict[int, str]
        s2i = self.s2i = {}  # type: Dict[str, int]
        if isinstance(enum, list):
            keys = range(len(enum))
        else:
            keys = list(enum)
        if any(isinstance(x, str) for x in keys):
            i2s, s2i = s2i, i2s  # type: ignore
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k

    def i2m(self,
            pkt,  # type: ASN1_Packet
            s,  # type: Union[bytes, str, int, ASN1_INTEGER]
            ):
        # type: (...) -> bytes
        if not isinstance(s, str):
            vs = s
        else:
            vs = self.s2i[s]
        return super(ASN1F_enum_INTEGER, self).i2m(pkt, vs)

    def i2repr(self,
               pkt,  # type: ASN1_Packet
               x,  # type: Union[str, int]
               ):
        # type: (...) -> str
        if x is not None and isinstance(x, ASN1_INTEGER):
            r = self.i2s.get(x.val)
            if r:
                return "'%s' %s" % (r, repr(x))
        return repr(x)


class ASN1F_BIT_STRING(ASN1F_field[str, ASN1_BIT_STRING]):
    ASN1_tag = ASN1_Class_UNIVERSAL.BIT_STRING

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Union[ASN1_BIT_STRING, AnyStr]]
                 default_readable=True,  # type: bool
                 context=None,  # type: Optional[Any]
                 implicit_tag=None,  # type: Optional[int]
                 explicit_tag=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        super(ASN1F_BIT_STRING, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )
        if isinstance(default, (bytes, str)):
            self.default = ASN1_BIT_STRING(default,
                                           readable=default_readable)
        else:
            self.default = default

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class ASN1F_STRING(ASN1F_field[str, ASN1_STRING]):
    ASN1_tag = ASN1_Class_UNIVERSAL.STRING

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class ASN1F_NULL(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.NULL


class ASN1F_OID(ASN1F_field[str, ASN1_OID]):
    ASN1_tag = ASN1_Class_UNIVERSAL.OID

    def randval(self):
        # type: () -> RandOID
        return RandOID()


class ASN1F_ENUMERATED(ASN1F_enum_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.ENUMERATED


class ASN1F_UTF8_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class ASN1F_NUMERIC_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class ASN1F_PRINTABLE_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class ASN1F_T61_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.T61_STRING


class ASN1F_VIDEOTEX_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class ASN1F_IA5_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IA5_STRING


class ASN1F_GENERAL_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class ASN1F_UTC_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTC_TIME

    def randval(self):  # type: ignore
        # type: () -> GeneralizedTime
        return GeneralizedTime()


class ASN1F_GENERALIZED_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

    def randval(self):  # type: ignore
        # type: () -> GeneralizedTime
        return GeneralizedTime()


class ASN1F_ISO646_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class ASN1F_UNIVERSAL_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class ASN1F_BMP_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.BMP_STRING


class ASN1F_SEQUENCE(ASN1F_field[List[Any], List[Any]]):
    # Here is how you could decode a SEQUENCE
    # with an unknown, private high-tag prefix :
    # class PrivSeq(ASN1_Packet):
    #     ASN1_codec = ASN1_Codecs.BER
    #     ASN1_root = ASN1F_SEQUENCE(
    #                       <asn1 field #0>,
    #                       ...
    #                       <asn1 field #N>,
    #                       explicit_tag=0,
    #                       flexible_tag=True)
    # Because we use flexible_tag, the value of the explicit_tag does not matter.  # noqa: E501
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    holds_packets = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        name = "dummy_seq_name"
        default = [field.default for field in seq]
        super(ASN1F_SEQUENCE, self).__init__(
            name, default, **kwargs
        )
        self.seq = seq
        self.islist = len(seq) > 1

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (ASN1_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[ASN1F_field[Any, Any]]
        return reduce(lambda x, y: x + y.get_fields_list(),
                      self.seq, [])

    def m2i(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        """
        ASN1F_SEQUENCE behaves transparently, with nested ASN1_objects being
        dissected one by one. Because we use obj.dissect (see loop below)
        instead of obj.m2i (as we trust dissect to do the appropriate set_vals)
        we do not directly retrieve the list of nested objects.
        Thus m2i returns an empty list (along with the proper remainder).
        It is discarded by dissect() and should not be missed elsewhere.
        """
        diff_tag, s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                      implicit_tag=self.implicit_tag,
                                      explicit_tag=self.explicit_tag,
                                      safe=self.flexible_tag,
                                      _fname=pkt.name)
        if diff_tag is not None:
            if self.implicit_tag is not None:
                self.implicit_tag = diff_tag
            elif self.explicit_tag is not None:
                self.explicit_tag = diff_tag
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i, s, remain = codec.check_type_check_len(s)
        if len(s) == 0:
            for obj in self.seq:
                obj.set_val(pkt, None)
        else:
            for obj in self.seq:
                try:
                    s = obj.dissect(pkt, s)
                except ASN1F_badsequence:
                    break
            if len(s) > 0:
                raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return [], remain

    def dissect(self, pkt, s):
        # type: (Any, bytes) -> bytes
        _, x = self.m2i(pkt, s)
        return x

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        s = reduce(lambda x, y: x + y.build(pkt),
                   self.seq, b"")
        return super(ASN1F_SEQUENCE, self).i2m(pkt, s)


class ASN1F_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET


_SEQ_T = Union[
    'ASN1_Packet',
    Type[ASN1F_field[Any, Any]],
    'ASN1F_PACKET',
    ASN1F_field[Any, Any],
]


class ASN1F_SEQUENCE_OF(ASN1F_field[List[_SEQ_T],
                                    List[ASN1_Object[Any]]]):
    """
    Two types are allowed as cls: ASN1_Packet, ASN1F_field
    """
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    islist = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 cls,  # type: _SEQ_T
                 context=None,  # type: Optional[Any]
                 implicit_tag=None,  # type: Optional[Any]
                 explicit_tag=None,  # type: Optional[Any]
                 ):
        # type: (...) -> None
        if isinstance(cls, type) and issubclass(cls, ASN1F_field) or \
                isinstance(cls, ASN1F_field):
            if isinstance(cls, type):
                self.fld = cls(name, b"")
            else:
                self.fld = cls
            self._extract_packet = lambda s, pkt: self.fld.m2i(pkt, s)
            self.holds_packets = 0
        elif hasattr(cls, "ASN1_root") or callable(cls):
            self.cls = cast("Type[ASN1_Packet]", cls)
            self._extract_packet = lambda s, pkt: self.extract_packet(
                self.cls, s, _underlayer=pkt)
            self.holds_packets = 1
        else:
            raise ValueError("cls should be an ASN1_Packet or ASN1_field")
        super(ASN1F_SEQUENCE_OF, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag
        )
        self.default = default

    def is_empty(self,
                 pkt,  # type: ASN1_Packet
                 ):
        # type: (...) -> bool
        return ASN1F_field.is_empty(self, pkt)

    def m2i(self,
            pkt,  # type: ASN1_Packet
            s,  # type: bytes
            ):
        # type: (...) -> Tuple[List[Any], bytes]
        diff_tag, s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                      implicit_tag=self.implicit_tag,
                                      explicit_tag=self.explicit_tag,
                                      safe=self.flexible_tag)
        if diff_tag is not None:
            if self.implicit_tag is not None:
                self.implicit_tag = diff_tag
            elif self.explicit_tag is not None:
                self.explicit_tag = diff_tag
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i, s, remain = codec.check_type_check_len(s)
        lst = []
        while s:
            c, s = self._extract_packet(s, pkt)  # type: ignore
            if c:
                lst.append(c)
        if len(s) > 0:
            raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return lst, remain

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and \
                val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = cast(Union[List[_SEQ_T], bytes], val)
        elif val is None:
            s = b""
        else:
            s = b"".join(raw(i) for i in val)
        return self.i2m(pkt, s)

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, _I) -> str
        if self.holds_packets:
            return super(ASN1F_SEQUENCE_OF, self).i2repr(pkt, x)  # type: ignore
        else:
            return "[%s]" % ", ".join(
                self.fld.i2repr(pkt, x) for x in x  # type: ignore
            )

    def randval(self):
        # type: () -> Any
        if self.holds_packets:
            return packet.fuzz(self.cls())
        else:
            return self.fld.randval()

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class ASN1F_SET_OF(ASN1F_SEQUENCE_OF):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET


class ASN1F_IPADDRESS(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IPADDRESS


class ASN1F_TIME_TICKS(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.TIME_TICKS


#############################
#    Complex ASN1 Fields    #
#############################

class ASN1F_optional(ASN1F_element):
    def __init__(self, field):
        # type: (ASN1F_field[Any, Any]) -> None
        field.flexible_tag = False
        self._field = field

    def __getattr__(self, attr):
        # type: (str) -> Optional[Any]
        return getattr(self._field, attr)

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        try:
            return self._field.m2i(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, BER_Decoding_Error):
            # ASN1_Error may be raised by ASN1F_CHOICE
            return None, s

    def dissect(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> bytes
        try:
            return self._field.dissect(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, BER_Decoding_Error):
            self._field.set_val(pkt, None)
            return s

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        if self._field.is_empty(pkt):
            return b""
        return self._field.build(pkt)

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> Any
        return self._field.any2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, Any) -> str
        return self._field.i2repr(pkt, x)


_CHOICE_T = Union['ASN1_Packet', Type[ASN1F_field[Any, Any]], 'ASN1F_PACKET']


class ASN1F_CHOICE(ASN1F_field[_CHOICE_T, ASN1_Object[Any]]):
    """
    Multiple types are allowed: ASN1_Packet, ASN1F_field and ASN1F_PACKET(),
    See layers/x509.py for examples.
    Other ASN1F_field instances than ASN1F_PACKET instances must not be used.
    """
    holds_packets = 1
    ASN1_tag = ASN1_Class_UNIVERSAL.ANY

    def __init__(self, name, default, *args, **kwargs):
        # type: (str, Any, *_CHOICE_T, **Any) -> None
        if "implicit_tag" in kwargs:
            err_msg = "ASN1F_CHOICE has been called with an implicit_tag"
            raise ASN1_Error(err_msg)
        self.implicit_tag = None
        for kwarg in ["context", "explicit_tag"]:
            setattr(self, kwarg, kwargs.get(kwarg))
        super(ASN1F_CHOICE, self).__init__(
            name, None, context=self.context,
            explicit_tag=self.explicit_tag
        )
        self.default = default
        self.current_choice = None
        self.choices = {}  # type: Dict[int, _CHOICE_T]
        self.pktchoices = {}
        for p in args:
            if hasattr(p, "ASN1_root"):
                p = cast('ASN1_Packet', p)
                # should be ASN1_Packet
                if hasattr(p.ASN1_root, "choices"):
                    root = cast(ASN1F_CHOICE, p.ASN1_root)
                    for k, v in root.choices.items():
                        # ASN1F_CHOICE recursion
                        self.choices[k] = v
                else:
                    self.choices[p.ASN1_root.network_tag] = p
            elif hasattr(p, "ASN1_tag"):
                if isinstance(p, type):
                    # should be ASN1F_field class
                    self.choices[int(p.ASN1_tag)] = p
                else:
                    # should be ASN1F_field instance
                    self.choices[p.network_tag] = p
                    self.pktchoices[hash(p.cls)] = (p.implicit_tag, p.explicit_tag)  # noqa: E501
            else:
                raise ASN1_Error("ASN1F_CHOICE: no tag found for one field")

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        """
        First we have to retrieve the appropriate choice.
        Then we extract the field/packet, according to this choice.
        """
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        _, s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                               explicit_tag=self.explicit_tag)
        tag, _ = BER_id_dec(s)
        if tag in self.choices:
            choice = self.choices[tag]
        else:
            if self.flexible_tag:
                choice = ASN1F_field
            else:
                raise ASN1_Error(
                    "ASN1F_CHOICE: unexpected field in '%s' "
                    "(tag %s not in possible tags %s)" % (
                        self.name, tag, list(self.choices.keys())
                    )
                )
        if hasattr(choice, "ASN1_root"):
            # we don't want to import ASN1_Packet in this module...
            return self.extract_packet(choice, s, _underlayer=pkt)  # type: ignore
        elif isinstance(choice, type):
            return choice(self.name, b"").m2i(pkt, s)
        else:
            # XXX check properly if this is an ASN1F_PACKET
            return choice.m2i(pkt, s)

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Any) -> bytes
        if x is None:
            s = b""
        else:
            s = raw(x)
            if hash(type(x)) in self.pktchoices:
                imp, exp = self.pktchoices[hash(type(x))]
                s = BER_tagging_enc(s,
                                    implicit_tag=imp,
                                    explicit_tag=exp)
        return BER_tagging_enc(s, explicit_tag=self.explicit_tag)

    def randval(self):
        # type: () -> RandChoice
        randchoices = []
        for p in self.choices.values():
            if hasattr(p, "ASN1_root"):
                # should be ASN1_Packet class
                randchoices.append(packet.fuzz(p()))  # type: ignore
            elif hasattr(p, "ASN1_tag"):
                if isinstance(p, type):
                    # should be (basic) ASN1F_field class
                    randchoices.append(p("dummy", None).randval())
                else:
                    # should be ASN1F_PACKET instance
                    randchoices.append(p.randval())
        return RandChoice(*randchoices)


class ASN1F_PACKET(ASN1F_field['ASN1_Packet', Optional['ASN1_Packet']]):
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[ASN1_Packet]
                 cls,  # type: Type[ASN1_Packet]
                 context=None,  # type: Optional[Any]
                 implicit_tag=None,  # type: Optional[int]
                 explicit_tag=None,  # type: Optional[int]
                 next_cls_cb=None,  # type: Optional[Callable[[ASN1_Packet], Type[ASN1_Packet]]]  # noqa: E501
                 ):
        # type: (...) -> None
        self.cls = cls
        self.next_cls_cb = next_cls_cb
        super(ASN1F_PACKET, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag
        )
        if implicit_tag is None and explicit_tag is None and cls is not None:
            if cls.ASN1_root.ASN1_tag == ASN1_Class_UNIVERSAL.SEQUENCE:
                self.network_tag = 16 | 0x20  # 16 + CONSTRUCTED
        self.default = default

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        if self.next_cls_cb:
            cls = self.next_cls_cb(pkt) or self.cls
        else:
            cls = self.cls
        if not hasattr(cls, "ASN1_root"):
            # A normal Packet (!= ASN1)
            return self.extract_packet(cls, s, _underlayer=pkt)
        diff_tag, s = BER_tagging_dec(s, hidden_tag=cls.ASN1_root.ASN1_tag,  # noqa: E501
                                      implicit_tag=self.implicit_tag,
                                      explicit_tag=self.explicit_tag,
                                      safe=self.flexible_tag,
                                      _fname=self.name)
        if diff_tag is not None:
            if self.implicit_tag is not None:
                self.implicit_tag = diff_tag
            elif self.explicit_tag is not None:
                self.explicit_tag = diff_tag
        if not s:
            return None, s
        return self.extract_packet(cls, s, _underlayer=pkt)

    def i2m(self,
            pkt,  # type: ASN1_Packet
            x  # type: Union[bytes, ASN1_Packet, None, ASN1_Object[Optional[ASN1_Packet]]]  # noqa: E501
            ):
        # type: (...) -> bytes
        if x is None:
            s = b""
        elif isinstance(x, bytes):
            s = x
        elif isinstance(x, ASN1_Object):
            if x.val:
                s = raw(x.val)
            else:
                s = b""
        else:
            s = raw(x)
            if not hasattr(x, "ASN1_root"):
                # A normal Packet (!= ASN1)
                return s
        return BER_tagging_enc(s,
                               implicit_tag=self.implicit_tag,
                               explicit_tag=self.explicit_tag)

    def any2i(self,
              pkt,  # type: ASN1_Packet
              x  # type: Union[bytes, ASN1_Packet, None, ASN1_Object[Optional[ASN1_Packet]]]  # noqa: E501
              ):
        # type: (...) -> 'ASN1_Packet'
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)  # type: ignore
        return super(ASN1F_PACKET, self).any2i(pkt, x)

    def randval(self):  # type: ignore
        # type: () -> ASN1_Packet
        return packet.fuzz(self.cls())


class ASN1F_BIT_STRING_ENCAPS(ASN1F_BIT_STRING):
    """
    We may emulate simple string encapsulation with explicit_tag=0x04,
    but we need a specific class for bit strings because of unused bits, etc.
    """
    ASN1_tag = ASN1_Class_UNIVERSAL.BIT_STRING

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[ASN1_Packet]
                 cls,  # type: Type[ASN1_Packet]
                 context=None,  # type: Optional[Any]
                 implicit_tag=None,  # type: Optional[int]
                 explicit_tag=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        self.cls = cls
        super(ASN1F_BIT_STRING_ENCAPS, self).__init__(  # type: ignore
            name,
            default and raw(default),
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )

    def m2i(self, pkt, s):  # type: ignore
        # type: (ASN1_Packet, bytes) -> Tuple[Optional[ASN1_Packet], bytes]
        bit_string, remain = super(ASN1F_BIT_STRING_ENCAPS, self).m2i(pkt, s)
        if len(bit_string.val) % 8 != 0:
            raise BER_Decoding_Error("wrong bit string", remaining=s)
        if bit_string.val_readable:
            p, s = self.extract_packet(self.cls, bit_string.val_readable,
                                       _underlayer=pkt)
        else:
            return None, bit_string.val_readable
        if len(s) > 0:
            raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return p, remain

    def i2m(self, pkt, x):  # type: ignore
        # type: (ASN1_Packet, Optional[ASN1_BIT_STRING]) -> bytes
        if not isinstance(x, ASN1_BIT_STRING):
            x = ASN1_BIT_STRING(
                b"" if x is None else bytes(x),  # type: ignore
                readable=True,
            )
        return super(ASN1F_BIT_STRING_ENCAPS, self).i2m(pkt, x)


class ASN1F_FLAGS(ASN1F_BIT_STRING):
    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[str]
                 mapping,  # type: List[str]
                 context=None,  # type: Optional[Any]
                 implicit_tag=None,  # type: Optional[int]
                 explicit_tag=None,  # type: Optional[Any]
                 ):
        # type: (...) -> None
        self.mapping = mapping
        super(ASN1F_FLAGS, self).__init__(
            name, default,
            default_readable=False,
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> str
        if isinstance(x, str):
            if any(y not in ["0", "1"] for y in x):
                # resolve the flags
                value = ["0"] * len(self.mapping)
                for i in x.split("+"):
                    value[self.mapping.index(i)] = "1"
                x = "".join(value)
            x = ASN1_BIT_STRING(x)
        return super(ASN1F_FLAGS, self).any2i(pkt, x)

    def get_flags(self, pkt):
        # type: (ASN1_Packet) -> List[str]
        fbytes = getattr(pkt, self.name).val
        return [self.mapping[i] for i, positional in enumerate(fbytes)
                if positional == '1' and i < len(self.mapping)]

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, Any) -> str
        if x is not None:
            pretty_s = ", ".join(self.get_flags(pkt))
            return pretty_s + " " + repr(x)
        return repr(x)


class ASN1F_STRING_PacketField(ASN1F_STRING):
    """
    ASN1F_STRING that holds packets.
    """
    holds_packets = 1

    def i2m(self, pkt, val):
        # type: (ASN1_Packet, Any) -> bytes
        if hasattr(val, "ASN1_root"):
            val = ASN1_STRING(bytes(val))  # type: ignore
        return super(ASN1F_STRING_PacketField, self).i2m(pkt, val)

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> Any
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return super(ASN1F_STRING_PacketField, self).any2i(pkt, x)
