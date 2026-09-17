# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>

"""
Classes that implement ASN.1 data structures.

ASN.1 schema fields form a tree (``ASN1F_SEQUENCE``, ``ASN1F_CHOICE``, …),
not a flat ``fields_desc`` list like Scapy ``Field`` instances. Leaf and
compound ``build`` / ``dissect`` go through ``i2m`` / ``m2i`` for BER and
OER. UPER compounds use a bit-stream walker in ``scapy.asn1.uper``.
"""

import copy

from functools import reduce

from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_Class,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_Decoding_Error,
    ASN1_Error,
    ASN1_INTEGER,
    ASN1_NULL,
    ASN1_OID,
    ASN1_Object,
    ASN1_STRING,
)
from scapy.asn1.ber import BER_Decoding_Error, BER_id_dec
from scapy.base_classes import BasePacket
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
                 minimum=None,  # type: Optional[int]
                 maximum=None,  # type: Optional[int]
                 extensible=False,  # type: bool
                 unsigned=False,  # type: bool
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
        self.minimum = minimum
        self.maximum = maximum
        self.extensible = bool(extensible)
        self.unsigned = bool(unsigned)
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

    def _tagging_tags(self, pkt):
        # type: (ASN1_Packet) -> Tuple[Optional[int], Optional[int]]
        imp = self.implicit_tag
        exp = self.explicit_tag
        if self.flexible_tag:
            observed = getattr(pkt, "_asn1_observed_tags", None) or {}
            diff = observed.get(id(self))
            if diff is not None:
                if imp is not None:
                    imp = diff
                elif exp is not None:
                    exp = diff
        return imp, exp

    def _tagging_enc(self, pkt, s, **kwargs):
        # type: (ASN1_Packet, bytes, **Any) -> bytes
        return pkt.ASN1_codec.tagging_enc(s, **kwargs)  # type: ignore

    def _apply_tagging_dec(self, s, pkt, hidden_tag=None, **kwargs):
        # type: (bytes, ASN1_Packet, Optional[Any], **Any) -> bytes
        # Always pass the field tags; callers may override hidden_tag (PACKET)
        # or add decode metadata such as _fname.
        if hidden_tag is None:
            hidden_tag = self.ASN1_tag
        # Codec provides tagging_*; absent handlers are a no-op (OER/UPER).
        diff_tag, s = pkt.ASN1_codec.tagging_dec(
            s,
            hidden_tag=hidden_tag,
            implicit_tag=self.implicit_tag,
            explicit_tag=self.explicit_tag,
            safe=self.flexible_tag,
            **kwargs,
        )
        # flexible_tag was True: record the observed tag on the packet so
        # shared field descriptors stay immutable across interleaved decodes.
        if diff_tag is not None:
            tags = pkt._asn1_observed_tags
            if tags is None:
                tags = {}
                pkt._asn1_observed_tags = tags
            tags[id(self)] = diff_tag
        return s

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, _I) -> str
        return repr(x)

    def i2h(self, pkt, x):
        # type: (ASN1_Packet, _I) -> Any
        return x

    def _codec_schema_kwargs(self):
        # type: () -> Dict[str, Any]
        """Resolved schema parameters for OER/UPER primitive codecs."""
        kw = {
            "minimum": self.minimum,
            "maximum": self.maximum,
            "extensible": self.extensible,
            "unsigned": self.unsigned,
        }  # type: Dict[str, Any]
        i2s = getattr(self, "i2s", None)
        if i2s is not None:
            kw["enum_values"] = sorted(i2s)
        return kw

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
        s = self._apply_tagging_dec(s, pkt, _fname=self.name)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        decode = codec.safedec if self.flexible_tag else codec.dec
        if pkt.ASN1_codec is ASN1_Codecs.OER or pkt.ASN1_codec is ASN1_Codecs.UPER:
            return cast(
                Tuple[_A, bytes],
                decode(
                    s,
                    context=self.context,
                    **self._codec_schema_kwargs(),
                ),
            )
        return cast(
            Tuple[_A, bytes],
            decode(s, context=self.context),
        )

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Union[bytes, _I, _A]) -> bytes
        if x is None:
            return b""
        # Encode the field value with codec kwargs, without field tagging.
        item = x
        if pkt.ASN1_codec is ASN1_Codecs.OER or pkt.ASN1_codec is ASN1_Codecs.UPER:
            kw = self._codec_schema_kwargs()  # type: Dict[str, Any]
        else:
            kw = {"size_len": self.size_len}
        if isinstance(item, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                    item.tag == ASN1_Class_UNIVERSAL.RAW or
                    item.tag == ASN1_Class_UNIVERSAL.ERROR):
                s = item.enc(pkt.ASN1_codec)
            elif self.ASN1_tag != item.tag:
                raise ASN1_Error(
                    "Encoding Error: got %r instead of an %r for field [%s]" %
                    (item, self.ASN1_tag, self.name)
                )
            else:
                item = item.val
                codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
                s = cast(bytes, codec.enc(item, **kw))
        else:
            if hasattr(item, "self_build"):
                # Packet values (e.g. ASN1F_STRING_PacketField) must still go
                # through the BER type codec so the universal tag/length are
                # applied.
                item = item.self_build()
            codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
            s = cast(bytes, codec.enc(item, **kw))
        imp, exp = self._tagging_tags(pkt)
        return self._tagging_enc(
            pkt, s,
            implicit_tag=imp,
            explicit_tag=exp,
        )

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> _I
        return cast(_I, x)

    def extract_packet(self,
                       cls,  # type: Type[ASN1_Packet]
                       s,  # type: bytes
                       _underlayer=None,  # type: Optional[ASN1_Packet]
                       _parent=None  # type: Optional[ASN1_Packet]
                       ):
        # type: (...) -> Tuple[ASN1_Packet, bytes]
        try:
            c = cls(s, _underlayer=_underlayer, _parent=_parent)
        except ASN1F_badsequence:
            c = packet.Raw(s, _underlayer=_underlayer, _parent=_parent)  # type: ignore
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
                 size_len=None,  # type: Optional[int]
                 minimum=None,  # type: Optional[int]
                 maximum=None,  # type: Optional[int]
                 extensible=False,  # type: bool
                 unsigned=False,  # type: bool
                 ):
        # type: (...) -> None
        super(ASN1F_enum_INTEGER, self).__init__(
            name, default, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            size_len=size_len,
            minimum=minimum,
            maximum=maximum,
            extensible=extensible,
            unsigned=unsigned,
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
                 size_len=None,  # type: Optional[int]
                 minimum=None,  # type: Optional[int]
                 maximum=None,  # type: Optional[int]
                 extensible=False,  # type: bool
                 unsigned=False,  # type: bool
                 ):
        # type: (...) -> None
        super(ASN1F_BIT_STRING, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            size_len=size_len,
            minimum=minimum,
            maximum=maximum,
            extensible=extensible,
            unsigned=unsigned,
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
        default = []
        for field in seq:
            if isinstance(field, ASN1F_DEFAULT):
                default.append(field._default)
            elif isinstance(field, ASN1F_optional):
                default.append(None)
            else:
                default.append(field.default)
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
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_DecoderContext, UPER_Decoding_Error
            dec = UPER_DecoderContext(s)
            dec.decode_sequence(self, pkt)
            remain = dec.remaining()
            if remain:
                raise UPER_Decoding_Error(
                    "unexpected remainder in %s" % pkt.__class__.__name__,
                )
            return [], remain
        if pkt.ASN1_codec is ASN1_Codecs.OER:
            return self._oer_m2i(pkt, s)
        return self._ber_m2i(pkt, s)

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_EncoderContext
            enc = UPER_EncoderContext()
            enc.encode_sequence(self, pkt)
            return cast(bytes, enc.finish())
        if pkt.ASN1_codec is ASN1_Codecs.OER:
            return self._oer_build(pkt)
        s = reduce(lambda x, y: x + y.build(pkt), self.seq, b"")
        return self.i2m(pkt, s)

    def _ber_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        s = self._apply_tagging_dec(s, pkt, _fname=pkt.name)
        codec = self.ASN1_tag.get_codec(ASN1_Codecs.BER)
        _i, s, remain = codec.check_type_check_len(s)

        def set_absent(obj):
            # type: (Any) -> None
            if isinstance(obj, (ASN1F_optional, ASN1F_DEFAULT)):
                obj.set_missing(pkt)
            else:
                obj.set_val(pkt, None)

        if len(s) == 0:
            for obj in self.seq:
                set_absent(obj)
        else:
            for idx, obj in enumerate(self.seq):
                try:
                    s = obj.dissect(pkt, s)
                except ASN1F_badsequence:
                    for absent in self.seq[idx:]:
                        set_absent(absent)
                    break
            if len(s) > 0:
                raise BER_Decoding_Error(
                    "unexpected remainder in %s" % pkt.name,
                    remaining=s,
                )
        return [], remain

    def _oer_build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        from scapy.asn1.oer import OER_Encoding_Error
        if isinstance(self, ASN1F_SET):
            raise OER_Encoding_Error("ASN1F_SET is not supported")
        optionals = [f for f in self.seq if isinstance(f, ASN1F_optional)]
        bits = [0] if self.extensible else []  # type: List[int]
        bits += [1 if opt.is_present(pkt) else 0 for opt in optionals]
        parts = []  # type: List[bytes]
        if bits:
            number_of_bytes = (len(bits) + 7) // 8
            value = 0
            for bit in bits:
                value = (value << 1) | bit
            value <<= 8 * number_of_bytes - len(bits)
            parts.append(value.to_bytes(number_of_bytes, "big"))
        for obj in self.seq:
            if isinstance(obj, ASN1F_optional) and not obj.is_present(pkt):
                continue
            parts.append(obj.build(pkt))
        return b"".join(parts)

    def _oer_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        from scapy.asn1.oer import OER_Decoding_Error
        if isinstance(self, ASN1F_SET):
            raise OER_Decoding_Error("ASN1F_SET is not supported")
        s = self._apply_tagging_dec(s, pkt, _fname=pkt.name)
        optionals = [f for f in self.seq if isinstance(f, ASN1F_optional)]
        number_of_bits = (1 if self.extensible else 0) + len(optionals)
        if number_of_bits == 0:
            presence = []  # type: List[bool]
        else:
            number_of_bytes = (number_of_bits + 7) // 8
            if len(s) < number_of_bytes:
                raise OER_Decoding_Error(
                    "ASN1F_SEQUENCE: Got %i bytes while expecting %i" %
                    (len(s), number_of_bytes),
                    remaining=s
                )
            value = int.from_bytes(s[:number_of_bytes], "big")
            bits = [
                bool((value >> (8 * number_of_bytes - 1 - i)) & 1)
                for i in range(number_of_bits)
            ]
            if self.extensible:
                if bits[0]:
                    raise OER_Decoding_Error(
                        "ASN1F_SEQUENCE: extension additions are not supported",
                        remaining=s,
                    )
                bits = bits[1:]
            presence = bits
            s = s[number_of_bytes:]
        opt_index = 0
        for obj in self.seq:
            if isinstance(obj, ASN1F_optional):
                if not presence[opt_index]:
                    obj.set_missing(pkt)
                    opt_index += 1
                    continue
                opt_index += 1
            try:
                s = obj.dissect(pkt, s)
            except ASN1F_badsequence:
                break
        return [], s


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

    Structured items are normally ASN1_Packet (or ASN1F_PACKET). Compound
    ASN1F_field elements (SEQUENCE / CHOICE / SEQUENCE OF) remain constructible
    for BER/OER; UPER rejects them at encode/decode time.
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
                 size_len=None,  # type: Optional[int]
                 minimum=None,  # type: Optional[int]
                 maximum=None,  # type: Optional[int]
                 extensible=False,  # type: bool
                 unsigned=False,  # type: bool
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
                self.cls, s, _underlayer=pkt, _parent=pkt)
            self.holds_packets = 1
        else:
            raise ValueError("cls should be an ASN1_Packet or ASN1_field")
        super(ASN1F_SEQUENCE_OF, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag,
            size_len=size_len,
            minimum=minimum,
            maximum=maximum,
            extensible=extensible,
            unsigned=unsigned,
        )
        self.default = default

    def is_empty(self,
                 pkt,  # type: ASN1_Packet
                 ):
        # type: (...) -> bool
        return ASN1F_field.is_empty(self, pkt)

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[List[Any], bytes]
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_DecoderContext
            dec = UPER_DecoderContext(s)
            dec.decode_sequence_of(self, pkt)
            return getattr(pkt, self.name), dec.remaining()
        if pkt.ASN1_codec is ASN1_Codecs.OER:
            return self._oer_m2i(pkt, s)
        return self._ber_m2i(pkt, s)

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_EncoderContext
            enc = UPER_EncoderContext()
            enc.encode_sequence_of(self, pkt)
            return cast(bytes, enc.finish())
        if pkt.ASN1_codec is ASN1_Codecs.OER:
            return self._oer_build(pkt)
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = val  # type: Any
        elif val is None:
            s = b""
        elif self.holds_packets:
            s = b"".join(bytes(i) for i in val)
        else:
            s = b"".join(self.fld.i2m(pkt, i) for i in val)
        return self.i2m(pkt, s)

    def _ber_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[List[Any], bytes]
        s = self._apply_tagging_dec(s, pkt)
        codec = self.ASN1_tag.get_codec(ASN1_Codecs.BER)
        _i, s, remain = codec.check_type_check_len(s)
        lst = []
        while s:
            c, s = self._extract_packet(s, pkt)  # type: ignore
            if c:
                lst.append(c)
        return lst, remain

    def _oer_build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        from scapy.asn1.oer import OER_unsigned_integer_enc
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            return self.i2m(pkt, val)  # type: ignore
        items = [] if val is None else val
        parts = [OER_unsigned_integer_enc(len(items))]
        parts.extend(
            bytes(item) if self.holds_packets else self.fld.i2m(pkt, item)
            for item in items
        )
        # Write assembled content directly: OERcodec_SET must not wrap SET OF.
        return b"".join(parts)

    def _oer_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[List[Any], bytes]
        from scapy.asn1.oer import OER_unsigned_integer_dec
        s = self._apply_tagging_dec(s, pkt)
        count, s = OER_unsigned_integer_dec(s)
        lst = []
        for _ in range(count):
            c, s = self._extract_packet(s, pkt)  # type: ignore
            if c:
                lst.append(c)
        return lst, s

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, _I) -> str
        if self.holds_packets:
            return super(ASN1F_SEQUENCE_OF, self).i2repr(pkt, x)  # type: ignore
        elif x is None:
            return "[]"
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
    """
    ASN.1 field that is optional.
    """
    def __init__(self, field):
        # type: (ASN1F_field[Any, Any]) -> None
        field.flexible_tag = False
        self._field = field

    def __getattr__(self, attr):
        # type: (str) -> Any
        if attr.startswith("_"):
            raise AttributeError(attr)
        return getattr(self._field, attr)

    @property
    def fld(self):
        # type: () -> ASN1F_field[Any, Any]
        return self._field

    def get_fields_list(self):
        # type: () -> List[ASN1F_field[Any, Any]]
        inner = self._field.get_fields_list()
        if inner == [self._field]:
            field = self._field.copy()
            field.default = None
            return [field]
        return inner

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        try:
            return self._field.m2i(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, ASN1_Decoding_Error):
            # ASN1_Error may be raised by ASN1F_CHOICE
            return None, s

    def dissect(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> bytes
        try:
            return self._field.dissect(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, ASN1_Decoding_Error):
            self.set_missing(pkt)
            return s

    def is_present(self, pkt):
        # type: (ASN1_Packet) -> bool
        # Delegate to the wrapped field: an optional SEQUENCE uses a dummy
        # name and is empty iff all of its children are.
        return not self._field.is_empty(pkt)

    def set_missing(self, pkt):
        # type: (ASN1_Packet) -> None
        """Called when the encoding does not carry the component."""
        self._field.set_val(pkt, None)

    def is_empty(self, pkt):
        # type: (ASN1_Packet) -> bool
        return not self.is_present(pkt)

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        # Through self, so that a DEFAULT component omits its default value.
        if not self.is_present(pkt):
            return b""
        return self._field.build(pkt)

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> Any
        return self._field.any2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (ASN1_Packet, Any) -> str
        return self._field.i2repr(pkt, x)


class ASN1F_DEFAULT(ASN1F_optional):
    """
    ASN.1 field holding a DEFAULT value: it is omitted from the encoding while
    it holds that value, and restored when the encoding does not carry it.

    As with OPTIONAL components, a BER encoding only tells the component apart
    from the one that follows it by its tag, so the schema must give it a
    distinct one. OER and PER describe presence in the preamble instead.
    """
    def __init__(self, field, default):
        # type: (ASN1F_field[Any, Any], Any) -> None
        super(ASN1F_DEFAULT, self).__init__(field)
        self._default = default

    def get_fields_list(self):
        # type: () -> List[ASN1F_field[Any, Any]]
        inner = self._field.get_fields_list()
        if inner == [self._field]:
            field = self._field.copy()
            default = self._default
            if default is not None and not isinstance(default, ASN1_Object):
                default = field.ASN1_tag.asn1_object(default)
            field.default = default
            return [field]
        return inner

    def is_present(self, pkt):
        # type: (ASN1_Packet) -> bool
        val = getattr(pkt, self._field.name, None)
        if val is None:
            return False
        if isinstance(val, ASN1_Object):
            val = val.val
        default = self._default
        if isinstance(default, ASN1_Object):
            default = default.val
        return bool(val != default)

    def set_missing(self, pkt):
        # type: (ASN1_Packet) -> None
        self._field.set_val(pkt, self._default)


class ASN1F_omit(ASN1F_field[None, None]):
    """
    ASN.1 field that is not specified. This is simply omitted on the network.
    This is different from ASN1F_NULL which has a network representation.
    """
    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[None, bytes]
        return None, s

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Optional[bytes]) -> bytes
        return b""


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
        context = kwargs.pop("context", None)
        explicit_tag = kwargs.pop("explicit_tag", None)
        # Remaining kwargs are schema constraints (e.g. extensible=).
        super(ASN1F_CHOICE, self).__init__(
            name, None, context=context,
            explicit_tag=explicit_tag,
            **kwargs
        )
        self.default = default
        self.choices = {}  # type: Dict[int, _CHOICE_T]
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
                    # should be ASN1F_PACKET instance
                    self.choices[p.network_tag] = p
            else:
                raise ASN1_Error("ASN1F_CHOICE: no tag found for one field")

    def alternative_tag(self, x):
        # type: (Any) -> Optional[int]
        """Return the CHOICE alternative tag that carries x, or None."""
        for tag, choice in self.choices.items():
            if isinstance(choice, type):
                if hasattr(choice, "ASN1_root"):
                    # ASN1_Packet subclass
                    if isinstance(x, choice):
                        return tag
                elif isinstance(x, ASN1_Object) and x.tag == choice.ASN1_tag:
                    # ASN1F_field subclass
                    return tag
            elif isinstance(x, choice.cls):
                # ASN1F_PACKET instance, holding a tagged packet
                return tag
        return None

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_DecoderContext
            dec = UPER_DecoderContext(s)
            dec.decode_choice(self, pkt)
            return getattr(pkt, self.name), dec.remaining()
        if pkt.ASN1_codec is ASN1_Codecs.OER:
            return self._oer_m2i(pkt, s)
        return self._ber_m2i(pkt, s)

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_EncoderContext
            enc = UPER_EncoderContext()
            enc.encode_choice(self, pkt)
            return cast(bytes, enc.finish())
        if pkt.ASN1_codec is ASN1_Codecs.OER:
            return self._oer_build(pkt)
        return self._ber_build(pkt)

    def _ber_build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        value = getattr(pkt, self.name)
        if value is None:
            s = b""
        else:
            if isinstance(value, ASN1_Object):
                s = value.enc(pkt.ASN1_codec)
            else:
                s = bytes(value)
            tag = self.alternative_tag(value)
            if tag is not None:
                choice = self.choices[tag]
                if not isinstance(choice, type) and hasattr(choice, "cls"):
                    s = self._tagging_enc(
                        pkt, s,
                        implicit_tag=choice.implicit_tag,
                        explicit_tag=choice.explicit_tag,
                    )
        _imp, exp = self._tagging_tags(pkt)
        return self._tagging_enc(pkt, s, explicit_tag=exp)

    def _ber_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        s = self._apply_tagging_dec(s, pkt)
        tag, _ = BER_id_dec(s)
        if tag in self.choices:
            choice = self.choices[tag]
        elif self.flexible_tag:
            choice = ASN1F_field
        else:
            raise ASN1_Error(
                "ASN1F_CHOICE: unexpected field in '%s' "
                "(tag %s not in possible tags %s)" % (
                    self.name, tag, list(self.choices.keys())
                )
            )
        if hasattr(choice, "ASN1_root"):
            return self.extract_packet(
                cast("Type[ASN1_Packet]", choice), s,
                _underlayer=pkt, _parent=pkt,
            )
        if isinstance(choice, type):
            return choice(self.name, b"").m2i(pkt, s)
        return choice.m2i(pkt, s)

    def _oer_build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        from scapy.asn1.oer import OER_tag_enc, OER_tag_parts
        value = getattr(pkt, self.name)
        if value is None:
            s = b""
        else:
            if isinstance(value, ASN1_Object):
                s = value.enc(pkt.ASN1_codec)
            else:
                s = bytes(value)
            tag = self.alternative_tag(value)
            if tag is None:
                raise ASN1_Error(
                    "ASN1F_CHOICE: cannot encode unknown alternative in '%s'" %
                    self.name
                )
            tag_class, tag_number = OER_tag_parts(tag)
            s = OER_tag_enc(tag_number, tag_class) + s
        return self._tagging_enc(pkt, s, explicit_tag=self.explicit_tag)

    def _oer_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        from scapy.asn1.oer import OER_tag_dec, OER_tag_parts
        s = self._apply_tagging_dec(s, pkt)
        tag_class, tag_number, payload = OER_tag_dec(s)
        choice = None
        for key, alternative in self.choices.items():
            if OER_tag_parts(key) == (tag_class, tag_number):
                choice = alternative
                break
        if choice is None:
            if not self.flexible_tag:
                raise ASN1_Error(
                    "ASN1F_CHOICE: unexpected field in '%s' "
                    "(tag %s not in possible tags %s)" % (
                        self.name, tag_class | tag_number,
                        list(self.choices.keys())
                    )
                )
            choice = ASN1F_field
        if hasattr(choice, "ASN1_root"):
            return self.extract_packet(
                cast("Type[ASN1_Packet]", choice), payload,
                _underlayer=pkt, _parent=pkt,
            )
        if isinstance(choice, type):
            return choice(self.name, b"").m2i(pkt, payload)
        cls = (
            (choice.next_cls_cb(pkt) or choice.cls)
            if choice.next_cls_cb else choice.cls
        )
        return self.extract_packet(cls, payload, _underlayer=pkt, _parent=pkt)

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
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_DecoderContext
            dec = UPER_DecoderContext(s)
            dec.decode_packet(self, pkt)
            return getattr(pkt, self.name), dec.remaining()
        # BER and OER share nested-packet tagging.
        return self._nested_m2i(pkt, s)

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        if pkt.ASN1_codec is ASN1_Codecs.UPER:
            from scapy.asn1.uper import UPER_EncoderContext
            enc = UPER_EncoderContext()
            enc.encode_packet(self, pkt)
            return cast(bytes, enc.finish())
        value = getattr(pkt, self.name)
        if value is None:
            s = b""
        elif isinstance(value, bytes):
            s = value
        elif isinstance(value, ASN1_Object):
            s = bytes(value.val) if value.val else b""
        else:
            s = bytes(value)
            from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
            if not isinstance(value, _ASN1_Packet):
                return s
        imp, exp = self._tagging_tags(pkt)
        return self._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp)

    def _nested_m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
        cls = (self.next_cls_cb(pkt) or self.cls) if self.next_cls_cb else self.cls
        if not issubclass(cls, _ASN1_Packet):
            return self.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)
        s = self._apply_tagging_dec(
            s, pkt,
            hidden_tag=cls.ASN1_root.ASN1_tag,
            _fname=self.name,
        )
        if not s:
            return None, s
        return self.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)

    def any2i(self,
              pkt,  # type: ASN1_Packet
              x  # type: Union[bytes, ASN1_Packet, None, ASN1_Object[Optional[ASN1_Packet]]]  # noqa: E501
              ):
        # type: (...) -> 'ASN1_Packet'
        # Kerberos EncryptedData.get_usage() walks underlayer; X.509 and
        # OER nested packets also use parent. Set both when available.
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)  # type: ignore
        if hasattr(x, "add_parent"):
            x.add_parent(pkt)  # type: ignore
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
            default and bytes(default),
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
                                       _underlayer=pkt, _parent=pkt)
        else:
            return None, bit_string.val_readable
        if len(s) > 0:
            raise BER_Decoding_Error(
                "unexpected remainder in %s" % pkt.name,
                remaining=s,
            )
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
                 size_len=None,  # type: Optional[int]
                 minimum=None,  # type: Optional[int]
                 maximum=None,  # type: Optional[int]
                 extensible=False,  # type: bool
                 unsigned=False,  # type: bool
                 ):
        # type: (...) -> None
        self.mapping = mapping
        super(ASN1F_FLAGS, self).__init__(
            name, default,
            default_readable=False,
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            size_len=size_len,
            minimum=minimum,
            maximum=maximum,
            extensible=extensible,
            unsigned=unsigned,
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
            val = ASN1_STRING(bytes(val))
        return super(ASN1F_STRING_PacketField, self).i2m(pkt, val)

    def any2i(self, pkt, x):
        # type: (ASN1_Packet, Any) -> Any
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        if hasattr(x, "add_parent"):
            x.add_parent(pkt)
        return super(ASN1F_STRING_PacketField, self).any2i(pkt, x)


class ASN1F_STRING_ENCAPS(ASN1F_STRING_PacketField):
    """
    ASN1F_STRING that encapsulates a single ASN1 packet.
    """

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
        super(ASN1F_STRING_ENCAPS, self).__init__(
            name,
            default and bytes(default),  # type: ignore
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )

    def m2i(self, pkt, s):  # type: ignore
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Packet, bytes]
        val = super(ASN1F_STRING_ENCAPS, self).m2i(pkt, s)
        return self.cls(val[0].val, _underlayer=pkt, _parent=pkt), val[1]
