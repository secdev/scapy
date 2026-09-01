# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>

"""
Classes that implement ASN.1 data structures.

ASN.1 schema fields form a tree (``ASN1F_SEQUENCE``, ``ASN1F_CHOICE``, …),
not a flat ``fields_desc`` list like Scapy ``Field`` instances. The
``encode_to`` / ``decode_from`` methods are the tree analogue of
``Field.addfield`` / ``Field.getfield``; ``build`` / ``dissect`` delegate to
those entry points for backward compatibility.
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
from scapy.asn1.ber import (
    BER_Decoding_Error,
    BER_tagging_dec,
    BER_tagging_enc,
)
from scapy.asn1.constraints import normalize_constraints
from scapy.asn1.context import per_bit_decoder, per_bit_encoder
from scapy.asn1.tag import asn1_tag_parts
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
                 **codec_opts  # type: Any
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
        self.constraints = normalize_constraints(codec_opts, size_len=size_len)
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

    def _apply_diff_tag(self, pkt, diff_tag):
        # type: (ASN1_Packet, Optional[int]) -> None
        # flexible_tag was True: record the observed tag on the packet so
        # shared field descriptors stay immutable across interleaved decodes.
        if diff_tag is not None:
            observed = getattr(pkt, "_asn1_observed_tags", None)
            if observed is None:
                pkt._asn1_observed_tags = {}  # type: ignore[attr-defined]
                observed = pkt._asn1_observed_tags  # type: ignore[attr-defined]
            observed[self.name] = diff_tag

    def _tagging_tags(self, pkt):
        # type: (ASN1_Packet) -> Tuple[Optional[int], Optional[int]]
        imp = self.implicit_tag
        exp = self.explicit_tag
        if self.flexible_tag:
            observed = getattr(pkt, "_asn1_observed_tags", None) or {}
            diff = observed.get(self.name)
            if diff is not None:
                if imp is not None:
                    imp = diff
                elif exp is not None:
                    exp = diff
        return imp, exp

    def _tagging_dec(self, pkt, s, **kwargs):
        # type: (ASN1_Packet, bytes, **Any) -> Tuple[Optional[int], bytes]
        # Only BER puts the tag of a field on the wire.
        if pkt.ASN1_codec is ASN1_Codecs.BER:
            return BER_tagging_dec(s, **kwargs)
        return None, s

    def _tagging_enc(self, pkt, s, **kwargs):
        # type: (ASN1_Packet, bytes, **Any) -> bytes
        if pkt.ASN1_codec is ASN1_Codecs.BER:
            return BER_tagging_enc(s, **kwargs)
        return s

    def _apply_tagging_dec(self, s, pkt, hidden_tag=None, **kwargs):
        # type: (bytes, ASN1_Packet, Optional[Any], **Any) -> bytes
        # Always pass the field tags; callers may override hidden_tag (PACKET)
        # or add decode metadata such as _fname.
        if hidden_tag is None:
            hidden_tag = self.ASN1_tag
        diff_tag, s = self._tagging_dec(
            pkt, s,
            hidden_tag=hidden_tag,
            implicit_tag=self.implicit_tag,
            explicit_tag=self.explicit_tag,
            safe=self.flexible_tag,
            **kwargs,
        )
        self._apply_diff_tag(pkt, diff_tag)
        return s


    def _encode_item(self, pkt, item):
        # type: (ASN1_Packet, Any) -> bytes
        """Encode a field value with codec kwargs, without field tagging."""
        if item is None:
            return b""
        if isinstance(item, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                    item.tag == ASN1_Class_UNIVERSAL.RAW or
                    item.tag == ASN1_Class_UNIVERSAL.ERROR):
                return item.enc(pkt.ASN1_codec)
            if self.ASN1_tag != item.tag:
                raise ASN1_Error(
                    "Encoding Error: got %r instead of an %r for field [%s]" %
                    (item, self.ASN1_tag, self.name)
                )
            item = item.val
        elif hasattr(item, "self_build"):
            # Packet values (e.g. ASN1F_STRING_PacketField) must still go through
            # the BER type codec so the universal tag/length are applied.
            item = item.self_build()
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        return codec.enc(item, field=self, pkt=pkt)

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
        s = self._apply_tagging_dec(s, pkt, _fname=self.name)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        dec = codec.safedec if self.flexible_tag else codec.dec
        return dec(s, context=self.context, field=self, pkt=pkt)  # type: ignore  # noqa: E501

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Union[bytes, _I, _A]) -> bytes
        if x is None:
            return b""
        s = self._encode_item(pkt, x)
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
                       _parent=None  # type: Optional[ASN1_Packet]
                       ):
        # type: (...) -> Tuple[ASN1_Packet, bytes]
        try:
            c = cls(s, _parent=_parent)
        except ASN1F_badsequence:
            c = packet.Raw(s, _parent=_parent)  # type: ignore
        cpad = c.getlayer(packet.Raw)
        s = b""
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def m2i_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> Any
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        return codec.dec_from_decoder(  # type: ignore[attr-defined]
            dec, field=self, pkt=pkt,
        )

    def dissect_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        self.set_val(pkt, self.m2i_from_decoder(pkt, dec))

    def encode_into(self, enc, pkt, value=None):
        # type: (Any, ASN1_Packet, Any) -> None
        if value is None:
            value = getattr(pkt, self.name)
        if value is None:
            return
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        if isinstance(value, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                    value.tag == ASN1_Class_UNIVERSAL.RAW or
                    value.tag == ASN1_Class_UNIVERSAL.ERROR or
                    self.ASN1_tag == value.tag):
                raw = value.val
            else:
                raise ASN1_Error(
                    "Encoding Error: got %r instead of an %r for field [%s]" %
                    (value, self.ASN1_tag, self.name)
                )
        else:
            raw = value
        bit_enc = per_bit_encoder(enc)
        if bit_enc is not None:
            codec.encode_into(  # type: ignore[attr-defined]
                bit_enc, raw, field=self, pkt=pkt,
            )
            return
        enc.write(codec.enc(raw, field=self, pkt=pkt))  # type: ignore[attr-defined]

    def encode_to(self, pkt, enc):
        # type: (ASN1_Packet, Any) -> None
        if per_bit_encoder(enc) is not None:
            self.encode_into(enc, pkt)
        else:
            enc.write(self.i2m(pkt, getattr(pkt, self.name)))

    def decode_from(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        if per_bit_decoder(dec) is not None:
            self.dissect_from_decoder(pkt, per_bit_decoder(dec))
        else:
            val, remain = self.m2i(pkt, dec.remaining())
            self.set_val(pkt, val)
            dec.set_remainder(remain)

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        enc = pkt.ASN1_codec.new_encoder()
        self.encode_to(pkt, enc)
        return enc.finish()

    def dissect(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> bytes
        dec = pkt.ASN1_codec.new_decoder(s)
        self.decode_from(pkt, dec)
        return dec.remaining()

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
                 **codec_opts  # type: Any
                 ):
        # type: (...) -> None
        super(ASN1F_enum_INTEGER, self).__init__(
            name, default, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            **codec_opts
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

    def uper_enum_values(self):
        # type: () -> List[int]
        return sorted(self.i2s)


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
                 **codec_opts  # type: Any
                 ):
        # type: (...) -> None
        super(ASN1F_BIT_STRING, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            **codec_opts,
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
        # Codecs that describe presence out of band (OER/PER preambles) need
        # the optional components in declaration order.
        self.optionals = tuple(
            f for f in seq if isinstance(f, ASN1F_optional)
        )  # type: Tuple[ASN1F_optional, ...]
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

    def _dissect_sequence_children(self, pkt, s):
        # type: (Any, bytes) -> bytes
        if len(s) == 0:
            for obj in self.seq:
                obj.set_val(pkt, None)
            return s
        for obj in self.seq:
            try:
                s = obj.dissect(pkt, s)
            except ASN1F_badsequence:
                break
        return s

    def m2i(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        dec = pkt.ASN1_codec.new_decoder(s)
        self.decode_from(pkt, dec)
        remain = dec.remaining()
        if per_bit_decoder(dec) is not None and remain:
            from scapy.asn1.uper import UPER_Decoding_Error
            raise UPER_Decoding_Error(
                "unexpected remainder in %s" % pkt.__class__.__name__,
            )
        return [], remain

    def encode_to(self, pkt, enc):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import sequence_encode_to
        sequence_encode_to(self, pkt, enc)

    def encode_into(self, enc, pkt, value=None):
        # type: (Any, ASN1_Packet, Any) -> None
        from scapy.asn1.compound import sequence_encode_to
        sequence_encode_to(self, pkt, enc)

    def dissect_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        self.decode_from(pkt, dec)

    def decode_from(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import sequence_decode_from
        sequence_decode_from(self, pkt, dec)


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
                 **codec_opts  # type: Any
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
                self.cls, s, _parent=pkt)
            self.holds_packets = 1
        else:
            raise ValueError("cls should be an ASN1_Packet or ASN1_field")
        super(ASN1F_SEQUENCE_OF, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag,
            **codec_opts,
        )
        self.default = default

    def is_empty(self,
                 pkt,  # type: ASN1_Packet
                 ):
        # type: (...) -> bool
        return ASN1F_field.is_empty(self, pkt)

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[List[Any], bytes]
        dec = pkt.ASN1_codec.new_decoder(s)
        self.decode_from(pkt, dec)
        return getattr(pkt, self.name), dec.remaining()

    def encode_to(self, pkt, enc):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import sequence_of_encode_to
        sequence_of_encode_to(self, pkt, enc)

    def decode_from(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import sequence_of_decode_from
        sequence_of_decode_from(self, pkt, dec)

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

    def dissect_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        self._field.dissect_from_decoder(pkt, dec)

    def encode_into(self, enc, pkt, value=None):
        # type: (Any, ASN1_Packet, Any) -> None
        self._field.encode_into(enc, pkt, value)

    def encode_to(self, pkt, enc):
        # type: (ASN1_Packet, Any) -> None
        if self.is_present(pkt):
            self._field.encode_to(pkt, enc)

    def decode_from(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        self._field.decode_from(pkt, dec)

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
            return [self._field.copy()]
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
        # Remaining kwargs are codec constraints (e.g. uper_extensible=).
        super(ASN1F_CHOICE, self).__init__(
            name, None, context=context,
            explicit_tag=explicit_tag,
            **kwargs
        )
        self.default = default
        self.choices = {}  # type: Dict[int, _CHOICE_T]
        self.pktchoices = {}  # type: Dict[type, Tuple[Optional[int], Optional[int]]]
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
                    self.pktchoices[p.cls] = (p.implicit_tag, p.explicit_tag)
            else:
                raise ASN1_Error("ASN1F_CHOICE: no tag found for one field")
        # X.691 10.2: PER indexes alternatives in canonical tag order.
        decl_items = list(self.choices.items())
        canon_items = sorted(
            decl_items,
            key=lambda item: asn1_tag_parts(item[0])[:2],
        )
        self.canonical_order = [alt for _tag, alt in canon_items]
        self.canonical_index = {
            tag: i for i, (tag, _alt) in enumerate(canon_items)
        }  # type: Dict[int, int]

    @property
    def choice_order(self):
        # type: () -> List[int]
        return list(self.choices.keys())

    def alternative_index(self, x):
        # type: (Any) -> Optional[int]
        """Position in choice_order of the alternative that carries x."""
        for index, choice in enumerate(self.choices.values()):
            if isinstance(choice, type):
                if hasattr(choice, "ASN1_root"):
                    # ASN1_Packet subclass
                    if isinstance(x, choice):
                        return index
                elif isinstance(x, ASN1_Object) and x.tag == choice.ASN1_tag:
                    # ASN1F_field subclass
                    return index
            elif isinstance(x, choice.cls):
                # ASN1F_PACKET instance, holding a tagged packet
                return index
        return None

    @property
    def choice_list(self):
        # type: () -> List[_CHOICE_T]
        return list(self.choices.values())

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        dec = pkt.ASN1_codec.new_decoder(s)
        self.decode_from(pkt, dec)
        return getattr(pkt, self.name), dec.remaining()

    def encode_to(self, pkt, enc):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import choice_encode_to
        choice_encode_to(self, pkt, enc)

    def encode_into(self, enc, pkt, value=None):
        # type: (Any, ASN1_Packet, Any) -> None
        from scapy.asn1.compound import choice_encode_to
        if value is None:
            choice_encode_to(self, pkt, enc)
            return
        old = getattr(pkt, self.name, None)
        setattr(pkt, self.name, value)
        try:
            choice_encode_to(self, pkt, enc)
        finally:
            setattr(pkt, self.name, old)

    def decode_from(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import choice_decode_from
        choice_decode_from(self, pkt, dec)

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

    def _resolve_cls(self, pkt):
        # type: (ASN1_Packet) -> Type[ASN1_Packet]
        if self.next_cls_cb:
            return self.next_cls_cb(pkt) or self.cls
        return self.cls

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        dec = pkt.ASN1_codec.new_decoder(s)
        self.decode_from(pkt, dec)
        return getattr(pkt, self.name), dec.remaining()

    def encode_to(self, pkt, enc):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import packet_encode_to
        packet_encode_to(self, pkt, enc)

    def encode_into(self, enc, pkt, value=None):
        # type: (Any, ASN1_Packet, Any) -> None
        from scapy.asn1.compound import packet_encode_to
        packet_encode_to(self, pkt, enc, value)

    def decode_from(self, pkt, dec):
        # type: (ASN1_Packet, Any) -> None
        from scapy.asn1.compound import packet_decode_from
        packet_decode_from(self, pkt, dec)

    def any2i(self,
              pkt,  # type: ASN1_Packet
              x  # type: Union[bytes, ASN1_Packet, None, ASN1_Object[Optional[ASN1_Packet]]]  # noqa: E501
              ):
        # type: (...) -> 'ASN1_Packet'
        if hasattr(x, "add_parent"):
            x.add_parent(pkt)  # type: ignore
        elif hasattr(x, "add_underlayer"):
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
                                       _parent=pkt)
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
                 **codec_opts  # type: Any
                 ):
        # type: (...) -> None
        self.mapping = mapping
        super(ASN1F_FLAGS, self).__init__(
            name, default,
            default_readable=False,
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            **codec_opts,
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
        return self.cls(val[0].val, _parent=pkt), val[1]
