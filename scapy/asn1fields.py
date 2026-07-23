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

from scapy import packet
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
    BER_id_dec,
    BER_tagging_dec,
    BER_tagging_enc,
)
from scapy.asn1.oer import (
    OER_id_dec,
    OER_tag_enc,
    OER_tagging_dec,
    OER_tagging_enc,
    OER_unsigned_integer_dec,
    OER_unsigned_integer_enc,
)
from scapy.asn1.uper import (
    UPER_Decoding_Error,
    UPER_Decoder,
    UPER_Encoder,
    UPER_bits_for_range,
    UPER_choice_index_dec,
    UPER_choice_index_enc,
    UPER_constrained_int_enc,
    UPER_has_unexpected_remainder,
)
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
                 oer_unsigned=False,  # type: Optional[bool]
                 uper_min=None,  # type: Optional[int]
                 uper_max=None,  # type: Optional[int]
                 uper_enum_values=None,  # type: Optional[List[int]]
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
        self.oer_unsigned = oer_unsigned
        self.uper_min = uper_min
        self.uper_max = uper_max
        self.uper_enum_values = uper_enum_values
        self.flexible_tag = flexible_tag
        if (implicit_tag is not None) and (explicit_tag is not None):
            err_msg = "field cannot be both implicitly and explicitly tagged"
            raise ASN1_Error(err_msg)
        self.implicit_tag = implicit_tag and int(implicit_tag)
        self.explicit_tag = explicit_tag and int(explicit_tag)
        # network_tag gets useful for ASN1F_CHOICE
        self.network_tag = int(implicit_tag or explicit_tag or self.ASN1_tag)
        self.owners = []  # type: List[Type[ASN1_Packet]]
        self._uper_kwargs_cache = None  # type: Optional[Dict[str, Any]]

    def register_owner(self, cls):
        # type: (Type[ASN1_Packet]) -> None
        self.owners.append(cls)

    def _apply_diff_tag(self, diff_tag):
        # type: (Optional[int]) -> None
        # this implies that flexible_tag was True
        if diff_tag is not None:
            if self.implicit_tag is not None:
                self.implicit_tag = diff_tag
            elif self.explicit_tag is not None:
                self.explicit_tag = diff_tag

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
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            diff_tag, s = OER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                          implicit_tag=self.implicit_tag,
                                          explicit_tag=self.explicit_tag,
                                          safe=self.flexible_tag,
                                          _fname=self.name)
        elif pkt.ASN1_codec != ASN1_Codecs.PER:
            diff_tag, s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                          implicit_tag=self.implicit_tag,
                                          explicit_tag=self.explicit_tag,
                                          safe=self.flexible_tag,
                                          _fname=self.name)
        else:
            diff_tag = None
        self._apply_diff_tag(diff_tag)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        codec_kwargs = {}  # type: Dict[str, Any]
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            codec_kwargs = {
                "size_len": self.size_len or 0,
                "oer_unsigned": self.oer_unsigned,
            }
        elif pkt.ASN1_codec == ASN1_Codecs.PER:
            codec_kwargs = self._uper_codec_kwargs()
        if self.flexible_tag:
            return codec.safedec(
                s, context=self.context, **codec_kwargs
            )  # type: ignore
        else:
            return codec.dec(s, context=self.context, **codec_kwargs)  # type: ignore

    def m2i_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, UPER_Decoder) -> _A
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        return cast(
            _A,
            codec.dec_from_decoder(  # type: ignore[attr-defined]
                dec, **self._uper_codec_kwargs(),
            ),
        )

    def dissect_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, UPER_Decoder) -> None
        self.set_val(pkt, self.m2i_from_decoder(pkt, dec))

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Union[bytes, _I, _A]) -> bytes
        if x is None:
            return b""
        if isinstance(x, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                    x.tag == ASN1_Class_UNIVERSAL.RAW or
                    x.tag == ASN1_Class_UNIVERSAL.ERROR or
                    self.ASN1_tag == x.tag):
                if pkt.ASN1_codec == ASN1_Codecs.PER:
                    codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
                    s = codec.enc(x.val, **self._uper_codec_kwargs())
                else:
                    s = x.enc(pkt.ASN1_codec)
            else:
                raise ASN1_Error("Encoding Error: got %r instead of an %r for field [%s]" % (x, self.ASN1_tag, self.name))  # noqa: E501
        else:
            codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
            size_len = self.size_len or 0
            if pkt.ASN1_codec == ASN1_Codecs.PER:
                s = codec.enc(x, **self._uper_codec_kwargs(size_len))
            else:
                s = codec.enc(x, size_len=size_len)
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            return cast(bytes, OER_tagging_enc(
                s,
                implicit_tag=self.implicit_tag,
                explicit_tag=self.explicit_tag,
            ))
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            return s
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

    def _uper_codec_kwargs(self, size_len=None):
        # type: (Optional[int]) -> Dict[str, Any]
        # These kwargs only depend on attributes set once at __init__ time,
        # so the common (no override) case is cached to avoid rebuilding the
        # dict on every field access during build/dissect.
        if size_len is None and self._uper_kwargs_cache is not None:
            return self._uper_kwargs_cache
        kwargs = {
            "size_len": (self.size_len if size_len is None else size_len) or 0,
            "oer_unsigned": self.oer_unsigned,
            "uper_min": self.uper_min,
            "uper_max": self.uper_max,
        }  # type: Dict[str, Any]
        if (
                getattr(self, "uper_extensible", False) and
                self.ASN1_tag == ASN1_Class_UNIVERSAL.INTEGER
        ):
            kwargs["uper_extensible"] = True
        if self.uper_enum_values is not None:
            kwargs["uper_enum_values"] = self.uper_enum_values
        if size_len is None:
            self._uper_kwargs_cache = kwargs
        return kwargs

    def _encode_item(self, pkt, item):
        # type: (ASN1_Packet, Any) -> bytes
        if isinstance(item, ASN1_Object):
            if pkt.ASN1_codec == ASN1_Codecs.PER:
                codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
                return codec.enc(item.val, **self._uper_codec_kwargs())
            return item.enc(pkt.ASN1_codec)
        if hasattr(item, "self_build"):
            return cast("ASN1_Packet", item).self_build()
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        size_len = self.size_len or 0
        if pkt.ASN1_codec == ASN1_Codecs.OER and self.oer_unsigned:
            return codec.enc(
                item, size_len=size_len, oer_unsigned=True
            )  # type: ignore[call-arg]
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            return codec.enc(item, **self._uper_codec_kwargs(size_len))
        return codec.enc(item, size_len=size_len)

    def _uper_encode_into(self, enc, pkt, value=None):
        # type: (UPER_Encoder, ASN1_Packet, Any) -> None
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
        codec.encode_into(  # type: ignore[attr-defined]
            enc, raw, **self._uper_codec_kwargs(),
        )


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

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Union[int, ASN1_INTEGER]]
                 context=None,  # type: Optional[Type[ASN1_Class]]
                 implicit_tag=None,  # type: Optional[int]
                 explicit_tag=None,  # type: Optional[int]
                 flexible_tag=False,  # type: Optional[bool]
                 size_len=None,  # type: Optional[int]
                 oer_unsigned=False,  # type: Optional[bool]
                 uper_min=None,  # type: Optional[int]
                 uper_max=None,  # type: Optional[int]
                 uper_extensible=False,  # type: bool
                 ):
        # type: (...) -> None
        super(ASN1F_INTEGER, self).__init__(
            name, cast(Optional[ASN1_INTEGER], default), context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag,
            flexible_tag=flexible_tag, size_len=size_len,
            oer_unsigned=oer_unsigned, uper_min=uper_min,
            uper_max=uper_max,
        )
        self.uper_extensible = uper_extensible

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, 2 ** 64 - 1)


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
        self.uper_enum_values = list(keys)

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
                 uper_min=None,  # type: Optional[int]
                 uper_max=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        super(ASN1F_BIT_STRING, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            uper_min=uper_min,
            uper_max=uper_max,
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
        uper_extensible = kwargs.pop("uper_extensible", False)
        name = "dummy_seq_name"
        default = [field.default for field in seq]
        super(ASN1F_SEQUENCE, self).__init__(
            name, default, **kwargs
        )
        self.uper_extensible = uper_extensible
        self.seq = seq
        self.islist = len(seq) > 1
        self._optionals = tuple(
            f for f in seq if isinstance(f, (ASN1F_optional, ASN1F_DEFAULT))
        )

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

    def _apply_tagging_dec(self, s, pkt):
        # type: (bytes, Any) -> bytes
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            diff_tag, s = OER_tagging_dec(
                s,
                hidden_tag=self.ASN1_tag,
                implicit_tag=self.implicit_tag,
                explicit_tag=self.explicit_tag,
                safe=self.flexible_tag,
                _fname=pkt.name,
            )
        else:
            diff_tag, s = BER_tagging_dec(
                s,
                hidden_tag=self.ASN1_tag,
                implicit_tag=self.implicit_tag,
                explicit_tag=self.explicit_tag,
                safe=self.flexible_tag,
                _fname=pkt.name,
            )
        self._apply_diff_tag(diff_tag)
        return s

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

    def _m2i_oer(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        s = self._apply_tagging_dec(s, pkt)
        s = self._dissect_sequence_children(pkt, s)
        return [], s

    def _m2i_per(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        dec = UPER_Decoder(s)
        self._uper_dissect_from_decoder(pkt, dec)
        if UPER_has_unexpected_remainder(dec):
            raise UPER_Decoding_Error(
                "unexpected remainder",
                remaining=dec.remaining(),
            )
        return [], b""

    def _m2i_ber(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        s = self._apply_tagging_dec(s, pkt)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i, s, remain = codec.check_type_check_len(s)
        s = self._dissect_sequence_children(pkt, s)
        if len(s) > 0:
            raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return [], remain

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
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            return self._m2i_oer(pkt, s)
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            return self._m2i_per(pkt, s)
        return self._m2i_ber(pkt, s)

    def _uper_dissect_from_decoder(self, pkt, dec):
        # type: (Any, UPER_Decoder) -> None
        if self.uper_extensible:
            if dec.read_bit():
                raise UPER_Decoding_Error(
                    "ASN1F_SEQUENCE: extension additions are not supported"
                )
        presence = [dec.read_bit() for _ in self._optionals]
        opt_idx = 0
        for obj in self.seq:
            if isinstance(obj, (ASN1F_optional, ASN1F_DEFAULT)):
                if not presence[opt_idx]:
                    obj.set_absent(pkt)
                    opt_idx += 1
                    continue
                opt_idx += 1
            try:
                obj.dissect_from_decoder(pkt, dec)
            except ASN1F_badsequence:
                break

    def dissect_from_decoder(self, pkt, dec):
        # type: (Any, UPER_Decoder) -> None
        self._uper_dissect_from_decoder(pkt, dec)

    def dissect(self, pkt, s):
        # type: (Any, bytes) -> bytes
        _, x = self.m2i(pkt, s)
        return x

    def build(self, pkt):
        # type: (ASN1_Packet) -> bytes
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            enc = UPER_Encoder()
            self._uper_encode_into(enc, pkt)
            return super(ASN1F_SEQUENCE, self).i2m(pkt, enc.as_bytes())
        s = reduce(lambda x, y: x + y.build(pkt),
                   self.seq, b"")
        return super(ASN1F_SEQUENCE, self).i2m(pkt, s)

    def _uper_encode_into(self, enc, pkt, value=None):
        # type: (UPER_Encoder, ASN1_Packet, Optional[Any]) -> None
        if self.uper_extensible:
            enc.append_bit(0)
        for opt in self._optionals:
            enc.append_bit(0 if opt.is_empty(pkt) else 1)
        for obj in self.seq:
            if isinstance(obj, (ASN1F_optional, ASN1F_DEFAULT)) and obj.is_empty(pkt):
                continue
            obj._uper_encode_into(enc, pkt)


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
                 uper_min=None,  # type: Optional[int]
                 uper_max=None,  # type: Optional[int]
                 uper_extensible=False,  # type: bool
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
        self.uper_min = uper_min
        self.uper_max = uper_max
        self.uper_extensible = uper_extensible

    def _uper_count_enc(self, enc, count):
        # type: (UPER_Encoder, int) -> None
        if self.uper_min is not None and self.uper_max is not None:
            UPER_constrained_int_enc(count, self.uper_min, self.uper_max, enc=enc)
        else:
            enc.append_length_determinant(count)

    def _uper_count_dec(self, dec):
        # type: (UPER_Decoder) -> int
        if self.uper_min is not None and self.uper_max is not None:
            size = self.uper_max - self.uper_min
            return cast(
                int,
                dec.read_non_negative_binary_integer(
                    UPER_bits_for_range(size),
                ) + self.uper_min,
            )
        return cast(int, dec.read_length_determinant())

    def is_empty(self,
                 pkt,  # type: ASN1_Packet
                 ):
        # type: (...) -> bool
        return ASN1F_field.is_empty(self, pkt)

    def _extract_packet_from_decoder(self, dec, pkt):
        # type: (UPER_Decoder, ASN1_Packet) -> Tuple[Any, bytes]
        if self.holds_packets:
            p = self.cls()
            p.add_underlayer(pkt)
            p.ASN1_root.dissect_from_decoder(p, dec)
            return p, b""
        return self.fld.m2i_from_decoder(pkt, dec), b""

    def m2i_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, UPER_Decoder) -> List[Any]
        if self.uper_extensible and dec.read_bit():
            count = dec.read_length_determinant()
        else:
            count = self._uper_count_dec(dec)
        lst = []
        for _ in range(count):
            item, _ = self._extract_packet_from_decoder(dec, pkt)
            lst.append(item)
        return lst

    def _uper_encode_into(self, enc, pkt, value=None):
        # type: (UPER_Encoder, ASN1_Packet, Any) -> None
        if value is None:
            value = getattr(pkt, self.name)
        if value is None:
            self._uper_count_enc(enc, 0)
            return
        count = len(value)
        if self.uper_extensible:
            if (
                    self.uper_min is not None and self.uper_max is not None and
                    self.uper_min <= count <= self.uper_max
            ):
                enc.append_bit(0)
            else:
                enc.append_bit(1)
                enc.append_length_determinant(count)
                for item in value:
                    if self.holds_packets:
                        cast("ASN1_Packet", item).ASN1_root._uper_encode_into(
                            enc, item,
                        )
                    else:
                        self.fld._uper_encode_into(enc, pkt, item)
                return
        self._uper_count_enc(enc, count)
        for item in value:
            if self.holds_packets:
                cast("ASN1_Packet", item).ASN1_root._uper_encode_into(
                    enc, item,
                )
            else:
                self.fld._uper_encode_into(enc, pkt, item)

    def m2i(self,
            pkt,  # type: ASN1_Packet
            s,  # type: bytes
            ):
        # type: (...) -> Tuple[List[Any], bytes]
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            diff_tag, s = OER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                          implicit_tag=self.implicit_tag,
                                          explicit_tag=self.explicit_tag,
                                          safe=self.flexible_tag)
            self._apply_diff_tag(diff_tag)
            count, s = OER_unsigned_integer_dec(s)
            lst = []
            for _ in range(count):
                c, s = self._extract_packet(s, pkt)  # type: ignore
                if c:
                    lst.append(c)
            return lst, s
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            dec = UPER_Decoder(s)
            if self.uper_extensible and dec.read_bit():
                count = dec.read_length_determinant()
            else:
                count = self._uper_count_dec(dec)
            lst = []
            for _ in range(count):
                c, _ = self._extract_packet_from_decoder(dec, pkt)
                if c:
                    lst.append(c)
            if UPER_has_unexpected_remainder(dec):
                raise UPER_Decoding_Error("unexpected remainder",
                                          remaining=dec.remaining())
            return lst, b""
        diff_tag, s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                                      implicit_tag=self.implicit_tag,
                                      explicit_tag=self.explicit_tag,
                                      safe=self.flexible_tag)
        self._apply_diff_tag(diff_tag)
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
            if pkt.ASN1_codec == ASN1_Codecs.OER:
                s = OER_unsigned_integer_enc(0)
            elif pkt.ASN1_codec == ASN1_Codecs.PER:
                enc = UPER_Encoder()
                enc.append_length_determinant(0)
                s = enc.as_bytes()
        else:
            if pkt.ASN1_codec == ASN1_Codecs.PER:
                enc = UPER_Encoder()
                self._uper_encode_into(enc, pkt, val)
                s = enc.as_bytes()
            elif self.holds_packets:
                s = b"".join(bytes(i) for i in val)
                if pkt.ASN1_codec == ASN1_Codecs.OER:
                    s = OER_unsigned_integer_enc(len(val)) + s
            else:
                s = b"".join(self.fld._encode_item(pkt, i) for i in val)
                if pkt.ASN1_codec == ASN1_Codecs.OER:
                    s = OER_unsigned_integer_enc(len(val)) + s
        return self.i2m(pkt, s)

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
        # type: (str) -> Optional[Any]
        return getattr(self._field, attr)

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
            self._field.set_val(pkt, None)
            return s

    def dissect_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, UPER_Decoder) -> None
        return self._field.dissect_from_decoder(pkt, dec)

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

    def set_val(self, pkt, val):
        # type: (ASN1_Packet, Any) -> None
        self._field.set_val(pkt, val)

    def set_absent(self, pkt):
        # type: (ASN1_Packet) -> None
        self.set_val(pkt, None)

    def is_empty(self, pkt):
        # type: (ASN1_Packet) -> bool
        val = getattr(pkt, self._field.name, None)
        if val is None:
            return True
        if getattr(self._field, "islist", 0) and val == []:
            return True
        return False

    def _uper_encode_into(self, enc, pkt, value=None):
        # type: (UPER_Encoder, ASN1_Packet, Optional[Any]) -> None
        self._field._uper_encode_into(enc, pkt, value)


class ASN1F_DEFAULT(ASN1F_optional):
    """
    ASN.1 field with a DEFAULT value (PER presence bit).
    """

    def __init__(self, field, default):
        # type: (ASN1F_field[Any, Any], Any) -> None
        super(ASN1F_DEFAULT, self).__init__(field)
        self._default = default

    def is_empty(self, pkt):
        # type: (ASN1_Packet) -> bool
        val = getattr(pkt, self._field.name, None)
        if val is None:
            return True
        if isinstance(val, ASN1_Object):
            val = val.val
        default = self._default
        if isinstance(default, ASN1_Object):
            default = default.val
        return bool(val == default)

    def set_absent(self, pkt):
        # type: (ASN1_Packet) -> None
        self.set_val(pkt, self._default)


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
        uper_extensible = kwargs.pop("uper_extensible", False)
        self.implicit_tag = None
        for kwarg in ["context", "explicit_tag"]:
            setattr(self, kwarg, kwargs.get(kwarg))
        super(ASN1F_CHOICE, self).__init__(
            name, None, context=self.context,
            explicit_tag=self.explicit_tag
        )
        self.uper_extensible = uper_extensible
        self.default = default
        self.current_choice = None
        self.choices = {}  # type: Dict[int, _CHOICE_T]
        self.choice_order = []  # type: List[int]
        self.choice_list = []  # type: List[_CHOICE_T]
        self.pktchoices = {}
        for p in args:
            if hasattr(p, "ASN1_root"):
                p = cast('ASN1_Packet', p)
                # should be ASN1_Packet
                if hasattr(p.ASN1_root, "choices"):
                    root = cast(ASN1F_CHOICE, p.ASN1_root)
                    for k in root.choice_order:
                        self._register_choice(k, root.choices[k])
                else:
                    self._register_choice(p.ASN1_root.network_tag, p)
            elif hasattr(p, "ASN1_tag"):
                if isinstance(p, type):
                    # should be ASN1F_field class
                    self._register_choice(int(p.ASN1_tag), p)
                else:
                    # should be ASN1F_field instance
                    self._register_choice(p.network_tag, p)
                    if hasattr(p, "cls"):
                        self.pktchoices[hash(p.cls)] = (p.implicit_tag, p.explicit_tag)  # noqa: E501
            else:
                raise ASN1_Error("ASN1F_CHOICE: no tag found for one field")
        self._tag_to_index = {
            tag: idx for idx, tag in enumerate(self.choice_order)
        }

    def _register_choice(self, tag, choice):
        # type: (int, _CHOICE_T) -> None
        self.choices[tag] = choice
        self.choice_order.append(tag)
        self.choice_list.append(choice)

    def _dissect_choice_payload(self, pkt, choice, payload):
        # type: (ASN1_Packet, _CHOICE_T, bytes) -> Tuple[ASN1_Object[Any], bytes]
        if hasattr(choice, "ASN1_root"):
            return self.extract_packet(choice, payload, _underlayer=pkt)  # type: ignore
        if isinstance(choice, type):
            return choice(self.name, b"").m2i(pkt, payload)
        return choice.m2i(pkt, payload)

    def _m2i_oer(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        _, s = OER_tagging_dec(
            s, hidden_tag=self.ASN1_tag, explicit_tag=self.explicit_tag,
        )
        tag, payload = OER_id_dec(s)
        return self._m2i_tagged(pkt, tag, payload)

    def _m2i_per(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        dec = UPER_Decoder(s)
        val = self.m2i_from_decoder(pkt, dec)
        if UPER_has_unexpected_remainder(dec):
            raise UPER_Decoding_Error(
                "unexpected remainder",
                remaining=dec.remaining(),
            )
        return val, b""

    def _m2i_ber(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        _, s = BER_tagging_dec(
            s, hidden_tag=self.ASN1_tag, explicit_tag=self.explicit_tag,
        )
        tag, _ = BER_id_dec(s)
        return self._m2i_tagged(pkt, tag, s)

    def _m2i_tagged(self, pkt, tag, payload):
        # type: (ASN1_Packet, int, bytes) -> Tuple[ASN1_Object[Any], bytes]
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
        return self._dissect_choice_payload(pkt, choice, payload)

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[ASN1_Object[Any], bytes]
        """
        First we have to retrieve the appropriate choice.
        Then we extract the field/packet, according to this choice.
        """
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            return self._m2i_oer(pkt, s)
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            return self._m2i_per(pkt, s)
        return self._m2i_ber(pkt, s)

    def _choice_tag_for(self, x):
        # type: (Any) -> Optional[int]
        index = self._choice_index_for(x)
        return None if index is None else self.choice_order[index]

    def _choice_index_for(self, x):
        # type: (Any) -> Optional[int]
        for index, choice in enumerate(self.choice_list):
            if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
                if isinstance(x, choice):
                    return index
            elif hasattr(choice, "ASN1_tag"):
                if isinstance(x, ASN1_Object) and x.tag == choice.ASN1_tag:
                    return index
        return None

    def _choice_for_index(self, index):
        # type: (int) -> _CHOICE_T
        return self.choice_list[index]

    def m2i_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, UPER_Decoder) -> ASN1_Object[Any]
        if self.uper_extensible:
            if dec.read_bit():
                raise UPER_Decoding_Error(
                    "ASN1F_CHOICE: extension additions are not supported"
                )
        if len(self.choice_order) > 1:
            index, _ = UPER_choice_index_dec(b"", len(self.choice_order), dec=dec)
        else:
            index = 0
        if index >= len(self.choice_order):
            raise ASN1_Error(
                "ASN1F_CHOICE: unexpected index %s in '%s'" %
                (index, self.name)
            )
        choice = self._choice_for_index(index)
        if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
            pkt_cls = cast("Type[ASN1_Packet]", choice)
            p = pkt_cls()
            p.add_underlayer(pkt)
            p.ASN1_root.dissect_from_decoder(p, dec)
            return cast(ASN1_Object[Any], p)
        if isinstance(choice, type):
            return cast(
                ASN1_Object[Any],
                choice(self.name, b"").m2i_from_decoder(pkt, dec),
            )
        return cast(ASN1_Object[Any], choice.m2i_from_decoder(pkt, dec))

    def _uper_encode_into(self, enc, pkt, value=None):
        # type: (UPER_Encoder, ASN1_Packet, Any) -> None
        if value is None:
            value = getattr(pkt, self.name)
        index = self._choice_index_for(value)
        if index is None:
            raise ASN1_Error(
                "ASN1F_CHOICE: cannot encode unknown alternative in '%s'" %
                self.name
            )
        if self.uper_extensible:
            enc.append_bit(0)
        if len(self.choice_order) > 1:
            UPER_choice_index_enc(index, len(self.choice_order), enc=enc)
        choice = self._choice_for_index(index)
        if hasattr(choice, "ASN1_root"):
            cast("ASN1_Packet", value).ASN1_root._uper_encode_into(enc, value)
        elif isinstance(choice, type):
            choice(self.name, b"")._uper_encode_into(enc, pkt, value)
        else:
            choice._uper_encode_into(enc, pkt, value)

    def i2m(self, pkt, x):
        # type: (ASN1_Packet, Any) -> bytes
        if x is None:
            s = b""
        elif pkt.ASN1_codec == ASN1_Codecs.PER:
            enc = UPER_Encoder()
            self._uper_encode_into(enc, pkt, x)
            s = enc.as_bytes()
        else:
            if isinstance(x, ASN1_Object):
                s = x.enc(pkt.ASN1_codec)
            elif hasattr(x, "self_build"):
                s = cast("ASN1_Packet", x).self_build()
            else:
                s = bytes(x)
            if pkt.ASN1_codec == ASN1_Codecs.OER:
                alt_tag = self._choice_tag_for(x)
                if alt_tag is not None:
                    s = OER_tag_enc(alt_tag & 0x3f, alt_tag & 0xc0) + s
            elif hash(type(x)) in self.pktchoices:
                imp, exp = self.pktchoices[hash(type(x))]
                s = BER_tagging_enc(s,
                                    implicit_tag=imp,
                                    explicit_tag=exp)
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            return cast(bytes, OER_tagging_enc(s, explicit_tag=self.explicit_tag))
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            return s
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

    def _resolve_cls(self, pkt):
        # type: (ASN1_Packet) -> Type[ASN1_Packet]
        if self.next_cls_cb:
            return self.next_cls_cb(pkt) or self.cls
        return self.cls

    def m2i_from_decoder(self, pkt, dec):
        # type: (ASN1_Packet, UPER_Decoder) -> Optional[ASN1_Packet]
        cls = self._resolve_cls(pkt)
        p = cls()
        p.add_underlayer(pkt)
        p.ASN1_root.dissect_from_decoder(p, dec)
        return p

    def _uper_encode_into(self, enc, pkt, value=None):
        # type: (UPER_Encoder, ASN1_Packet, Any) -> None
        if value is None:
            value = getattr(pkt, self.name)
        if value is None:
            return
        if isinstance(value, ASN1_Object):
            value = value.val
        cast("ASN1_Packet", value).ASN1_root._uper_encode_into(enc, value)

    def m2i(self, pkt, s):
        # type: (ASN1_Packet, bytes) -> Tuple[Any, bytes]
        cls = self._resolve_cls(pkt)
        if not hasattr(cls, "ASN1_root"):
            # A normal Packet (!= ASN1)
            return self.extract_packet(cls, s, _underlayer=pkt)
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            diff_tag, s = OER_tagging_dec(s, hidden_tag=cls.ASN1_root.ASN1_tag,  # noqa: E501
                                          implicit_tag=self.implicit_tag,
                                          explicit_tag=self.explicit_tag,
                                          safe=self.flexible_tag,
                                          _fname=self.name)
        elif pkt.ASN1_codec != ASN1_Codecs.PER:
            diff_tag, s = BER_tagging_dec(s, hidden_tag=cls.ASN1_root.ASN1_tag,  # noqa: E501
                                          implicit_tag=self.implicit_tag,
                                          explicit_tag=self.explicit_tag,
                                          safe=self.flexible_tag,
                                          _fname=self.name)
        else:
            diff_tag = None
        self._apply_diff_tag(diff_tag)
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
        elif pkt.ASN1_codec == ASN1_Codecs.PER:
            enc = UPER_Encoder()
            self._uper_encode_into(enc, pkt, x)
            s = enc.as_bytes()
        elif isinstance(x, bytes):
            s = x
        elif isinstance(x, ASN1_Object):
            if x.val:
                s = bytes(x.val)
            else:
                s = b""
        else:
            s = bytes(x)
            if not hasattr(x, "ASN1_root"):
                # A normal Packet (!= ASN1)
                return s
        if pkt.ASN1_codec == ASN1_Codecs.PER:
            return s
        if pkt.ASN1_codec == ASN1_Codecs.OER:
            return cast(bytes, OER_tagging_enc(
                s,
                implicit_tag=self.implicit_tag,
                explicit_tag=self.explicit_tag,
            ))
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
                 uper_min=None,  # type: Optional[int]
                 uper_max=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        self.mapping = mapping
        super(ASN1F_FLAGS, self).__init__(
            name, default,
            default_readable=False,
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag,
            uper_min=uper_min,
            uper_max=uper_max,
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
        return self.cls(val[0].val, _underlayer=pkt), val[1]
