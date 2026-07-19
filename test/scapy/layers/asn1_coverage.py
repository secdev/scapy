# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Additional coverage for UPER, OER, and asn1fields helpers.
"""


def _raises(exc, func):
    # type: (type, Any) -> None
    try:
        func()
    except exc:
        return
    raise AssertionError("Expected %s" % exc.__name__)


from typing import Any
from unittest import mock

from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_Error,
    ASN1_INTEGER,
    ASN1_STRING,
    ASN1_TIME_TICKS,
)
from scapy.asn1.ber import BER_Decoding_Error
from scapy.contrib.oer import (
    OER_Decoding_Error,
    OER_Encoding_Error,
    OERcodec_BIT_STRING,
    OERcodec_IPADDRESS,
    OERcodec_SEQUENCE,
    OERcodec_SET,
)
from scapy.contrib.uper import (
    UPER_Decoding_Error,
    UPER_Encoding_Error,
    UPER_Decoder,
    UPER_Encoder,
    UPERcodec_BIT_STRING,
    UPERcodec_ENUMERATED,
    UPERcodec_IPADDRESS,
    UPERcodec_SEQUENCE,
    UPERcodec_SET,
)
from scapy.asn1fields import (
    ASN1F_BIT_STRING,
    ASN1F_BIT_STRING_ENCAPS,
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_DEFAULT,
    ASN1F_FLAGS,
    ASN1F_IPADDRESS,
    ASN1F_INTEGER,
    ASN1F_OID,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_SET_OF,
    ASN1F_STRING,
    ASN1F_STRING_ENCAPS,
    ASN1F_STRING_PacketField,
    ASN1F_TIME_TICKS,
    ASN1F_UTC_TIME,
    ASN1F_badsequence,
    ASN1F_enum_INTEGER,
    ASN1F_omit,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import Raw, raw


class _InnerRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("mode", ASN1_INTEGER(0), ["off", "on"]),
    )


class _EncapsRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING_ENCAPS("payload", None, _InnerRecord),
    )


class _FlagsRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_FLAGS("f", "000", ["read", "write", "exec"]),
    )


class _SetOfRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF("items", [], ASN1F_INTEGER)


class _PacketFieldRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING_PacketField("data", b""),
    )


class _ExplicitPacket(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_PACKET("inner", None, _InnerRecord, explicit_tag=0xA2)


class _BitEncapsRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_BIT_STRING_ENCAPS("b", None, _InnerRecord),
    )


def check_uper_error_str():
    # type: () -> None
    obj = ASN1_INTEGER(2)
    err = UPER_Encoding_Error("enc", encoded=obj, remaining=b"x")
    assert "Already encoded" in str(err)
    err2 = UPER_Decoding_Error("dec", decoded=obj, remaining=b"y")
    assert "Already decoded" in str(err2)


def check_uper_length_determinant_extended():
    # type: () -> None
    enc = UPER_Encoder()
    assert enc.append_length_determinant(32768) == 32768
    assert enc.as_bytes() == b"\xc2"

    enc = UPER_Encoder()
    assert enc.append_length_determinant(49152) == 49152
    assert enc.as_bytes() == b"\xc3"

    enc = UPER_Encoder()
    assert enc.append_length_determinant(65535) == 49152
    assert enc.as_bytes() == b"\xc3"


def check_uper_unconstrained_whole_number():
    # type: () -> None
    enc = UPER_Encoder()
    enc.append_unconstrained_whole_number(-256)
    dec = UPER_Decoder(enc.as_bytes())
    assert dec.read_unconstrained_whole_number() == -256

    enc = UPER_Encoder()
    enc.append_unconstrained_whole_number(0)
    dec = UPER_Decoder(enc.as_bytes())
    assert dec.read_unconstrained_whole_number() == 0


def check_uper_bit_string_paths():
    # type: () -> None
    encoded = UPERcodec_BIT_STRING.enc("1010", uper_min=1, uper_max=20)
    obj, remain = UPERcodec_BIT_STRING.do_dec(
        encoded, uper_min=1, uper_max=20,
    )
    assert obj.val == "1010"

    encoded2 = UPERcodec_BIT_STRING.enc(b"\xab", uper_min=4, uper_max=8)
    obj2, _ = UPERcodec_BIT_STRING.do_dec(encoded2, uper_min=4, uper_max=8)
    assert len(obj2.val) == 8

    fixed = UPERcodec_BIT_STRING.enc("1010101111001101", uper_min=16, uper_max=16)
    obj3, _ = UPERcodec_BIT_STRING.do_dec(fixed, uper_min=16, uper_max=16)
    assert obj3.val == "1010101111001101"


def check_uper_enumerated_range():
    # type: () -> None
    encoded = UPERcodec_ENUMERATED.enc(3, uper_min=0, uper_max=7)
    obj, remain = UPERcodec_ENUMERATED.do_dec(encoded, uper_min=0, uper_max=7)
    assert obj.val == 3
    assert remain == b""

    enc = UPER_Encoder()
    UPERcodec_ENUMERATED.encode_into(enc, 2, uper_min=0, uper_max=3)
    obj2 = UPERcodec_ENUMERATED.dec_from_decoder(
        UPER_Decoder(enc.as_bytes()),
        uper_min=0,
        uper_max=3,
    )
    assert obj2.val == 2


def check_uper_sequence_errors():
    # type: () -> None
    _raises(UPER_Encoding_Error, lambda: UPERcodec_SEQUENCE.enc([ASN1_INTEGER(1)]))

    _raises(UPER_Decoding_Error, lambda: UPERcodec_SEQUENCE.do_dec(b"\x00"))

    assert UPERcodec_SET.enc(b"raw") == b"raw"


def check_uper_ipaddress():
    # type: () -> None
    encoded = UPERcodec_IPADDRESS.enc("10.0.0.1")
    obj, remain = UPERcodec_IPADDRESS.do_dec(encoded)
    assert obj.val == "10.0.0.1"
    assert remain == b""

    _raises(UPER_Encoding_Error, lambda: UPERcodec_IPADDRESS.enc("bad-ip"))


def check_oer_error_str():
    # type: () -> None
    obj = ASN1_INTEGER(1)
    err = OER_Encoding_Error("enc", encoded=obj, remaining=b"z")
    assert "Already encoded" in str(err)
    err2 = OER_Decoding_Error("dec", decoded=obj, remaining=b"w")
    assert "Already decoded" in str(err2)


def check_oer_ipaddress_and_sequence():
    # type: () -> None
    encoded = OERcodec_IPADDRESS.enc("127.0.0.1")
    obj, remain = OERcodec_IPADDRESS.do_dec(encoded)
    assert obj.val == "127.0.0.1"
    assert remain == b""

    fixed = OERcodec_IPADDRESS.enc("127.0.0.1", size_len=4)
    obj2, remain2 = OERcodec_IPADDRESS.do_dec(fixed, size_len=4)
    assert obj2.val == "127.0.0.1"
    assert remain2 == b""

    _raises(OER_Encoding_Error, lambda: OERcodec_IPADDRESS.enc("bad-ip"))

    _raises(OER_Decoding_Error, lambda: OERcodec_IPADDRESS.do_dec(b"\x01"))

    assert OERcodec_SEQUENCE.enc(b"payload") == b"payload"
    assert OERcodec_SET.enc(b"payload") == b"payload"

    _raises(OER_Decoding_Error, lambda: OERcodec_SEQUENCE.do_dec(b"\x00"))

    empty, remain = OERcodec_BIT_STRING.do_dec(OERcodec_BIT_STRING.enc(""))
    assert empty.val == ""
    assert remain == b""


def check_asn1fields_enum_and_flags():
    # type: () -> None
    pkt = _InnerRecord(mode="on")
    built = raw(pkt)
    decoded = _InnerRecord(built)
    assert decoded.mode.val == 1

    flags = _FlagsRecord(f="read+exec")
    assert flags.f.val == "101"
    assert "read, exec" in _FlagsRecord.ASN1_root.seq[0].i2repr(flags, flags.f)

    set_pkt = _SetOfRecord(items=[ASN1_INTEGER(0), ASN1_INTEGER(1)])
    set_raw = raw(set_pkt)
    set_dec = _SetOfRecord(set_raw)
    assert [x.val for x in set_dec.items] == [0, 1]


def check_asn1fields_encaps_and_packet():
    # type: () -> None
    inner = _InnerRecord(mode=1)
    enc = _EncapsRecord()
    enc.payload = inner
    enc_raw = raw(enc)
    enc_dec = _EncapsRecord(enc_raw)
    assert enc_dec.payload.mode.val == 1

    pkt_field = _PacketFieldRecord()
    pkt_field.data = _InnerRecord(mode=0)
    pf_raw = raw(pkt_field)
    pf_dec = _PacketFieldRecord(pf_raw)
    assert isinstance(pf_dec.data.val, bytes)

    explicit = _ExplicitPacket()
    explicit.inner = _InnerRecord(mode=1)
    ex_raw = raw(explicit)
    ex_dec = _ExplicitPacket(ex_raw)
    assert ex_dec.inner.mode.val == 1


def check_asn1fields_choice_and_special():
    # type: () -> None
    class _OerChoiceRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    class _BerChoiceRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    oer = _OerChoiceRecord(c=ASN1_INTEGER(1))
    oer_dec = _OerChoiceRecord(raw(oer))
    assert oer_dec.c.val == 1

    ber = _BerChoiceRecord(c=ASN1_INTEGER(0))
    ber_dec = _BerChoiceRecord(raw(ber))
    assert ber_dec.c.val == 0

    inner_bytes = raw(_InnerRecord(mode=0))
    bit_payload = ASN1_BIT_STRING(
        inner_bytes,
        readable=True,
    )
    bit_pkt = _BitEncapsRecord(b=bit_payload)
    bit_dec = _BitEncapsRecord(raw(bit_pkt))
    assert bit_dec.b.mode.val == 0

    class _TicksRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_TIME_TICKS("t", ASN1_TIME_TICKS(0))

    class _IpRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_IPADDRESS("addr", ASN1_STRING(b""))

    ticks = _TicksRecord(t=ASN1_TIME_TICKS(1234))
    assert raw(ticks).endswith(b"\x04\xd2")

    ip = _IpRecord()
    ip.addr = "192.168.1.1"
    assert raw(ip) == b"\x40\x04\xc0\xa8\x01\x01"


def check_asn1fields_optional_dissect():
    # type: () -> None
    class _OptRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0),
            ASN1F_optional(ASN1F_INTEGER("extra", 0)),
        )

    class _BerChoiceRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    pkt = _OptRecord(id=0, extra=None)
    assert raw(pkt)
    decoded = _OptRecord(raw(pkt))
    assert decoded.extra is None

    choice_rand = _BerChoiceRecord.ASN1_root.randval()
    assert choice_rand is not None


def check_asn1fields_default_and_omit():
    # type: () -> None
    class _DefaultRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, uper_min=0, uper_max=255),
            ASN1F_DEFAULT(
                ASN1F_INTEGER(
                    "count", 600,
                    uper_min=0, uper_max=86401, oer_unsigned=True,
                ),
                600,
            ),
        )

    absent = _DefaultRecord(id=1)
    assert raw(absent) == b"\x00\x80"
    decoded = _DefaultRecord(raw(absent))
    assert decoded.id.val == 1
    assert decoded.count == 600 or decoded.count.val == 600

    present = _DefaultRecord(id=1, count=86400)
    decoded = _DefaultRecord(raw(present))
    assert decoded.count.val == 86400

    class _OmitRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0),
            ASN1F_omit("ignored", None),
        )

    omit_pkt = _OmitRecord(id=7)
    assert raw(omit_pkt) == bytes.fromhex("3003020107")


def check_asn1fields_extensible_per():
    # type: () -> None
    class _ExtSeq(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, uper_min=0, uper_max=255),
            ASN1F_optional(ASN1F_INTEGER("extra", 0, uper_min=0, uper_max=7)),
            uper_extensible=True,
        )

    pkt = _ExtSeq(id=2, extra=3)
    data = raw(pkt)
    decoded = _ExtSeq(data)
    assert decoded.id.val == 2
    assert decoded.extra.val == 3

    dec = UPER_Decoder(b"\x80")
    _raises(
        UPER_Decoding_Error,
        lambda: _ExtSeq.ASN1_root.dissect_from_decoder(_ExtSeq(), dec),
    )

    class _ExtChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
            uper_extensible=True,
        )

    choice = _ExtChoice(c=ASN1_INTEGER(4))
    assert raw(choice)
    dec = UPER_Decoder(b"\x80")
    _raises(
        UPER_Decoding_Error,
        lambda: _ExtChoice.ASN1_root.m2i_from_decoder(_ExtChoice(), dec),
    )

    class _InnerItem(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_INTEGER("n", 0, uper_min=0, uper_max=7)

    class _ExtSeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE_OF(
            "items", [], _InnerItem,
            uper_min=1, uper_max=2, uper_extensible=True,
        )

    in_range = _ExtSeqOf(items=[_InnerItem(n=1)])
    assert raw(in_range)
    decoded = _ExtSeqOf(raw(in_range))
    assert decoded.items[0].n.val == 1

    out_of_range = _ExtSeqOf(
        items=[_InnerItem(n=i) for i in range(4)],
    )
    assert raw(out_of_range)
    decoded = _ExtSeqOf(raw(out_of_range))
    assert len(decoded.items) == 4


def check_asn1fields_sequence_of_advanced():
    # type: () -> None
    class _Inner(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_INTEGER("n", 0, uper_min=0, uper_max=7)

    class _SeqOfPackets(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE_OF(
            "items", [], _Inner, uper_min=1, uper_max=3,
        )

    pkt = _SeqOfPackets(items=[_Inner(n=1), _Inner(n=2)])
    decoded = _SeqOfPackets(raw(pkt))
    assert [x.n.val for x in decoded.items] == [1, 2]

    class _OerSeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER)

    oer_pkt = _OerSeqOf(values=[1, 2])
    oer_dec = _OerSeqOf(raw(oer_pkt))
    assert [x.val for x in oer_dec.values] == [1, 2]

    class _EmptySeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER)

    empty = _EmptySeqOf(values=None)
    assert raw(empty) == b"\x00"
    assert _EmptySeqOf.ASN1_root.i2repr(empty, None) == "[]"
    assert _EmptySeqOf.ASN1_root.i2repr(
        _EmptySeqOf(values=[ASN1_INTEGER(1)]),
        [ASN1_INTEGER(1)],
    ).startswith("[")

    _raises(ValueError, lambda: ASN1F_SEQUENCE_OF("bad", [], object()))


def check_asn1fields_choice_advanced():
    # type: () -> None
    class _InnerChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    class _NestedChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), _InnerChoice, ASN1F_INTEGER,
        )

    nested = _NestedChoice(c=_InnerChoice(c=ASN1_STRING(b"xy")))
    assert len(raw(nested)) > 0
    nested_dec = _NestedChoice(raw(nested))
    assert isinstance(nested_dec.c, (_InnerChoice, ASN1_STRING))

    class _OerTaggedChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
            explicit_tag=0xA1,
        )

    oer_choice = _OerTaggedChoice(c=ASN1_INTEGER(9))
    assert raw(oer_choice)

    class _PacketChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c",
            ASN1_INTEGER(0),
            ASN1F_PACKET("inner", None, _InnerRecord, explicit_tag=0xA2),
            ASN1F_INTEGER,
        )

    packet_choice = _PacketChoice(
        c=_InnerRecord(mode=ASN1_INTEGER(1)),
    )
    packet_dec = _PacketChoice(raw(packet_choice))
    assert packet_dec.c.mode.val == 1

    class _PerChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    _raises(
        ASN1_Error,
        lambda: ASN1F_CHOICE(
            "c", 0, ASN1F_INTEGER, implicit_tag=0xA0,
        ),
    )
    _raises(
        ASN1_Error,
        lambda: _PerChoice.ASN1_root.m2i(_PerChoice(), b""),
    )
    _raises(
        ASN1_Error,
        lambda: _PerChoice.ASN1_root._uper_encode_into(
            UPER_Encoder(), _PerChoice(), 42,
        ),
    )


def check_asn1fields_enum_bitstring_and_flags():
    # type: () -> None
    class _NamedEnum(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_enum_INTEGER(
            "state", 0, ["off", "on", "auto"],
        )

    named = _NamedEnum(state="on")
    built = raw(named)
    decoded = _NamedEnum(built)
    assert decoded.state.val == 1
    assert "'on'" in _NamedEnum.ASN1_root.i2repr(decoded, decoded.state)

    class _BitRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_BIT_STRING("bits", b"\xaa")

    assert raw(_BitRecord())

    flags = _FlagsRecord()
    flags.f = ASN1_BIT_STRING("101")
    assert "read, exec" in _FlagsRecord.ASN1_root.seq[0].i2repr(flags, flags.f)

    class _BadBitEncaps(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_BIT_STRING_ENCAPS("b", None, _InnerRecord)

    _raises(
        BER_Decoding_Error,
        lambda: _BadBitEncaps.ASN1_root.m2i(
            _BadBitEncaps(),
            b"\x03\x02\x01\x00",
        ),
    )


def check_asn1fields_packet_and_sequence_errors():
    # type: () -> None
    class _PerInner(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_INTEGER("mode", 0, uper_min=0, uper_max=1)

    class _PacketWrap(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_PACKET("inner", None, _PerInner)

    inner = _PerInner(mode=1)
    wrap = _PacketWrap(inner=inner)
    decoded = _PacketWrap(raw(wrap))
    assert decoded.inner.mode.val == 1

    class _DynamicPacket(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_PACKET(
            "inner", None, _PerInner,
            next_cls_cb=lambda pkt: _PerInner,
        )

    dyn = _DynamicPacket(inner=_PerInner(mode=0))
    assert _DynamicPacket.ASN1_root._resolve_cls(dyn) is _PerInner

    empty_packet = _PacketWrap(inner=None)
    assert raw(empty_packet) == b""

    class _BerSeq(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0),
            ASN1F_INTEGER("extra", 0),
        )

    _raises(
        BER_Decoding_Error,
        lambda: _BerSeq.ASN1_root.m2i(
            _BerSeq(),
            bytes.fromhex("300702010102010200ff"),
        ),
    )

    class _OerSeq(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, size_len=1, oer_unsigned=True),
        )

    _, remain = _OerSeq.ASN1_root.m2i(_OerSeq(), b"\x01\xff")
    assert remain == b"\xff"

    class _PerSeq(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, uper_min=0, uper_max=255),
        )

    _raises(
        UPER_Decoding_Error,
        lambda: _PerSeq.ASN1_root.m2i(_PerSeq(), b"\x80\xff"),
    )

    empty_seq = _BerSeq()
    _BerSeq.ASN1_root._dissect_sequence_children(empty_seq, b"")
    assert empty_seq.id is None
    assert empty_seq.extra is None

    class _OptListRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, uper_min=0, uper_max=255),
            ASN1F_optional(
                ASN1F_SEQUENCE_OF("items", [], ASN1F_INTEGER),
            ),
        )

    opt_list = _OptListRecord(id=1, items=None)
    assert raw(opt_list)

    field = ASN1F_INTEGER("n", 0)
    with mock.patch.object(
        _InnerRecord, "__init__", side_effect=ASN1F_badsequence,
    ):
        pkt_obj, remain = field.extract_packet(
            _InnerRecord, b"\xab\xcd", _underlayer=None,
        )
    assert isinstance(pkt_obj, Raw)
    assert pkt_obj.load == b"\xab\xcd"
    assert remain == b"\xab\xcd"


def check_asn1fields_more_coverage():
    # type: () -> None
    _raises(
        ASN1_Error,
        lambda: ASN1F_INTEGER("x", 0, implicit_tag=1, explicit_tag=2),
    )

    class _IntRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_INTEGER("n", 0)

    field = _IntRecord.ASN1_root
    _raises(
        ASN1_Error,
        lambda: field.i2m(_IntRecord(), ASN1_STRING(b"bad")),
    )

    flex_field = ASN1F_INTEGER("n", 0, flexible_tag=True, explicit_tag=0xA0)
    obj, remain = flex_field.m2i(_IntRecord(), bytes.fromhex("a1020101"))
    assert obj.tag != ASN1_Class_UNIVERSAL.INTEGER or remain == b""

    class _FlexSeq(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0),
            explicit_tag=0xA1,
            flexible_tag=True,
        )

    flex_seq = _FlexSeq(id=1)
    assert raw(flex_seq)
    decoded = _FlexSeq(raw(flex_seq))
    assert decoded.id.val == 1

    assert ASN1F_BOOLEAN("b", False).randval() is not None
    assert ASN1F_BIT_STRING("b", b"").randval() is not None
    assert ASN1F_OID("o", None).randval() is not None
    assert ASN1F_UTC_TIME("t", "").randval() is not None
    assert "<ASN1F_SEQUENCE" in repr(_FlexSeq.ASN1_root)

    class _EmptySeq(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_optional(ASN1F_INTEGER("id", 0)),
        )

    empty = _EmptySeq()
    empty.id = None
    assert _EmptySeq.ASN1_root.is_empty(empty)

    class _StrEnum(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_enum_INTEGER(
            "mode", 0, {"off": 0, "on": 1},
        )

    str_enum = _StrEnum(mode=1)
    built = raw(str_enum)
    decoded = _StrEnum(built)
    assert "'on'" in _StrEnum.ASN1_root.i2repr(decoded, decoded.mode)

    omit_field = ASN1F_omit("ignored", None)
    val, remain = omit_field.m2i(_IntRecord(), b"leftover")
    assert val is None and remain == b"leftover"

    class _OptList(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, uper_min=0, uper_max=255),
            ASN1F_optional(
                ASN1F_SEQUENCE_OF("items", [], ASN1F_INTEGER),
            ),
        )

    opt = _OptList(id=1, items=[])
    opt_field = _OptList.ASN1_root.seq[1]
    assert opt_field.is_empty(opt)

    class _DefaultPkt(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_DEFAULT(ASN1F_INTEGER("n", 5, uper_min=0, uper_max=10), 5),
        )

    default_pkt = _DefaultPkt(n=5)
    default_field = _DefaultPkt.ASN1_root.seq[0]
    assert default_field.is_empty(default_pkt)

    class _BerChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    assert _BerChoice.ASN1_root.randval() is not None

    class _PacketChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c",
            ASN1_INTEGER(0),
            ASN1F_PACKET("inner", None, _InnerRecord, explicit_tag=0xA2),
            ASN1F_INTEGER,
        )

    assert _PacketChoice.ASN1_root.randval() is not None
    packet_field = _PacketChoice.ASN1_root.choice_list[0]
    assert packet_field.randval() is not None

    class _FlexPacket(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_PACKET(
            "inner", None, _InnerRecord,
            explicit_tag=0xA2,
        )

    _FlexPacket.ASN1_root.flexible_tag = True
    inner_pkt = _InnerRecord(mode=0)
    flex_pkt = _FlexPacket(inner=inner_pkt)
    assert raw(flex_pkt)

    packet_field = _FlexPacket.ASN1_root
    built_inner = raw(_InnerRecord(mode=1))
    assert len(packet_field.i2m(_FlexPacket(), built_inner)) > 0

    empty_inner, remain = packet_field.m2i(_FlexPacket(), b"")
    assert empty_inner is None and remain == b""

    obj_val = packet_field.i2m(_FlexPacket(), _InnerRecord(mode=0))
    assert len(obj_val) > 0

    flags_field = _FlagsRecord.ASN1_root.seq[0]
    assert flags_field.i2repr(_FlagsRecord(), None) == "None"

    class _OerFlexSeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_SEQUENCE_OF(
            "values", [], ASN1F_INTEGER,
            explicit_tag=0xA1,
        )

    _OerFlexSeqOf.ASN1_root.flexible_tag = True

    oer_seq = _OerFlexSeqOf(values=[1])
    data = raw(oer_seq)
    decoded = _OerFlexSeqOf(data)
    assert decoded.values[0].val == 1

    class _BerFlexSeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE_OF(
            "values", [], ASN1F_INTEGER,
            explicit_tag=0xA1,
        )

    _BerFlexSeqOf.ASN1_root.flexible_tag = True

    ber_seq = _BerFlexSeqOf(values=[2])
    assert raw(ber_seq)

    class _ExtChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
            uper_extensible=True,
        )

    dec = UPER_Decoder(b"\x80")
    _raises(
        UPER_Decoding_Error,
        lambda: _ExtChoice.ASN1_root.m2i_from_decoder(_ExtChoice(), dec),
    )

    class _SingleChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_CHOICE("c", ASN1_INTEGER(0), ASN1F_INTEGER)

    single = _SingleChoice(c=ASN1_INTEGER(3))
    assert raw(single)

    class _FlexChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
            flexible_tag=True,
        )

    flex_choice = _FlexChoice(c=ASN1_INTEGER(4))
    assert raw(flex_choice)

    class _OerPktChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    oer_pkt_choice = _OerPktChoice(c=ASN1_STRING(b"hi"))
    assert raw(oer_pkt_choice)

