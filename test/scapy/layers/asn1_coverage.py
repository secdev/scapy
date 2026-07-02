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

from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_Codecs,
    ASN1_INTEGER,
    ASN1_STRING,
    ASN1_TIME_TICKS,
)
from scapy.asn1.oer import (
    OER_Decoding_Error,
    OER_Encoding_Error,
    OERcodec_BIT_STRING,
    OERcodec_IPADDRESS,
    OERcodec_SEQUENCE,
    OERcodec_SET,
)
from scapy.asn1.uper import (
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
    ASN1F_BIT_STRING_ENCAPS,
    ASN1F_CHOICE,
    ASN1F_FLAGS,
    ASN1F_IPADDRESS,
    ASN1F_INTEGER,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SET_OF,
    ASN1F_STRING,
    ASN1F_STRING_ENCAPS,
    ASN1F_STRING_PacketField,
    ASN1F_TIME_TICKS,
    ASN1F_enum_INTEGER,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import raw


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
