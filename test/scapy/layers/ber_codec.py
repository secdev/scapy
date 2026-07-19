# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
BER codec and helper coverage tests.
"""

from typing import Any


def _raises(exc, func):
    # type: (type, Any) -> None
    try:
        func()
    except exc:
        return
    raise AssertionError("Expected %s" % exc.__name__)


from scapy.asn1.asn1 import (
    ASN1_Class_UNIVERSAL,
    ASN1_DECODING_ERROR,
    ASN1_INTEGER,
    ASN1_Object,
)
from scapy.asn1.ber import (
    BER_BadTag_Decoding_Error,
    BER_Decoding_Error,
    BER_Encoding_Error,
    BER_Exception,
    BER_id_dec,
    BER_id_enc,
    BER_len_dec,
    BER_len_enc,
    BER_num_dec,
    BER_num_enc,
    BER_tagging_dec,
    BER_tagging_enc,
    BERcodec_BIT_STRING,
    BERcodec_INTEGER,
    BERcodec_IPADDRESS,
    BERcodec_NULL,
    BERcodec_Object,
    BERcodec_OID,
    BERcodec_SEQUENCE,
    BERcodec_SET,
    BERcodec_STRING,
)
from scapy.config import conf


def check_ber_error_str():
    # type: () -> None
    obj = ASN1_INTEGER(1)
    enc_err = BER_Encoding_Error("enc", encoded=obj, remaining=b"rest")
    assert "Already encoded" in str(enc_err)
    enc_err2 = BER_Encoding_Error("enc", encoded="raw", remaining=b"")
    assert "raw" in str(enc_err2)

    dec_err = BER_Decoding_Error("dec", decoded=obj, remaining=b"tail")
    assert "Already decoded" in str(dec_err)
    dec_err2 = BER_Decoding_Error("dec", decoded=[1], remaining=b"")
    assert "[1]" in str(dec_err2)


def check_ber_len_enc_dec():
    # type: () -> None
    for value in [0, 1, 127, 128, 999]:
        encoded = BER_len_enc(value)
        length, remain = BER_len_dec(encoded)
        assert length == value
        assert remain == b""

    assert BER_len_enc(45, size=None) == BER_len_enc(45, size=0)
    assert BER_len_enc(45, size=4) == b"\x84\x00\x00\x00-"

    _raises(BER_Exception, lambda: BER_len_enc(0, size=128))

    _raises(BER_Decoding_Error, lambda: BER_len_dec(b"\x82"))


def check_ber_num_enc_dec():
    # type: () -> None
    for value in [0, 1, 127, 256, 16384]:
        encoded = BER_num_enc(value)
        decoded, remain = BER_num_dec(encoded)
        assert decoded == value
        assert remain == b""

    _raises(BER_Decoding_Error, lambda: BER_num_dec(b""))

    _raises(BER_Decoding_Error, lambda: BER_num_dec(b"\x80\x80"))


def check_ber_id_enc_dec():
    # type: () -> None
    for tag in [0x02, 0x30, 0x81, 0xA0]:
        encoded = BER_id_enc(tag)
        decoded, remain = BER_id_dec(encoded)
        assert decoded == tag
        assert remain == b""

    high_tag = (0x03 << 5) + 0x22
    encoded = BER_id_enc(high_tag)
    decoded, remain = BER_id_dec(encoded)
    assert decoded == high_tag
    assert remain == b""


def check_ber_tagging():
    # type: () -> None
    inner = BERcodec_INTEGER.enc(7)
    implicit = BER_tagging_enc(inner, implicit_tag=0xA0)
    assert implicit.startswith(b"\xa0")
    real_tag, payload = BER_tagging_dec(
        implicit,
        hidden_tag=ASN1_Class_UNIVERSAL.INTEGER,
        implicit_tag=0xA0,
    )
    assert real_tag is None
    assert payload[0] == int(ASN1_Class_UNIVERSAL.INTEGER)

    conf.ASN1_default_long_size = 4
    try:
        explicit = BER_tagging_enc(inner, explicit_tag=0xA1)
        assert explicit.startswith(b"\xa1\x84")
        real_tag, payload = BER_tagging_dec(
            explicit,
            explicit_tag=0xA1,
        )
        assert real_tag is None
        assert payload == inner
    finally:
        conf.ASN1_default_long_size = 0

    _raises(BER_Decoding_Error, lambda: BER_tagging_dec(
        implicit,
        hidden_tag=ASN1_Class_UNIVERSAL.INTEGER,
        implicit_tag=0xA1,
    ))

    safe_tag, _ = BER_tagging_dec(
        implicit,
        hidden_tag=ASN1_Class_UNIVERSAL.INTEGER,
        implicit_tag=0xA1,
        safe=True,
    )
    assert safe_tag == 0xA0


def check_ber_integer():
    # type: () -> None
    for value in [0, 1, 127, 128, 255, -1, -128, -129]:
        encoded = BERcodec_INTEGER.enc(value)
        obj, remain = BERcodec_INTEGER.do_dec(encoded)
        assert obj.val == value
        assert remain == b""

    _raises(BER_BadTag_Decoding_Error, lambda: BERcodec_INTEGER.do_dec(BERcodec_STRING.enc(b"x")))

    _raises(BER_Decoding_Error, lambda: BERcodec_INTEGER.check_type_get_len(b"\x02"))


def check_ber_bit_string():
    # type: () -> None
    encoded = BERcodec_BIT_STRING.enc("1011")
    obj, remain = BERcodec_BIT_STRING.do_dec(encoded)
    assert obj.val == "1011"
    assert remain == b""

    padded = BERcodec_BIT_STRING.enc("10110000")
    obj2, _ = BERcodec_BIT_STRING.do_dec(padded)
    assert obj2.val == "10110000"

    _raises(BER_Decoding_Error, lambda: BERcodec_BIT_STRING.do_dec(b"\x03\x01\x08", safe=True))

    _raises(BER_Decoding_Error, lambda: BERcodec_BIT_STRING.do_dec(b"\x03\x00"))


def check_ber_string_and_null():
    # type: () -> None
    encoded = BERcodec_STRING.enc(b"hello")
    obj, remain = BERcodec_STRING.do_dec(encoded)
    assert obj.val == b"hello"
    assert remain == b""

    null = BERcodec_NULL.enc(0)
    assert null == b"\x05\x00"
    obj, remain = BERcodec_NULL.do_dec(null)
    assert obj.val == 0

    non_null = BERcodec_NULL.enc(42)
    obj, remain = BERcodec_NULL.do_dec(non_null)
    assert obj.val == 42


def check_ber_oid():
    # type: () -> None
    encoded = BERcodec_OID.enc("1.2.840.113556.1.4.529")
    obj, remain = BERcodec_OID.do_dec(encoded)
    assert obj.val == "1.2.840.113556.1.4.529"
    assert remain == b""

    empty, remain = BERcodec_OID.do_dec(BERcodec_OID.enc(""))
    assert empty.val == ""
    assert remain == b""


def check_ber_sequence_and_set():
    # type: () -> None
    payload = BERcodec_INTEGER.enc(1) + BERcodec_INTEGER.enc(2)
    seq = BERcodec_SEQUENCE.enc(payload)
    obj, remain = BERcodec_SEQUENCE.do_dec(seq)
    assert len(obj.val) == 2
    assert obj.val[0].val == 1
    assert obj.val[1].val == 2
    assert remain == b""

    as_list = BERcodec_SEQUENCE.enc([ASN1_INTEGER(3), ASN1_INTEGER(4)])
    obj2, remain2 = BERcodec_SEQUENCE.do_dec(as_list)
    assert [x.val for x in obj2.val] == [3, 4]
    assert remain2 == b""

    st = BERcodec_SET.enc(payload)
    obj3, remain3 = BERcodec_SET.do_dec(st)
    assert len(obj3.val) == 2
    assert remain3 == b""

    conf.ASN1_default_long_size = 4
    try:
        long_seq = BERcodec_SEQUENCE.enc(payload)
        assert long_seq.startswith(b"0\x84")
    finally:
        conf.ASN1_default_long_size = 0

    _raises(BER_Decoding_Error, lambda: BERcodec_SEQUENCE.do_dec(b"\x30\x05" + BERcodec_INTEGER.enc(1)))


def check_ber_ipaddress():
    # type: () -> None
    encoded = BERcodec_IPADDRESS.enc("192.168.0.1")
    obj, remain = BERcodec_IPADDRESS.do_dec(encoded)
    assert obj.val == "192.168.0.1"
    assert remain == b""

    _raises(BER_Encoding_Error, lambda: BERcodec_IPADDRESS.enc("not-an-ip"))

    _raises(BER_Decoding_Error, lambda: BERcodec_IPADDRESS.do_dec(BERcodec_STRING.enc(b"bad")))


def check_ber_object_dispatch():
    # type: () -> None
    encoded = BERcodec_INTEGER.enc(99)
    obj, remain = BERcodec_Object.do_dec(encoded)
    assert obj.val == 99
    assert remain == b""

    _raises(BER_Decoding_Error, lambda: BERcodec_Object.check_string(b""))

    _raises(BER_Decoding_Error, lambda: BERcodec_Object.do_dec(b"\xff\x00"))

    bad, remain = BERcodec_Object.safedec(b"\x02\x01\x01")
    assert isinstance(bad, ASN1_INTEGER)
    assert bad.val == 1

    unknown, remain = BERcodec_Object.safedec(b"\xff\x00")
    assert isinstance(unknown, ASN1_DECODING_ERROR)

    truncated, remain = BERcodec_Object.dec(b"\x02\x05\x01", safe=True)
    assert isinstance(truncated, ASN1_DECODING_ERROR)
    assert remain == b""

    _raises(TypeError, lambda: BERcodec_Object.enc(object()))
    assert BERcodec_Object.enc("42") == BERcodec_STRING.enc("42")
