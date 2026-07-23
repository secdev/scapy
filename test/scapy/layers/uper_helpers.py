# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER low-level helper and bitstream tests.
"""

from scapy.asn1.uper import (
    UPER_Decoder,
    UPER_Encoder,
    UPER_choice_index_dec,
    UPER_choice_index_enc,
    UPER_constrained_int_dec,
    UPER_constrained_int_enc,
    UPER_count_dec,
    UPER_count_enc,
    UPER_has_unexpected_remainder,
    UPER_join_encodings,
    UPER_octet_string_dec,
    UPER_octet_string_enc,
    UPER_optional_presence_enc,
    UPERcodec_INTEGER,
)


def check_uper_length_determinant():
    # type: () -> None
    for length, expected in [
        (0, b"\x00"),
        (1, b"\x01"),
        (127, b"\x7f"),
        (128, b"\x80\x80"),
        (16383, b"\xbf\xff"),
        (16384, b"\xc1"),
    ]:
        enc = UPER_Encoder()
        enc.append_length_determinant(length)
        assert enc.as_bytes() == expected


def check_uper_count_roundtrip():
    # type: () -> None
    for count in [0, 1, 3, 127]:
        enc = UPER_Encoder()
        UPER_count_enc(count, enc=enc)
        got, _ = UPER_count_dec(enc.as_bytes())
        assert got == count


def check_uper_choice_index_roundtrip():
    # type: () -> None
    for index, choices in [(0, 2), (1, 5), (3, 5)]:
        enc = UPER_Encoder()
        UPER_choice_index_enc(index, choices, enc=enc)
        got, _ = UPER_choice_index_dec(enc.as_bytes(), choices)
        assert got == index


def check_uper_optional_presence():
    # type: () -> None
    enc = UPER_Encoder()
    UPER_optional_presence_enc([0, 1, 0], enc=enc)
    assert enc.as_bytes() == b"\x40"


def check_uper_constrained_integer():
    # type: () -> None
    data = UPER_constrained_int_enc(10, 0, 15)
    value, remain = UPER_constrained_int_dec(data, 0, 15)
    assert value == 10
    assert remain == b""


def check_uper_constrained_signed_integer():
    # type: () -> None
    for value, expected in [(0, b"\x80"), (-1, b"\x7f"), (127, b"\xff"), (-128, b"\x00")]:
        data = UPER_constrained_int_enc(value, -128, 127)
        assert data == expected
        decoded, remain = UPER_constrained_int_dec(data, -128, 127)
        assert decoded == value
        assert remain == b""


def check_uper_octet_string_roundtrip():
    # type: () -> None
    for data, minimum, maximum in [
        (b"AB", None, None),
        (b"\x12\x34\x56", 3, 3),
        (bytes.fromhex("afbc4583"), 1, 20),
    ]:
        encoded = UPER_octet_string_enc(data, minimum, maximum)
        dec = UPER_Decoder(encoded)
        decoded, _ = UPER_octet_string_dec(encoded, minimum, maximum, dec=dec)
        assert decoded == data
        assert not UPER_has_unexpected_remainder(dec)


def check_uper_has_unexpected_remainder():
    # type: () -> None
    assert UPER_has_unexpected_remainder(UPER_Decoder(b"\x00")) is False
    assert UPER_has_unexpected_remainder(UPER_Decoder(b"\x80")) is True


def check_uper_join_encodings():
    # type: () -> None
    a = UPERcodec_INTEGER.enc(1)
    b = UPERcodec_INTEGER.enc(2)
    joined = UPER_join_encodings(a, b)
    dec = UPER_Decoder(joined)
    assert dec.read_unconstrained_whole_number() == 1
    assert dec.read_unconstrained_whole_number() == 2


def check_uper_chained_encode_into():
    # type: () -> None
    enc = UPER_Encoder()
    UPERcodec_INTEGER.encode_into(enc, 42)
    UPERcodec_INTEGER.encode_into(enc, -7)
    dec = UPER_Decoder(enc.as_bytes())
    assert dec.read_unconstrained_whole_number() == 42
    assert dec.read_unconstrained_whole_number() == -7
