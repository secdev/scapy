# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
RFC9000 QUIC Transport Parameters
"""

from scapy.compat import raw
from scapy.fields import (
    PacketListField,
    Field,
    FieldLenField,
    EnumField,
    StrLenField,
    StrFixedLenField,
)
from scapy.packet import Packet
from typing import Tuple
# from scapy.layers.tls.session import _GenericTLSSessionInheritance


def _quic_m2varint(m: bytes) -> Tuple[int, int]:
    """Decode QUIC variable-length integers"""
    length = 1 << ((m[0] & 0xC0) >> 6)
    if len(m) < length:
        raise ValueError(
            "QUIC variable-length integer decoding expects %d byte(s), "
            "while %d byte(s) given" % (length, len(m))
        )
    mask = (0x40 << (length - 1) * 8) - 1
    return int.from_bytes(m[:length], "big") & mask, length


def _quic_i2mask_len(i: int) -> Tuple[int, int]:
    length = i.bit_length()
    if length <= 6:
        return 0, 1
    elif length <= 14:
        return 0x4000, 2
    elif length <= 30:
        return 0x80000000, 4
    elif length <= 62:
        return 0xC000000000000000, 8
    else:
        raise ValueError(
            "cannot apply QUIC variable-length encoding on integer "
            "with more than 62 bits"
        )


def _quic_i2m(i: int) -> bytes:
    mask, length = _quic_i2mask_len(i)
    return (i | mask).to_bytes(length, "big")


class _QuicVarIntMixin:
    def getfield(self, pkt, s):
        val, val_len = _quic_m2varint(s)
        return s[val_len:], val

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def i2len(self, pkt, x):
        return _quic_i2mask_len(x)[1]


class QuicVarIntField(_QuicVarIntMixin, Field):
    def i2m(self, pkt, x):
        return _quic_i2m(super(QuicVarIntField, self).i2m(pkt, x))


class QuicVarLenField(_QuicVarIntMixin, FieldLenField):
    def i2m(self, pkt, x):
        return _quic_i2m(super(QuicVarLenField, self).i2m(pkt, x))


class QuicVarEnumField(_QuicVarIntMixin, EnumField):
    def i2m(self, pkt, x):
        return _quic_i2m(super(QuicVarEnumField, self).i2m(pkt, x))


_quic_tp_type = {
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0D: "preferred_address",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
}


class Quic_Tp_Unknown(Packet):
    name = "QUIC Transport Parameter - Scapy Unknown"
    fields_desc = [
        QuicVarEnumField("type", None, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        StrLenField("value", None, length_from=lambda pkt: pkt.len),
    ]


class Quic_Tp_OriginalDestinationConnectionId(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Original Destination Connection Id"
    fields_desc = [
        QuicVarEnumField("type", 0x00, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        StrLenField("value", None, length_from=lambda pkt: pkt.len),
    ]


class Quic_Tp_MaxIdleTimeout(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Max Idle Timeout"
    fields_desc = [
        QuicVarEnumField("type", 0x01, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_StatelessResetToken(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Stateless Reset Token"
    fields_desc = [
        QuicVarEnumField("type", 0x02, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        StrFixedLenField("value", None, 16),
    ]


class Quic_Tp_MaxUdpPayloadSize(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Max Udp Payload Size"
    fields_desc = [
        QuicVarEnumField("type", 0x03, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialMaxData(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Max Data"
    fields_desc = [
        QuicVarEnumField("type", 0x04, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialMaxStreamDataBidiLocal(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Max Stream Data Bidi Local"
    fields_desc = [
        QuicVarEnumField("type", 0x05, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialMaxStreamDataBidiRemote(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Max Stream Data Bidi Remote"
    fields_desc = [
        QuicVarEnumField("type", 0x06, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialMaxStreamDataUni(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Max Stream Data Uni"
    fields_desc = [
        QuicVarEnumField("type", 0x07, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialMaxStreamsBidi(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Max Streams Bidi"
    fields_desc = [
        QuicVarEnumField("type", 0x08, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialMaxStreamsUni(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Max Streams Uni"
    fields_desc = [
        QuicVarEnumField("type", 0x09, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_AckDelayExponent(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Ack Delay Exponent"
    fields_desc = [
        QuicVarEnumField("type", 0x0A, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_MaxAckDelay(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Max Ack Delay"
    fields_desc = [
        QuicVarEnumField("type", 0x0B, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_DisableActiveMigration(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Disable Active Migration"
    fields_desc = [
        QuicVarEnumField("type", 0x0C, _quic_tp_type),
        QuicVarIntField("len", 0),
    ]


class Quic_Tp_PreferredAddress(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Preferred Address"
    fields_desc = [
        QuicVarEnumField("type", 0x0D, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        StrLenField("value", None, length_from=lambda pkt: pkt.len),
    ]


class Quic_Tp_ActiveConnectionIdLimit(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Active Connection Id Limit"
    fields_desc = [
        QuicVarEnumField("type", 0x0E, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        QuicVarIntField("value", None),
    ]


class Quic_Tp_InitialSourceConnectionId(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Initial Source Connection Id"
    fields_desc = [
        QuicVarEnumField("type", 0x0F, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        StrLenField("value", None, length_from=lambda pkt: pkt.len),
    ]


class Quic_Tp_RetrySourceConnectionId(Quic_Tp_Unknown):
    name = "QUIC Transport Parameters - Retry Source Connection Id"
    fields_desc = [
        QuicVarEnumField("type", 0x10, _quic_tp_type),
        QuicVarLenField("len", None, length_of="value"),
        StrLenField("value", None, length_from=lambda pkt: pkt.len),
    ]


_quic_tp_cls = {
    0x00: Quic_Tp_OriginalDestinationConnectionId,
    0x01: Quic_Tp_MaxIdleTimeout,
    0x02: Quic_Tp_StatelessResetToken,
    0x03: Quic_Tp_MaxUdpPayloadSize,
    0x04: Quic_Tp_InitialMaxData,
    0x05: Quic_Tp_InitialMaxStreamDataBidiLocal,
    0x06: Quic_Tp_InitialMaxStreamDataBidiRemote,
    0x07: Quic_Tp_InitialMaxStreamDataUni,
    0x08: Quic_Tp_InitialMaxStreamsBidi,
    0x09: Quic_Tp_InitialMaxStreamsUni,
    0x0A: Quic_Tp_AckDelayExponent,
    0x0B: Quic_Tp_MaxAckDelay,
    0x0C: Quic_Tp_DisableActiveMigration,
    0x0D: Quic_Tp_PreferredAddress,
    0x0E: Quic_Tp_ActiveConnectionIdLimit,
    0x0F: Quic_Tp_InitialSourceConnectionId,
    0x10: Quic_Tp_RetrySourceConnectionId,
}


class _QuicTransportParametersField(PacketListField):
    def m2i(self, pkt, m):
        res = []
        while len(m) >= 2:
            ty, ty_len = _quic_m2varint(m)
            vl, vl_len = _quic_m2varint(m[ty_len:])
            pay_len = ty_len + vl_len + vl
            cls = _quic_tp_cls.get(ty, Quic_Tp_Unknown)
            res.append(cls(m[:pay_len]))
            m = m[pay_len:]
        return res

    def getfield(self, pkt, s):
        tmp_len = self.length_from(pkt) or 0
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])

    def i2m(self, pkt, i):
        if i is None:
            return b""
        else:
            return b"".join(map(raw, i))
