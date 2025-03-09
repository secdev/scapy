# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
RFC9000 QUIC Transport Parameters
"""
import struct

from scapy.config import conf
from scapy.fields import (
    PacketListField,
    FieldLenField,
    StrLenField,
)
from scapy.packet import Packet

from scapy.layers.quic import (
    QuicVarIntField,
    QuicVarLenField,
    QuicVarEnumField,
)


_QUIC_TP_type = {
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

# Generic values


class QUIC_TP_Unknown(Packet):
    name = "QUIC Transport Parameter - Scapy Unknown"
    fields_desc = [
        QuicVarEnumField("type", None, _QUIC_TP_type),
        QuicVarLenField("len", None, length_of="value"),
        StrLenField("value", None, length_from=lambda pkt: pkt.len),
    ]

    def default_payload_class(self, _):
        return conf.padding_layer


class _QUIC_VarInt_Len(FieldLenField):
    def i2m(self, pkt, x):
        if x is None and pkt is not None:
            fld, fval = pkt.getfield_and_val(self.length_of)
            value = fld.i2len(pkt, fval) or 0
            if value < 0 or value > 0xFFFFFFFF:
                raise struct.error("requires 0 <= number <= 0xFFFFFFFF")
            if value < 0x100:
                return 1
            elif value < 0x10000:
                return 2
            elif value < 0x100000000:
                return 3
            else:
                return 4
        elif x is None:
            return 1
        return x


class _QUIC_TP_VarIntValue(QUIC_TP_Unknown):
    fields_desc = [
        QuicVarEnumField("type", None, _QUIC_TP_type),
        _QUIC_VarInt_Len("len", None, length_of="value", fmt="B"),
        QuicVarIntField("value", None),
    ]


# RFC 9000 sect 18.2


class QUIC_TP_OriginalDestinationConnectionId(QUIC_TP_Unknown):
    name = "QUIC Transport Parameters - Original Destination Connection Id"
    type = 0x00


class QUIC_TP_MaxIdleTimeout(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Max Idle Timeout"
    type = 0x01


class QUIC_TP_StatelessResetToken(QUIC_TP_Unknown):
    name = "QUIC Transport Parameters - Stateless Reset Token"
    type = 0x02


class QUIC_TP_MaxUdpPayloadSize(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Max Udp Payload Size"
    type = 0x03


class QUIC_TP_InitialMaxData(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Initial Max Data"
    type = 0x04


class QUIC_TP_InitialMaxStreamDataBidiLocal(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Initial Max Stream Data Bidi Local"
    type = 0x05


class QUIC_TP_InitialMaxStreamDataBidiRemote(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Initial Max Stream Data Bidi Remote"
    type = 0x06


class QUIC_TP_InitialMaxStreamDataUni(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Initial Max Stream Data Uni"
    type = 0x07


class QUIC_TP_InitialMaxStreamsBidi(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Initial Max Streams Bidi"
    type = 0x08


class QUIC_TP_InitialMaxStreamsUni(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Initial Max Streams Uni"
    type = 0x09


class QUIC_TP_AckDelayExponent(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Ack Delay Exponent"
    type = 0x0A


class QUIC_TP_MaxAckDelay(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Max Ack Delay"
    type = 0x0B


class QUIC_TP_DisableActiveMigration(QUIC_TP_Unknown):
    name = "QUIC Transport Parameters - Disable Active Migration"
    fields_desc = [
        QuicVarEnumField("type", 0x0C, _QUIC_TP_type),
        QuicVarIntField("len", 0),
    ]


class QUIC_TP_PreferredAddress(QUIC_TP_Unknown):
    name = "QUIC Transport Parameters - Preferred Address"
    type = 0x0D


class QUIC_TP_ActiveConnectionIdLimit(_QUIC_TP_VarIntValue):
    name = "QUIC Transport Parameters - Active Connection Id Limit"
    type = 0x0E


class QUIC_TP_InitialSourceConnectionId(QUIC_TP_Unknown):
    name = "QUIC Transport Parameters - Initial Source Connection Id"
    type = 0x0F


class QUIC_TP_RetrySourceConnectionId(QUIC_TP_Unknown):
    name = "QUIC Transport Parameters - Retry Source Connection Id"
    type = 0x10


_QUIC_TP_cls = {
    0x00: QUIC_TP_OriginalDestinationConnectionId,
    0x01: QUIC_TP_MaxIdleTimeout,
    0x02: QUIC_TP_StatelessResetToken,
    0x03: QUIC_TP_MaxUdpPayloadSize,
    0x04: QUIC_TP_InitialMaxData,
    0x05: QUIC_TP_InitialMaxStreamDataBidiLocal,
    0x06: QUIC_TP_InitialMaxStreamDataBidiRemote,
    0x07: QUIC_TP_InitialMaxStreamDataUni,
    0x08: QUIC_TP_InitialMaxStreamsBidi,
    0x09: QUIC_TP_InitialMaxStreamsUni,
    0x0A: QUIC_TP_AckDelayExponent,
    0x0B: QUIC_TP_MaxAckDelay,
    0x0C: QUIC_TP_DisableActiveMigration,
    0x0D: QUIC_TP_PreferredAddress,
    0x0E: QUIC_TP_ActiveConnectionIdLimit,
    0x0F: QUIC_TP_InitialSourceConnectionId,
    0x10: QUIC_TP_RetrySourceConnectionId,
}


class _QuicTransportParametersField(PacketListField):
    _varfield = QuicVarIntField("", 0)

    def __init__(self, name, default, **kwargs):
        kwargs["next_cls_cb"] = self.cls_from_quictptype
        super(_QuicTransportParametersField, self).__init__(
            name,
            default,
            **kwargs,
        )

    @classmethod
    def cls_from_quictptype(cls, pkt, lst, cur, remain):
        _, typ = cls._varfield.getfield(None, remain)
        return _QUIC_TP_cls.get(
            typ,
            QUIC_TP_Unknown,
        )
