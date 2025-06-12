# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
QUIC

The draft of a very basic implementation of the structures from [RFC 9000].
This isn't binded to UDP by default as currently too incomplete.

TODO:
- payloads.
- encryption.
- automaton.
- etc.
"""
from scapy.layers.quic.basefields import (
    _quic_long_hdr,
    _quic_long_pkttyp,
    _quic_versions,
    QuicVarIntField,
    QuicVarLenField,
    QuicPacketNumberBitFieldLenField,
    QuicPacketNumberField,
)

from scapy.layers.quic.crypto import QUICCrypto
from scapy.packet import (
    Packet,
)

from scapy.fields import (
    BitEnumField,
    BitField,
    FieldLenField,
    FieldListField,
    IntEnumField,
    IntField,
    StrLenField,
)


class QUIC(Packet):
    match_subclass = True

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """
        if _pkt:
            hdr = _pkt[0]
            if hdr & 0x80:
                # Long Header packets
                return QUIC_Long.dispatch_hook(_pkt, *args, **kargs)
            else:
                # Short Header packets
                return QUIC_1RTT
        return None

    def mysummary(self):
        return self.name
    
class QUIC_Long(QUIC):
    """
    Base class for QUIC Long Header packets.
    """
    name = "QUIC - Long Header"
    fields_desc = [
        BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
        BitField("FixedBit", 1, 1),
        BitEnumField("LongPacketType", None, 2, _quic_long_pkttyp),
        BitField("TypeSpecific", None, 4),
        IntEnumField("Version", 1, _quic_versions),
        FieldLenField("DstConnIDLen", None, length_of="DstConnID", fmt="B"),
        StrLenField("DstConnID", "", length_from=lambda pkt: pkt.DstConnIDLen),
        FieldLenField("SrcConnIDLen", None, length_of="SrcConnID", fmt="B"),
        StrLenField("SrcConnID", "", length_from=lambda pkt: pkt.SrcConnIDLen),
    ]


    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """
        if _pkt:
            if _pkt[1:5] == b"\x00\x00\x00\x00":
                # Version Negotiation packet
                return QUIC_Version
            hdr = _pkt[0]
            typ = (hdr & 0x30) >> 4
            return {
                0: QUIC_Initial,
                1: QUIC_0RTT,
                2: QUIC_Handshake,
                3: QUIC_Retry,
            }[typ]

# RFC9000 sect 17.2.1


class QUIC_Version(QUIC):
    name = "QUIC - Version Negotiation"
    fields_desc = (
        [
            QUIC_Long.fields_desc[0],
            BitField("Unused", None, 7),
        ]
        + QUIC_Long.fields_desc[4:9]
        + [
            FieldListField("SupportedVersions", [], IntField("", 0)),
        ]
    )



class QUIC_Initial(QUIC_Long):
    name = "QUIC - Initial"
    LongPacketType = 0
    fields_desc = (
        QUIC_Long.fields_desc[:3]
        + [
            BitField("Reserved", 0, 2),
            QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        ]
        + QUIC_Long.fields_desc[4:9]
        + [
            QuicVarLenField("TokenLen", None, length_of="Token"),
            StrLenField("Token", "", length_from=lambda pkt: pkt.TokenLen),
            QuicVarIntField("Length", 0),
            QuicPacketNumberField("PacketNumber", 0),
        ]
    )

    def pre_dissect(self, s):
        _, protected_header = BitField("", 0, 8).getfield(self, s)
        _, quic_version = IntEnumField("", 1, _quic_versions).getfield(self, s)
        _, dst_conn_id_len = FieldLenField("", None, fmt="B").getfield(self, s)
        _, dst_connd_id = StrLenField("", None, length_from=lambda pkt: dst_conn_id_len).getfield(self, s)
        _, src_conn_id_len = FieldLenField("", None, length_of="SrcConnID", fmt="B").getfield(self, s)
        _, _ = StrLenField("", None, length_from=lambda pkt: src_conn_id_len).getfield(self, s)
        token_len = QuicVarLenField("").getfield(self, s)
        _token = StrLenField("", "", length_from=lambda pkt: token_len).getfield(self, s)
        _length = QuicVarIntField("", None).getfield(self, s)
        protected_packet_number = IntField("", None).getfield(self, s)
        sample = BitField("", 0, 8*16).getfield(self, s)

        self.crypto = QUICCrypto(dst_connd_id, quic_version)
        unprotected_header, raw_packet_number = self.crypto.header_protect(sample, protected_header, protected_packet_number)
        return s

    def post_dissect(self, s):
        """
        Post-dissection hook to handle the payload.
        """
        self.crypto = QUICCrypto(self.DstConnID, self.Version)
        sample = s[4:4+16]
        unprotected_header, raw_packet_number = self.crypto.header_protect(sample, self.ProtectedHeader, s[0:4])
        self.fields_desc.append()
        return s


# RFC9000 sect 17.2.3
class QUIC_0RTT(QUIC_Long):
    name = "QUIC - 0-RTT"
    LongPacketType = 1
    fields_desc = (
        QUIC_Long.fields_desc[:3]
        + [
            BitField("Reserved", None, 2),
            QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        ]
        + QUIC_Long.fields_desc[4:9]
        + [
            QuicVarIntField("Length", 0),
            QuicPacketNumberField("PacketNumber", 0),
        ]
    )


# RFC9000 sect 17.2.4
class QUIC_Handshake(QUIC_Long):
    name = "QUIC - Handshake"
    LongPacketType = 2
    fields_desc = (
        QUIC_Long.fields_desc[:3]
        + [
            BitField("Reserved", None, 2),
            QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        ]
        + QUIC_Long.fields_desc[4:9]
        + [
            QuicVarIntField("Length", 0),
            QuicPacketNumberField("PacketNumber", 0),
        ]
    )


# RFC9000 sect 17.2.5
class QUIC_Retry(QUIC_Long):
    name = "QUIC - Retry"
    fields_desc = (
        QUIC_Long.fields_desc[:3]
        + [
            BitField("Unused", 0, 4),
        ]
        + [QUIC_Long.fields_desc[4]]
    )


# RFC9000 sect 17.3
class QUIC_1RTT(QUIC):
    name = "QUIC - 1-RTT"
    fields_desc = [
        BitEnumField("HeaderForm", 0, 1, _quic_long_hdr),
        BitField("FixedBit", 1, 1),
        BitField("SpinBit", 0, 1),
        BitField("Reserved", 0, 2),
        BitField("KeyPhase", 0, 1),
        QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        # FIXME - Destination Connection ID
        QuicPacketNumberField("PacketNumber", 0),
    ]

# Bindings
# bind_bottom_up(UDP, QUIC, dport=443)
# bind_bottom_up(UDP, QUIC, sport=443)
# bind_layers(UDP, QUIC, dport=443, sport=443)
