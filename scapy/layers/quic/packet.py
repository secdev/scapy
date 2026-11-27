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
from scapy.layers.quic.frame import Frame
from scapy.layers.quic.session import _GenericQUICSessionInheritance

from scapy.fields import (
    BitEnumField,
    BitField,
    FieldLenField,
    FieldListField,
    IntEnumField,
    IntField,
    PacketListField,
    StrLenField,
)


class QUIC(_GenericQUICSessionInheritance):
    name = "QUIC"
    match_subclass = True
    __slots__ = ["client"]

    def __init__(self, *args, client=True, **kwargs):
        # TODO: This should be set according to the direction of the packet
        self.client = client
        super().__init__(*args, **kwargs)

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
            PacketListField(
                "Frames",
                [],
                Frame,
            ),
        ]
    )

    def pre_dissect(self, s):
        unencrypted_packet = bytearray(s)
        s, protected_header = BitField("", 0, 8).getfield(self, s)
        s, quic_version = IntEnumField("", 1, _quic_versions).getfield(self, s)
        s, dst_conn_id_len = FieldLenField("", None, fmt="B").getfield(self, s)
        s, dst_conn_id = StrLenField("", None, length_from=lambda pkt: dst_conn_id_len).getfield(self, s)
        s, src_conn_id_len = FieldLenField("", None, length_of="SrcConnID", fmt="B").getfield(self, s)
        s, src_conn_id = StrLenField("", None, length_from=lambda pkt: src_conn_id_len).getfield(self, s)
        s, token_len = QuicVarLenField("", None).getfield(self, s)
        s, _ = StrLenField("", "", length_from=lambda pkt: token_len).getfield(self, s)
        s, length = QuicVarIntField("", None).getfield(self, s)
        packet_number_offset = len(unencrypted_packet) - len(s)
        s, protected_packet_number = IntField("", None).getfield(self, s)
        _, sample = BitField("", 0, 8*16).getfield(self, s)
        sample = sample.to_bytes(16, 'big')
        protected_packet_number = protected_packet_number.to_bytes(4, 'big')
        # crypto_conn_id = src_conn_id if self.client else dst_conn_id
        crypto_conn_id = dst_conn_id if self.client else src_conn_id
        self.crypto = QUICCrypto(crypto_conn_id, quic_version)
        unprotected_header, raw_packet_number = self.crypto.header_protect(sample, protected_header, protected_packet_number, self.client)
        unencrypted_packet[0] = unprotected_header[0]
        unprotected_header, _ = BitField("", None, 1).getfield(self, unprotected_header)
        unprotected_header, _ = BitField("", None, 1).getfield(self, unprotected_header)
        unprotected_header, _ = BitField("", None, 2).getfield(self, unprotected_header)
        unprotected_header, _ = BitField("", None, 2).getfield(self, unprotected_header)
        unprotected_header, packet_number_len = QuicPacketNumberBitFieldLenField("", None, 2).getfield(self, unprotected_header)
        packet_number_len += 1
        packet_number = raw_packet_number[:packet_number_len]
        unencrypted_packet[packet_number_offset:packet_number_offset + packet_number_len] = packet_number
        plaintext = self.crypto.decrypt_packet(
            is_client=self.client,
            pn=int.from_bytes(packet_number, 'big'),
            recdata=bytes(unencrypted_packet[:packet_number_offset+packet_number_len]),
            ciphertext=bytes(unencrypted_packet[packet_number_offset+packet_number_len:packet_number_offset+length])
        )
        unencrypted_packet[packet_number_offset+packet_number_len:packet_number_offset+length] = plaintext
        return bytes(unencrypted_packet)


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
