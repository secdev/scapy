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

import struct

from scapy.packet import (
    Packet,
)
from scapy.fields import (
    _EnumField,
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    EnumField,
    Field,
    FieldLenField,
    FieldListField,
    IntField,
    MultipleTypeField,
    ShortField,
    StrLenField,
    ThreeBytesField,
)

# Typing imports
from typing import (
    Any,
    Optional,
    Tuple,
)

# RFC9000 table 3
_quic_payloads = {
    0x00: "PADDING",
    0x01: "PING",
    0x02: "ACK",
    0x04: "RESET_STREAM",
    0x05: "STOP_SENDING",
    0x06: "CRYPTO",
    0x07: "NEW_TOKEN",
    0x08: "STREAM",
    0x10: "MAX_DATA",
    0x11: "MAX_STREAM_DATA",
    0x12: "MAX_STREAMS",
    0x14: "DATA_BLOCKED",
    0x15: "STREAM_DATA_BLOCKED",
    0x16: "STREAMS_BLOCKED",
    0x18: "NEW_CONNECTION_ID",
    0x19: "RETIRE_CONNECTION_ID",
    0x1A: "PATH_CHALLENGE",
    0x1B: "PATH_RESPONSE",
    0x1C: "CONNECTION_CLOSE",
    0x1E: "HANDSHAKE_DONE",
}


# RFC9000 sect 16
class QuicVarIntField(Field[int, int]):
    def addfield(self, pkt: Packet, s: bytes, val: Optional[int]):
        val = self.i2m(pkt, val)
        if val < 0 or val > 0x3FFFFFFFFFFFFFFF:
            raise struct.error("requires 0 <= number <= 4611686018427387903")
        if val < 0x40:
            return s + struct.pack("!B", val)
        elif val < 0x4000:
            return s + struct.pack("!H", val | 0x4000)
        elif val < 0x40000000:
            return s + struct.pack("!I", val | 0x80000000)
        else:
            return s + struct.pack("!Q", val | 0xC000000000000000)

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, int]:
        length = (s[0] & 0xC0) >> 6
        if length == 0:
            return s[1:], struct.unpack("!B", s[:1])[0] & 0x3F
        elif length == 1:
            return s[2:], struct.unpack("!H", s[:2])[0] & 0x3FFF
        elif length == 2:
            return s[4:], struct.unpack("!I", s[:4])[0] & 0x3FFFFFFF
        elif length == 3:
            return s[8:], struct.unpack("!Q", s[:8])[0] & 0x3FFFFFFFFFFFFFFF
        else:
            raise Exception("Impossible.")


class QuicVarLenField(FieldLenField, QuicVarIntField):
    pass


class QuicVarEnumField(QuicVarIntField, _EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Any, int) -> None
        _EnumField.__init__(self, name, default, enum)  # type: ignore
        QuicVarIntField.__init__(self, name, default)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        return _EnumField.any2i(self, pkt, x)  # type: ignore

    def i2repr(
        self,
        pkt,  # type: Optional[Packet]
        x,  # type: int
    ):
        # type: (...) -> Any
        return _EnumField.i2repr(self, pkt, x)


# -- Headers --


# RFC9000 sect 17.2
_quic_long_hdr = {
    0: "Short",
    1: "Long",
}

_quic_long_pkttyp = {
    # RFC9000 table 5
    0x00: "Initial",
    0x01: "0-RTT",
    0x02: "Handshake",
    0x03: "Retry",
}

# RFC9000 sect 17 abstraction


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
                if hdr & 0x40 == 0:
                    return QUIC_Version
                else:
                    typ = (hdr & 0x30) >> 4
                    return {
                        0: QUIC_Initial,
                        1: QUIC_0RTT,
                        2: QUIC_Handshake,
                        3: QUIC_Retry,
                    }[typ]
            else:
                # Short Header packets
                return QUIC_1RTT
        return QUIC_Initial

    def mysummary(self):
        return self.name


# RFC9000 sect 17.2.1


class QUIC_Version(QUIC):
    name = "QUIC - Version Negotiation"
    fields_desc = [
        BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
        BitField("Unused", 0, 7),
        IntField("Version", 0),
        FieldLenField("DstConnIDLen", None, length_of="DstConnID", fmt="B"),
        StrLenField("DstConnID", "", length_from=lambda pkt: pkt.DstConnIDLen),
        FieldLenField("SrcConnIDLen", None, length_of="SrcConnID", fmt="B"),
        StrLenField("SrcConnID", "", length_from=lambda pkt: pkt.SrcConnIDLen),
        FieldListField("SupportedVersions", [], IntField("", 0)),
    ]


# RFC9000 sect 17.2.2

QuicPacketNumberField = lambda name, default: MultipleTypeField(
    [
        (
            ByteField(name, default),
            (
                lambda pkt: pkt.PacketNumberLen == 0,
                lambda _, val: val < 0x100,
            ),
        ),
        (
            ShortField(name, default),
            (
                lambda pkt: pkt.PacketNumberLen == 1,
                lambda _, val: val < 0x10000,
            ),
        ),
        (
            ThreeBytesField(name, default),
            (
                lambda pkt: pkt.PacketNumberLen == 2,
                lambda _, val: val < 0x1000000,
            ),
        ),
        (
            IntField(name, default),
            (
                lambda pkt: pkt.PacketNumberLen == 3,
                lambda _, val: val < 0x100000000,
            ),
        ),
    ],
    ByteField(name, default),
)


class QuicPacketNumberBitFieldLenField(BitField):
    def i2m(self, pkt, x):
        if x is None and pkt is not None:
            PacketNumber = pkt.PacketNumber or 0
            if PacketNumber < 0 or PacketNumber > 0xFFFFFFFF:
                raise struct.error("requires 0 <= number <= 0xFFFFFFFF")
            if PacketNumber < 0x100:
                return 0
            elif PacketNumber < 0x10000:
                return 1
            elif PacketNumber < 0x1000000:
                return 2
            else:
                return 3
        elif x is None:
            return 0
        return x


class QUIC_Initial(QUIC):
    name = "QUIC - Initial"
    Version = 0x00000001
    fields_desc = (
        [
            BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
            BitField("FixedBit", 1, 1),
            BitEnumField("LongPacketType", 0, 2, _quic_long_pkttyp),
            BitField("Reserved", 0, 2),
            QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        ]
        + QUIC_Version.fields_desc[2:7]
        + [
            QuicVarLenField("TokenLen", None, length_of="Token"),
            StrLenField("Token", "", length_from=lambda pkt: pkt.TokenLen),
            QuicVarIntField("Length", 0),
            QuicPacketNumberField("PacketNumber", 0),
        ]
    )


# RFC9000 sect 17.2.3
class QUIC_0RTT(QUIC):
    name = "QUIC - 0-RTT"
    LongPacketType = 1
    fields_desc = QUIC_Initial.fields_desc[:10] + [
        QuicVarIntField("Length", 0),
        QuicPacketNumberField("PacketNumber", 0),
    ]


# RFC9000 sect 17.2.4
class QUIC_Handshake(QUIC):
    name = "QUIC - Handshake"
    LongPacketType = 2
    fields_desc = QUIC_0RTT.fields_desc


# RFC9000 sect 17.2.5
class QUIC_Retry(QUIC):
    name = "QUIC - Retry"
    LongPacketType = 3
    Version = 0x00000001
    fields_desc = (
        QUIC_Initial.fields_desc[:3]
        + [
            BitField("Unused", 0, 4),
        ]
        + QUIC_Version.fields_desc[2:7]
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


# RFC9000 sect 19.1
class QUIC_PADDING(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x00, _quic_payloads),
    ]


# RFC9000 sect 19.2
class QUIC_PING(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x01, _quic_payloads),
    ]


# RFC9000 sect 19.3
class QUIC_ACK(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x02, _quic_payloads),
    ]


# Bindings
# bind_bottom_up(UDP, QUIC, dport=443)
# bind_bottom_up(UDP, QUIC, sport=443)
# bind_layers(UDP, QUIC, dport=443, sport=443)
