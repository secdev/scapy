# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Zenoh Protocol
# scapy.contrib.status = loads

"""
Zenoh protocol for Scapy.

Implements the zenoh 1.0 wire format for publish/subscribe/query
communication in IoT and edge computing environments.

Default ports:
- UDP 7446: scouting (multicast peer discovery)
- UDP/TCP 7447: data transport

References:
- https://zenoh.io/
- https://github.com/eclipse-zenoh/zenoh
"""

from scapy.compat import chb, orb
from scapy.config import conf
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    ConditionalField,
    Field,
    LELongField,
    LEShortField,
    PacketListField,
    StrLenField,
)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_layers
from scapy.volatile import RandNum

# ============================================================================
# Custom Fields
# ============================================================================


class ZenohVarIntField(Field):
    """Variable-length integer field (zenoh varint encoding).

    Uses little-endian 7-bit groups: each byte contributes 7 bits,
    bit 7 (MSB) of each byte indicates more bytes follow.

    Example: 300 decimal (0x12C):
      byte 0: (0x12C & 0x7F) | 0x80 = 0xAC  (more bytes follow)
      byte 1: 0x12C >> 7      = 0x02  (last byte)
    Wire representation: [0xAC, 0x02]
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def addfield(self, pkt, s, val):
        if val is None:
            val = 0
        data = bytearray()
        while val > 0x7F:
            data.append((val & 0x7F) | 0x80)
            val >>= 7
        data.append(val & 0x7F)
        return s + bytes(data)

    def getfield(self, pkt, s):
        value = 0
        shift = 0
        for i in range(len(s)):
            b = orb(s[i])
            value |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                return s[i + 1:], value
        return b"", value

    def i2repr(self, pkt, val):
        return repr(val)

    def randval(self):
        return RandNum(0, 0xFFFF)


class ZenohIDField(Field):
    """Zenoh node ID field.

    Wire format: 1-byte length prefix followed by the ID bytes (0-16 bytes).
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def addfield(self, pkt, s, val):
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode()
        return s + chb(len(val)) + val

    def getfield(self, pkt, s):
        if not s:
            return b"", b""
        length = orb(s[0])
        return s[1 + length:], s[1:1 + length]

    def i2repr(self, pkt, val):
        if isinstance(val, bytes):
            return val.hex()
        return ""

    def i2h(self, pkt, val):
        return val if val is not None else b""

    def h2i(self, pkt, val):
        if isinstance(val, str):
            try:
                return bytes.fromhex(val)
            except ValueError:
                return val.encode()
        return val if val is not None else b""


class ZenohBytesField(Field):
    """Variable-length bytes field with VarInt length prefix.

    Used for cookie and payload fields in zenoh messages.
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def _encode_varint(self, val):
        data = bytearray()
        while val > 0x7F:
            data.append((val & 0x7F) | 0x80)
            val >>= 7
        data.append(val & 0x7F)
        return bytes(data)

    def _decode_varint(self, s):
        value = 0
        shift = 0
        for i in range(len(s)):
            b = orb(s[i])
            value |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                return value, i + 1
        return 0, 0

    def addfield(self, pkt, s, val):
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode()
        return s + self._encode_varint(len(val)) + val

    def getfield(self, pkt, s):
        if not s:
            return b"", b""
        length, consumed = self._decode_varint(s)
        return s[consumed + length:], s[consumed:consumed + length]

    def i2repr(self, pkt, val):
        if isinstance(val, bytes):
            return val.hex()
        return ""


# ============================================================================
# Constants
# ============================================================================

# Scouting message IDs (bits [4:0] of the header byte)
ZENOH_SCOUTING_MID = {
    0x01: "Scout",
    0x02: "Hello",
}

# Transport message IDs (bits [4:0] of the header byte)
ZENOH_TRANSPORT_MID = {
    0x00: "Init",
    0x01: "Open",
    0x04: "KeepAlive",
    0x05: "Close",
    0x06: "Frame",
    0x07: "Fragment",
    0x08: "Join",
}

# Network message IDs (bits [4:0] of header byte within a Frame payload)
ZENOH_NETWORK_MID = {
    0x00: "Push",
    0x01: "Request",
    0x02: "Response",
    0x03: "ResponseFinal",
    0x05: "Declare",
    0x1f: "OAM",
}

# WhatAmI bitmask values
ZENOH_WHATAMI = {
    0x01: "Router",
    0x02: "Peer",
    0x04: "Client",
}

# Close reason codes
ZENOH_CLOSE_REASON = {
    0x00: "Generic",
    0x01: "Unsupported",
    0x02: "Invalid",
    0x03: "MaxLinks",
    0x04: "Expired",
}


# ============================================================================
# Scouting Messages (typically on UDP port 7446)
# ============================================================================

class ZenohScout(Packet):
    """Zenoh Scout message - sent to discover peers on the network.

    Header byte layout: [_|_|Z][SCOUT(0x01)]
      bit 7: _ (reserved)
      bit 6: _ (reserved)
      bit 5: Z - zenoh extensions present
      bits[4:0]: 0x01 (Scout MID)
    """
    name = "ZenohScout"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitField("flag_z", 0, 1),
        BitEnumField("mid", 0x01, 5, ZENOH_SCOUTING_MID),
        ByteField("version", 0x01),
        ZenohVarIntField("what", 0x07),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class ZenohHello(Packet):
    """Zenoh Hello message - unicast response to Scout.

    Header byte layout: [L|_|Z][HELLO(0x02)]
      bit 7: L - locators list is present
      bit 6: _ (reserved)
      bit 5: Z - zenoh extensions present
      bits[4:0]: 0x02 (Hello MID)
    """
    name = "ZenohHello"
    fields_desc = [
        BitEnumField("flag_l", 0, 1, {0: "NoLocators", 1: "Locators"}),
        BitField("flag_reserved", 0, 1),
        BitField("flag_z", 0, 1),
        BitEnumField("mid", 0x02, 5, ZENOH_SCOUTING_MID),
        ByteField("version", 0x01),
        ZenohVarIntField("what", 0x02),
        ZenohIDField("zid", b""),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


# ============================================================================
# Transport Messages (TCP/UDP port 7447)
# ============================================================================

class ZenohInit(Packet):
    """Zenoh Init message - bidirectional session initialization.

    When flag_a == 0: InitSyn (client → router/peer)
    When flag_a == 1: InitAck (router/peer → client)

    Header byte layout: [A|S|Z][INIT(0x00)]
      bit 7: A - Ack (0=Syn, 1=Ack)
      bit 6: S - SN/batch-size resolution present
      bit 5: Z - zenoh extensions present
      bits[4:0]: 0x00 (Init MID)
    """
    name = "ZenohInit"
    fields_desc = [
        BitEnumField("flag_a", 0, 1, {0: "Syn", 1: "Ack"}),
        BitField("flag_s", 0, 1),
        BitField("flag_z", 0, 1),
        BitEnumField("mid", 0x00, 5, ZENOH_TRANSPORT_MID),
        ByteField("version", 0x01),
        ZenohVarIntField("what", 0x02),
        ZenohIDField("zid", b""),
        # Resolution and batch size are present when flag_s == 1
        ConditionalField(ZenohVarIntField("resolution", 0x0200),
                         lambda pkt: pkt.flag_s == 1),
        ConditionalField(LEShortField("batch_size", 65535),
                         lambda pkt: pkt.flag_s == 1),
        # Nonce and cookie are only in the Ack (flag_a == 1)
        ConditionalField(LELongField("nonce", 0),
                         lambda pkt: pkt.flag_a == 1),
        ConditionalField(ZenohBytesField("cookie", b""),
                         lambda pkt: pkt.flag_a == 1),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class ZenohOpen(Packet):
    """Zenoh Open message - opens a confirmed transport session.

    When flag_a == 0: OpenSyn (initiator)
    When flag_a == 1: OpenAck (responder)

    Header byte layout: [A|_|Z][OPEN(0x01)]
      bit 7: A - Ack (0=Syn, 1=Ack)
      bit 6: _ (reserved)
      bit 5: Z - zenoh extensions present
      bits[4:0]: 0x01 (Open MID)
    """
    name = "ZenohOpen"
    fields_desc = [
        BitEnumField("flag_a", 0, 1, {0: "Syn", 1: "Ack"}),
        BitField("flag_reserved", 0, 1),
        BitField("flag_z", 0, 1),
        BitEnumField("mid", 0x01, 5, ZENOH_TRANSPORT_MID),
        # Lease is present only in the Syn (flag_a == 0)
        ConditionalField(ZenohVarIntField("lease", 10000),
                         lambda pkt: pkt.flag_a == 0),
        ZenohVarIntField("initial_sn", 0),
        # Cookie is present only in the Syn (flag_a == 0)
        ConditionalField(ZenohBytesField("cookie", b""),
                         lambda pkt: pkt.flag_a == 0),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class ZenohClose(Packet):
    """Zenoh Close message - terminates a session or link.

    Header byte layout: [L|_|_][CLOSE(0x05)]
      bit 7: L - link-only close (0=full session, 1=link only)
      bit 6: _ (reserved)
      bit 5: _ (reserved)
      bits[4:0]: 0x05 (Close MID)
    """
    name = "ZenohClose"
    fields_desc = [
        BitEnumField("flag_l", 0, 1, {0: "Session", 1: "Link"}),
        BitField("flag_reserved1", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x05, 5, ZENOH_TRANSPORT_MID),
        # Reason is only present for session close (flag_l == 0)
        ConditionalField(ByteField("reason", 0),
                         lambda pkt: pkt.flag_l == 0),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class ZenohKeepAlive(Packet):
    """Zenoh KeepAlive message - maintains an active session.

    Header byte layout: [A|_|_][KEEPALIVE(0x04)]
      bit 7: A - Reply (0=request, 1=reply)
      bit 6: _ (reserved)
      bit 5: _ (reserved)
      bits[4:0]: 0x04 (KeepAlive MID)
    """
    name = "ZenohKeepAlive"
    fields_desc = [
        BitEnumField("flag_a", 0, 1, {0: "Request", 1: "Reply"}),
        BitField("flag_reserved1", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x04, 5, ZENOH_TRANSPORT_MID),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class ZenohNetworkMsg(Packet):
    """Zenoh network message dispatched within a Frame.

    Network messages begin with a 1-byte header containing the message ID
    in bits [4:0]. This class dispatches to the specific network message
    type based on that ID.
    """
    name = "ZenohNetworkMsg"
    fields_desc = []

    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        if not payload:
            return conf.padding_layer
        mid = orb(payload[0]) & 0x1F
        return _NETWORK_MSG_CLASSES.get(mid, conf.raw_layer)


class ZenohFrame(Packet):
    """Zenoh Frame message - transport container for network messages.

    The payload of this message contains one or more zenoh network
    messages (Push, Request, Response, etc.).

    Header byte layout: [_|_|R][FRAME(0x06)]
      bit 7: _ (reserved)
      bit 6: _ (reserved)
      bit 5: R - Reliable channel (0=BestEffort, 1=Reliable)
      bits[4:0]: 0x06 (Frame MID)
    """
    name = "ZenohFrame"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("flag_r", 0, 1, {0: "BestEffort", 1: "Reliable"}),
        BitEnumField("mid", 0x06, 5, ZENOH_TRANSPORT_MID),
        ZenohVarIntField("sn", 0),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            return conf.padding_layer
        mid = orb(payload[0]) & 0x1F
        return _NETWORK_MSG_CLASSES.get(mid, conf.raw_layer)


class ZenohFragment(Packet):
    """Zenoh Fragment message - carries a fragment of a large network message.

    Header byte layout: [M|_|R][FRAGMENT(0x07)]
      bit 7: M - More fragments follow
      bit 6: _ (reserved)
      bit 5: R - Reliable channel (0=BestEffort, 1=Reliable)
      bits[4:0]: 0x07 (Fragment MID)
    """
    name = "ZenohFragment"
    fields_desc = [
        BitEnumField("flag_m", 0, 1, {0: "Last", 1: "More"}),
        BitField("flag_reserved", 0, 1),
        BitEnumField("flag_r", 0, 1, {0: "BestEffort", 1: "Reliable"}),
        BitEnumField("mid", 0x07, 5, ZENOH_TRANSPORT_MID),
        ZenohVarIntField("sn", 0),
    ]


class ZenohJoin(Packet):
    """Zenoh Join message - announces presence on a multicast transport.

    Header byte layout: [_|T|Z][JOIN(0x08)]
      bit 7: _ (reserved)
      bit 6: T - Lease time present
      bit 5: Z - zenoh extensions present
      bits[4:0]: 0x08 (Join MID)
    """
    name = "ZenohJoin"
    fields_desc = [
        BitField("flag_reserved", 0, 1),
        BitEnumField("flag_t", 0, 1, {0: "NoLease", 1: "Lease"}),
        BitField("flag_z", 0, 1),
        BitEnumField("mid", 0x08, 5, ZENOH_TRANSPORT_MID),
        ByteField("version", 0x01),
        ZenohVarIntField("what", 0x02),
        ZenohIDField("zid", b""),
        ZenohVarIntField("resolution", 0x0200),
        LEShortField("batch_size", 65535),
        ConditionalField(ZenohVarIntField("lease", 10000),
                         lambda pkt: pkt.flag_t == 1),
        # Sequence numbers: reliable SN and best-effort SN
        ZenohVarIntField("next_sn_reliable", 0),
        ZenohVarIntField("next_sn_best_effort", 0),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


# ============================================================================
# Network Messages (within ZenohFrame payload)
# ============================================================================

class ZenohPush(Packet):
    """Zenoh Push (data publication) network message.

    Header byte layout: [N|Z|_][PUSH(0x00)]
      bit 7: N - No subscribers (hint)
      bit 6: Z - zenoh extensions present
      bit 5: _ (reserved)
      bits[4:0]: 0x00 (Push MID)
    """
    name = "ZenohPush"
    fields_desc = [
        BitEnumField("flag_n", 0, 1, {0: "Subscribers", 1: "NoSubscribers"}),
        BitField("flag_z", 0, 1),
        BitField("flag_reserved", 0, 1),
        BitEnumField("mid", 0x00, 5, ZENOH_NETWORK_MID),
        ZenohVarIntField("wire_expr_id", 0),
    ]


class ZenohRequest(Packet):
    """Zenoh Request (query) network message.

    Header byte layout: [_|Z|_][REQUEST(0x01)]
      bit 7: _ (reserved)
      bit 6: Z - zenoh extensions present
      bit 5: _ (reserved)
      bits[4:0]: 0x01 (Request MID)
    """
    name = "ZenohRequest"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_z", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x01, 5, ZENOH_NETWORK_MID),
        ZenohVarIntField("rid", 0),
        ZenohVarIntField("wire_expr_id", 0),
    ]


class ZenohResponse(Packet):
    """Zenoh Response network message - carries a query reply.

    Header byte layout: [_|Z|_][RESPONSE(0x02)]
      bit 7: _ (reserved)
      bit 6: Z - zenoh extensions present
      bit 5: _ (reserved)
      bits[4:0]: 0x02 (Response MID)
    """
    name = "ZenohResponse"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_z", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x02, 5, ZENOH_NETWORK_MID),
        ZenohVarIntField("rid", 0),
        ZenohVarIntField("entity_id", 0),
    ]


class ZenohResponseFinal(Packet):
    """Zenoh ResponseFinal network message - signals end of query responses.

    Header byte layout: [_|Z|_][RESPONSE_FINAL(0x03)]
      bit 7: _ (reserved)
      bit 6: Z - zenoh extensions present
      bit 5: _ (reserved)
      bits[4:0]: 0x03 (ResponseFinal MID)
    """
    name = "ZenohResponseFinal"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_z", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x03, 5, ZENOH_NETWORK_MID),
        ZenohVarIntField("rid", 0),
        ZenohVarIntField("entity_id", 0),
    ]


class ZenohDeclare(Packet):
    """Zenoh Declare network message - declares resources, subscribers, etc.

    Header byte layout: [_|Z|_][DECLARE(0x05)]
      bit 7: _ (reserved)
      bit 6: Z - zenoh extensions present
      bit 5: _ (reserved)
      bits[4:0]: 0x05 (Declare MID)
    """
    name = "ZenohDeclare"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_z", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x05, 5, ZENOH_NETWORK_MID),
    ]


class ZenohOAM(Packet):
    """Zenoh OAM (Operations, Administration, and Maintenance) network message.

    Header byte layout: [_|Z|_][OAM(0x1f)]
      bit 7: _ (reserved)
      bit 6: Z - zenoh extensions present
      bit 5: _ (reserved)
      bits[4:0]: 0x1f (OAM MID)
    """
    name = "ZenohOAM"
    fields_desc = [
        BitField("flag_reserved1", 0, 1),
        BitField("flag_z", 0, 1),
        BitField("flag_reserved2", 0, 1),
        BitEnumField("mid", 0x1f, 5, ZENOH_NETWORK_MID),
        ZenohVarIntField("oam_id", 0),
    ]


# ============================================================================
# Dispatch Tables
# ============================================================================

# Maps transport MID → message class (message includes its own header byte)
_TRANSPORT_MSG_CLASSES = {
    0x00: ZenohInit,
    0x01: ZenohOpen,
    0x04: ZenohKeepAlive,
    0x05: ZenohClose,
    0x06: ZenohFrame,
    0x07: ZenohFragment,
    0x08: ZenohJoin,
}

# Maps scouting MID → message class
_SCOUTING_MSG_CLASSES = {
    0x01: ZenohScout,
    0x02: ZenohHello,
}

# Maps network MID → message class (for messages within a Frame)
_NETWORK_MSG_CLASSES = {
    0x00: ZenohPush,
    0x01: ZenohRequest,
    0x02: ZenohResponse,
    0x03: ZenohResponseFinal,
    0x05: ZenohDeclare,
    0x1f: ZenohOAM,
}


# ============================================================================
# Top-level Dispatch Layers
# ============================================================================

class ZenohScouting(Packet):
    """Dispatcher for zenoh scouting messages (UDP port 7446).

    Reads the first byte of the payload and dispatches to the appropriate
    scouting message class based on the 5-bit message ID (bits [4:0]).
    """
    name = "ZenohScouting"
    fields_desc = []

    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        if not payload:
            return conf.padding_layer
        mid = orb(payload[0]) & 0x1F
        return _SCOUTING_MSG_CLASSES.get(mid, conf.raw_layer)


class ZenohTransport(Packet):
    """Dispatcher for zenoh transport messages (TCP/UDP port 7447).

    Reads the first byte of the payload and dispatches to the appropriate
    transport message class based on the 5-bit message ID (bits [4:0]).
    """
    name = "ZenohTransport"
    fields_desc = []

    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        if not payload:
            return conf.padding_layer
        mid = orb(payload[0]) & 0x1F
        return _TRANSPORT_MSG_CLASSES.get(mid, conf.raw_layer)


# ============================================================================
# Layer Bindings
# ============================================================================

# Scouting messages on UDP port 7446
bind_layers(UDP, ZenohScouting, dport=7446)
bind_layers(UDP, ZenohScouting, sport=7446)

# Transport messages on UDP port 7447
bind_layers(UDP, ZenohTransport, dport=7447)
bind_layers(UDP, ZenohTransport, sport=7447)

# Transport messages on TCP port 7447
bind_layers(TCP, ZenohTransport, dport=7447)
bind_layers(TCP, ZenohTransport, sport=7447)
