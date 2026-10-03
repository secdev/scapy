# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Zenoh Protocol
# scapy.contrib.status = loads

"""
Zenoh protocol for Scapy.

Implements the Zenoh 1.x wire format used for publish/subscribe/query
communication in IoT and edge computing environments. The three protocol
layers defined by Zenoh are supported:

- *scouting* messages (Scout, Hello) used for peer discovery, usually on
  UDP port 7446,
- *transport* messages (Init, Open, Close, KeepAlive, Frame, Fragment, Join,
  OAM) which establish and maintain a session, usually on TCP or UDP
  port 7447,
- *network* messages (Push, Request, Response, ResponseFinal, Interest,
  Declare, OAM) carried inside transport Frames, together with the
  *zenoh* messages (Put, Del, Query, Reply, Err) that hold the user payload.

Transport messages are grouped in batches. On datagram links a batch is the
datagram itself (:class:`ZenohBatch`); on stream links such as TCP every batch
is prefixed with its length as a 16-bit little endian integer
(:class:`ZenohStreamBatch`).

Example::

    >>> pkt = IP()/UDP(dport=7446)/ZenohScout(what="Router+Peer")
    >>> msg = ZenohPush(key_scope=1, key_suffix="temp")/ZenohPut(data=b"42")
    >>> batch = IP()/TCP(dport=7447)/ZenohStreamBatch(
    ...     messages=[ZenohFrame(sn=1, messages=[msg])])

References:

- https://zenoh.io/
- https://github.com/eclipse-zenoh/zenoh (``commons/zenoh-protocol`` and
  ``commons/zenoh-codec`` hold the normative wire format description)
"""

from scapy.compat import chb, orb
from scapy.config import conf
from scapy.fields import (
    BitEnumField,
    BitField,
    BitFieldLenField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FlagsField,
    LEShortField,
    PacketListField,
    XStrLenField,
)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_bottom_up, bind_layers
from scapy.volatile import RandBin, RandNum

# ============================================================================
# Constants
# ============================================================================

ZENOH_VERSION = 0x09

ZENOH_PORT_SCOUTING = 7446
ZENOH_PORT_TRANSPORT = 7447

# Scouting message IDs, bits [4:0] of the header byte
ZENOH_MID_SCOUT = 0x01
ZENOH_MID_HELLO = 0x02

ZENOH_SCOUTING_MID = {
    ZENOH_MID_SCOUT: "Scout",
    ZENOH_MID_HELLO: "Hello",
}

# Transport message IDs, bits [4:0] of the header byte. They never collide
# with the network message IDs, which is what allows a Frame to be followed
# by another transport message inside the same batch.
ZENOH_MID_T_OAM = 0x00
ZENOH_MID_INIT = 0x01
ZENOH_MID_OPEN = 0x02
ZENOH_MID_CLOSE = 0x03
ZENOH_MID_KEEPALIVE = 0x04
ZENOH_MID_FRAME = 0x05
ZENOH_MID_FRAGMENT = 0x06
ZENOH_MID_JOIN = 0x07

ZENOH_TRANSPORT_MID = {
    ZENOH_MID_T_OAM: "OAM",
    ZENOH_MID_INIT: "Init",
    ZENOH_MID_OPEN: "Open",
    ZENOH_MID_CLOSE: "Close",
    ZENOH_MID_KEEPALIVE: "KeepAlive",
    ZENOH_MID_FRAME: "Frame",
    ZENOH_MID_FRAGMENT: "Fragment",
    ZENOH_MID_JOIN: "Join",
}

# Network message IDs, bits [4:0] of the header byte
ZENOH_MID_INTEREST = 0x19
ZENOH_MID_RESPONSE_FINAL = 0x1a
ZENOH_MID_RESPONSE = 0x1b
ZENOH_MID_REQUEST = 0x1c
ZENOH_MID_PUSH = 0x1d
ZENOH_MID_DECLARE = 0x1e
ZENOH_MID_N_OAM = 0x1f

ZENOH_NETWORK_MID = {
    ZENOH_MID_INTEREST: "Interest",
    ZENOH_MID_RESPONSE_FINAL: "ResponseFinal",
    ZENOH_MID_RESPONSE: "Response",
    ZENOH_MID_REQUEST: "Request",
    ZENOH_MID_PUSH: "Push",
    ZENOH_MID_DECLARE: "Declare",
    ZENOH_MID_N_OAM: "OAM",
}

# Zenoh (payload) message IDs, bits [4:0] of the header byte
ZENOH_MID_PUT = 0x01
ZENOH_MID_DEL = 0x02
ZENOH_MID_QUERY = 0x03
ZENOH_MID_REPLY = 0x04
ZENOH_MID_ERR = 0x05

ZENOH_ZENOH_MID = {
    ZENOH_MID_PUT: "Put",
    ZENOH_MID_DEL: "Del",
    ZENOH_MID_QUERY: "Query",
    ZENOH_MID_REPLY: "Reply",
    ZENOH_MID_ERR: "Err",
}

# Declaration IDs, bits [4:0] of the declaration header byte
ZENOH_DECL_KEYEXPR = 0x00
ZENOH_DECL_U_KEYEXPR = 0x01
ZENOH_DECL_SUBSCRIBER = 0x02
ZENOH_DECL_U_SUBSCRIBER = 0x03
ZENOH_DECL_QUERYABLE = 0x04
ZENOH_DECL_U_QUERYABLE = 0x05
ZENOH_DECL_TOKEN = 0x06
ZENOH_DECL_U_TOKEN = 0x07
ZENOH_DECL_FINAL = 0x1a

ZENOH_DECLARATION_ID = {
    ZENOH_DECL_KEYEXPR: "DeclareKeyExpr",
    ZENOH_DECL_U_KEYEXPR: "UndeclareKeyExpr",
    ZENOH_DECL_SUBSCRIBER: "DeclareSubscriber",
    ZENOH_DECL_U_SUBSCRIBER: "UndeclareSubscriber",
    ZENOH_DECL_QUERYABLE: "DeclareQueryable",
    ZENOH_DECL_U_QUERYABLE: "UndeclareQueryable",
    ZENOH_DECL_TOKEN: "DeclareToken",
    ZENOH_DECL_U_TOKEN: "UndeclareToken",
    ZENOH_DECL_FINAL: "DeclareFinal",
}

# WhatAmI, as a 2-bit value in Hello/Init/Join
ZENOH_WHATAMI = {
    0x00: "Router",
    0x01: "Peer",
    0x02: "Client",
}

# WhatAmI, as a 3-bit interest bitmap in Scout
ZENOH_WHATAMI_FLAGS = ["Router", "Peer", "Client"]

# SN/ID resolution, 2 bits per field
ZENOH_RESOLUTION = {
    0x00: "8bit",
    0x01: "16bit",
    0x02: "32bit",
    0x03: "64bit",
}

# Close reasons
ZENOH_CLOSE_REASON = {
    0x00: "Generic",
    0x01: "Unsupported",
    0x02: "Invalid",
    0x03: "MaxSessions",
    0x04: "MaxLinks",
    0x05: "Expired",
    0x06: "Unresponsive",
    0x07: "ConnectionToSelf",
}

# Interest declaration modes, bits [6:5] of the header byte
ZENOH_INTEREST_MODE = {
    0x00: "Final",
    0x01: "Current",
    0x02: "Future",
    0x03: "CurrentFuture",
}

# Interest options, one bit each
ZENOH_INTEREST_OPTIONS = [
    "keyexprs",
    "subscribers",
    "queryables",
    "tokens",
    "restricted",
    "named",
    "mapping",
    "aggregate",
]

ZENOH_CONSOLIDATION = {
    0x00: "Auto",
    0x01: "None",
    0x02: "Monotonic",
    0x03: "Latest",
}

# Extension body encodings, bits [6:5] of the extension header byte
ZENOH_EXT_ENCODING = {
    0x00: "Unit",
    0x01: "Z64",
    0x02: "ZBuf",
    0x03: "Reserved",
}

# Well-known encoding IDs. Zenoh does not enforce this mapping, it is only
# a convention of the Zenoh API and used here to render a readable name.
ZENOH_ENCODING_ID = {
    0: "zenoh/bytes",
    1: "zenoh/string",
    2: "zenoh/serialized",
    3: "application/octet-stream",
    4: "text/plain",
    5: "application/json",
    6: "text/json",
    7: "application/cdr",
    8: "application/cbor",
    9: "application/yaml",
    10: "text/yaml",
    11: "text/json5",
    12: "application/python-serialized-object",
    13: "application/protobuf",
    14: "application/java-serialized-object",
    15: "application/openmetrics-text",
    16: "image/png",
    17: "image/jpeg",
    18: "image/gif",
    19: "image/bmp",
    20: "image/webp",
    21: "application/xml",
    22: "application/x-www-form-urlencoded",
    23: "text/html",
    24: "text/xml",
    25: "text/css",
    26: "text/javascript",
    27: "text/markdown",
    28: "text/csv",
    29: "application/sql",
    30: "application/coap-payload",
    31: "application/json-patch+json",
    32: "application/json-seq",
    33: "application/jsonpath",
    34: "application/jwt",
    35: "application/mp4",
    36: "application/soap+xml",
    37: "application/yang",
    38: "audio/aac",
    39: "audio/flac",
    40: "audio/mp4",
    41: "audio/ogg",
    42: "audio/vorbis",
    43: "video/h261",
    44: "video/h263",
    45: "video/h264",
    46: "video/h265",
    47: "video/h266",
    48: "video/mp4",
    49: "video/ogg",
    50: "video/raw",
    51: "video/vp8",
    52: "video/vp9",
}


# ============================================================================
# VLE (variable length encoding) codec
# ============================================================================

# A zint never spans more than 9 bytes: the 9th byte carries 8 payload bits
# instead of 7, which is enough to cover the remaining bits of an u64.
ZENOH_ZINT_MAX_LEN = 9


def zenoh_zint_encode(val):
    # type: (int) -> bytes
    """Encode an unsigned integer using the zenoh VLE (``zint``) format."""
    if val < 0:
        raise ValueError("zint values must not be negative")
    if val > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("zint values must fit in 64 bits")
    data = bytearray()
    while val > 0x7F and len(data) < ZENOH_ZINT_MAX_LEN - 1:
        data.append((val & 0x7F) | 0x80)
        val >>= 7
    data.append(val & 0xFF)
    return bytes(data)


def zenoh_zint_decode(s):
    # type: (bytes) -> tuple
    """Decode a zenoh VLE integer.

    Returns a ``(value, consumed)`` tuple. ``consumed`` is 0 when the buffer
    holds a truncated integer, in which case the partially decoded value is
    still returned.
    """
    value = 0
    for i in range(min(len(s), ZENOH_ZINT_MAX_LEN)):
        b = orb(s[i])
        if i == ZENOH_ZINT_MAX_LEN - 1:
            return value | (b << (7 * i)), i + 1
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return value, i + 1
    return value, 0


class ZenohZIntField(Field):
    """Unsigned integer with the zenoh VLE encoding.

    Each byte carries 7 payload bits, least significant group first, with
    bit 7 set on every byte but the last one. For example 300 (0x12C) is
    encoded as ``ac 02``.
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def addfield(self, pkt, s, val):
        return s + zenoh_zint_encode(self.i2m(pkt, val))

    def getfield(self, pkt, s):
        value, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", value
        return s[consumed:], value

    def i2len(self, pkt, val):
        return len(zenoh_zint_encode(self.i2m(pkt, val)))

    def randval(self):
        return RandNum(0, 0xFFFFFFFF)


class ZenohZIntLenField(FieldLenField):
    """:class:`ZenohZIntField` computed from the length or count of a field."""

    def __init__(self, name, default, **kwargs):
        kwargs.setdefault("fmt", "B")
        FieldLenField.__init__(self, name, default, **kwargs)

    def addfield(self, pkt, s, val):
        return s + zenoh_zint_encode(self.i2m(pkt, val))

    def getfield(self, pkt, s):
        value, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", value
        return s[consumed:], value

    def i2len(self, pkt, val):
        return len(zenoh_zint_encode(self.i2m(pkt, val)))


class ZenohZBufField(Field):
    """Byte buffer prefixed by its length as a zint (spec ``<u8;zN>``)."""

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def i2m(self, pkt, x):
        if x is None:
            return b""
        if isinstance(x, str):
            return x.encode()
        return bytes(x)

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        return s + zenoh_zint_encode(len(val)) + val

    def getfield(self, pkt, s):
        length, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", b""
        return s[consumed + length:], s[consumed:consumed + length]

    def i2len(self, pkt, val):
        val = self.i2m(pkt, val)
        return len(zenoh_zint_encode(len(val))) + len(val)

    def i2repr(self, pkt, val):
        if isinstance(val, bytes):
            return val.hex()
        return repr(val)

    def randval(self):
        return RandBin(RandNum(0, 16))


class ZenohZStrField(ZenohZBufField):
    """UTF-8 string prefixed by its length as a zint.

    Buffers that are not valid UTF-8 are kept as bytes so that a dissected
    packet still rebuilds to the original bytes.
    """

    def getfield(self, pkt, s):
        remain, val = ZenohZBufField.getfield(self, pkt, s)
        try:
            return remain, val.decode("utf-8")
        except UnicodeDecodeError:
            return remain, val

    def i2repr(self, pkt, val):
        return repr(val)

    def randval(self):
        return RandBin(RandNum(0, 16))


class ZenohEncodingField(Field):
    """Zenoh ``encoding``: a zint holding ``(id << 1) | S`` and a schema.

    The field value is the encoding ID as an integer, or an
    ``(id, schema)`` tuple when the S flag announces a schema.
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def i2m(self, pkt, x):
        if x is None:
            return (0, None)
        if isinstance(x, tuple):
            eid, schema = x
            if isinstance(schema, str):
                schema = schema.encode()
            return (eid, schema)
        return (x, None)

    def addfield(self, pkt, s, val):
        eid, schema = self.i2m(pkt, val)
        raw = (eid << 1) | (0x01 if schema is not None else 0x00)
        s += zenoh_zint_encode(raw)
        if schema is not None:
            s += zenoh_zint_encode(len(schema)) + schema
        return s

    def getfield(self, pkt, s):
        raw, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", 0
        s = s[consumed:]
        eid = raw >> 1
        if not raw & 0x01:
            return s, eid
        length, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", (eid, b"")
        return s[consumed + length:], (eid, s[consumed:consumed + length])

    def i2repr(self, pkt, val):
        eid, schema = self.i2m(pkt, val)
        name = ZENOH_ENCODING_ID.get(eid, str(eid))
        if schema:
            try:
                return "%s;%s" % (name, schema.decode("utf-8"))
            except UnicodeDecodeError:
                return "%s;%s" % (name, schema.hex())
        return name

    def randval(self):
        return RandNum(0, 52)


class ZenohConsolidationField(ZenohZIntField):
    """Query consolidation mode, a zint with well known values."""

    def i2repr(self, pkt, val):
        return ZENOH_CONSOLIDATION.get(val, str(val))


class ZenohTimestampField(Field):
    """Zenoh timestamp: an NTP64 counter followed by the ID of its source.

    The field value is a ``(ntp64, source_id)`` tuple; a plain integer is
    understood as a timestamp without source ID. NTP64 counts seconds in its
    upper 32 bits and fractions of a second in its lower 32 bits.
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def i2m(self, pkt, x):
        if x is None:
            return (0, b"")
        if isinstance(x, tuple):
            ntp64, source_id = x
            if isinstance(source_id, str):
                source_id = source_id.encode()
            return (int(ntp64), bytes(source_id))
        return (int(x), b"")

    def addfield(self, pkt, s, val):
        ntp64, source_id = self.i2m(pkt, val)
        return (s + zenoh_zint_encode(ntp64) +
                zenoh_zint_encode(len(source_id)) + source_id)

    def getfield(self, pkt, s):
        ntp64, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", (ntp64, b"")
        s = s[consumed:]
        length, consumed = zenoh_zint_decode(s)
        if not consumed:
            return b"", (ntp64, b"")
        return s[consumed + length:], (ntp64, s[consumed:consumed + length])

    def i2len(self, pkt, val):
        return len(self.addfield(pkt, b"", val))

    def i2repr(self, pkt, val):
        ntp64, source_id = self.i2m(pkt, val)
        return "%d.%09d/%s" % (
            ntp64 >> 32,
            ((ntp64 & 0xFFFFFFFF) * 10 ** 9) >> 32,
            source_id.hex(),
        )

    def randval(self):
        return RandNum(0, 0xFFFFFFFFFFFFFFFF)


# ============================================================================
# Extensions
# ============================================================================

class ZenohExtension(Packet):
    """Zenoh extension, encoded as a type-length-value triple.

    Every zenoh message may be followed by extensions when the Z flag is set
    in its header. The extension header byte is::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|ENC|M|   ID  |
        +-+---+-+-------+
        %    length     % -- if ENC == ZBuf
        +---------------+
        ~     [u8]      ~ -- if ENC == ZBuf
        +---------------+

    ``Z`` announces a further extension, ``M`` marks the extension as
    mandatory (a receiver that does not understand it must drop the message)
    and ``ENC`` selects the body encoding: no body, a zint value, or a
    length-prefixed buffer.

    The meaning of ``eid`` depends on the enclosing message, e.g. 0x1 is QoS
    and 0x2 is a timestamp for most network messages.

    Extensions are the last field of a message unless the diagram of that
    message shows them elsewhere, which is the case whenever a payload or a
    nested message follows.
    """
    name = "ZenohExt"
    fields_desc = [
        BitField("more", 0, 1),
        BitEnumField("enc", 0, 2, ZENOH_EXT_ENCODING),
        BitField("mandatory", 0, 1),
        BitField("eid", 0, 4),
        ConditionalField(ZenohZIntField("value", 0),
                         lambda pkt: pkt.enc == 0x01),
        ConditionalField(ZenohZBufField("body", b""),
                         lambda pkt: pkt.enc == 0x02),
    ]

    def extract_padding(self, s):
        return b"", s

    def default_payload_class(self, payload):
        return conf.padding_layer


class ZenohExtensionsField(PacketListField):
    """List of :class:`ZenohExtension`, chained through their ``more`` bit.

    The ``more`` bit is a structural flag and is therefore recomputed while
    building, just like a length field.
    """

    def addfield(self, pkt, s, val):
        parts = [self.i2m(pkt, v) for v in val]
        parts = [p for p in parts if p]
        for i, part in enumerate(parts):
            first = orb(part[0])
            if i < len(parts) - 1:
                first |= 0x80
            else:
                first &= 0x7F
            s += chb(first) + part[1:]
        return s


def _next_extension(pkt, lst, cur, remain):
    if not remain:
        return None
    if cur is None:
        return ZenohExtension if pkt.getfieldval("flag_z") else None
    return ZenohExtension if cur.more else None


def _extensions_field():
    return ZenohExtensionsField("extensions", [], next_cls_cb=_next_extension)


# ============================================================================
# Message bases
# ============================================================================

def _is_set(value):
    """True when a field holds a value that is meant to go on the wire."""
    if value is None:
        return False
    if isinstance(value, (bytes, str, list)) and not len(value):
        return False
    return True


def _flag_or_value(flag, name):
    """Condition of an optional field announced by a header flag.

    While dissecting, the flag decides. While building, giving the field a
    value is enough: :meth:`_ZenohMsg.post_build` then sets the flag, unless
    it was set explicitly.
    """
    def _cond(pkt):
        if pkt.getfieldval(flag):
            return True
        return _is_set(pkt.fields.get(name))
    return _cond


class _ZenohMsg(Packet):
    """Base class of all zenoh messages.

    Zenoh messages are siblings inside a batch or a frame, not enclosing
    layers of each other, so trailing bytes are handed back to the enclosing
    list instead of being dissected as a payload.
    """

    # Flags that announce an optional field, as
    # (flag field, announced field, header byte index, bit mask) tuples.
    auto_flags = []  # type: list

    def post_build(self, p, pay):
        for flag, name, index, mask in self.auto_flags:
            if flag in self.fields or len(p) <= index:
                continue
            if _is_set(self.fields.get(name)):
                p = p[:index] + chb(orb(p[index]) | mask) + p[index + 1:]
        # The Z flag is bit 7 of the header byte of every zenoh message.
        if p and self.extensions and "flag_z" not in self.fields:
            p = chb(orb(p[0]) | 0x80) + p[1:]
        return p + pay

    def extract_padding(self, s):
        return b"", s

    def mysummary(self):
        return self.name


class _ZenohMsgWithBody(_ZenohMsg):
    """Zenoh message that carries another zenoh message as its payload."""

    def extract_padding(self, s):
        return s, b""


def _guess_msg_class(payload, table):
    if not payload:
        return conf.padding_layer
    return table.get(orb(payload[0]) & 0x1F, conf.raw_layer)


def _interest_option(pkt, mask):
    """True when an Interest carries options and the given one is set."""
    if pkt.mode == 0x00:
        return False
    options = pkt.options
    if options is None:
        return False
    return bool(int(options) & mask)


# ============================================================================
# Scouting messages
# ============================================================================

class ZenohScouting(Packet):
    """Dispatcher for zenoh scouting messages (UDP port 7446)."""
    name = "ZenohScouting"
    fields_desc = []

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            return _SCOUTING_MSG_CLASSES.get(orb(_pkt[0]) & 0x1F,
                                             conf.raw_layer)
        return cls


class ZenohScout(_ZenohMsg):
    """Scout message, multicast to discover the zenoh nodes of a network.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|X|  SCOUT  |
        +-+-+-+---------+
        |    version    |
        +---------------+
        |zid_len|I| what|
        +-+-+-+-+-+-+-+-+
        ~      [u8]     ~ if I==1 -- Zenoh ID
        +---------------+

    ``what`` is a bitmap of the node kinds the sender is interested in and
    ``zid_len`` holds the Zenoh ID length minus one.
    """
    name = "ZenohScout"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("mid", ZENOH_MID_SCOUT, 5, ZENOH_SCOUTING_MID),
        ByteField("version", ZENOH_VERSION),
        BitFieldLenField("zid_len", None, 4, length_of="zid",
                         adjust=lambda pkt, x: max(x, 1) - 1),
        BitField("flag_i", 0, 1),
        FlagsField("what", 0x07, 3, ZENOH_WHATAMI_FLAGS),
        ConditionalField(
            XStrLenField("zid", b"",
                         length_from=lambda pkt: (pkt.zid_len or 0) + 1),
            _flag_or_value("flag_i", "zid"),
        ),
        _extensions_field(),
    ]
    auto_flags = [("flag_i", "zid", 2, 0x08)]


class ZenohLocator(Packet):
    """A single locator of a Hello message, e.g. ``tcp/192.168.1.1:7447``."""
    name = "ZenohLocator"
    fields_desc = [ZenohZStrField("locator", "")]

    def extract_padding(self, s):
        return b"", s

    def default_payload_class(self, payload):
        return conf.padding_layer


class ZenohHello(_ZenohMsg):
    """Hello message, sent in reply to a Scout or to advertise a node.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|L|  HELLO  |
        +-+-+-+---------+
        |    version    |
        +---------------+
        |zid_len|X|X|wai|
        +-+-+-+-+-+-+-+-+
        ~     [u8]      ~ -- Zenoh ID
        +---------------+
        ~   <utf8;z8>   ~ if L==1 -- List of locators
        +---------------+
    """
    name = "ZenohHello"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitEnumField("flag_l", 0, 1, {0: "NoLocators", 1: "Locators"}),
        BitEnumField("mid", ZENOH_MID_HELLO, 5, ZENOH_SCOUTING_MID),
        ByteField("version", ZENOH_VERSION),
        BitFieldLenField("zid_len", None, 4, length_of="zid",
                         adjust=lambda pkt, x: max(x, 1) - 1),
        BitField("res2", 0, 2),
        BitEnumField("whatami", 0x01, 2, ZENOH_WHATAMI),
        XStrLenField("zid", b"\x01",
                     length_from=lambda pkt: (pkt.zid_len or 0) + 1),
        ConditionalField(
            ZenohZIntLenField("num_locators", None, count_of="locators"),
            _flag_or_value("flag_l", "locators"),
        ),
        ConditionalField(
            PacketListField("locators", [], ZenohLocator,
                            count_from=lambda pkt: pkt.num_locators or 0),
            _flag_or_value("flag_l", "locators"),
        ),
        _extensions_field(),
    ]
    auto_flags = [("flag_l", "locators", 0, 0x20)]


# ============================================================================
# Transport messages
# ============================================================================

def _resolution_fields():
    """SN/ID resolution byte and batch size, present when the S flag is set."""
    return [
        ConditionalField(BitField("res_resolution", 0, 4),
                         lambda pkt: pkt.flag_s),
        ConditionalField(BitEnumField("rid_resolution", 0x02, 2,
                                      ZENOH_RESOLUTION),
                         lambda pkt: pkt.flag_s),
        ConditionalField(BitEnumField("fsn_resolution", 0x02, 2,
                                      ZENOH_RESOLUTION),
                         lambda pkt: pkt.flag_s),
        ConditionalField(LEShortField("batch_size", 65535),
                         lambda pkt: pkt.flag_s),
    ]


class ZenohInit(_ZenohMsg):
    """Init message, the first half of the session establishment handshake.

    ``flag_a`` tells an InitSyn (0, sent by the initiator) from an InitAck
    (1, sent by the responder). Only the InitAck carries a cookie, which the
    initiator has to echo in its OpenSyn.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|S|A|   INIT  |
        +-+-+-+---------+
        |    version    |
        +---------------+
        |zid_len|x|x|wai|
        +-------+-+-+---+
        ~      [u8]     ~ -- Zenoh ID of the sender
        +---------------+
        |x|x|x|x|rid|fsn| \\               -- SN/ID resolution
        +---------------+  | if S==1
        |      u16      | /               -- Batch size
        +---------------+
        ~    <u8;z16>   ~ if A==1 -- Cookie
        +---------------+
    """
    name = "ZenohInit"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("flag_s", 0, 1),
        BitEnumField("flag_a", 0, 1, {0: "Syn", 1: "Ack"}),
        BitEnumField("mid", ZENOH_MID_INIT, 5, ZENOH_TRANSPORT_MID),
        ByteField("version", ZENOH_VERSION),
        BitFieldLenField("zid_len", None, 4, length_of="zid",
                         adjust=lambda pkt, x: max(x, 1) - 1),
        BitField("res1", 0, 2),
        BitEnumField("whatami", 0x01, 2, ZENOH_WHATAMI),
        XStrLenField("zid", b"\x01",
                     length_from=lambda pkt: (pkt.zid_len or 0) + 1),
    ] + _resolution_fields() + [
        ConditionalField(ZenohZBufField("cookie", b""),
                         lambda pkt: pkt.flag_a),
        _extensions_field(),
    ]


class ZenohOpen(_ZenohMsg):
    """Open message, the second half of the session establishment handshake.

    ``flag_a`` tells an OpenSyn (0) from an OpenAck (1); only the OpenSyn
    echoes the cookie received in the InitAck. ``flag_t`` selects the unit of
    the lease period: seconds when set, milliseconds otherwise.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|T|A|   OPEN  |
        +-+-+-+---------+
        %     lease     %
        +---------------+
        %  initial_sn   %
        +---------------+
        ~    <u8;z16>   ~ if A==0 -- Cookie
        +---------------+
    """
    name = "ZenohOpen"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_t", 0, 1, {0: "Milliseconds", 1: "Seconds"}),
        BitEnumField("flag_a", 0, 1, {0: "Syn", 1: "Ack"}),
        BitEnumField("mid", ZENOH_MID_OPEN, 5, ZENOH_TRANSPORT_MID),
        ZenohZIntField("lease", 10000),
        ZenohZIntField("initial_sn", 0),
        ConditionalField(ZenohZBufField("cookie", b""),
                         lambda pkt: pkt.flag_a == 0),
        _extensions_field(),
    ]


class ZenohClose(_ZenohMsg):
    """Close message, terminating either a single link or the whole session.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|S|  CLOSE  |
        +-+-+-+---------+
        |     reason    |
        +---------------+
    """
    name = "ZenohClose"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitEnumField("flag_s", 0, 1, {0: "Link", 1: "Session"}),
        BitEnumField("mid", ZENOH_MID_CLOSE, 5, ZENOH_TRANSPORT_MID),
        ByteEnumField("reason", 0, ZENOH_CLOSE_REASON),
        _extensions_field(),
    ]


class ZenohKeepAlive(_ZenohMsg):
    """KeepAlive message, refreshing the lease period of a link.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|X| KALIVE  |
        +-+-+-+---------+
    """
    name = "ZenohKeepAlive"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("mid", ZENOH_MID_KEEPALIVE, 5, ZENOH_TRANSPORT_MID),
        _extensions_field(),
    ]


class ZenohFrame(_ZenohMsg):
    """Frame message, carrying one or more complete network messages.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|R|  FRAME  |
        +-+-+-+---------+
        %    seq num    %
        +---------------+
        ~  [FrameExts]  ~ if Z==1
        +---------------+
        ~  [NetworkMsg] ~
        +---------------+

    Network messages are collected in the ``messages`` list. Since network
    and transport message IDs cannot collide, dissection stops as soon as a
    byte that is not a network message ID is found, which leaves room for a
    further transport message in the same batch.
    """
    name = "ZenohFrame"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitEnumField("flag_r", 0, 1, {0: "BestEffort", 1: "Reliable"}),
        BitEnumField("mid", ZENOH_MID_FRAME, 5, ZENOH_TRANSPORT_MID),
        ZenohZIntField("sn", 0),
        _extensions_field(),
        PacketListField("messages", [],
                        next_cls_cb=lambda pkt, lst, cur, remain:
                        _next_network_msg(remain)),
    ]

    def mysummary(self):
        return "ZenohFrame sn=%s" % self.sn


class ZenohFragment(_ZenohMsg):
    """Fragment message, carrying a piece of an oversized network message.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|M|R| FRAGMENT|
        +-+-+-+---------+
        %    seq num    %
        +---------------+
        ~   [FragExts]  ~ if Z==1
        +---------------+
        ~      [u8]     ~
        +---------------+

    The fragment payload runs to the end of the batch, so a Fragment is
    always the last message of its batch.
    """
    name = "ZenohFragment"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Last", 1: "More"}),
        BitEnumField("flag_r", 0, 1, {0: "BestEffort", 1: "Reliable"}),
        BitEnumField("mid", ZENOH_MID_FRAGMENT, 5, ZENOH_TRANSPORT_MID),
        ZenohZIntField("sn", 0),
        _extensions_field(),
    ]

    def extract_padding(self, s):
        return s, b""

    def guess_payload_class(self, payload):
        return conf.raw_layer if payload else conf.padding_layer


class ZenohJoin(_ZenohMsg):
    """Join message, advertising the transport parameters on a multicast link.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|S|T|   JOIN  |
        +-+-+-+---------+
        |    version    |
        +---------------+
        |zid_len|x|x|wai|
        +-------+-+-+---+
        ~      [u8]     ~ -- Zenoh ID of the sender
        +---------------+
        |x|x|x|x|rid|fsn| \\               -- SN/ID resolution
        +---------------+  | if S==1
        |      u16      | /               -- Batch size
        +---------------+
        %     lease     %
        +---------------+
        %  next_sn (x2) % -- Reliable and best effort next sequence numbers
        +---------------+
    """
    name = "ZenohJoin"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("flag_s", 0, 1),
        BitEnumField("flag_t", 0, 1, {0: "Milliseconds", 1: "Seconds"}),
        BitEnumField("mid", ZENOH_MID_JOIN, 5, ZENOH_TRANSPORT_MID),
        ByteField("version", ZENOH_VERSION),
        BitFieldLenField("zid_len", None, 4, length_of="zid",
                         adjust=lambda pkt, x: max(x, 1) - 1),
        BitField("res1", 0, 2),
        BitEnumField("whatami", 0x01, 2, ZENOH_WHATAMI),
        XStrLenField("zid", b"\x01",
                     length_from=lambda pkt: (pkt.zid_len or 0) + 1),
    ] + _resolution_fields() + [
        ZenohZIntField("lease", 10000),
        ZenohZIntField("next_sn_reliable", 0),
        ZenohZIntField("next_sn_best_effort", 0),
        _extensions_field(),
    ]


class ZenohTransportOAM(_ZenohMsg):
    """Transport level operation, administration and maintenance message.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|ENC|   OAM   |
        +-+-+-+---------+
        ~    id:z16     ~
        +---------------+
        ~   [OamExts]   ~ if Z==1
        +---------------+
        %    length     % \\ if ENC == Z64 or ZBuf
        ~     [u8]      ~ / if ENC == ZBuf
        +---------------+
    """
    name = "ZenohTransportOAM"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("enc", 0, 2, ZENOH_EXT_ENCODING),
        BitEnumField("mid", ZENOH_MID_T_OAM, 5, ZENOH_TRANSPORT_MID),
        ZenohZIntField("oam_id", 0),
        _extensions_field(),
        ConditionalField(ZenohZIntField("value", 0),
                         lambda pkt: pkt.enc == 0x01),
        ConditionalField(ZenohZBufField("body", b""),
                         lambda pkt: pkt.enc == 0x02),
    ]


# ============================================================================
# Network messages
# ============================================================================

def _wire_expr_fields():
    """Key expression: a scope ID plus an optional suffix, announced by N."""
    return [
        ZenohZIntField("key_scope", 0),
        ConditionalField(ZenohZStrField("key_suffix", ""),
                         _flag_or_value("flag_n", "key_suffix")),
    ]


# The N flag of the key expression sits in bit 5 of the header byte.
_AUTO_FLAG_N = [("flag_n", "key_suffix", 0, 0x20)]


class ZenohPush(_ZenohMsgWithBody):
    """Push message, publishing data towards the subscribers of a key.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|M|N|  PUSH   |
        +-+-+-+---------+
        ~ key_scope:z16 ~
        +---------------+
        ~  key_suffix   ~ if N==1
        +---------------+
        ~  [PushExts]   ~ if Z==1
        +---------------+
        ~   PushBody    ~ -- Put or Del
        +---------------+
    """
    name = "ZenohPush"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Receiver", 1: "Sender"}),
        BitField("flag_n", 0, 1),
        BitEnumField("mid", ZENOH_MID_PUSH, 5, ZENOH_NETWORK_MID),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]
    auto_flags = _AUTO_FLAG_N

    def guess_payload_class(self, payload):
        return _guess_msg_class(payload, _PUSH_BODY_CLASSES)

    def mysummary(self):
        return "ZenohPush %s" % _key_expr_repr(self)


class ZenohRequest(_ZenohMsgWithBody):
    """Request message, sending a query to the queryables of a key.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|M|N| REQUEST |
        +-+-+-+---------+
        ~ request_id:z32~
        +---------------+
        ~ key_scope:z16 ~
        +---------------+
        ~  key_suffix   ~ if N==1
        +---------------+
        ~   [ReqExts]   ~ if Z==1
        +---------------+
        ~  RequestBody  ~ -- Query
        +---------------+
    """
    name = "ZenohRequest"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Receiver", 1: "Sender"}),
        BitField("flag_n", 0, 1),
        BitEnumField("mid", ZENOH_MID_REQUEST, 5, ZENOH_NETWORK_MID),
        ZenohZIntField("request_id", 0),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]

    auto_flags = _AUTO_FLAG_N

    def guess_payload_class(self, payload):
        return _guess_msg_class(payload, _REQUEST_BODY_CLASSES)

    def mysummary(self):
        return "ZenohRequest id=%s %s" % (self.request_id,
                                          _key_expr_repr(self))


class ZenohResponse(_ZenohMsgWithBody):
    """Response message, answering a Request.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|M|N| RESPONSE|
        +-+-+-+---------+
        ~ request_id:z32~
        +---------------+
        ~ key_scope:z16 ~
        +---------------+
        ~  key_suffix   ~ if N==1
        +---------------+
        ~  [RespExts]   ~ if Z==1
        +---------------+
        ~  ResponseBody ~ -- Reply or Err
        +---------------+
    """
    name = "ZenohResponse"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Receiver", 1: "Sender"}),
        BitField("flag_n", 0, 1),
        BitEnumField("mid", ZENOH_MID_RESPONSE, 5, ZENOH_NETWORK_MID),
        ZenohZIntField("request_id", 0),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]

    auto_flags = _AUTO_FLAG_N

    def guess_payload_class(self, payload):
        return _guess_msg_class(payload, _RESPONSE_BODY_CLASSES)

    def mysummary(self):
        return "ZenohResponse id=%s %s" % (self.request_id,
                                           _key_expr_repr(self))


class ZenohResponseFinal(_ZenohMsg):
    """ResponseFinal message, closing the response stream of a Request.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|X| ResFinal|
        +-+-+-+---------+
        ~ request_id:z32~
        +---------------+
    """
    name = "ZenohResponseFinal"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("mid", ZENOH_MID_RESPONSE_FINAL, 5, ZENOH_NETWORK_MID),
        ZenohZIntField("request_id", 0),
        _extensions_field(),
    ]


class ZenohInterest(_ZenohMsg):
    """Interest message, requesting the transmission of declarations.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|Mod|INTEREST |
        +-+-+-+---------+
        ~    id:z32     ~
        +---------------+
        |A|M|N|R|T|Q|S|K| if Mod!=Final
        +---------------+
        ~ key_scope:z16 ~ if Mod!=Final and R==1
        +---------------+
        ~  key_suffix   ~ if Mod!=Final and R==1 and N==1
        +---------------+
    """
    name = "ZenohInterest"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("mode", 0x01, 2, ZENOH_INTEREST_MODE),
        BitEnumField("mid", ZENOH_MID_INTEREST, 5, ZENOH_NETWORK_MID),
        ZenohZIntField("interest_id", 0),
        ConditionalField(FlagsField("options", 0, 8, ZENOH_INTEREST_OPTIONS),
                         lambda pkt: pkt.mode != 0x00),
        ConditionalField(ZenohZIntField("key_scope", 0),
                         lambda pkt: _interest_option(pkt, 0x10)),
        ConditionalField(ZenohZStrField("key_suffix", ""),
                         lambda pkt: _interest_option(pkt, 0x10) and
                         _interest_option(pkt, 0x20)),
        _extensions_field(),
    ]


class ZenohDeclare(_ZenohMsgWithBody):
    """Declare message, carrying a single declaration.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|I| DECLARE |
        +-+-+-+---------+
        ~interest_id:z32~ if I==1
        +---------------+
        ~  [DeclExts]   ~ if Z==1
        +---------------+
        ~  declaration  ~
        +---------------+
    """
    name = "ZenohDeclare"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("flag_i", 0, 1),
        BitEnumField("mid", ZENOH_MID_DECLARE, 5, ZENOH_NETWORK_MID),
        ConditionalField(ZenohZIntField("interest_id", 0),
                         _flag_or_value("flag_i", "interest_id")),
        _extensions_field(),
    ]
    auto_flags = [("flag_i", "interest_id", 0, 0x20)]

    def guess_payload_class(self, payload):
        return _guess_msg_class(payload, _DECLARATION_CLASSES)


class ZenohNetworkOAM(_ZenohMsg):
    """Network level operation, administration and maintenance message.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|ENC|   OAM   |
        +-+-+-+---------+
        ~    id:z16     ~
        +---------------+
        ~   [OamExts]   ~ if Z==1
        +---------------+
        %    length     % \\ if ENC == Z64 or ZBuf
        ~     [u8]      ~ / if ENC == ZBuf
        +---------------+
    """
    name = "ZenohNetworkOAM"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("enc", 0, 2, ZENOH_EXT_ENCODING),
        BitEnumField("mid", ZENOH_MID_N_OAM, 5, ZENOH_NETWORK_MID),
        ZenohZIntField("oam_id", 0),
        _extensions_field(),
        ConditionalField(ZenohZIntField("value", 0),
                         lambda pkt: pkt.enc == 0x01),
        ConditionalField(ZenohZBufField("body", b""),
                         lambda pkt: pkt.enc == 0x02),
    ]


# ============================================================================
# Declarations, carried by a Declare message
# ============================================================================

class ZenohDeclareKeyExpr(_ZenohMsg):
    """Bind a numerical expression ID to a key expression.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|N| D_KEXPR |
        +---------------+
        ~  expr_id:z16  ~
        +---------------+
        ~ key_scope:z16 ~
        +---------------+
        ~  key_suffix   ~ if N==1
        +---------------+
    """
    name = "ZenohDeclareKeyExpr"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("flag_n", 0, 1),
        BitEnumField("did", ZENOH_DECL_KEYEXPR, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("expr_id", 0),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]
    auto_flags = _AUTO_FLAG_N


class ZenohUndeclareKeyExpr(_ZenohMsg):
    """Release an expression ID previously bound by a DeclareKeyExpr."""
    name = "ZenohUndeclareKeyExpr"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("did", ZENOH_DECL_U_KEYEXPR, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("expr_id", 0),
        _extensions_field(),
    ]


class _ZenohDeclareEntity(_ZenohMsg):
    """Common layout of the subscriber, queryable and token declarations."""
    auto_flags = _AUTO_FLAG_N


class ZenohDeclareSubscriber(_ZenohDeclareEntity):
    """Announce a subscriber on a key expression.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|M|N|  D_SUB  |
        +---------------+
        ~  subs_id:z32  ~
        +---------------+
        ~ key_scope:z16 ~
        +---------------+
        ~  key_suffix   ~ if N==1
        +---------------+
    """
    name = "ZenohDeclareSubscriber"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Receiver", 1: "Sender"}),
        BitField("flag_n", 0, 1),
        BitEnumField("did", ZENOH_DECL_SUBSCRIBER, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("subscriber_id", 0),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]


class ZenohUndeclareSubscriber(_ZenohMsg):
    """Withdraw a subscriber. The key expression travels in extension 0x0f."""
    name = "ZenohUndeclareSubscriber"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("did", ZENOH_DECL_U_SUBSCRIBER, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("subscriber_id", 0),
        _extensions_field(),
    ]


class ZenohDeclareQueryable(_ZenohDeclareEntity):
    """Announce a queryable on a key expression."""
    name = "ZenohDeclareQueryable"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Receiver", 1: "Sender"}),
        BitField("flag_n", 0, 1),
        BitEnumField("did", ZENOH_DECL_QUERYABLE, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("queryable_id", 0),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]


class ZenohUndeclareQueryable(_ZenohMsg):
    """Withdraw a queryable. The key expression travels in extension 0x0f."""
    name = "ZenohUndeclareQueryable"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("did", ZENOH_DECL_U_QUERYABLE, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("queryable_id", 0),
        _extensions_field(),
    ]


class ZenohDeclareToken(_ZenohDeclareEntity):
    """Announce a liveliness token on a key expression."""
    name = "ZenohDeclareToken"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitEnumField("flag_m", 0, 1, {0: "Receiver", 1: "Sender"}),
        BitField("flag_n", 0, 1),
        BitEnumField("did", ZENOH_DECL_TOKEN, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("token_id", 0),
    ] + _wire_expr_fields() + [
        _extensions_field(),
    ]


class ZenohUndeclareToken(_ZenohMsg):
    """Withdraw a token. The key expression travels in extension 0x0f."""
    name = "ZenohUndeclareToken"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("did", ZENOH_DECL_U_TOKEN, 5, ZENOH_DECLARATION_ID),
        ZenohZIntField("token_id", 0),
        _extensions_field(),
    ]


class ZenohDeclareFinal(_ZenohMsg):
    """Mark the end of the declarations sent in response to an Interest."""
    name = "ZenohDeclareFinal"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("res2", 0, 1),
        BitEnumField("did", ZENOH_DECL_FINAL, 5, ZENOH_DECLARATION_ID),
        _extensions_field(),
    ]


# ============================================================================
# Zenoh messages, the user facing payload of the network messages
# ============================================================================

class ZenohPut(_ZenohMsg):
    """Put message, holding the published payload.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|E|T|   PUT   |
        +-+-+-+---------+
        ~ ts: <u8;z16>  ~ if T==1
        +---------------+
        ~   encoding    ~ if E==1
        +---------------+
        ~   [PutExts]   ~ if Z==1
        +---------------+
        ~ pl: <u8;z32>  ~ -- Payload
        +---------------+

    The payload is exposed as ``data``, since ``payload`` is reserved by
    Scapy for the next layer.
    """
    name = "ZenohPut"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("flag_e", 0, 1),
        BitField("flag_t", 0, 1),
        BitEnumField("mid", ZENOH_MID_PUT, 5, ZENOH_ZENOH_MID),
        ConditionalField(ZenohTimestampField("timestamp", None),
                         _flag_or_value("flag_t", "timestamp")),
        ConditionalField(ZenohEncodingField("encoding", 0),
                         _flag_or_value("flag_e", "encoding")),
        _extensions_field(),
        ZenohZBufField("data", b""),
    ]
    auto_flags = [("flag_t", "timestamp", 0, 0x20),
                  ("flag_e", "encoding", 0, 0x40)]

    def mysummary(self):
        # The key expression of the enclosing message tells what was written,
        # so ask for its summary to be kept.
        return "ZenohPut %d bytes" % len(self.data or b""), _summary_parents()


class ZenohDel(_ZenohMsg):
    """Del message, deleting the data associated with a key expression.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|T|   DEL   |
        +-+-+-+---------+
        ~ ts: <u8;z16>  ~ if T==1
        +---------------+
    """
    name = "ZenohDel"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("flag_t", 0, 1),
        BitEnumField("mid", ZENOH_MID_DEL, 5, ZENOH_ZENOH_MID),
        ConditionalField(ZenohTimestampField("timestamp", None),
                         _flag_or_value("flag_t", "timestamp")),
        _extensions_field(),
    ]
    auto_flags = [("flag_t", "timestamp", 0, 0x20)]

    def mysummary(self):
        return self.name, _summary_parents()


class ZenohQuery(_ZenohMsg):
    """Query message, the body of a Request.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|P|C|  QUERY  |
        +-+-+-+---------+
        % consolidation % if C==1
        +---------------+
        ~ ps: <u8;z16>  ~ if P==1 -- Selector parameters
        +---------------+
    """
    name = "ZenohQuery"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("flag_p", 0, 1),
        BitField("flag_c", 0, 1),
        BitEnumField("mid", ZENOH_MID_QUERY, 5, ZENOH_ZENOH_MID),
        ConditionalField(ZenohConsolidationField("consolidation", 0),
                         _flag_or_value("flag_c", "consolidation")),
        ConditionalField(ZenohZStrField("parameters", ""),
                         _flag_or_value("flag_p", "parameters")),
        _extensions_field(),
    ]
    auto_flags = [("flag_c", "consolidation", 0, 0x20),
                  ("flag_p", "parameters", 0, 0x40)]

    def mysummary(self):
        if self.parameters:
            return "ZenohQuery ?%s" % self.parameters, _summary_parents()
        return self.name, _summary_parents()


class ZenohReply(_ZenohMsgWithBody):
    """Reply message, the body of a successful Response.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|X|C|  REPLY  |
        +-+-+-+---------+
        % consolidation % if C==1
        +---------------+
        ~  [ReplyExts]  ~ if Z==1
        +---------------+
        ~   ReplyBody   ~ -- Put or Del
        +---------------+
    """
    name = "ZenohReply"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("res1", 0, 1),
        BitField("flag_c", 0, 1),
        BitEnumField("mid", ZENOH_MID_REPLY, 5, ZENOH_ZENOH_MID),
        ConditionalField(ZenohConsolidationField("consolidation", 0),
                         _flag_or_value("flag_c", "consolidation")),
        _extensions_field(),
    ]
    auto_flags = [("flag_c", "consolidation", 0, 0x20)]

    def guess_payload_class(self, payload):
        return _guess_msg_class(payload, _REPLY_BODY_CLASSES)


class ZenohErr(_ZenohMsg):
    """Err message, the body of a failed Response.

    ::

         7 6 5 4 3 2 1 0
        +-+-+-+-+-+-+-+-+
        |Z|E|X|   ERR   |
        +-+-+-+---------+
        ~   encoding    ~ if E==1
        +---------------+
        ~   [ErrExts]   ~ if Z==1
        +---------------+
        ~ pl: <u8;z32>  ~ -- Payload
        +---------------+
    """
    name = "ZenohErr"
    fields_desc = [
        BitField("flag_z", 0, 1),
        BitField("flag_e", 0, 1),
        BitField("res1", 0, 1),
        BitEnumField("mid", ZENOH_MID_ERR, 5, ZENOH_ZENOH_MID),
        ConditionalField(ZenohEncodingField("encoding", 0),
                         _flag_or_value("flag_e", "encoding")),
        _extensions_field(),
        ZenohZBufField("data", b""),
    ]
    auto_flags = [("flag_e", "encoding", 0, 0x40)]

    def mysummary(self):
        return "ZenohErr %d bytes" % len(self.data or b""), _summary_parents()


# ============================================================================
# Batches
# ============================================================================

class ZenohBatch(Packet):
    """A batch of zenoh transport messages, as carried by one datagram.

    Datagram links keep the message boundaries themselves, so no length
    prefix is present. Stream links use :class:`ZenohStreamBatch` instead.
    """
    name = "ZenohBatch"
    fields_desc = [
        PacketListField("messages", [],
                        next_cls_cb=lambda pkt, lst, cur, remain:
                        _next_transport_msg(remain)),
    ]

    def mysummary(self):
        return "ZenohBatch %s" % " / ".join(m.name for m in self.messages)


class ZenohStreamBatch(Packet):
    """A batch of zenoh transport messages on a stream link, e.g. TCP.

    Streams do not preserve message boundaries, so every batch is prefixed
    with its total length as a 16-bit little endian integer. A single TCP
    segment may hold several batches.
    """
    name = "ZenohStreamBatch"
    fields_desc = [
        FieldLenField("len", None, fmt="<H", length_of="messages"),
        PacketListField("messages", [],
                        next_cls_cb=lambda pkt, lst, cur, remain:
                        _next_transport_msg(remain),
                        length_from=lambda pkt: pkt.len),
    ]

    def guess_payload_class(self, payload):
        # Several batches may share one segment, but a truncated batch is
        # better left alone than dissected into nonsense.
        if len(payload) > 2:
            length = orb(payload[0]) | (orb(payload[1]) << 8)
            if 0 < length <= len(payload) - 2:
                return ZenohStreamBatch
        return Packet.guess_payload_class(self, payload)

    def mysummary(self):
        return "ZenohStreamBatch %s" % " / ".join(m.name
                                                  for m in self.messages)


# ============================================================================
# Dispatch tables
# ============================================================================

_SCOUTING_MSG_CLASSES = {
    ZENOH_MID_SCOUT: ZenohScout,
    ZENOH_MID_HELLO: ZenohHello,
}

_TRANSPORT_MSG_CLASSES = {
    ZENOH_MID_T_OAM: ZenohTransportOAM,
    ZENOH_MID_INIT: ZenohInit,
    ZENOH_MID_OPEN: ZenohOpen,
    ZENOH_MID_CLOSE: ZenohClose,
    ZENOH_MID_KEEPALIVE: ZenohKeepAlive,
    ZENOH_MID_FRAME: ZenohFrame,
    ZENOH_MID_FRAGMENT: ZenohFragment,
    ZENOH_MID_JOIN: ZenohJoin,
}

_NETWORK_MSG_CLASSES = {
    ZENOH_MID_INTEREST: ZenohInterest,
    ZENOH_MID_RESPONSE_FINAL: ZenohResponseFinal,
    ZENOH_MID_RESPONSE: ZenohResponse,
    ZENOH_MID_REQUEST: ZenohRequest,
    ZENOH_MID_PUSH: ZenohPush,
    ZENOH_MID_DECLARE: ZenohDeclare,
    ZENOH_MID_N_OAM: ZenohNetworkOAM,
}

_PUSH_BODY_CLASSES = {
    ZENOH_MID_PUT: ZenohPut,
    ZENOH_MID_DEL: ZenohDel,
}

_REQUEST_BODY_CLASSES = {
    ZENOH_MID_QUERY: ZenohQuery,
}

_RESPONSE_BODY_CLASSES = {
    ZENOH_MID_REPLY: ZenohReply,
    ZENOH_MID_ERR: ZenohErr,
}

_REPLY_BODY_CLASSES = dict(_PUSH_BODY_CLASSES)

_DECLARATION_CLASSES = {
    ZENOH_DECL_KEYEXPR: ZenohDeclareKeyExpr,
    ZENOH_DECL_U_KEYEXPR: ZenohUndeclareKeyExpr,
    ZENOH_DECL_SUBSCRIBER: ZenohDeclareSubscriber,
    ZENOH_DECL_U_SUBSCRIBER: ZenohUndeclareSubscriber,
    ZENOH_DECL_QUERYABLE: ZenohDeclareQueryable,
    ZENOH_DECL_U_QUERYABLE: ZenohUndeclareQueryable,
    ZENOH_DECL_TOKEN: ZenohDeclareToken,
    ZENOH_DECL_U_TOKEN: ZenohUndeclareToken,
    ZENOH_DECL_FINAL: ZenohDeclareFinal,
}


def _next_transport_msg(remain):
    """Class of the next transport message of a batch, if any."""
    if not remain:
        return None
    return _TRANSPORT_MSG_CLASSES.get(orb(remain[0]) & 0x1F, conf.raw_layer)


def _next_network_msg(remain):
    """Class of the next network message of a frame, if any.

    Returning None ends the frame, which lets the enclosing batch look for a
    further transport message.
    """
    if not remain:
        return None
    return _NETWORK_MSG_CLASSES.get(orb(remain[0]) & 0x1F)


def _key_expr_repr(pkt):
    suffix = pkt.key_suffix
    if isinstance(suffix, bytes):
        suffix = suffix.decode("utf-8", "replace")
    if not suffix:
        return str(pkt.key_scope or 0)
    return "%d/%s" % (pkt.key_scope or 0, suffix)


def _summary_parents():
    """Messages whose summary is worth keeping in front of a body message."""
    return [ZenohPush, ZenohRequest, ZenohResponse, ZenohReply]


# ============================================================================
# Layer bindings
# ============================================================================

# Only the destination port is bound top down, so that building a packet does
# not set the source port as well.
bind_layers(UDP, ZenohScouting, dport=ZENOH_PORT_SCOUTING)
bind_bottom_up(UDP, ZenohScouting, sport=ZENOH_PORT_SCOUTING)

bind_layers(UDP, ZenohBatch, dport=ZENOH_PORT_TRANSPORT)
bind_bottom_up(UDP, ZenohBatch, sport=ZENOH_PORT_TRANSPORT)

bind_layers(TCP, ZenohStreamBatch, dport=ZENOH_PORT_TRANSPORT)
bind_bottom_up(TCP, ZenohStreamBatch, sport=ZENOH_PORT_TRANSPORT)
