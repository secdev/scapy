# SPDX-License-Identifier: GPL-2.0-or-later
"""
HTTP/3 (RFC 9114) framing - minimal contrib dissector.

Parses H3 frames (type, length, data) using QUIC varints.
This is framing-only: we don't decode HEADERS/QPACK here.
Use for dissecting decrypted H3 stream data or building synthetic test vectors.
"""

from scapy.packet import Packet
from scapy.fields import Field, StrLenField
from scapy.error import Scapy_Exception


def _varint_decode(b, i=0):
    """Decode a QUIC varint from bytes b
    starting at index i; return (value, next_index)."""
    if i >= len(b):
        raise Scapy_Exception("varint: empty")
    fb = b[i]
    prefix = fb >> 6
    sizes = (1, 2, 4, 8)
    size = sizes[prefix]
    if i + size > len(b):
        raise Scapy_Exception("varint: truncated")
    val = fb & 0x3F
    for _ in range(1, size):
        i += 1
        val = (val << 8) | b[i]
    return val, i + 1


def _varint_encode(v):
    """Encode an int v as QUIC varint bytes."""
    if v < (1 << 6):
        return bytes([v | 0x00])
    if v < (1 << 14):
        return bytes([(0x40 | (v >> 8)) & 0xFF, v & 0xFF])
    if v < (1 << 30):
        return bytes([
            (0x80 | ((v >> 24) & 0x3F)),
            (v >> 16) & 0xFF,
            (v >> 8) & 0xFF,
            v & 0xFF,
        ])
    if v < (1 << 62):
        return bytes([
            (0xC0 | ((v >> 56) & 0x3F)),
            (v >> 48) & 0xFF, (v >> 40) & 0xFF, (v >> 32) & 0xFF,
            (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF,
        ])
    raise Scapy_Exception("varint too large")


class QUICVarIntField(Field):
    def __init__(self, name, default=0):
        Field.__init__(self, name, default, fmt="B")

    def i2m(self, pkt, val):
        return _varint_encode(int(val))

    def m2i(self, pkt, val):
        return val

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        v, idx = _varint_decode(s, 0)
        return s[idx:], v


# H3 frame type constants (subset)
H3_DATA = 0x00
H3_HEADERS = 0x01
H3_PRIORITY_UPDATE_REQ = 0x0F
H3_PRIORITY_UPDATE_PUSH = 0x10
H3_SETTINGS = 0x04
H3_GOAWAY = 0x07
H3_CANCEL_PUSH = 0x03


class H3Frame(Packet):
    name = "H3Frame"
    fields_desc = [
        QUICVarIntField("type", 0),
        QUICVarIntField("length", 0),
        # Use 'data' (NOT 'payload') to avoid clashing with Packet.payload
        StrLenField("data", b"", length_from=lambda p: p.length),
    ]

    def post_build(self, p, pay):
        # Auto-fix length if zero but data present
        if self.length == 0 and self.data:
            plen = len(self.data)
            p = _varint_encode(self.type) + _varint_encode(plen) + (self.data or b"")
        return p + pay


def h3_parse_frames(blob: bytes):
    """Return a list of H3Frame from a concatenated frames blob."""
    out = []
    i = 0
    while i < len(blob):
        t, j = _varint_decode(blob, i)
        l, k = _varint_decode(blob, j)
        end = k + l
        if end > len(blob):
            raise Scapy_Exception("H3 frame truncated")
        pay = blob[k:end]
        out.append(H3Frame(type=t, length=l, data=pay))
        i = end
    return out


__all__ = [
    "H3Frame",
    "h3_parse_frames",
    "H3_DATA", 
    "H3_HEADERS", 
    "H3_SETTINGS", 
    "H3_GOAWAY", 
    "H3_CANCEL_PUSH", 
    "H3_PRIORITY_UPDATE_REQ", 
    "H3_PRIORITY_UPDATE_PUSH",
]
