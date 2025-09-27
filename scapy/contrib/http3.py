# SPDX-License-Identifier: GPL-2.0-only
"""
HTTP/3 (RFC 9114) framing — minimal contrib layer.

This provides a thin "frame" abstraction used by HTTP/3 on top of QUIC streams:
  - frame type: QUIC varint
  - frame length: QUIC varint
  - frame payload: raw bytes (opaque here)

It is intentionally framing-only: it does not implement QPACK or parse HEADERS.

Typical uses:
  - dissecting **decrypted** HTTP/3 stream data (e.g., after TLS/QUIC decryption)
  - crafting small synthetic H3 test vectors

Examples
--------
>>> from scapy.contrib.http3 import H3Frame, h3_parse_frames, h3_parse_settings
>>> # Build a DATA frame (type=0x00) with "abc"
>>> f = H3Frame(type=0x00, length=3, data=b"abc")
>>> raw(f)
b'\\x00\\x03abc'

>>> # Length can be auto-filled from data if left to 0
>>> H3Frame(type=0x01, data=b'\\x01\\x02').build()
b'\\x01\\x02\\x01\\x02'

>>> # Parse a blob of concatenated frames
>>> blob = b'\\x00\\x03abc' + b'\\x01\\x01Z'
>>> frames = h3_parse_frames(blob)
>>> [ (fr.type, fr.length, bytes(fr.data)) for fr in frames ]
[(0, 3, b'abc'), (1, 1, b'Z')]

>>> # SETTINGS helper (payload is varint-id/varint-value pairs)
>>> # id=0x1 -> 0x100 (256) encodes as 0x41 0x00 ; id=0x3 -> 0x40 (64) as 0x40 0x40
>>> settings_payload = b'\\x01\\x41\\x00' + b'\\x03\\x40\\x40'
>>> h3_parse_settings(settings_payload)
[(1, 256), (3, 64)]
"""

from typing import List, Tuple

from scapy.packet import Packet
from scapy.fields import StrLenField
from scapy.layers.quic import QuicVarIntField

# --- H3 frame type constants (subset) ---
H3_DATA                  = 0x00
H3_HEADERS               = 0x01
H3_CANCEL_PUSH           = 0x03
H3_SETTINGS              = 0x04
H3_GOAWAY                = 0x07
H3_PRIORITY_UPDATE_REQ   = 0x0F
H3_PRIORITY_UPDATE_PUSH  = 0x10


class H3Frame(Packet):
    name = "H3Frame"
    fields_desc = [
        QuicVarIntField("type", 0),
        QuicVarIntField("length", 0),
        # keep "data" (not "payload") to avoid clashing with Packet.payload
        StrLenField("data", b"", length_from=lambda p: p.length),
    ]

    def post_build(self, p, pay):
        # If user didn't set length (or set it to 0) but provided data,
        # recompute the header using the actual data length.
        if (self.length in (None, 0)) and self.data:
            t = self.getfieldval("type")
            d = self.getfieldval("data") or b""
            p = H3Frame(type=t, length=len(d), data=d).build()
        return p + pay


def _quic_varint_decode_at(buf: bytes, i: int) -> Tuple[int, int]:
    """
    Decode one QUIC varint located at buf[i:], using Scapy's QuicVarIntField.
    Returns (value, next_index).
    """
    fld = QuicVarIntField("tmp", 0)
    rest, val = fld.getfield(None, buf[i:])
    next_i = len(buf) - len(rest)
    return val, next_i


def h3_parse_frames(blob: bytes):
    """
    Parse a concatenated frames blob into a list of H3Frame.
    Raises ValueError on truncation.
    """
    out = []
    i = 0
    while i < len(blob):
        tmp = H3Frame(blob[i:])
        header_only = H3Frame(type=tmp.type, length=tmp.length).build()
        hdr_len = len(header_only)
        end = i + hdr_len + tmp.length
        if end > len(blob):
            raise ValueError("H3 frame truncated")
        out.append(H3Frame(blob[i:end]))
        i = end
    return out


def h3_parse_settings(payload: bytes) -> List[Tuple[int, int]]:
    """
    Parse a SETTINGS payload (sequence of varint-id / varint-value pairs) and
    return a list of (setting_id, value). Silently stops on first truncated pair.
    """
    res: List[Tuple[int, int]] = []
    i = 0
    L = len(payload)
    while i < L:
        try:
            sid, j = _quic_varint_decode_at(payload, i)
            sval, k = _quic_varint_decode_at(payload, j)
        except Exception:
            break
        res.append((sid, sval))
        i = k
    return res


__all__ = [
    "H3Frame",
    "h3_parse_frames",
    "h3_parse_settings",
    "H3_DATA",
    "H3_HEADERS",
    "H3_SETTINGS",
    "H3_GOAWAY",
    "H3_CANCEL_PUSH",
    "H3_PRIORITY_UPDATE_REQ",
    "H3_PRIORITY_UPDATE_PUSH",
]

# Register contrib (so UTScapy `-P "load_contrib('http3')"` works)
from scapy.config import conf
conf.contribs["http3"] = "scapy.contrib.http3"
