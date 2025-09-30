# SPDX-License-Identifier: GPL-2.0-only
"""
HTTP/3 (RFC 9114) framing — contrib layer.

This provides a "frame" abstraction used by HTTP/3 on top of QUIC streams:
  - frame type: QUIC varint
  - frame length: QUIC varint
  - frame payload: raw bytes (opaque here, with helpers for a few control frames)

Focus: practical crafting/inspection of **decrypted** HTTP/3 stream data. No QPACK.

Examples
--------
>>> from scapy.contrib.http3 import (
...     H3Frame, h3_parse_frames, h3_iterparse, h3_parse_settings,
...     h3_build_data, h3_build_headers, h3_build_settings,
...     h3_build_goaway, h3_parse_goaway,
...     h3_build_priority_update_req, h3_build_priority_update_push,
...     h3_parse_priority_update,
... )
>>> raw(h3_build_data(b"abc"))
b'\\x00\\x03abc'

>>> # Concatenated frames
>>> blob = raw(h3_build_data(b"abc")) + raw(h3_build_headers(b"\\x82"))
>>> [(fr.type, fr.length) for fr in h3_parse_frames(blob)]
[(0, 3), (1, 1)]

>>> # SETTINGS (varint pairs)
>>> sp = b'\\x01\\x41\\x00' + b'\\x03\\x40\\x40'  # (1->256),(3->64)
>>> h3_parse_settings(sp)
[(1, 256), (3, 64)]
>>> raw(h3_build_settings([(1,256),(3,64)]))
b'\\x04\\x04\\x01A\\x00\\x03@@'

>>> # GOAWAY (identifier as a varint)
>>> f = h3_build_goaway(1234)
>>> h3_parse_goaway(bytes(H3Frame(raw(f)).data))
1234
"""

from typing import Iterable, Iterator, List, Tuple

from scapy.packet import Packet
from scapy.fields import StrLenField
from scapy.layers.quic import QuicVarIntField
from scapy.config import conf


# --- H3 frame type constants (subset from RFC 9114 §7) ---
H3_DATA                 = 0x00
H3_HEADERS              = 0x01
H3_CANCEL_PUSH          = 0x03
H3_SETTINGS             = 0x04
H3_PUSH_PROMISE         = 0x05
H3_GOAWAY               = 0x07
H3_PRIORITY_UPDATE_REQ  = 0x0F
H3_PRIORITY_UPDATE_PUSH = 0x10

_H3_TYPE_NAMES = {
    H3_DATA: "DATA",
    H3_HEADERS: "HEADERS",
    H3_CANCEL_PUSH: "CANCEL_PUSH",
    H3_SETTINGS: "SETTINGS",
    H3_PUSH_PROMISE: "PUSH_PROMISE",
    H3_GOAWAY: "GOAWAY",
    H3_PRIORITY_UPDATE_REQ: "PRIORITY_UPDATE(Request)",
    H3_PRIORITY_UPDATE_PUSH: "PRIORITY_UPDATE(Push)",
}


class H3Frame(Packet):
    """
    Generic HTTP/3 frame.

    Notes:
      - 'data' is kept opaque (except for helpers below) to stay flexible.
      - Length is auto-fixed from 'data' in post_build.
      - extract_padding() ensures chained frames dissect cleanly.
    """
    name = "H3Frame"
    fields_desc = [
        QuicVarIntField("type", 0),
        QuicVarIntField("length", 0),
        StrLenField("data", b"", length_from=lambda p: p.length),
    ]

    def post_build(self, p, pay):
        d = self.getfieldval("data") or b""
        want_len = len(d)
        cur_len = int(self.getfieldval("length") or 0)
        if want_len != cur_len:
            t = int(self.getfieldval("type") or 0)
            f = QuicVarIntField("tmp", 0)
            hdr = f.addfield(None, b"", t) + f.addfield(None, b"", want_len)
            p = hdr + d
        return p + pay

    def mysummary(self):
        tname = _H3_TYPE_NAMES.get(self.type, f"0x{self.type:x}")
        return f"H3Frame {tname} len={self.length}"

    def extract_padding(self, s):
        dlen = int(self.length or 0)
        if dlen > len(s):
            dlen = len(s)
        return s[:dlen], s[dlen:]


# ---------- Varint-at-offset + bulk/streaming parsers ----------

def _quic_varint_decode_at(buf: bytes, i: int) -> Tuple[int, int]:
    fld = QuicVarIntField("tmp", 0)
    rest, val = fld.getfield(None, buf[i:])
    next_i = len(buf) - len(rest)
    return val, next_i


def h3_parse_frames(blob: bytes) -> List[H3Frame]:
    out: List[H3Frame] = []
    i = 0
    L = len(blob)
    while i < L:
        try:
            ftype, j = _quic_varint_decode_at(blob, i)
            flen,  k = _quic_varint_decode_at(blob, j)
        except Exception as e:
            raise ValueError(f"Invalid H3 frame header at {i}: {e!r}")
        end = k + flen
        if end > L:
            raise ValueError("H3 frame truncated")
        out.append(H3Frame(blob[i:end]))
        i = end
    return out


def h3_iterparse(chunks: Iterable[bytes]) -> Iterator[H3Frame]:
    """
    Incrementally parse frames from an iterable of byte chunks.
    Yields H3Frame as soon as a full frame is available.
    """
    buf = bytearray()
    for chunk in chunks:
        if not chunk:
            continue
        buf += chunk
        # Try to peel as many frames as possible from the front
        while True:
            if not buf:
                break
            try:
                ftype, j = _quic_varint_decode_at(buf, 0)
                flen,  k = _quic_varint_decode_at(buf, j)
            except Exception:
                # Not enough for header yet
                break
            end = k + flen
            if end > len(buf):
                # Not enough for payload yet
                break
            yield H3Frame(bytes(buf[:end]))
            del buf[:end]


# ---------- SETTINGS encode/decode ----------

def h3_parse_settings(payload: bytes) -> List[Tuple[int, int]]:
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


def h3_build_settings_pairs(pairs: Iterable[Tuple[int, int]]) -> bytes:
    f = QuicVarIntField("tmp", 0)
    out = b""
    for sid, sval in pairs:
        out += f.addfield(None, b"", int(sid))
        out += f.addfield(None, b"", int(sval))
    return out


# ---------- Convenience frame builders (DATA/HEADERS/SETTINGS) ----------

def h3_build_data(data: bytes) -> H3Frame:
    return H3Frame(type=H3_DATA, data=bytes(data))


def h3_build_headers(block: bytes) -> H3Frame:
    return H3Frame(type=H3_HEADERS, data=bytes(block))


def h3_build_settings(pairs: Iterable[Tuple[int, int]]) -> H3Frame:
    payload = h3_build_settings_pairs(pairs)
    return H3Frame(type=H3_SETTINGS, data=payload)


# ---------- Control-frame helpers: GOAWAY & PRIORITY_UPDATE ----------

def h3_build_goaway(identifier: int) -> H3Frame:
    f = QuicVarIntField("tmp", 0)
    pay = f.addfield(None, b"", int(identifier))
    return H3Frame(type=H3_GOAWAY, data=pay)


def h3_parse_goaway(payload: bytes) -> int:
    _, ident = QuicVarIntField("tmp", 0).getfield(None, payload)
    return int(ident)


def h3_build_priority_update_req(element_id: int, value: bytes) -> H3Frame:
    """
    PRIORITY_UPDATE(request-stream): payload = varint(element_id) + field-value-bytes.
    We don't parse the field-value semantics here (opaque per RFC 9218).
    """
    f = QuicVarIntField("tmp", 0)
    pay = f.addfield(None, b"", int(element_id)) + bytes(value or b"")
    return H3Frame(type=H3_PRIORITY_UPDATE_REQ, data=pay)


def h3_build_priority_update_push(push_id: int, value: bytes) -> H3Frame:
    f = QuicVarIntField("tmp", 0)
    pay = f.addfield(None, b"", int(push_id)) + bytes(value or b"")
    return H3Frame(type=H3_PRIORITY_UPDATE_PUSH, data=pay)


def h3_parse_priority_update(payload: bytes) -> Tuple[int, bytes]:
    """
    Parse PRIORITY_UPDATE payload into (id, value_bytes).
    (For request variant: id = element-id; for push variant: id = push-id)
    """
    rest, ident = QuicVarIntField("tmp", 0).getfield(None, payload)
    consumed = len(payload) - len(rest)
    return int(ident), payload[consumed:]


__all__ = [
    # Types
    "H3Frame",
    # Parsers
    "h3_parse_frames",
    "h3_iterparse",
    "h3_parse_settings",
    "h3_parse_goaway",
    "h3_parse_priority_update",
    # Builders
    "h3_build_settings_pairs",
    "h3_build_data",
    "h3_build_headers",
    "h3_build_settings",
    "h3_build_goaway",
    "h3_build_priority_update_req",
    "h3_build_priority_update_push",
    # Constants
    "H3_DATA",
    "H3_HEADERS",
    "H3_SETTINGS",
    "H3_GOAWAY",
    "H3_CANCEL_PUSH",
    "H3_PUSH_PROMISE",
    "H3_PRIORITY_UPDATE_REQ",
    "H3_PRIORITY_UPDATE_PUSH",
]

# Register contrib (so UTScapy `-P "load_contrib('http3')"` works)
conf.contribs["http3"] = "scapy.contrib.http3"
