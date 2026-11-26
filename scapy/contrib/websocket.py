# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Lucas Drufva <lucas.drufva@gmail.com>

# scapy.contrib.description = WebSocket
# scapy.contrib.status = loads

"""WebSocket framing (RFC 6455) and permessage-deflate (RFC 7692).

Bind TCP to WebSocket on the application's port to follow an HTTP upgrade
with TCPSession. No port is bound by default, since HTTP ports carry other
application protocols too.
"""

import base64
import struct
import zlib
from enum import Enum
from hashlib import sha1

from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import (
    BitEnumField,
    BitField,
    ConditionalField,
    XStrFixedLenField,
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP
from scapy.packet import Packet

# Limit the decoded size of a message, including all its continuation frames.
conf.contribs.setdefault("websocket", {}).setdefault("max_decompression", 1024 * 1024)


class WebSocketPayloadLenField(BitField):
    """Encode and decode the variable-width payload length from RFC 6455, section 5.2.

    Values up to 125 fit in seven bits; markers 126 and 127 introduce a
    16-bit or 64-bit length in network byte order. An unspecified length is
    calculated from the payload when building a frame.
    """

    def i2m(self, pkt, val):
        # Count the cached wire body, excluding any subsequent frames.
        if val is None:
            return len(pkt.payload.self_build())
        return val

    def getfield(self, pkt, s):
        # RFC6455 sect 5.2 - "[...] expressed in network byte order."
        data, bits = s
        length = data[0] & 0x7F
        if length == 126:
            return data[3:], struct.unpack("!H", data[1:3])[0]
        if length == 127:
            return data[9:], struct.unpack("!Q", data[1:9])[0]
        return data[1:], length

    def addfield(self, pkt, s, val):
        # Compute only unspecified lengths and keep shared field objects immutable.
        val = self.i2m(pkt, val)
        data, bits, mask = s
        mask <<= 7
        if val <= 125:
            return data + struct.pack("!B", mask | val)
        if val <= 0xFFFF:
            return data + struct.pack("!BH", mask | 126, val)
        return data + struct.pack("!BQ", mask | 127, val)


class WebSocketDeflateDecoder:
    """Maintain one sender's compression context across frames and messages."""

    def __init__(self, window_bits=15, no_context_takeover=False):
        # Each direction owns a separate DEFLATE stream.
        self.window_bits = window_bits
        self.no_context_takeover = no_context_takeover
        self.decoder = zlib.decompressobj(wbits=-window_bits)
        self.history = b""
        self.compressed = False
        self.decoded_length = 0

    def decompress(self, pkt, data):
        # Control frames can interrupt a fragmented message without changing it.
        if pkt.opcode >= 8:
            return data

        # RFC7692 sect 7.2.3.1 - "RSV1 [...] only on the first frame."
        if pkt.opcode in (1, 2):
            self.compressed = bool(pkt.rsv & 4)
            self.decoded_length = 0
        if not self.compressed:
            return data

        # RFC7692 sect 7.2.2 - "Append 4 octets of 0x00 0x00 0xff 0xff [...]"
        # The omitted trailer belongs at the message's end, not every frame.
        encoded = data + b"\x00\x00\xff\xff" if pkt.fin else data
        limit = conf.contribs["websocket"]["max_decompression"]
        decoded = []
        try:
            # Bound the output across all DEFLATE streams in this message.
            while encoded:
                chunk = self.decoder.decompress(
                    encoded, max(1, limit - self.decoded_length + 1)
                )
                self.decoded_length += len(chunk)
                if self.decoded_length > limit:
                    raise ValueError("WebSocket decompression limit reached")
                decoded.append(chunk)

                # Keep only the negotiated sliding window for the next stream.
                self.history = (self.history + chunk)[-(1 << self.window_bits) :]
                if not self.decoder.eof:
                    break

                # RFC7692 sect 7.2.1 - "[...] BFINAL [...] set to 1."
                # A final DEFLATE block can precede more blocks or messages.
                encoded = self.decoder.unused_data
                self.decoder = zlib.decompressobj(
                    wbits=-self.window_bits, zdict=self.history
                )
        except (ValueError, zlib.error) as exc:
            # Retain the wire payload if the compression context is unusable.
            log_runtime.debug("WebSocket decompression failed: %s", exc)
            self.decoder = zlib.decompressobj(wbits=-self.window_bits)
            self.history = b""
            self.compressed = False
            return data

        # RFC7692 sect 7.2.2 - "[...] an empty LZ77 sliding window."
        # Reset only when the sender negotiated no context takeover.
        if pkt.fin:
            self.compressed = False
            if self.no_context_takeover:
                self.decoder = zlib.decompressobj(wbits=-self.window_bits)
                self.history = b""
        return b"".join(decoded)


class WebSocket(Packet):
    __slots__ = ["decoder", "extensions"]

    class HandshakeState(Enum):
        WAITING_FOR_REQUEST = 0
        WAITING_FOR_RESPONSE = 1
        OPEN = 2

    name = "WebSocket"
    fields_desc = [
        BitField("fin", 0, 1),
        BitField("rsv", 0, 3),
        BitEnumField(
            "opcode",
            0,
            4,
            {
                0x0: "none",
                0x1: "text",
                0x2: "binary",
                0x8: "close",
                0x9: "ping",
                0xA: "pong",
            },
        ),
        BitField("mask", 0, 1),
        WebSocketPayloadLenField("payloadLen", None, 7),
        # RFC6455 sect 5.2 - "Masking-key: 0 or 4 bytes"
        ConditionalField(
            XStrFixedLenField("maskingKey", b"\x00" * 4, 4), lambda pkt: pkt.mask
        ),
    ]

    def __init__(self, _pkt=b"", extensions=None, decoder=None, *args, **fields):
        # Avoid sharing mutable extension defaults between packet instances.
        self.extensions = extensions if extensions is not None else {}
        self.decoder = decoder
        super().__init__(_pkt, *args, **fields)

    def extract_padding(self, s):
        # Leave subsequent frames for TCPSession to reassemble separately.
        return s[: self.payloadLen], s[self.payloadLen :]

    def do_dissect_payload(self, s):
        # Remove masking before decoding the message's compressed bytes.
        if self.mask:
            # RFC6455 sect 5.3 - "j = i MOD 4"
            # Repeat the key so each payload byte is XORed with key[i % 4].
            key = self.maskingKey
            mask = key * (len(s) // 4) + key[: len(s) % 4]
            s = (int.from_bytes(s, "big") ^ int.from_bytes(mask, "big")).to_bytes(
                len(s), "big"
            )

        # Expose decoded content while caching the encoded body, as HTTP does.
        encoded = s
        if self.decoder is not None:
            s = self.decoder.decompress(self, s)
        self.add_payload(conf.raw_layer(load=s))
        self.payload.raw_packet_cache = encoded
        self.payload.raw_packet_cache_fields = {}

    def do_build_payload(self):
        # The Raw payload cache preserves compressed bytes after header edits.
        payload = super().do_build_payload()
        if not self.mask:
            return payload

        # Mask only this frame's body, leaving any following frames untouched.
        length = len(self.payload.self_build())
        data = payload[:length]

        # RFC6455 sect 5.3 - "same steps [...] to mask [...] as to unmask"
        key = self.maskingKey
        mask = key * (len(data) // 4) + key[: len(data) % 4]
        data = (int.from_bytes(data, "big") ^ int.from_bytes(mask, "big")).to_bytes(
            len(data), "big"
        )
        return data + payload[length:]

    @staticmethod
    def _deflate_decoder(extensions, sender):
        # Validate the window size negotiated for this sender's compressed stream.
        # RFC7692 sect 7.1.2.1 - "[...] 8 to 15, inclusive [...]"
        window_bits = int(extensions.get(sender + "_max_window_bits", 15))
        if not 8 <= window_bits <= 15:
            raise ValueError("Invalid WebSocket window size")

        # Preserve compression history unless this sender must reset each message.
        return WebSocketDeflateDecoder(
            window_bits,
            sender + "_no_context_takeover" in extensions,
        )

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        # Start by waiting for the client's HTTP upgrade request.
        handshake_state = session.setdefault(
            "handshake-state", cls.HandshakeState.WAITING_FOR_REQUEST
        )
        session.setdefault("extensions", {})

        # TCPSession clears metadata before revisiting this segment's padding.
        if "original" in metadata and "server-port" in session:
            session["last-direction-is-server"] = (
                metadata["original"][TCP].sport == session["server-port"]
            )

        # Keep HTTP headers buffered until the upgrade can be inspected.
        if handshake_state != cls.HandshakeState.OPEN:
            # Do not consume a partial HTTP header or the next protocol's bytes.
            end = data.find(b"\r\n\r\n")
            if end < 0:
                return None
            end += 4
            http = HTTP(data[:end])
            upgrading = False
            if HTTPRequest in http:
                # A repeated request can replace an unsuccessful upgrade attempt.
                request = http[HTTPRequest]
                if (
                    request.Method == b"GET"
                    and (request.Upgrade or b"").lower() == b"websocket"
                    and request.Sec_WebSocket_Key is not None
                ):
                    # Save the client key for checking the server's accept value.
                    session["handshake-key"] = request.Sec_WebSocket_Key

                    # Retain the server port to identify each TCP stream's sender.
                    if "original" in metadata:
                        session["server-port"] = metadata["original"][TCP].dport

                    # Wait for the server to complete the HTTP upgrade.
                    session["handshake-state"] = cls.HandshakeState.WAITING_FOR_RESPONSE
                    upgrading = True
            elif (
                handshake_state == cls.HandshakeState.WAITING_FOR_RESPONSE
                and HTTPResponse in http
            ):
                # Ordinary HTTP errors have no Upgrade header and remain HTTP.
                response = http[HTTPResponse]
                if (
                    response.Status_Code == b"101"
                    and (response.Upgrade or b"").lower() == b"websocket"
                ):
                    # Keep dissecting malformed handshakes, as Scapy permits.
                    # RFC6455 sect 4.2.2 - "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                    accept = base64.b64encode(
                        sha1(
                            session["handshake-key"]
                            + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                        ).digest()
                    )
                    if response.Sec_WebSocket_Accept != accept:
                        log_runtime.debug("WebSocket accept key mismatch")

                    # Collect the compression parameters accepted by the server.
                    extensions = session["extensions"] = {}
                    extension_header = response.Sec_WebSocket_Extensions or b""

                    # Each extension has a name followed by semicolon-separated options.
                    for extension in extension_header.split(b","):
                        # Ignore extensions this decoder does not implement.
                        parameters = extension.split(b";")
                        if parameters[0].strip() != b"permessage-deflate":
                            continue

                        # Record the extension and its key/value or flag parameters.
                        extensions["permessage-deflate"] = None
                        for parameter in parameters[1:]:
                            key, separator, value = parameter.strip().partition(b"=")
                            extensions[key.decode("ascii", errors="replace")] = (
                                value.strip(b'"').decode("ascii", errors="replace")
                                if separator
                                else None
                            )

                    # Create separate compression contexts for the two senders.
                    if "permessage-deflate" in extensions:
                        try:
                            # Configure the client's outgoing stream.
                            session["client-decoder"] = cls._deflate_decoder(
                                extensions, "client"
                            )

                            # Configure the server's outgoing stream.
                            session["server-decoder"] = cls._deflate_decoder(
                                extensions, "server"
                            )
                        except (TypeError, ValueError, zlib.error) as exc:
                            # Preserve frames if malformed parameters prevent decoding.
                            log_runtime.debug("Invalid WebSocket extension: %s", exc)
                            session.pop("client-decoder", None)
                            session.pop("server-decoder", None)

                    # The upgrade is complete; subsequent data contains frames.
                    session["handshake-state"] = cls.HandshakeState.OPEN
                    upgrading = True

            # Keep ordinary HTTP bodies; only upgrades delimit WebSocket frames.
            if not upgrading:
                return HTTP(data)

            # Preserve the HTTP wrapper on both sides of the upgrade.
            if len(data) > end:
                http /= conf.padding_layer(data[end:])
            return http

        # Every frame starts with two bytes: FIN/RSV/opcode, then MASK/length.
        if len(data) < 2:
            return None
        masked = bool(data[1] & 0x80)

        # Reuse the packet field after the mask bit, without copying the payload.
        try:
            remaining, payload_length = cls.payloadLen.getfield(
                None, (memoryview(data)[1:], 1)
            )
        except struct.error:
            # The extended length is split across TCP segments.
            return None
        header_length = len(data) - len(remaining)

        # A masked frame also carries a four-byte key before its payload.
        if masked:
            header_length += 4
        end = header_length + payload_length
        if len(data) < end:
            metadata["tcp_min_len"] = end
            return None

        # Prefer the TCP direction even for frames with an atypical mask bit.
        is_server = session.get("last-direction-is-server", not masked)
        decoder = session.get("server-decoder" if is_server else "client-decoder")
        packet = cls(data[:end], extensions=session["extensions"], decoder=decoder)

        # Return remaining frames as padding for TCPSession's next invocation.
        if len(data) > end:
            packet /= conf.padding_layer(data[end:])
        return packet
