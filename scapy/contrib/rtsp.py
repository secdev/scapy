# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Real Time Streaming Protocol (RTSP)
RFC 2326
"""

# scapy.contrib.description = Real Time Streaming Protocol (RTSP)
# scapy.contrib.status = loads

import re

from scapy.packet import (
    bind_bottom_up,
    bind_layers,
)
from scapy.layers.http import (
    HTTP,
    _HTTPContent,
    _HTTPHeaderField,
    _generate_headers,
    _dissect_headers,
)
from scapy.layers.inet import TCP


RTSP_REQ_HEADERS = [
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
    "Authorization",
    "From",
    "If-Modified-Since",
    "Range",
    "Referer",
    "User-Agent",
]
RTSP_RESP_HEADERS = [
    "Location",
    "Proxy-Authenticate",
    "Public",
    "Retry-After",
    "Server",
    "Vary",
    "WWW-Authenticate",
]


class RTSPRequest(_HTTPContent):
    name = "RTSP Request"
    fields_desc = (
        [
            # First line
            _HTTPHeaderField("Method", "DESCRIBE"),
            _HTTPHeaderField("Request_Uri", "*"),
            _HTTPHeaderField("Version", "RTSP/1.0"),
            # Headers
        ]
        + (
            _generate_headers(
                RTSP_REQ_HEADERS,
            )
        )
        + [
            _HTTPHeaderField("Unknown-Headers", None),
        ]
    )

    def do_dissect(self, s):
        first_line, body = _dissect_headers(self, s)
        try:
            method, uri, version = re.split(rb"\s+", first_line, maxsplit=2)
            self.setfieldval("Method", method)
            self.setfieldval("Request_Uri", uri)
            self.setfieldval("Version", version)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[: -len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%RTSPRequest.Method% %RTSPRequest.Request_Uri% " "%RTSPRequest.Version%"
        )


class RTSPResponse(_HTTPContent):
    name = "RTSP Response"
    fields_desc = (
        [
            # First line
            _HTTPHeaderField("Version", "RTSP/1.1"),
            _HTTPHeaderField("Status_Code", "200"),
            _HTTPHeaderField("Reason_Phrase", "OK"),
            # Headers
        ]
        + (
            _generate_headers(
                RTSP_RESP_HEADERS,
            )
        )
        + [
            _HTTPHeaderField("Unknown-Headers", None),
        ]
    )

    def answers(self, other):
        return RTSPRequest in other

    def do_dissect(self, s):
        first_line, body = _dissect_headers(self, s)
        try:
            Version, Status, Reason = re.split(rb"\s+", first_line, maxsplit=2)
            self.setfieldval("Version", Version)
            self.setfieldval("Status_Code", Status)
            self.setfieldval("Reason_Phrase", Reason)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[: -len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%RTSPResponse.Version% %RTSPResponse.Status_Code% "
            "%RTSPResponse.Reason_Phrase%"
        )


class RTSP(HTTP):
    name = "RTSP"
    clsreq = RTSPRequest
    clsresp = RTSPResponse
    hdr = b"RTSP"
    reqmethods = b"|".join(
        [
            b"DESCRIBE",
            b"ANNOUNCE",
            b"GET_PARAMETER",
            b"OPTIONS",
            b"PAUSE",
            b"PLAY",
            b"RECORD",
            b"REDIRECT",
            b"SETUP",
            b"SET_PARAMETER",
            b"TEARDOWN",
        ]
    )

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return cls


bind_bottom_up(TCP, RTSP, sport=554)
bind_bottom_up(TCP, RTSP, dport=554)
bind_layers(TCP, RTSP, dport=554, sport=554)
