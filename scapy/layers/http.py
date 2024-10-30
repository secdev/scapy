# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2012 Luca Invernizzi <invernizzi.l@gmail.com>
# Copyright (C) 2012 Steeve Barbeau <http://www.sbarbeau.fr>
# Copyright (C) 2019 Gabriel Potter <gabriel[]potter[]fr>

"""
HTTP 1.0 layer.

Load using::

    from scapy.layers.http import *

Or (console only)::

    >>> load_layer("http")

Note that this layer ISN'T loaded by default, as quite experimental for now.

To follow HTTP packets streams = group packets together to get the
whole request/answer, use ``TCPSession`` as::

    >>> sniff(session=TCPSession)  # Live on-the-flow session
    >>> sniff(offline="./http_chunk.pcap", session=TCPSession)  # pcap

This will decode HTTP packets using ``Content_Length`` or chunks,
and will also decompress the packets when needed.
Note: on failure, decompression will be ignored.

You can turn auto-decompression/auto-compression off with::

    >>> conf.contribs["http"]["auto_compression"] = False

(Defaults to True)

You can also turn auto-chunking/dechunking off with::

    >>> conf.contribs["http"]["auto_chunk"] = False

(Defaults to True)
"""

# This file is a rewritten version of the former scapy_http plugin.
# It was reimplemented for scapy 2.4.3+ using sessions, stream handling.
# Original Authors : Steeve Barbeau, Luca Invernizzi

import base64
import datetime
import gzip
import io
import os
import re
import socket
import ssl
import struct
import subprocess

from enum import Enum

from scapy.compat import plain_str, bytes_encode

from scapy.automaton import Automaton, ATMT
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.error import warning, log_loading, log_interactive, Scapy_Exception
from scapy.fields import StrField
from scapy.packet import Packet, bind_layers, bind_bottom_up, Raw
from scapy.supersocket import StreamSocket, SSLStreamSocket
from scapy.utils import get_temp_file, ContextManagerSubprocess

from scapy.layers.gssapi import (
    GSS_S_COMPLETE,
    GSS_S_FAILURE,
    GSS_S_CONTINUE_NEEDED,
    GSSAPI_BLOB,
)
from scapy.layers.inet import TCP

try:
    import brotli
    _is_brotli_available = True
except ImportError:
    _is_brotli_available = False

try:
    import lzw
    _is_lzw_available = True
except ImportError:
    _is_lzw_available = False

try:
    import zstandard
    _is_zstd_available = True
except ImportError:
    _is_zstd_available = False

if "http" not in conf.contribs:
    conf.contribs["http"] = {}
    conf.contribs["http"]["auto_compression"] = True
    conf.contribs["http"]["auto_chunk"] = True

# https://en.wikipedia.org/wiki/List_of_HTTP_header_fields

GENERAL_HEADERS = [
    "Cache-Control",
    "Connection",
    "Permanent",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Keep-Alive",
    "Pragma",
    "Upgrade",
    "Via",
    "Warning"
]

COMMON_UNSTANDARD_GENERAL_HEADERS = [
    "X-Request-ID",
    "X-Correlation-ID"
]

REQUEST_HEADERS = [
    "A-IM",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Datetime",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
    "Authorization",
    "Cookie",
    "Expect",
    "Forwarded",
    "From",
    "Host",
    "HTTP2-Settings",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent"
]

COMMON_UNSTANDARD_REQUEST_HEADERS = [
    "Upgrade-Insecure-Requests",
    "X-Requested-With",
    "DNT",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Front-End-Https",
    "X-Http-Method-Override",
    "X-ATT-DeviceId",
    "X-Wap-Profile",
    "Proxy-Connection",
    "X-UIDH",
    "X-Csrf-Token",
    "Save-Data",
]

RESPONSE_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Accept-Patch",
    "Accept-Ranges",
    "Age",
    "Allow",
    "Alt-Svc",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Location",
    "Content-Range",
    "Delta-Base",
    "ETag",
    "Expires",
    "IM",
    "Last-Modified",
    "Link",
    "Location",
    "P3P",
    "Proxy-Authenticate",
    "Public-Key-Pins",
    "Retry-After",
    "Server",
    "Set-Cookie",
    "Strict-Transport-Security",
    "Trailer",
    "Transfer-Encoding",
    "Tk",
    "Vary",
    "WWW-Authenticate",
    "X-Frame-Options",
]

COMMON_UNSTANDARD_RESPONSE_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Security-Policy",
    "X-WebKit-CSP",
    "Refresh",
    "Status",
    "Timing-Allow-Origin",
    "X-Content-Duration",
    "X-Content-Type-Options",
    "X-Powered-By",
    "X-UA-Compatible",
    "X-XSS-Protection",
]

# Dissection / Build tools


def _strip_header_name(name):
    """Takes a header key (i.e., "Host" in "Host: www.google.com",
    and returns a stripped representation of it
    """
    return plain_str(name.strip()).replace("-", "_")


def _header_line(name, val):
    """Creates a HTTP header line"""
    # Python 3.4 doesn't support % on bytes
    return bytes_encode(name) + b": " + bytes_encode(val)


def _parse_headers(s):
    headers = s.split(b"\r\n")
    headers_found = {}
    for header_line in headers:
        try:
            key, value = header_line.split(b':', 1)
        except ValueError:
            continue
        header_key = _strip_header_name(key).lower()
        headers_found[header_key] = (key, value.strip())
    return headers_found


def _parse_headers_and_body(s):
    ''' Takes a HTTP packet, and returns a tuple containing:
      _ the first line (e.g., "GET ...")
      _ the headers in a dictionary
      _ the body
    '''
    crlfcrlf = b"\r\n\r\n"
    crlfcrlfIndex = s.find(crlfcrlf)
    if crlfcrlfIndex != -1:
        headers = s[:crlfcrlfIndex + len(crlfcrlf)]
        body = s[crlfcrlfIndex + len(crlfcrlf):]
    else:
        headers = s
        body = b''
    first_line, headers = headers.split(b"\r\n", 1)
    return first_line.strip(), _parse_headers(headers), body


def _dissect_headers(obj, s):
    """Takes a HTTP packet as the string s, and populates the scapy layer obj
    (either HTTPResponse or HTTPRequest). Returns the first line of the
    HTTP packet, and the body
    """
    first_line, headers, body = _parse_headers_and_body(s)
    for f in obj.fields_desc:
        # We want to still parse wrongly capitalized fields
        stripped_name = _strip_header_name(f.name).lower()
        try:
            _, value = headers.pop(stripped_name)
        except KeyError:
            continue
        obj.setfieldval(f.name, value)
    if headers:
        headers = dict(headers.values())
        obj.setfieldval('Unknown_Headers', headers)
    return first_line, body


class _HTTPContent(Packet):
    __slots__ = ["_original_len"]

    # https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Transfer-Encoding
    def _get_encodings(self):
        encodings = []
        if isinstance(self, HTTPResponse):
            if self.Transfer_Encoding:
                encodings += [plain_str(x).strip().lower() for x in
                              plain_str(self.Transfer_Encoding).split(",")]
            if self.Content_Encoding:
                encodings += [plain_str(x).strip().lower() for x in
                              plain_str(self.Content_Encoding).split(",")]
        return encodings

    def hashret(self):
        return b"HTTP1"

    def post_dissect(self, s):
        self._original_len = len(s)
        encodings = self._get_encodings()
        # Un-chunkify
        if conf.contribs["http"]["auto_chunk"] and "chunked" in encodings:
            data = b""
            while s:
                length, _, body = s.partition(b"\r\n")
                try:
                    length = int(length, 16)
                except ValueError:
                    # Not a valid chunk. Ignore
                    break
                else:
                    load = body[:length]
                    if body[length:length + 2] != b"\r\n":
                        # Invalid chunk. Ignore
                        break
                    s = body[length + 2:]
                    data += load
            if not s:
                s = data
        if not conf.contribs["http"]["auto_compression"]:
            return s
        # Decompress
        try:
            if "deflate" in encodings:
                import zlib
                s = zlib.decompress(s)
            elif "gzip" in encodings:
                s = gzip.decompress(s)
            elif "compress" in encodings:
                if _is_lzw_available:
                    s = lzw.decompress(s)
                else:
                    log_loading.info(
                        "Can't import lzw. compress decompression "
                        "will be ignored !"
                    )
            elif "br" in encodings:
                if _is_brotli_available:
                    s = brotli.decompress(s)
                else:
                    log_loading.info(
                        "Can't import brotli. brotli decompression "
                        "will be ignored !"
                    )
            elif "zstd" in encodings:
                if _is_zstd_available:
                    # Using its streaming API since its simple API could handle
                    # only cases where there is content size data embedded in
                    # the frame
                    bio = io.BytesIO(s)
                    reader = zstandard.ZstdDecompressor().stream_reader(bio)
                    s = reader.read()
                else:
                    log_loading.info(
                        "Can't import zstandard. zstd decompression "
                        "will be ignored !"
                    )
        except Exception:
            # Cannot decompress - probably incomplete data
            pass
        return s

    def post_build(self, pkt, pay):
        encodings = self._get_encodings()
        if conf.contribs["http"]["auto_compression"]:
            # Compress
            if "deflate" in encodings:
                import zlib
                pay = zlib.compress(pay)
            elif "gzip" in encodings:
                pay = gzip.compress(pay)
            elif "compress" in encodings:
                if _is_lzw_available:
                    pay = lzw.compress(pay)
                else:
                    log_loading.info(
                        "Can't import lzw. compress compression "
                        "will be ignored !"
                    )
            elif "br" in encodings:
                if _is_brotli_available:
                    pay = brotli.compress(pay)
                else:
                    log_loading.info(
                        "Can't import brotli. brotli compression will "
                        "be ignored !"
                    )
            elif "zstd" in encodings:
                if _is_zstd_available:
                    pay = zstandard.ZstdCompressor().compress(pay)
                else:
                    log_loading.info(
                        "Can't import zstandard. zstd compression will "
                        "be ignored !"
                    )
        # Chunkify
        if conf.contribs["http"]["auto_chunk"] and "chunked" in encodings:
            # Dumb: 1 single chunk.
            pay = (b"%X" % len(pay)) + b"\r\n" + pay + b"\r\n0\r\n\r\n"
        return pkt + pay

    def self_build(self, **kwargs):
        ''' Takes an HTTPRequest or HTTPResponse object, and creates its
        string representation.'''
        if not isinstance(self.underlayer, HTTP):
            warning(
                "An HTTPResponse/HTTPRequest should always be below an HTTP"
            )
        # Check for cache
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        p = b""
        encodings = self._get_encodings()
        # Walk all the fields, in order
        for i, f in enumerate(self.fields_desc):
            if f.name == "Unknown_Headers":
                continue
            # Get the field value
            val = self.getfieldval(f.name)
            if not val:
                if f.name == "Content_Length" and "chunked" not in encodings:
                    # Add Content-Length anyways
                    val = str(len(self.payload or b""))
                elif f.name == "Date" and isinstance(self, HTTPResponse):
                    val = datetime.datetime.now(datetime.timezone.utc).strftime(
                        '%a, %d %b %Y %H:%M:%S GMT'
                    )
                else:
                    # Not specified. Skip
                    continue

            if i >= 3:
                val = _header_line(f.real_name, val)
            # Fields used in the first line have a space as a separator,
            # whereas headers are terminated by a new line
            if i <= 1:
                separator = b' '
            else:
                separator = b'\r\n'
            # Add the field into the packet
            p = f.addfield(self, p, val + separator)
        # Handle Unknown_Headers
        if self.Unknown_Headers:
            headers_text = b""
            for name, value in self.Unknown_Headers.items():
                headers_text += _header_line(name, value) + b"\r\n"
            p = self.get_field("Unknown_Headers").addfield(
                self, p, headers_text
            )
        # The packet might be empty, and in that case it should stay empty.
        if p:
            # Add an additional line after the last header
            p = f.addfield(self, p, b'\r\n')
        return p

    def guess_payload_class(self, payload):
        """Detect potential payloads
        """
        if not hasattr(self, "Connection"):
            return super(_HTTPContent, self).guess_payload_class(payload)
        if self.Connection and b"Upgrade" in self.Connection:
            from scapy.contrib.http2 import H2Frame
            return H2Frame
        return super(_HTTPContent, self).guess_payload_class(payload)


class _HTTPHeaderField(StrField):
    """Modified StrField to handle HTTP Header names"""
    __slots__ = ["real_name"]

    def __init__(self, name, default):
        self.real_name = name
        name = _strip_header_name(name)
        StrField.__init__(self, name, default, fmt="H")

    def i2repr(self, pkt, x):
        if isinstance(x, bytes):
            return x.decode(errors="backslashreplace")
        return x


def _generate_headers(*args):
    """Generate the header fields based on their name"""
    # Order headers
    all_headers = []
    for headers in args:
        all_headers += headers
    # Generate header fields
    results = []
    for h in sorted(all_headers):
        results.append(_HTTPHeaderField(h, None))
    return results

# Create Request and Response packets


class HTTPRequest(_HTTPContent):
    name = "HTTP Request"
    fields_desc = [
        # First line
        _HTTPHeaderField("Method", "GET"),
        _HTTPHeaderField("Path", "/"),
        _HTTPHeaderField("Http-Version", "HTTP/1.1"),
        # Headers
    ] + (
        _generate_headers(
            GENERAL_HEADERS,
            REQUEST_HEADERS,
            COMMON_UNSTANDARD_GENERAL_HEADERS,
            COMMON_UNSTANDARD_REQUEST_HEADERS
        )
    ) + [
        _HTTPHeaderField("Unknown-Headers", None),
    ]

    def do_dissect(self, s):
        """From the HTTP packet string, populate the scapy object"""
        first_line, body = _dissect_headers(self, s)
        try:
            Method, Path, HTTPVersion = re.split(br"\s+", first_line, maxsplit=2)
            self.setfieldval('Method', Method)
            self.setfieldval('Path', Path)
            self.setfieldval('Http_Version', HTTPVersion)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[:-len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%HTTPRequest.Method% '%HTTPRequest.Path%' "
        )


class HTTPResponse(_HTTPContent):
    name = "HTTP Response"
    fields_desc = [
        # First line
        _HTTPHeaderField("Http-Version", "HTTP/1.1"),
        _HTTPHeaderField("Status-Code", "200"),
        _HTTPHeaderField("Reason-Phrase", "OK"),
        # Headers
    ] + (
        _generate_headers(
            GENERAL_HEADERS,
            RESPONSE_HEADERS,
            COMMON_UNSTANDARD_GENERAL_HEADERS,
            COMMON_UNSTANDARD_RESPONSE_HEADERS
        )
    ) + [
        _HTTPHeaderField("Unknown-Headers", None),
    ]

    def answers(self, other):
        return HTTPRequest in other

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        try:
            HTTPVersion, Status, Reason = re.split(br"\s+", first_line, maxsplit=2)
            self.setfieldval('Http_Version', HTTPVersion)
            self.setfieldval('Status_Code', Status)
            self.setfieldval('Reason_Phrase', Reason)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[:-len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%HTTPResponse.Status_Code% %HTTPResponse.Reason_Phrase%"
        )

# General HTTP class + defragmentation


class HTTP(Packet):
    name = "HTTP 1"
    fields_desc = []
    show_indent = 0
    clsreq = HTTPRequest
    clsresp = HTTPResponse
    hdr = b"HTTP"
    reqmethods = b"|".join([
        b"OPTIONS",
        b"GET",
        b"HEAD",
        b"POST",
        b"PUT",
        b"DELETE",
        b"TRACE",
        b"CONNECT",
    ])

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 9:
            from scapy.contrib.http2 import _HTTP2_types, H2Frame
            # To detect a valid HTTP2, we check that the type is correct
            # that the Reserved bit is set and length makes sense.
            while _pkt:
                if len(_pkt) < 9:
                    # Invalid total length
                    return cls
                if ord(_pkt[3:4]) not in _HTTP2_types:
                    # Invalid type
                    return cls
                length = struct.unpack("!I", b"\0" + _pkt[:3])[0] + 9
                if length > len(_pkt):
                    # Invalid length
                    return cls
                sid = struct.unpack("!I", _pkt[5:9])[0]
                if sid >> 31 != 0:
                    # Invalid Reserved bit
                    return cls
                _pkt = _pkt[length:]
            return H2Frame
        return cls

    # tcp_reassemble is used by TCPSession in session.py
    @classmethod
    def tcp_reassemble(cls, data, metadata, _):
        detect_end = metadata.get("detect_end", None)
        is_unknown = metadata.get("detect_unknown", True)
        # General idea of the following is explained at
        # https://datatracker.ietf.org/doc/html/rfc2616#section-4.4
        if not detect_end or is_unknown:
            metadata["detect_unknown"] = False
            http_packet = cls(data)
            # Detect packing method
            if not isinstance(http_packet.payload, _HTTPContent):
                return http_packet
            is_response = isinstance(http_packet.payload, cls.clsresp)
            # Packets may have a Content-Length we must honnor
            length = http_packet.Content_Length
            # Heuristic to try and detect instant HEAD responses, as those include a
            # Content-Length that must not be honored. This is a bit crappy, and assumes
            # that a 'HEAD' will never include an Encoding...
            if (
                is_response and
                data.endswith(b"\r\n\r\n") and
                not http_packet[HTTPResponse]._get_encodings()
            ):
                detect_end = lambda _: True
            elif length is not None:
                # The packet provides a Content-Length attribute: let's
                # use it. When the total size of the frags is high enough,
                # we have the packet
                length = int(length)
                # Subtract the length of the "HTTP*" layer
                if http_packet.payload.payload or length == 0:
                    http_length = len(data) - http_packet.payload._original_len
                    detect_end = lambda dat: len(dat) - http_length >= length
                else:
                    # The HTTP layer isn't fully received.
                    detect_end = lambda dat: False
                    metadata["detect_unknown"] = True
            else:
                # It's not Content-Length based. It could be chunked
                encodings = http_packet[cls].payload._get_encodings()
                chunked = ("chunked" in encodings)
                if chunked:
                    detect_end = lambda dat: dat.endswith(b"0\r\n\r\n")
                # HTTP Requests that do not have any content,
                # end with a double CRLF. Same for HEAD responses
                elif isinstance(http_packet.payload, cls.clsreq):
                    detect_end = lambda dat: dat.endswith(b"\r\n\r\n")
                    # In case we are handling a HTTP Request,
                    # we want to continue assessing the data,
                    # to handle requests with a body (POST)
                    metadata["detect_unknown"] = True
                elif is_response and http_packet.Status_Code == b"101":
                    # If it's an upgrade response, it may also hold a
                    # different protocol data.
                    # make sure all headers are present
                    detect_end = lambda dat: dat.find(b"\r\n\r\n")
                else:
                    # If neither Content-Length nor chunked is specified,
                    # it means it's the TCP packet that contains the data,
                    # or that the information hasn't been given yet.
                    detect_end = lambda dat: metadata.get("tcp_end", False)
                    metadata["detect_unknown"] = True
            metadata["detect_end"] = detect_end
            if detect_end(data):
                return http_packet
        else:
            if detect_end(data):
                http_packet = cls(data)
                return http_packet

    def guess_payload_class(self, payload):
        """Decides if the payload is an HTTP Request or Response, or
        something else.
        """
        try:
            prog = re.compile(
                br"^(?:" + self.reqmethods + br") " +
                br"(?:.+?) " +
                self.hdr + br"/\d\.\d$"
            )
            crlfIndex = payload.index(b"\r\n")
            req = payload[:crlfIndex]
            result = prog.match(req)
            if result:
                return self.clsreq
            else:
                prog = re.compile(b"^" + self.hdr + br"/\d\.\d \d\d\d .*$")
                result = prog.match(req)
                if result:
                    return self.clsresp
        except ValueError:
            # Anything that isn't HTTP but on port 80
            pass
        return Raw


class HTTP_AUTH_MECHS(Enum):
    NONE = "NONE"
    BASIC = "Basic"
    NTLM = "NTLM"
    NEGOTIATE = "Negotiate"


class HTTP_Client(object):
    """
    A basic HTTP client

    :param mech: one of HTTP_AUTH_MECHS
    :param ssl: whether to use HTTPS or not
    :param ssp: the SSP object to use for binding
    """

    def __init__(
        self,
        mech=HTTP_AUTH_MECHS.NONE,
        verb=True,
        sslcontext=None,
        ssp=None,
        no_check_certificate=False,
    ):
        self.sock = None
        self._sockinfo = None
        self.authmethod = mech
        self.verb = verb
        self.sslcontext = sslcontext
        self.ssp = ssp
        self.sspcontext = None
        self.no_check_certificate = no_check_certificate

    def _connect_or_reuse(self, host, port=None, tls=False, timeout=5):
        # Get the port
        if port is None:
            port = 443 if tls else 80
        # If the current socket matches, keep it.
        if self._sockinfo == (host, port):
            return
        # A new socket is needed
        if self._sockinfo:
            self.close()
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.settimeout(timeout)
        if self.verb:
            print(
                "\u2503 Connecting to %s on port %s%s..."
                % (
                    host,
                    port,
                    " with SSL" if tls else "",
                )
            )
        sock.connect((host, port))
        if self.verb:
            print(
                conf.color_theme.green(
                    "\u2514 Connected from %s" % repr(sock.getsockname())
                )
            )
        if tls:
            if self.sslcontext is None:
                if self.no_check_certificate:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context = ssl.create_default_context()
            else:
                context = self.sslcontext
            sock = context.wrap_socket(sock, server_hostname=host)
            self.sock = SSLStreamSocket(sock, HTTP)
        else:
            self.sock = StreamSocket(sock, HTTP)
        # Store information regarding the current socket
        self._sockinfo = (host, port)

    def sr1(self, req, **kwargs):
        if self.verb:
            print(conf.color_theme.opening(">> %s" % req.summary()))
        resp = self.sock.sr1(
            HTTP() / req,
            verbose=0,
            **kwargs,
        )
        if self.verb:
            print(
                conf.color_theme.success(
                    "<< %s" % (resp and resp.summary())
                )
            )
        return resp

    def request(self, url, data=b"", timeout=5, follow_redirects=True, **headers):
        """
        Perform a HTTP(s) request.
        """
        # Parse request url
        m = re.match(r"(https?)://([^/:]+)(?:\:(\d+))?(?:/(.*))?", url)
        if not m:
            raise ValueError("Bad URL !")
        transport, host, port, path = m.groups()
        if transport == "https":
            tls = True
        else:
            tls = False

        path = path or "/"
        port = port and int(port)

        # Connect (or reuse) socket
        self._connect_or_reuse(host, port=port, tls=tls, timeout=timeout)

        # Build request
        http_headers = {
            "Accept_Encoding": b'gzip, deflate',
            "Cache_Control": b'no-cache',
            "Pragma": b'no-cache',
            "Connection": b'keep-alive',
            "Host": host,
            "Path": path,
        }
        http_headers.update(headers)
        req = HTTP() / HTTPRequest(**http_headers)
        if data:
            req /= data

        while True:
            # Perform the request.
            resp = self.sr1(req)
            if not resp:
                break
            # First case: auth was required. Handle that
            if resp.Status_Code in [b"401", b"407"]:
                # Authentication required
                if self.authmethod in [
                    HTTP_AUTH_MECHS.NTLM,
                    HTTP_AUTH_MECHS.NEGOTIATE,
                ]:
                    # Parse authenticate
                    if b" " in resp.WWW_Authenticate:
                        method, data = resp.WWW_Authenticate.split(b" ", 1)
                        try:
                            ssp_blob = GSSAPI_BLOB(base64.b64decode(data))
                        except Exception:
                            raise Scapy_Exception("Invalid WWW-Authenticate")
                    else:
                        method = resp.WWW_Authenticate
                        ssp_blob = None
                    if plain_str(method) != self.authmethod.value:
                        raise Scapy_Exception("Invalid WWW-Authenticate")
                    # SPNEGO / Kerberos / NTLM
                    self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                        self.sspcontext,
                        ssp_blob,
                        req_flags=0,
                    )
                    if status not in [GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED]:
                        raise Scapy_Exception("Authentication failure")
                    req.Authorization = (
                        self.authmethod.value.encode() + b" " +
                        base64.b64encode(bytes(token))
                    )
                    continue
            # Second case: follow redirection
            if resp.Status_Code in [b"301", b"302"] and follow_redirects:
                return self.request(
                    resp.Location.decode(),
                    data=data,
                    timeout=timeout,
                    follow_redirects=follow_redirects,
                    **headers,
                )
            break
        return resp

    def close(self):
        if self.verb:
            print("X Connection to %s closed\n" % repr(self.sock.ins.getpeername()))
        self.sock.close()


def http_request(host, path="/", port=None, timeout=3,
                 display=False, tls=False, verbose=0, **headers):
    """
    Util to perform an HTTP request.

    :param host: the host to connect to
    :param path: the path of the request (default /)
    :param port: the port (default 80/443)
    :param timeout: timeout before None is returned
    :param display: display the result in the default browser (default False)
    :param iface: interface to use. Changing this turns on "raw"
    :param headers: any additional headers passed to the request

    :returns: the HTTPResponse packet
    """
    client = HTTP_Client(HTTP_AUTH_MECHS.NONE, verb=verbose)
    if port is None:
        port = 443 if tls else 80
    ans = client.request(
        "http%s://%s:%s%s" % (tls and "s" or "", host, port, path),
        timeout=timeout,
    )

    if ans:
        if display:
            if Raw not in ans:
                warning("No HTTP content returned. Cannot display")
                return ans
            # Write file
            file = get_temp_file(autoext=".html")
            with open(file, "wb") as fd:
                fd.write(ans.load)
            # Open browser
            if WINDOWS:
                os.startfile(file)
            else:
                with ContextManagerSubprocess(conf.prog.universal_open):
                    subprocess.Popen([conf.prog.universal_open, file])
        return ans


# Bindings


bind_bottom_up(TCP, HTTP, sport=80)
bind_bottom_up(TCP, HTTP, dport=80)
bind_layers(TCP, HTTP, sport=80, dport=80)

bind_bottom_up(TCP, HTTP, sport=8080)
bind_bottom_up(TCP, HTTP, dport=8080)


# Automatons

class HTTP_Server(Automaton):
    """
    HTTP server automaton

    :param ssp: the SSP to serve. If None, unauthenticated (or basic).
    :param mech: the HTTP_AUTH_MECHS to use (default: NONE)

    Other parameters:

    :param BASIC_IDENTITIES: a dict that contains {"user": "password"} for Basic
                             authentication.
    :param BASIC_REALM: the basic realm.
    """

    pkt_cls = HTTP

    def __init__(
        self,
        mech=HTTP_AUTH_MECHS.NONE,
        verb=True,
        ssp=None,
        *args,
        **kwargs,
    ):
        self.verb = verb
        if "sock" not in kwargs:
            raise ValueError(
                "HTTP_Server cannot be started directly ! Use HTTP_Server.spawn"
            )
        self.ssp = ssp
        self.authmethod = mech.value
        self.sspcontext = None
        self.basic = False
        self.BASIC_IDENTITIES = kwargs.pop("BASIC_IDENTITIES", {})
        self.BASIC_REALM = kwargs.pop("BASIC_REALM", "default")
        if mech == HTTP_AUTH_MECHS.BASIC:
            if not self.BASIC_IDENTITIES:
                raise ValueError("Please provide 'BASIC_IDENTITIES' !")
            if ssp is not None:
                raise ValueError("Can't use 'BASIC_IDENTITIES' with 'ssp' !")
            self.basic = True
        elif mech == HTTP_AUTH_MECHS.NONE:
            if ssp is not None:
                raise ValueError("Cannot use ssp with mech=NONE !")
        # Initialize
        Automaton.__init__(self, *args, **kwargs)

    def send(self, resp):
        self.sock.send(HTTP() / resp)

    def vprint(self, s=""):
        """
        Verbose print (if enabled)
        """
        if self.verb:
            if conf.interactive:
                log_interactive.info("> %s", s)
            else:
                print("> %s" % s)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.authenticated = False
        self.sspcontext = None

    @ATMT.condition(BEGIN, prio=0)
    def should_authenticate(self):
        if self.authmethod == HTTP_AUTH_MECHS.NONE.value:
            raise self.SERVE()
        else:
            raise self.AUTH()

    @ATMT.state()
    def AUTH(self):
        pass

    @ATMT.state()
    def AUTH_ERROR(self, proxy):
        self.sspcontext = None
        self._ask_authorization(proxy, self.authmethod)
        self.vprint("AUTH ERROR")

    @ATMT.condition(AUTH_ERROR)
    def allow_reauth(self):
        raise self.AUTH()

    def _ask_authorization(self, proxy, data):
        if proxy:
            self.send(
                HTTPResponse(
                    Status_Code=b"407",
                    Reason_Phrase=b"Proxy Authentication Required",
                    Proxy_Authenticate=data,
                )
            )
        else:
            self.send(
                HTTPResponse(
                    Status_Code=b"401",
                    Reason_Phrase=b"Unauthorized",
                    WWW_Authenticate=data,
                )
            )

    @ATMT.receive_condition(AUTH, prio=1)
    def received_unauthenticated(self, pkt):
        if HTTPRequest in pkt:
            self.vprint(pkt.summary())
            if pkt.Method == b"CONNECT":
                # HTTP tunnel (proxy)
                proxy = True
            else:
                # HTTP non-tunnel
                proxy = False
            # Get authorization
            if proxy:
                authorization = pkt.Proxy_Authorization
            else:
                authorization = pkt.Authorization
            if not authorization:
                # Initial ask.
                data = self.authmethod
                if self.basic:
                    data += " realm='%s'" % self.BASIC_REALM
                self._ask_authorization(proxy, data)
                return
            # Parse authorization
            method, data = authorization.split(b" ", 1)
            if plain_str(method) != self.authmethod:
                raise self.AUTH_ERROR(proxy)
            try:
                data = base64.b64decode(data)
            except Exception:
                raise self.AUTH_ERROR(proxy)
            # Now process the authorization
            if not self.basic:
                try:
                    ssp_blob = GSSAPI_BLOB(data)
                except Exception:
                    self.sspcontext = None
                    self._ask_authorization(proxy, self.authmethod)
                    raise self.AUTH_ERROR(proxy)
                # And call the SSP
                self.sspcontext, tok, status = self.ssp.GSS_Accept_sec_context(
                    self.sspcontext, ssp_blob
                )
            else:
                # This is actually Basic authentication
                try:
                    next(
                        True
                        for k, v in self.BASIC_IDENTITIES.items()
                        if ("%s:%s" % (k, v)).encode() == data
                    )
                    tok, status = None, GSS_S_COMPLETE
                except StopIteration:
                    tok, status = None, GSS_S_FAILURE
            # Send answer
            if status not in [GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED]:
                raise self.AUTH_ERROR(proxy)
            elif status == GSS_S_CONTINUE_NEEDED:
                data = self.authmethod.encode()
                if tok:
                    data += b" " + base64.b64encode(bytes(tok))
                self._ask_authorization(proxy, data)
                raise self.AUTH()
            else:
                # Authenticated !
                self.authenticated = True
                self.vprint("AUTH OK")
                raise self.SERVE(pkt)

    @ATMT.eof(AUTH)
    def auth_eof(self):
        raise self.CLOSED()

    @ATMT.state(error=1)
    def ERROR(self):
        self.send(
            HTTPResponse(
                Status_Code="400",
                Reason_Phrase="Bad Request",
            )
        )

    @ATMT.state(final=1)
    def CLOSED(self):
        self.vprint("CLOSED")

    # Serving

    @ATMT.state()
    def SERVE(self, pkt=None):
        if pkt is None:
            return
        answer = self.answer(pkt)
        if answer:
            self.send(answer)
            self.vprint("%s -> %s" % (pkt.summary(), answer.summary()))
        else:
            self.vprint("%s" % pkt.summary())

    @ATMT.eof(SERVE)
    def serve_eof(self):
        raise self.CLOSED()

    @ATMT.receive_condition(SERVE)
    def new_request(self, pkt):
        raise self.SERVE(pkt)

    # DEV: overwrite this function

    def answer(self, pkt):
        """
        HTTP_server answer function.

        :param pkt: a HTTPRequest packet
        :returns: a HTTPResponse packet
        """
        if pkt.Path == b"/":
            return HTTPResponse() / (
                "<!doctype html><html><body><h1>OK</h1></body></html>"
            )
        else:
            return HTTPResponse(
                Status_Code=b"404",
                Reason_Phrase=b"Not Found",
            ) / (
                "<!doctype html><html><body><h1>404 - Not Found</h1></body></html>"
            )


class HTTPS_Server(HTTP_Server):
    """
    HTTPS server automaton

    This has the same arguments and attributes as HTTP_Server, with the addition of:

    :param sslcontext: an optional SSLContext object.
                       If used, cert and key are ignored.
    :param cert: path to the certificate
    :param key: path to the key
    """

    socketcls = None

    def __init__(
        self,
        mech=HTTP_AUTH_MECHS.NONE,
        verb=True,
        cert=None,
        key=None,
        sslcontext=None,
        ssp=None,
        *args,
        **kwargs,
    ):
        if "sock" not in kwargs:
            raise ValueError(
                "HTTPS_Server cannot be started directly ! Use HTTPS_Server.spawn"
            )
        # wrap socket in SSL
        if sslcontext is None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
        else:
            context = sslcontext
        kwargs["sock"] = SSLStreamSocket(
            context.wrap_socket(kwargs["sock"], server_side=True),
            self.pkt_cls,
        )
        super(HTTPS_Server, self).__init__(
            mech=mech,
            verb=verb,
            ssp=ssp,
            *args,
            **kwargs,
        )
