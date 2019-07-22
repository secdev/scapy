# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) 2019 Gabriel Potter <gabriel@potter.fr>
# Copyright (C) 2012 Luca Invernizzi <invernizzi.l@gmail.com>
# Copyright (C) 2012 Steeve Barbeau <http://www.sbarbeau.fr>

# This program is published under a GPLv2 license

"""
HTTP 1.0 layer.

Load using:
>>> load_layer("http")
Note that this layer ISN'T loaded by default, as quite experimental for now.

To follow HTTP packets streams = group packets together to get the
whole request/answer, use `TCPSession` as:
>>> sniff(session=TCPSession)  # Live on-the-flow session
>>> sniff(offline="./http_chunk.pcap", session=TCPSession)  # pcap

This will decode HTTP packets using `Content_Length` or chunks,
and will also decompress the packets when needed.
Note: on failure, decompression will be ignored.

You can turn auto-decompression/auto-compression off with:
>>> conf.contribs["http"]["auto_compression"] = True
"""

# This file is a modified version of the former scapy_http plugin.
# It was reimplemented for scapy 2.4.3+ using sessions, stream handling.
# Original Authors : Steeve Barbeau, Luca Invernizzi
# Originally published under a GPLv2 license

import os
import re
import subprocess

from scapy.compat import plain_str, bytes_encode, \
    gzip_compress, gzip_decompress
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.error import warning
from scapy.fields import StrField
from scapy.packet import Packet, bind_layers, bind_bottom_up, Raw
from scapy.utils import get_temp_file, ContextManagerSubprocess

from scapy.layers.inet import TCP, TCP_client

from scapy.modules import six
from scapy.base_classes import Packet_metaclass
from typing import Any
from typing import Optional
from typing import Dict
from typing import List
from typing import Union
from typing import Tuple

if "http" not in conf.contribs:
    conf.contribs["http"] = {}
    conf.contribs["http"]["auto_compression"] = True

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
    "Permanent",
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
    # type: (Union[bytes, str]) -> str
    """Takes a header key (i.e., "Host" in "Host: www.google.com",
    and returns a stripped representation of it
    """
    return plain_str(name.strip()).replace("-", "_")


def _header_line(name, val):
    """Creates a HTTP header line"""
    # Python 3.4 doesn't support % on bytes
    return bytes_encode(name) + b": " + bytes_encode(val)


def _parse_headers(s):
    # type: (bytes) -> Dict[str, Tuple[bytes, bytes]]
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
    # type: (bytes) -> Tuple[bytes, Dict[str, Tuple[bytes, bytes]], bytes]
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
    # type: (Union[HTTPRequest, HTTPResponse], bytes) -> Tuple[bytes, bytes]
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
        headers = {key: value for key, value in six.itervalues(headers)}
        obj.setfieldval('Unknown_Headers', headers)
    return first_line, body


class _HTTPContent(Packet):
    # https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Transfer-Encoding
    def _get_encodings(self):
        # type: () -> List[str]
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
        # type: () -> bytes
        # The only field both Answers and Responses have in common
        return self.Http_Version

    def post_dissect(self, s):
        # type: (bytes) -> bytes
        if not conf.contribs["http"]["auto_compression"]:
            return s
        encodings = self._get_encodings()
        # Un-chunkify
        if "chunked" in encodings:
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
        # Decompress
        try:
            if "deflate" in encodings:
                import zlib
                s = zlib.decompress(s)
            elif "gzip" in encodings:
                s = gzip_decompress(s)
            elif "compress" in encodings:
                import lzw
                s = lzw.decompress(s)
        except Exception:
            # Cannot decompress - probably incomplete data
            pass
        return s

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        if not conf.contribs["http"]["auto_compression"]:
            return pkt + pay
        encodings = self._get_encodings()
        # Compress
        if "deflate" in encodings:
            import zlib
            pay = zlib.compress(pay)
        elif "gzip" in encodings:
            pay = gzip_compress(pay)
        elif "compress" in encodings:
            import lzw
            pay = lzw.compress(pay)
        return pkt + pay

    def self_build(self, field_pos_list=None):
        # type: (Optional[Any]) -> bytes
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
        # Walk all the fields, in order
        for f in self.fields_desc:
            if f.name == "Unknown_Headers":
                continue
            # Get the field value
            val = self.getfieldval(f.name)
            if not val:
                # Not specified. Skip
                continue
            if f.name not in ['Method', 'Path', 'Reason_Phrase',
                              'Http_Version', 'Status_Code']:
                val = _header_line(f.real_name, val)
            # Fields used in the first line have a space as a separator,
            # whereas headers are terminated by a new line
            if isinstance(self, HTTPRequest):
                if f.name in ['Method', 'Path']:
                    separator = b' '
                else:
                    separator = b'\r\n'
            elif isinstance(self, HTTPResponse):
                if f.name in ['Http_Version', 'Status_Code']:
                    separator = b' '
                else:
                    separator = b'\r\n'
            # Add the field into the packet
            p = f.addfield(self, p, val + separator)
        # Handle Unknown_Headers
        if self.Unknown_Headers:
            headers_text = b""
            for name, value in six.iteritems(self.Unknown_Headers):
                headers_text += _header_line(name, value) + b"\r\n"
            p = self.get_field("Unknown_Headers").addfield(
                self, p, headers_text
            )
        # The packet might be empty, and in that case it should stay empty.
        if p:
            # Add an additional line after the last header
            p = f.addfield(self, p, b'\r\n')
        return p


class _HTTPHeaderField(StrField):
    """Modified StrField to handle HTTP Header names"""
    __slots__ = ["real_name"]

    def __init__(self, name, default):
        # type: (str, Optional[str]) -> None
        self.real_name = name
        name = _strip_header_name(name)
        StrField.__init__(self, name, default, fmt="H")


def _generate_headers(*args):
    # type: (*List[str]) -> List[_HTTPHeaderField]
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
        # type: (bytes) -> bytes
        """From the HTTP packet string, populate the scapy object"""
        first_line, body = _dissect_headers(self, s)
        try:
            Method, Path, HTTPVersion = re.split(br"\s+", first_line, 2)
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
        # type: () -> str
        return self.sprintf(
            "%HTTPRequest.Method% %HTTPRequest.Path% "
            "%HTTPRequest.Http_Version%"
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
        # type: (HTTPRequest) -> bool
        return HTTPRequest in other

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        try:
            HTTPVersion, Status, Reason = re.split(br"\s+", first_line, 2)
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
        # type: () -> str
        return self.sprintf(
            "%HTTPResponse.Http_Version% %HTTPResponse.Status_Code% "
            "%HTTPResponse.Reason_Phrase%"
        )

# General HTTP class + defragmentation


class HTTP(Packet):
    name = "HTTP 1"
    fields_desc = []
    show_indent = 0

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Packet_metaclass
        if _pkt and False:
            # XXX TODO
            from scapy.contrib.contrib.http2 import H2Frame
            return H2Frame
        return cls

    # tcp_reassemble is used by TCPSession in session.py
    @classmethod
    def tcp_reassemble(cls, data, metadata):
        # type: (bytes, Dict[str, Any]) -> Optional[HTTP]
        detect_end = metadata.get("detect_end", None)
        is_unknown = metadata.get("detect_unknown", True)
        if not detect_end or is_unknown:
            metadata["detect_unknown"] = False
            http_packet = HTTP(data)
            # Detect packing method
            if not isinstance(http_packet.payload, _HTTPContent):
                return http_packet
            length = http_packet.Content_Length
            if length is not None:
                # The packet provides a Content-Length attribute: let's
                # use it. When the total size of the frags is high enough,
                # we have the packet
                length = int(length)
                # Subtract the length of the "HTTP*" layer
                if http_packet.payload.payload or length == 0:
                    http_length = len(data) - len(http_packet.payload.payload)
                    detect_end = lambda dat: len(dat) - http_length >= length
                else:
                    # The HTTP layer isn't fully received.
                    detect_end = lambda dat: False
                    metadata["detect_unknown"] = True
            else:
                # It's not Content-Length based. It could be chunked
                encodings = http_packet[HTTP].payload._get_encodings()
                chunked = ("chunked" in encodings)
                if chunked:
                    detect_end = lambda dat: dat.endswith(b"\r\n\r\n")
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
                http_packet = HTTP(data)
                return http_packet

    def guess_payload_class(self, payload):
        # type: (bytes) -> Packet_metaclass
        """Decides if the payload is an HTTP Request or Response, or
        something else.
        """
        try:
            prog = re.compile(
                br"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) "
                br"(?:.+?) "
                br"HTTP/\d\.\d$"
            )
            crlfIndex = payload.index(b"\r\n")
            req = payload[:crlfIndex]
            result = prog.match(req)
            if result:
                return HTTPRequest
            else:
                prog = re.compile(br"^HTTP/\d\.\d \d\d\d .*$")
                result = prog.match(req)
                if result:
                    return HTTPResponse
        except ValueError:
            # Anything that isn't HTTP but on port 80
            pass
        return Raw


def http_request(host,  # type: str
                 path="/",  # type: str
                 port=80,  # type: int
                 timeout=3,  # type: int
                 display=False,  # type: bool
                 verbose=None,  # type: Optional[Any]
                 **headers  # type: Any
                 ):
    # type: (...) -> HTTP
    """Util to perform an HTTP request, using the TCP_client.

    :param host: the host to connect to
    :param path: the path of the request (default /)
    :param port: the port (default 80)
    :param timeout: timeout before None is returned
    :param display: display the resullt in the default browser (default False)
    :param **headers: any additional headers passed to the request

    :returns: the HTTPResponse packet
    """
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
    tcp_client = TCP_client.tcplink(HTTP, host, 80)
    ans = None
    try:
        ans = tcp_client.sr1(req, timeout=timeout, verbose=verbose)
    finally:
        tcp_client.close()
    if ans:
        if display:
            # Write file
            file = get_temp_file(autoext=".html")
            with open(file, "wb") as fd:
                fd.write(ans.load)
            # Open browser
            if WINDOWS:
                os.startfile(file)
            else:
                with ContextManagerSubprocess("http_request()",
                                              conf.prog.universal_open):
                    subprocess.Popen([conf.prog.universal_open, file])
        else:
            return ans


# Bindings


bind_bottom_up(TCP, HTTP, sport=80)
bind_bottom_up(TCP, HTTP, dport=80)
bind_layers(TCP, HTTP, sport=80, dport=80)

bind_bottom_up(TCP, HTTP, sport=8080)
bind_bottom_up(TCP, HTTP, dport=8080)
