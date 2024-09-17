#! /usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = Diagnostic over IP (DoIP) / ISO 13400
# scapy.contrib.status = loads

import socket
import ssl
import struct
import time
from typing import (
    Any,
    Union,
    Tuple,
    Optional,
    Dict,
    Type,
)

from scapy.contrib.automotive import log_automotive
from scapy.contrib.automotive.uds import UDS
from scapy.data import MTU
from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    IntField,
    MayEnd,
    StrFixedLenField,
    XByteEnumField,
    XByteField,
    XIntField,
    XShortEnumField,
    XShortField,
    XStrField,
)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.supersocket import SSLStreamSocket


# ISO 13400-2 sect 9.2


class DoIP(Packet):
    """
    Implementation of the DoIP (ISO 13400) protocol. DoIP packets can be sent
    via UDP and TCP. Depending on the payload type, the correct connection
    need to be chosen:

    +--------------+--------------------------------------------------------------+-----------------+
    | Payload Type | Payload Type Name                                            | Connection Kind |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0000       | Generic DoIP header negative acknowledge                     | UDP / TCP       |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0001       | Vehicle Identification request message                       | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0002       | Vehicle identification request message with EID              | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0003       | Vehicle identification request message with VIN              | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0004       | Vehicle announcement message/vehicle identification response | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0005       | Routing activation request                                   | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0006       | Routing activation response                                  | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0007       | Alive Check request                                          | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x0008       | Alive Check response                                         | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x4001       | IP entity status request                                     | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x4002       | DoIP entity status response                                  | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x4003       | Diagnostic power mode information request                    | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x4004       | Diagnostic power mode information response                   | UDP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x8001       | Diagnostic message                                           | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x8002       | Diagnostic message positive acknowledgement                  | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+
    | 0x8003       | Diagnostic message negative acknowledgement                  | TCP             |
    +--------------+--------------------------------------------------------------+-----------------+

    Example with UDP:
        >>> socket = L3RawSocket(iface="eth0")
        >>> resp = socket.sr1(IP(dst="169.254.117.238")/UDP(dport=13400)/DoIP(payload_type=1))

    Example with TCP:
        >>> socket = DoIPSocket("169.254.117.238")
        >>> pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)

    Example with UDS:
        >>> socket = UDS_DoIPSocket("169.254.117.238")
        >>> pkt = UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)
    """  # noqa: E501
    payload_types = {
        0x0000: "Generic DoIP header NACK",
        0x0001: "Vehicle identification request",
        0x0002: "Vehicle identification request with EID",
        0x0003: "Vehicle identification request with VIN",
        0x0004: "Vehicle announcement message/vehicle identification response message",  # noqa: E501
        0x0005: "Routing activation request",
        0x0006: "Routing activation response",
        0x0007: "Alive check request",
        0x0008: "Alive check response",
        0x4001: "DoIP entity status request",
        0x4002: "DoIP entity status response",
        0x4003: "Diagnostic power mode information request",
        0x4004: "Diagnostic power mode information response",
        0x8001: "Diagnostic message",
        0x8002: "Diagnostic message ACK",
        0x8003: "Diagnostic message NACK"}
    name = 'DoIP'
    fields_desc = [
        XByteField("protocol_version", 0x02),
        XByteField("inverse_version", 0xFD),
        XShortEnumField("payload_type", 0, payload_types),
        IntField("payload_length", None),
        ConditionalField(ByteEnumField("nack", 0, {
            0: "Incorrect pattern format", 1: "Unknown payload type",
            2: "Message too large", 3: "Out of memory",
            4: "Invalid payload length"
        }), lambda p: p.payload_type in [0x0]),
        ConditionalField(StrFixedLenField("vin", b"", 17),
                         lambda p: p.payload_type in [3, 4]),
        ConditionalField(XShortField("logical_address", 0),
                         lambda p: p.payload_type in [4]),
        ConditionalField(StrFixedLenField("eid", b"", 6),
                         lambda p: p.payload_type in [2, 4]),
        ConditionalField(StrFixedLenField("gid", b"", 6),
                         lambda p: p.payload_type in [4]),
        ConditionalField(MayEnd(XByteEnumField("further_action", 0, {
            0x00: "No further action required",
            0x01: "Reserved by ISO 13400", 0x02: "Reserved by ISO 13400",
            0x03: "Reserved by ISO 13400", 0x04: "Reserved by ISO 13400",
            0x05: "Reserved by ISO 13400", 0x06: "Reserved by ISO 13400",
            0x07: "Reserved by ISO 13400", 0x08: "Reserved by ISO 13400",
            0x09: "Reserved by ISO 13400", 0x0a: "Reserved by ISO 13400",
            0x0b: "Reserved by ISO 13400", 0x0c: "Reserved by ISO 13400",
            0x0d: "Reserved by ISO 13400", 0x0e: "Reserved by ISO 13400",
            0x0f: "Reserved by ISO 13400",
            0x10: "Routing activation required to initiate central security",
        })), lambda p: p.payload_type in [4]),
        # VIN/GID sync. status is marked as optional, so the packet MayEnd
        # on further_action
        ConditionalField(XByteEnumField("vin_gid_status", 0, {
            0x00: "VIN and/or GID are synchronized",
            0x01: "Reserved by ISO 13400", 0x02: "Reserved by ISO 13400",
            0x03: "Reserved by ISO 13400", 0x04: "Reserved by ISO 13400",
            0x05: "Reserved by ISO 13400", 0x06: "Reserved by ISO 13400",
            0x07: "Reserved by ISO 13400", 0x08: "Reserved by ISO 13400",
            0x09: "Reserved by ISO 13400", 0x0a: "Reserved by ISO 13400",
            0x0b: "Reserved by ISO 13400", 0x0c: "Reserved by ISO 13400",
            0x0d: "Reserved by ISO 13400", 0x0e: "Reserved by ISO 13400",
            0x0f: "Reserved by ISO 13400",
            0x10: "Incomplete: VIN and GID are NOT synchronized"
        }), lambda p: p.payload_type in [4]),
        ConditionalField(XShortField("source_address", 0),
                         lambda p: p.payload_type in [5, 8, 0x8001, 0x8002, 0x8003]),  # noqa: E501
        ConditionalField(XByteEnumField("activation_type", 0, {
            0: "Default", 1: "WWH-OBD", 0xe0: "Central security",
            0x16: "Default", 0x116: "Diagnostic", 0xe016: "Central security"
        }), lambda p: p.payload_type in [5]),
        ConditionalField(XShortField("logical_address_tester", 0),
                         lambda p: p.payload_type in [6]),
        ConditionalField(XShortField("logical_address_doip_entity", 0),
                         lambda p: p.payload_type in [6]),
        ConditionalField(XByteEnumField("routing_activation_response", 0, {
            0x00: "Routing activation denied due to unknown source address.",
            0x01: "Routing activation denied because all concurrently supported TCP_DATA sockets are registered and active.",  # noqa: E501
            0x02: "Routing activation denied because an SA different from the table connection entry was received on the already activated TCP_DATA socket.",  # noqa: E501
            0x03: "Routing activation denied because the SA is already registered and active on a different TCP_DATA socket.",  # noqa: E501
            0x04: "Routing activation denied due to missing authentication.",
            0x05: "Routing activation denied due to rejected confirmation.",
            0x06: "Routing activation denied due to unsupported routing activation type.",  # noqa: E501
            0x07: "Routing activation denied because the specified activation type requires a secure TLS TCP_DATA socket.",  # noqa: E501
            0x08: "Reserved by ISO 13400.",
            0x09: "Reserved by ISO 13400.", 0x0a: "Reserved by ISO 13400.",
            0x0b: "Reserved by ISO 13400.", 0x0c: "Reserved by ISO 13400.",
            0x0d: "Reserved by ISO 13400.", 0x0e: "Reserved by ISO 13400.",
            0x0f: "Reserved by ISO 13400.",
            0x10: "Routing successfully activated.",
            0x11: "Routing will be activated; confirmation required."
        }), lambda p: p.payload_type in [6]),
        ConditionalField(XIntField("reserved_iso", 0),
                         lambda p: p.payload_type in [5, 6]),
        ConditionalField(XStrField("reserved_oem", b""),
                         lambda p: p.payload_type in [5, 6]),
        ConditionalField(XByteEnumField("diagnostic_power_mode", 0, {
            0: "not ready", 1: "ready", 2: "not supported"
        }), lambda p: p.payload_type in [0x4004]),
        ConditionalField(ByteEnumField("node_type", 0, {
            0: "DoIP gateway", 1: "DoIP node"
        }), lambda p: p.payload_type in [0x4002]),
        ConditionalField(XByteField("max_open_sockets", 1),
                         lambda p: p.payload_type in [0x4002]),
        ConditionalField(XByteField("cur_open_sockets", 0),
                         lambda p: p.payload_type in [0x4002]),
        ConditionalField(IntField("max_data_size", 0),
                         lambda p: p.payload_type in [0x4002]),
        ConditionalField(XShortField("target_address", 0),
                         lambda p: p.payload_type in [0x8001, 0x8002, 0x8003]),  # noqa: E501
        ConditionalField(XByteEnumField("ack_code", 0, {0: "ACK"}),
                         lambda p: p.payload_type in [0x8002]),
        ConditionalField(ByteEnumField("nack_code", 0, {
            0x00: "Reserved by ISO 13400", 0x01: "Reserved by ISO 13400",
            0x02: "Invalid source address", 0x03: "Unknown target address",
            0x04: "Diagnostic message too large", 0x05: "Out of memory",
            0x06: "Target unreachable", 0x07: "Unknown network",
            0x08: "Transport protocol error"
        }), lambda p: p.payload_type in [0x8003]),
        ConditionalField(XStrField("previous_msg", b""),
                         lambda p: p.payload_type in [0x8002, 0x8003])
    ]

    def answers(self, other):
        # type: (Packet) -> int
        """DEV: true if self is an answer from other"""
        if isinstance(other, type(self)):
            if self.payload_type == 0:
                return 1

            matches = [(4, 1), (4, 2), (4, 3), (6, 5), (8, 7),
                       (0x4002, 0x4001), (0x4004, 0x4003),
                       (0x8001, 0x8001), (0x8003, 0x8001)]
            if (self.payload_type, other.payload_type) in matches:
                if self.payload_type == 0x8001:
                    return self.payload.answers(other.payload)
                return 1
        return 0

    def hashret(self):
        # type: () -> bytes
        if self.payload_type in [0x8001, 0x8002, 0x8003]:
            return bytes(self)[:2] + struct.pack(
                "H", self.target_address ^ self.source_address)
        return bytes(self)[:2]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """
        This will set the Field 'payload_length' to the correct value.
        """
        if self.payload_length is None:
            pkt = pkt[:4] + struct.pack(
                "!I", len(pay) + len(pkt) - 8) + pkt[8:]
        return pkt + pay

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        if self.payload_type == 0x8001:
            return s[:self.payload_length - 4], s[self.payload_length - 4:]
        else:
            return b"", s

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        # type: (bytes, Dict[str, Any], Dict[str, Any]) -> Optional[Packet]
        length = struct.unpack("!I", data[4:8])[0] + 8
        if len(data) >= length:
            return DoIP(data)
        return None


bind_bottom_up(UDP, DoIP, sport=13400)
bind_bottom_up(UDP, DoIP, dport=13400)
bind_layers(UDP, DoIP, sport=13400, dport=13400)

bind_layers(TCP, DoIP, sport=13400)
bind_layers(TCP, DoIP, dport=13400)

bind_layers(DoIP, UDS, payload_type=0x8001)


class DoIPSSLStreamSocket(SSLStreamSocket):
    """Custom SSLStreamSocket for DoIP communication.
    """

    def __init__(self, sock, basecls=None):
        # type: (socket.socket, Optional[Type[Packet]]) -> None
        super(DoIPSSLStreamSocket, self).__init__(sock, basecls or DoIP)
        self.buffer = b""

    def recv(self, x=MTU, **kwargs):
        # type: (Optional[int], **Any) -> Optional[Packet]
        if len(self.buffer) < 8:
            self.buffer += self.ins.recv(8)
        if len(self.buffer) < 8:
            return None
        len_data = self.buffer[:8]

        len_int = struct.unpack(">I", len_data[4:8])[0]
        len_int += 8

        self.buffer += self.ins.recv(len_int - len(self.buffer))
        if len(self.buffer) < len_int:
            return None
        pktbuf = self.buffer[:len_int]
        self.buffer = self.buffer[len_int:]

        pkt = self.basecls(pktbuf, **kwargs)  # type: Packet
        return pkt


class DoIPSocket(DoIPSSLStreamSocket):
    """Socket for DoIP communication. This sockets automatically
    sends a routing activation request as soon as a TCP or TLS connection is
    established.

    :param ip: IP address of destination
    :param port: destination port, usually 13400
    :param tls_port: destination port for TLS connection, usually 3496
    :param activate_routing: If true, routing activation request is
                             automatically sent
    :param source_address: DoIP source address
    :param target_address: DoIP target address, this is automatically
                           determined if routing activation request is sent
    :param activation_type: This allows to set a different activation type for
                            the routing activation request
    :param reserved_oem: Optional parameter to set value for reserved_oem field
                         of routing activation request
    :param force_tls: Skip establishing of a TCP connection and directly try to
                      connect via SSL/TLS
    :param context: Optional ssl.SSLContext object for initialization of ssl socket
                    connections.

    Example:
        >>> socket = DoIPSocket("169.254.0.131")
        >>> pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)
    """  # noqa: E501

    def __init__(self,
                 ip='127.0.0.1',  # type: str
                 port=13400,  # type: int
                 tls_port=3496,  # type: int
                 activate_routing=True,  # type: bool
                 source_address=0xe80,  # type: int
                 target_address=0,  # type: int
                 activation_type=0,  # type: int
                 reserved_oem=b"",  # type: bytes
                 force_tls=False,  # type: bool
                 context=None  # type: Optional[ssl.SSLContext]
                 ):  # type: (...) -> None
        self.ip = ip
        self.port = port
        self.tls_port = tls_port
        self.activate_routing = activate_routing
        self.source_address = source_address
        self.target_address = target_address
        self.activation_type = activation_type
        self.reserved_oem = reserved_oem
        self.force_tls = force_tls
        self.context = context
        try:
            self._init_socket()
        except Exception:
            self.close()
            raise

    def _init_socket(self):
        # type: () -> None
        connected = False
        addrinfo = socket.getaddrinfo(self.ip, self.port, proto=socket.IPPROTO_TCP)
        sock_family = addrinfo[0][0]

        s = socket.socket(sock_family, socket.SOCK_STREAM)
        s.settimeout(5)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if not self.force_tls:
            s.connect(addrinfo[0][-1])
            connected = True
            DoIPSSLStreamSocket.__init__(self, s)

            if not self.activate_routing:
                return

            activation_return = self._activate_routing()
        else:
            # Let's overwrite activation_return to force TLS Connection
            activation_return = 0x07

        if activation_return == 0x10:
            # Routing successfully activated.
            return
        elif activation_return == 0x07:
            # Routing activation denied because the specified activation
            # type requires a secure TLS TCP_DATA socket.
            if self.context is None:
                raise ValueError("SSLContext 'context' can not be None")
            if connected:
                s.close()
                s = socket.socket(sock_family, socket.SOCK_STREAM)
                s.settimeout(5)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            ss = self.context.wrap_socket(s)
            addrinfo = socket.getaddrinfo(
                self.ip, self.tls_port, proto=socket.IPPROTO_TCP)
            ss.connect(addrinfo[0][-1])
            DoIPSSLStreamSocket.__init__(self, ss)

            if not self.activate_routing:
                return

            activation_return = self._activate_routing()
            if activation_return == 0x10:
                # Routing successfully activated.
                return
            else:
                raise Exception(
                    "DoIPSocket activate_routing failed with "
                    "routing_activation_response 0x%x" % activation_return)

        elif activation_return == -1:
            raise Exception("DoIPSocket._activate_routing failed")
        else:
            raise Exception(
                "DoIPSocket activate_routing failed with "
                "routing_activation_response 0x%x!" % activation_return)

    def _activate_routing(self):  # type: (...) -> int
        resp = self.sr1(
            DoIP(payload_type=0x5, activation_type=self.activation_type,
                 source_address=self.source_address, reserved_oem=self.reserved_oem),
            verbose=False, timeout=1)
        if resp and resp.payload_type == 0x6 and \
                resp.routing_activation_response == 0x10:
            self.target_address = (
                self.target_address or resp.logical_address_doip_entity)
            log_automotive.info(
                "Routing activation successful! Target address set to: 0x%x",
                self.target_address)
        else:
            log_automotive.error(
                "Routing activation failed! Response: %s", repr(resp))

        if resp and resp.payload_type == 0x6:
            return resp.routing_activation_response
        else:
            return -1


class UDS_DoIPSocket(DoIPSocket):
    """
    Application-Layer socket for DoIP endpoints. This socket takes care about
    the encapsulation of UDS packets into DoIP packets.

    Example:
        >>> socket = UDS_DoIPSocket("169.254.117.238")
        >>> pkt = UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)
    """

    def send(self, x):
        # type: (Union[Packet, bytes]) -> int
        if isinstance(x, UDS):
            pkt = DoIP(payload_type=0x8001,
                       source_address=self.source_address,
                       target_address=self.target_address
                       ) / x
        else:
            pkt = x

        try:
            x.sent_time = time.time()  # type: ignore
        except AttributeError:
            pass

        return super().send(pkt)

    def recv(self, x=MTU, **kwargs):
        # type: (Optional[int], **Any) -> Optional[Packet]
        pkt = super().recv(x, **kwargs)
        if pkt and pkt.payload_type == 0x8001:
            return pkt.payload
        else:
            return pkt

    pass
