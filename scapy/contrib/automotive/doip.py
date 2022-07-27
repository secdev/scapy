#! /usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = Diagnostic over IP (DoIP) / ISO 13400
# scapy.contrib.status = loads

import struct
import socket
import time

from scapy.contrib.automotive import log_automotive
from scapy.fields import ByteEnumField, ConditionalField, \
    XByteField, XShortField, XIntField, XShortEnumField, XByteEnumField, \
    IntField, StrFixedLenField, XStrField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.supersocket import StreamSocket
from scapy.layers.inet import TCP, UDP
from scapy.contrib.automotive.uds import UDS
from scapy.data import MTU
from scapy.compat import Union, Tuple, Optional


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
        ConditionalField(XByteEnumField("further_action", 0, {
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
        }), lambda p: p.payload_type in [4]),
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
            pkt = pkt[:4] + struct.pack("!I", len(pay) + len(pkt) - 8) + \
                pkt[8:]
        return pkt + pay

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        if self.payload_type == 0x8001:
            return s[:self.payload_length - 4], None
        else:
            return b"", None


class DoIPSocket(StreamSocket):
    """ Custom StreamSocket for DoIP communication. This sockets automatically
    sends a routing activation request as soon as a TCP connection is
    established.

    :param ip: IP address of destination
    :param port: destination port, usually 13400
    :param activate_routing: If true, routing activation request is
                             automatically sent
    :param source_address: DoIP source address
    :param target_address: DoIP target address, this is automatically
                           determined if routing activation request is sent
    :param activation_type: This allows to set a different activation type for
                            the routing activation request
    :param reserved_oem: Optional parameter to set value for reserved_oem field
                         of routing activation request

    Example:
        >>> socket = DoIPSocket("169.254.0.131")
        >>> pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)
    """  # noqa: E501
    def __init__(self, ip='127.0.0.1', port=13400, activate_routing=True,
                 source_address=0xe80, target_address=0,
                 activation_type=0, reserved_oem=b""):
        # type: (str, int, bool, int, int, int, bytes) -> None
        self.ip = ip
        self.port = port
        self.source_address = source_address
        self._init_socket()

        if activate_routing:
            self._activate_routing(
                source_address, target_address, activation_type, reserved_oem)

    def _init_socket(self, sock_family=socket.AF_INET):
        # type: (int) -> None
        s = socket.socket(sock_family, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((self.ip, self.port))
        StreamSocket.__init__(self, s, DoIP)

    def _activate_routing(self,
                          source_address,  # type: int
                          target_address,  # type: int
                          activation_type,  # type: int
                          reserved_oem=b""  # type: bytes
                          ):  # type: (...) -> None
        resp = self.sr1(
            DoIP(payload_type=0x5, activation_type=activation_type,
                 source_address=source_address, reserved_oem=reserved_oem),
            verbose=False, timeout=1)
        if resp and resp.payload_type == 0x6 and \
                resp.routing_activation_response == 0x10:
            self.target_address = target_address or \
                resp.logical_address_doip_entity
            log_automotive.info(
                "Routing activation successful! Target address set to: 0x%x",
                self.target_address)
        else:
            log_automotive.error(
                "Routing activation failed! Response: %s", repr(resp))


class DoIPSocket6(DoIPSocket):
    """ Custom StreamSocket for DoIP communication over IPv6.
    This sockets automatically sends a routing activation request as soon as
    a TCP connection is established.

    :param ip: IPv6 address of destination
    :param port: destination port, usually 13400
    :param activate_routing: If true, routing activation request is
                             automatically sent
    :param source_address: DoIP source address
    :param target_address: DoIP target address, this is automatically
                           determined if routing activation request is sent
    :param activation_type: This allows to set a different activation type for
                            the routing activation request
    :param reserved_oem: Optional parameter to set value for reserved_oem field
                         of routing activation request

    Example:
        >>> socket = DoIPSocket6("2001:16b8:3f0e:2f00:21a:37ff:febf:edb9")
        >>> pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)
    """  # noqa: E501
    def __init__(self, ip='::1', port=13400, activate_routing=True,
                 source_address=0xe80, target_address=0,
                 activation_type=0, reserved_oem=b""):
        # type: (str, int, bool, int, int, int, bytes) -> None
        self.ip = ip
        self.port = port
        self.source_address = source_address
        super(DoIPSocket6, self)._init_socket(socket.AF_INET6)

        if activate_routing:
            super(DoIPSocket6, self)._activate_routing(
                source_address, target_address, activation_type, reserved_oem)


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
            pkt = DoIP(payload_type=0x8001, source_address=self.source_address,
                       target_address=self.target_address) / x
        else:
            pkt = x

        try:
            x.sent_time = time.time()  # type: ignore
        except AttributeError:
            pass

        return super(UDS_DoIPSocket, self).send(pkt)

    def recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        pkt = super(UDS_DoIPSocket, self).recv(x)
        if pkt and pkt.payload_type == 0x8001:
            return pkt.payload
        else:
            return pkt


class UDS_DoIPSocket6(DoIPSocket6, UDS_DoIPSocket):
    """
    Application-Layer socket for DoIP endpoints. This socket takes care about
    the encapsulation of UDS packets into DoIP packets.

    Example:
        >>> socket = UDS_DoIPSocket6("2001:16b8:3f0e:2f00:21a:37ff:febf:edb9")
        >>> pkt = UDS() / UDS_RDBI(identifiers=[0x1000])
        >>> resp = socket.sr1(pkt, timeout=1)
    """
    pass


bind_bottom_up(UDP, DoIP, sport=13400)
bind_bottom_up(UDP, DoIP, dport=13400)
bind_layers(UDP, DoIP, sport=13400, dport=13400)

bind_layers(TCP, DoIP, sport=13400)
bind_layers(TCP, DoIP, dport=13400)

bind_layers(DoIP, UDS, payload_type=0x8001)
