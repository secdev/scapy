# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Cesar A. Bernardini <mesarpe@gmail.com>
#               Intern at INRIA Grand Nancy Est
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>
"""
6LoWPAN Protocol Stack
======================

This implementation follows the next documents:

- Transmission of IPv6 Packets over IEEE 802.15.4 Networks: RFC 4944
- Compression Format for IPv6 Datagrams in Low Power and Lossy
  networks (6LoWPAN): RFC 6282
- RFC 4291

+----------------------------+-----------------------+
|  Application               | Application Protocols |
+----------------------------+------------+----------+
|  Transport                 |   UDP      |   TCP    |
+----------------------------+------------+----------+
|  Network                   |          IPv6         |
+----------------------------+-----------------------+
|                            |         LoWPAN        |
+----------------------------+-----------------------+
|  Data Link Layer           |   IEEE 802.15.4 MAC   |
+----------------------------+-----------------------+
|  Physical                  |   IEEE 802.15.4 PHY   |
+----------------------------+-----------------------+

Note that:

 - Only IPv6 is supported
 - LoWPAN is in the middle between network and data link layer

The Internet Control Message protocol v6 (ICMPv6) is used for control
messaging.

Adaptation between full IPv6 and the LoWPAN format is performed by routers at
the edge of 6LoWPAN islands.

A LoWPAN support addressing; a direct mapping between the link-layer address
and the IPv6 address is used for achieving compression.

Known Issues:
    * Unimplemented context information
    * Unimplemented IPv6 extensions fields
"""

import socket
import struct

from scapy.compat import chb, orb, raw
from scapy.data import ETHER_TYPES

from scapy.packet import Packet, bind_layers, bind_top_down
from scapy.fields import (
    BitEnumField,
    BitField,
    BitFixedLenField,
    BitScalingField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    StrFixedLenField,
    XBitField,
    XLongField,
    XShortField,
)

from scapy.layers.dot15d4 import Dot15d4Data
from scapy.layers.inet6 import (
    IP6Field,
    IPv6,
    _IPv6ExtHdr,
    ipv6nh,
)
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

from scapy.utils import mac2str
from scapy.config import conf
from scapy.error import warning

from scapy.packet import Raw
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.volatile import RandShort

ETHER_TYPES[0xA0ED] = "6LoWPAN"

LINK_LOCAL_PREFIX = b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # noqa: E501


##########
# Fields #
##########


class IP6FieldLenField(IP6Field):
    __slots__ = ["length_of"]

    def __init__(self, name, default, length_of=None):
        IP6Field.__init__(self, name, default)
        self.length_of = length_of

    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        tmp_len = self.length_of(pkt)
        if tmp_len == 0:
            return s
        internal = self.i2m(pkt, val)[-tmp_len:]
        return s + struct.pack("!%ds" % tmp_len, internal)

    def getfield(self, pkt, s):
        tmp_len = self.length_of(pkt)
        assert tmp_len >= 0 and tmp_len <= 16
        if tmp_len <= 0:
            return s, b""
        return (s[tmp_len:],
                self.m2i(pkt, b"\x00" * (16 - tmp_len) + s[:tmp_len]))


#################
# Basic 6LoWPAN #
#################
# https://tools.ietf.org/html/rfc4944


class LoWPANUncompressedIPv6(Packet):
    name = "6LoWPAN Uncompressed IPv6"
    fields_desc = [
        BitField("_type", 0x41, 8)
    ]

    def default_payload_class(self, pay):
        return IPv6

# https://tools.ietf.org/html/rfc4944#section-5.2


class LoWPANMesh(Packet):
    name = "6LoWPAN Mesh Packet"
    deprecated_fields = {
        "_v": ("v", "2.4.4"),
        "_f": ("f", "2.4.4"),
        "_sourceAddr": ("src", "2.4.4"),
        "_destinyAddr": ("dst", "2.4.4"),
    }
    fields_desc = [
        BitField("reserved", 0x2, 2),
        BitEnumField("v", 0x0, 1, ["EUI-64", "Short"]),
        BitEnumField("f", 0x0, 1, ["EUI-64", "Short"]),
        BitField("hopsLeft", 0x0, 4),
        MultipleTypeField(
            [(XShortField("src", 0x0), lambda pkt: pkt.v == 1)],
            XLongField("src", 0x0)
        ),
        MultipleTypeField(
            [(XShortField("dst", 0x0), lambda pkt: pkt.v == 1)],
            XLongField("dst", 0x0)
        )
    ]


# https://tools.ietf.org/html/rfc4944#section-10.1
# This implementation is NOT RECOMMENDED according to RFC 6282


class LoWPAN_HC2_UDP(Packet):
    name = "6LoWPAN HC1 UDP encoding"
    fields_desc = [
        BitEnumField("sc", 0, 1, ["In-line", "Compressed"]),
        BitEnumField("dc", 0, 1, ["In-line", "Compressed"]),
        BitEnumField("lc", 0, 1, ["In-line", "Compressed"]),
        BitField("res", 0, 5),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


def _get_hc1_pad(pkt):
    """
    Get LoWPAN_HC1 padding

    LoWPAN_HC1 is not recommended for several reasons, one
    of them being that padding is a mess (not 8-bit regular)
    We therefore add padding bits that are not in the spec to restore
    8-bit parity. Wireshark seems to agree
    """
    length = 0  # in bits, of the fields that are not //8
    if not pkt.tc_fl:
        length += 20
    if pkt.hc2:
        if pkt.nh == 1:
            length += pkt.hc2Field.sc * 4
            length += pkt.hc2Field.dc * 4
    return (-length) % 8


class LoWPAN_HC1(Packet):
    name = "LoWPAN_HC1 Compressed IPv6"
    fields_desc = [
        # https://tools.ietf.org/html/rfc4944#section-10.1
        ByteField("reserved", 0x42),
        BitEnumField("sp", 0, 1, ["In-line", "Compressed"]),
        BitEnumField("si", 0, 1, ["In-line", "Elided"]),
        BitEnumField("dp", 0, 1, ["In-line", "Compressed"]),
        BitEnumField("di", 0, 1, ["In-line", "Elided"]),
        BitEnumField("tc_fl", 0, 1, ["Not compressed", "zero"]),
        BitEnumField("nh", 0, 2, {0: "not compressed",
                                  1: "UDP",
                                  2: "ICMP",
                                  3: "TCP"}),
        BitEnumField("hc2", 0, 1, ["No more header compression bits",
                                   "HC2 Present"]),
        # https://tools.ietf.org/html/rfc4944#section-10.2
        ConditionalField(
            MultipleTypeField(
                [
                    (PacketField("hc2Field", LoWPAN_HC2_UDP(),
                                 LoWPAN_HC2_UDP),
                        lambda pkt: pkt.nh == 1),
                    # TODO: ICMP & TCP not implemented yet for HC1
                    # (PacketField("hc2Field", LoWPAN_HC2_ICMP(),
                    #              LoWPAN_HC2_ICMP),
                    #     lambda pkt: pkt.nh == 2),
                    # (PacketField("hc2Field", LoWPAN_HC2_TCP(),
                    #              LoWPAN_HC2_TCP),
                    #     lambda pkt: pkt.nh == 3),
                ],
                StrFixedLenField("hc2Field", b"", 0),
            ),
            lambda pkt: pkt.hc2
        ),
        # IPv6 header fields
        # https://tools.ietf.org/html/rfc4944#section-10.3.1
        ByteField("hopLimit", 0x0),
        IP6FieldLenField("src", "::",
                         lambda pkt: (0 if pkt.sp else 8) +
                                     (0 if pkt.si else 8)),
        IP6FieldLenField("dst", "::",
                         lambda pkt: (0 if pkt.dp else 8) +
                                     (0 if pkt.di else 8)),
        ConditionalField(
            ByteField("traffic_class", 0),
            lambda pkt: not pkt.tc_fl
        ),
        ConditionalField(
            BitField("flow_label", 0, 20),
            lambda pkt: not pkt.tc_fl
        ),
        # Other fields
        # https://tools.ietf.org/html/rfc4944#section-10.3.2
        ConditionalField(
            MultipleTypeField(
                [(BitScalingField("udpSourcePort", 0, 4, offset=0xF0B0),
                    lambda pkt: getattr(pkt.hc2Field, "sc", 0))],
                BitField("udpSourcePort", 0, 16)
            ),
            lambda pkt: pkt.nh == 1 and pkt.hc2
        ),
        ConditionalField(
            MultipleTypeField(
                [(BitScalingField("udpDestPort", 0, 4, offset=0xF0B0),
                    lambda pkt: getattr(pkt.hc2Field, "dc", 0))],
                BitField("udpDestPort", 0, 16)
            ),
            lambda pkt: pkt.nh == 1 and pkt.hc2
        ),
        ConditionalField(
            BitField("udpLength", 0, 16),
            lambda pkt: pkt.nh == 1 and pkt.hc2 and not pkt.hc2Field.lc
        ),
        ConditionalField(
            XBitField("udpChecksum", 0, 16),
            lambda pkt: pkt.nh == 1 and pkt.hc2
        ),
        # Out of spec
        BitFixedLenField("pad", 0, _get_hc1_pad)
    ]

    def post_dissect(self, data):
        # uncompress payload
        packet = IPv6()
        packet.version = IPHC_DEFAULT_VERSION
        packet.tc = self.traffic_class
        packet.fl = self.flow_label
        nh_match = {
            1: socket.IPPROTO_UDP,
            2: socket.IPPROTO_ICMP,
            3: socket.IPPROTO_TCP
        }
        if self.nh:
            packet.nh = nh_match.get(self.nh)
        packet.hlim = self.hopLimit

        packet.src = self.decompressSourceAddr()
        packet.dst = self.decompressDestAddr()

        if self.hc2 and self.nh == 1:  # UDP
            udp = UDP()
            udp.sport = self.udpSourcePort
            udp.dport = self.udpDestPort
            udp.len = self.udpLength or None
            udp.chksum = self.udpChecksum
            udp.add_payload(data)
            packet.add_payload(udp)
        else:
            packet.add_payload(data)
        data = raw(packet)
        return Packet.post_dissect(self, data)

    def decompressSourceAddr(self):
        if not self.sp and not self.si:
            # Prefix & Interface
            return self.src
        elif not self.si:
            # Only interface
            addr = inet_pton(socket.AF_INET6, self.src)[-8:]
            addr = LINK_LOCAL_PREFIX[:8] + addr
        else:
            # Interface not provided
            addr = _extract_upperaddress(self, source=True)
        self.src = inet_ntop(socket.AF_INET6, addr)
        return self.src

    def decompressDestAddr(self):
        if not self.dp and not self.di:
            # Prefix & Interface
            return self.dst
        elif not self.di:
            # Only interface
            addr = inet_pton(socket.AF_INET6, self.dst)[-8:]
            addr = LINK_LOCAL_PREFIX[:8] + addr
        else:
            # Interface not provided
            addr = _extract_upperaddress(self, source=False)
        self.dst = inet_ntop(socket.AF_INET6, addr)
        return self.dst

    def do_build(self):
        if not isinstance(self.payload, IPv6):
            return Packet.do_build(self)
        # IPv6
        ipv6 = self.payload
        self.src = ipv6.src
        self.dst = ipv6.dst
        self.flow_label = ipv6.fl
        self.traffic_class = ipv6.tc
        self.hopLimit = ipv6.hlim
        if isinstance(ipv6.payload, UDP):
            self.nh = 1
            self.hc2 = 1
            udp = ipv6.payload
            self.udpSourcePort = udp.sport
            self.udpDestPort = udp.dport
            if not udp.len or not udp.chksum:
                udp = UDP(raw(udp))
            self.udpLength = udp.len
            self.udpChecksum = udp.chksum
        return Packet.do_build(self)

    def do_build_payload(self):
        # Elide the IPv6 and UDP payload
        if isinstance(self.payload, IPv6):
            if isinstance(self.payload.payload, UDP):
                return raw(self.payload.payload.payload)
            return raw(self.payload.payload)
        return Packet.do_build_payload(self)

# https://tools.ietf.org/html/rfc4944#section-5.3


class LoWPANFragmentationFirst(Packet):
    name = "6LoWPAN First Fragmentation Packet"
    fields_desc = [
        BitField("reserved", 0x18, 5),
        BitField("datagramSize", 0x0, 11),
        XShortField("datagramTag", 0x0),
    ]


class LoWPANFragmentationSubsequent(Packet):
    name = "6LoWPAN Subsequent Fragmentation Packet"
    fields_desc = [
        BitField("reserved", 0x1C, 5),
        BitField("datagramSize", 0x0, 11),
        XShortField("datagramTag", RandShort()),
        ByteField("datagramOffset", 0x0),  # VALUE PRINTED IN OCTETS, wireshark does in bits (128 bits == 16 octets)  # noqa: E501
    ]


# https://tools.ietf.org/html/rfc4944#section-11.1

class LoWPANBroadcast(Packet):
    name = "6LoWPAN Broadcast"
    fields_desc = [
        ByteField("reserved", 0x50),
        ByteField("seq", 0)
    ]


#########################
# LoWPAN_IPHC (RFC6282) #
#########################


IPHC_DEFAULT_VERSION = 6
IPHC_DEFAULT_TF = 0
IPHC_DEFAULT_FL = 0


def source_addr_size(pkt):
    """Source address size

    This function depending on the arguments returns the amount of bits to be
    used by the source address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.sac == 0x0:
        if pkt.sam == 0x0:
            return 16
        elif pkt.sam == 0x1:
            return 8
        elif pkt.sam == 0x2:
            return 2
        elif pkt.sam == 0x3:
            return 0
    else:
        if pkt.sam == 0x0:
            return 0
        elif pkt.sam == 0x1:
            return 8
        elif pkt.sam == 0x2:
            return 2
        elif pkt.sam == 0x3:
            return 0


def dest_addr_size(pkt):
    """Destination address size

    This function depending on the arguments returns the amount of bits to be
    used by the destination address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.m == 0 and pkt.dac == 0:
        if pkt.dam == 0x0:
            return 16
        elif pkt.dam == 0x1:
            return 8
        elif pkt.dam == 0x2:
            return 2
        else:
            return 0
    elif pkt.m == 0 and pkt.dac == 1:
        if pkt.dam == 0x0:
            # reserved
            return 0
        elif pkt.dam == 0x1:
            return 8
        elif pkt.dam == 0x2:
            return 2
        else:
            return 0
    elif pkt.m == 1 and pkt.dac == 0:
        if pkt.dam == 0x0:
            return 16
        elif pkt.dam == 0x1:
            return 6
        elif pkt.dam == 0x2:
            return 4
        elif pkt.dam == 0x3:
            return 1
    elif pkt.m == 1 and pkt.dac == 1:
        if pkt.dam == 0x0:
            return 6
        elif pkt.dam == 0x1:
            # reserved
            return 0
        elif pkt.dam == 0x2:
            # reserved
            return 0
        elif pkt.dam == 0x3:
            # reserved
            return 0


def _extract_upperaddress(pkt, source=True):
    """This function extracts the source/destination address of a 6LoWPAN
    from its upper layer.

    (Upper layer could be 802.15.4 data, Ethernet...)

    params:
     - source: if True, the address is the source one. Otherwise, it is the
               destination.
    returns: (upper_address, ipv6_address)
    """
    # https://tools.ietf.org/html/rfc6282#section-3.2.2
    SUPPORTED_LAYERS = (Ether, Dot15d4Data)
    underlayer = pkt.underlayer
    while underlayer and not isinstance(underlayer, SUPPORTED_LAYERS):
        underlayer = underlayer.underlayer
    # Extract and process address
    if type(underlayer) == Ether:
        addr = mac2str(underlayer.src if source else underlayer.dst)
        # https://tools.ietf.org/html/rfc2464#section-4
        return LINK_LOCAL_PREFIX[:8] + addr[:3] + b"\xff\xfe" + addr[3:]
    elif type(underlayer) == Dot15d4Data:
        addr = underlayer.src_addr if source else underlayer.dest_addr
        addr = struct.pack(">Q", addr)
        if underlayer.underlayer.fcf_destaddrmode == 3:  # Extended/long
            tmp_ip = LINK_LOCAL_PREFIX[0:8] + addr
            # Turn off the bit 7.
            return tmp_ip[0:8] + struct.pack("B", (orb(tmp_ip[8]) ^ 0x2)) + tmp_ip[9:16]  # noqa: E501
        elif underlayer.underlayer.fcf_destaddrmode == 2:  # Short
            return (
                LINK_LOCAL_PREFIX[0:8] +
                b"\x00\x00\x00\xff\xfe\x00" +
                addr[6:]
            )
    else:
        # Most of the times, it's necessary the IEEE 802.15.4 data to extract
        # this address, sometimes another layer.
        warning(
            'Unimplemented: Unsupported upper layer: %s' % type(underlayer)
        )
        return b"\x00" * 16


class LoWPAN_IPHC(Packet):
    """6LoWPAN IPv6 header compressed packets

    It follows the implementation of RFC6282
    """
    __slots__ = ["_ipv6"]
    # the LOWPAN_IPHC encoding utilizes 13 bits, 5 dispatch type
    name = "LoWPAN IP Header Compression Packet"
    _address_modes = ["Unspecified (0)", "1", "16-bits inline (3)",
                      "Compressed (3)"]
    _state_mode = ["Stateless (0)", "Stateful (1)"]
    deprecated_fields = {
        "_nhField": ("nhField", "2.4.4"),
        "_hopLimit": ("hopLimit", "2.4.4"),
        "sourceAddr": ("src", "2.4.4"),
        "destinyAddr": ("dst", "2.4.4"),
        "udpDestinyPort": ("udpDestPort", "2.4.4"),
    }
    fields_desc = [
        # Base Format https://tools.ietf.org/html/rfc6282#section-3.1.2
        BitField("_reserved", 0x03, 3),
        BitField("tf", 0x0, 2),
        BitEnumField("nh", 0x0, 1, ["Inline", "Compressed"]),
        BitEnumField("hlim", 0x0, 2, {0: "Inline",
                                      1: "Compressed/HL1",
                                      2: "Compressed/HL64",
                                      3: "Compressed/HL255"}),
        BitEnumField("cid", 0x0, 1, {1: "Present (1)"}),
        BitEnumField("sac", 0x0, 1, _state_mode),
        BitEnumField("sam", 0x0, 2, _address_modes),
        BitEnumField("m", 0x0, 1, {1: "multicast (1)"}),
        BitEnumField("dac", 0x0, 1, _state_mode),
        BitEnumField("dam", 0x0, 2, _address_modes),
        # https://tools.ietf.org/html/rfc6282#section-3.1.2
        # Context Identifier Extension
        ConditionalField(
            BitField("sci", 0, 4),
            lambda pkt: pkt.cid == 0x1
        ),
        ConditionalField(
            BitField("dci", 0, 4),
            lambda pkt: pkt.cid == 0x1
        ),
        # https://tools.ietf.org/html/rfc6282#section-3.2.1
        ConditionalField(
            BitField("tc_ecn", 0, 2),
            lambda pkt: pkt.tf in [0, 1, 2]
        ),
        ConditionalField(
            BitField("tc_dscp", 0, 6),
            lambda pkt: pkt.tf in [0, 2],
        ),
        ConditionalField(
            MultipleTypeField(
                [(BitField("rsv", 0, 4), lambda pkt: pkt.tf == 0)],
                BitField("rsv", 0, 2),
            ),
            lambda pkt: pkt.tf in [0, 1]
        ),
        ConditionalField(
            BitField("flowlabel", 0, 20),
            lambda pkt: pkt.tf in [0, 1]
        ),
        # Inline fields https://tools.ietf.org/html/rfc6282#section-3.1.1
        ConditionalField(
            ByteEnumField("nhField", 0x0, ipv6nh),
            lambda pkt: pkt.nh == 0x0
        ),
        ConditionalField(
            ByteField("hopLimit", 0x0),
            lambda pkt: pkt.hlim == 0x0
        ),
        # The src and dst fields are filled up or removed in the
        # pre_dissect and post_build, depending on the other options.
        IP6FieldLenField("src", "::", length_of=source_addr_size),
        IP6FieldLenField("dst", "::", length_of=dest_addr_size),  # problem when it's 0  # noqa: E501
    ]

    def post_dissect(self, data):
        """dissect the IPv6 package compressed into this IPHC packet.

        The packet payload needs to be decompressed and depending on the
        arguments, several conversions should be done.
        """

        # uncompress payload
        packet = IPv6()
        packet.tc, packet.fl = self._getTrafficClassAndFlowLabel()
        if not self.nh:
            packet.nh = self.nhField
        # HLIM: Hop Limit
        if self.hlim == 0:
            packet.hlim = self.hopLimit
        elif self.hlim == 0x1:
            packet.hlim = 1
        elif self.hlim == 0x2:
            packet.hlim = 64
        else:
            packet.hlim = 255

        packet.src = self.decompressSourceAddr(packet)
        packet.dst = self.decompressDestAddr(packet)

        pay_cls = self.guess_payload_class(data)
        if pay_cls == IPv6:
            packet.add_payload(data)
            data = raw(packet)
        elif pay_cls == LoWPAN_NHC:
            self._ipv6 = packet
        return Packet.post_dissect(self, data)

    def decompressDestAddr(self, packet):
        # https://tools.ietf.org/html/rfc6282#section-3.1.1
        try:
            tmp_ip = inet_pton(socket.AF_INET6, self.dst)
        except socket.error:
            tmp_ip = b"\x00" * 16

        if self.m == 0 and self.dac == 0:
            if self.dam == 0:
                # Address fully carried
                pass
            elif self.dam == 1:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + tmp_ip[-8:]
            elif self.dam == 2:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + b"\x00\x00\x00\xff\xfe\x00" + tmp_ip[-2:]  # noqa: E501
            elif self.dam == 3:
                tmp_ip = _extract_upperaddress(self, source=False)

        elif self.m == 0 and self.dac == 1:
            if self.dam == 0:
                # reserved
                pass
            elif self.dam == 0x3:
                # should use context IID + encapsulating header
                tmp_ip = _extract_upperaddress(self, source=False)
            elif self.dam not in [0x1, 0x2]:
                # https://tools.ietf.org/html/rfc6282#page-9
                # Should use context information: unimplemented
                pass
        elif self.m == 1 and self.dac == 0:
            if self.dam == 0:
                # Address fully carried
                pass
            elif self.dam == 1:
                tmp = b"\xff" + chb(tmp_ip[16 - dest_addr_size(self)])
                tmp_ip = tmp + b"\x00" * 9 + tmp_ip[-5:]
            elif self.dam == 2:
                tmp = b"\xff" + chb(tmp_ip[16 - dest_addr_size(self)])
                tmp_ip = tmp + b"\x00" * 11 + tmp_ip[-3:]
            else:  # self.dam == 3:
                tmp_ip = b"\xff\x02" + b"\x00" * 13 + tmp_ip[-1:]
        elif self.m == 1 and self.dac == 1:
            if self.dam == 0x0:
                # https://tools.ietf.org/html/rfc6282#page-10
                # https://github.com/wireshark/wireshark/blob/f54611d1104d85a425e52c7318c522ed249916b6/epan/dissectors/packet-6lowpan.c#L2149-L2166
                # Format: ffXX:XXLL:PPPP:PPPP:PPPP:PPPP:XXXX:XXXX
                # P and L should be retrieved from context
                P = b"\x00" * 16
                L = b"\x00"
                X = tmp_ip[-6:]
                tmp_ip = b"\xff" + X[:2] + L + P[:8] + X[2:6]
            else:  # all the others values: reserved
                pass

        self.dst = inet_ntop(socket.AF_INET6, tmp_ip)
        return self.dst

    def compressSourceAddr(self, ipv6):
        # https://tools.ietf.org/html/rfc6282#section-3.1.1
        tmp_ip = inet_pton(socket.AF_INET6, ipv6.src)

        if self.sac == 0:
            if self.sam == 0x0:
                pass
            elif self.sam == 0x1:
                tmp_ip = tmp_ip[8:16]
            elif self.sam == 0x2:
                tmp_ip = tmp_ip[14:16]
            else:  # self.sam == 0x3:
                pass
        else:  # self.sac == 1
            if self.sam == 0x0:
                tmp_ip = b"\x00" * 16
            elif self.sam == 0x1:
                tmp_ip = tmp_ip[8:16]
            elif self.sam == 0x2:
                tmp_ip = tmp_ip[14:16]

        self.src = inet_ntop(socket.AF_INET6, b"\x00" * (16 - len(tmp_ip)) + tmp_ip)  # noqa: E501
        return self.src

    def compressDestAddr(self, ipv6):
        # https://tools.ietf.org/html/rfc6282#section-3.1.1
        tmp_ip = inet_pton(socket.AF_INET6, ipv6.dst)

        if self.m == 0 and self.dac == 0:
            if self.dam == 0x0:
                pass
            elif self.dam == 0x1:
                tmp_ip = b"\x00" * 8 + tmp_ip[8:16]
            elif self.dam == 0x2:
                tmp_ip = b"\x00" * 14 + tmp_ip[14:16]
        elif self.m == 0 and self.dac == 1:
            if self.dam == 0x1:
                tmp_ip = b"\x00" * 8 + tmp_ip[8:16]
            elif self.dam == 0x2:
                tmp_ip = b"\x00" * 14 + tmp_ip[14:16]
        elif self.m == 1 and self.dac == 0:
            if self.dam == 0x0:
                pass
            if self.dam == 0x1:
                tmp_ip = b"\x00" * 10 + tmp_ip[1:2] + tmp_ip[11:16]
            elif self.dam == 0x2:
                tmp_ip = b"\x00" * 12 + tmp_ip[1:2] + tmp_ip[13:16]
            elif self.dam == 0x3:
                tmp_ip = b"\x00" * 15 + tmp_ip[15:16]
        elif self.m == 1 and self.dac == 1:
            if self.dam == 0:
                tmp_ip = b"\x00" * 10 + tmp_ip[1:3] + tmp_ip[12:16]

        self.dst = inet_ntop(socket.AF_INET6, tmp_ip)

    def decompressSourceAddr(self, packet):
        # https://tools.ietf.org/html/rfc6282#section-3.1.1
        try:
            tmp_ip = inet_pton(socket.AF_INET6, self.src)
        except socket.error:
            tmp_ip = b"\x00" * 16

        if self.sac == 0:
            if self.sam == 0x0:
                # Full address is carried in-line
                pass
            elif self.sam == 0x1:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + tmp_ip[16 - source_addr_size(self):16]  # noqa: E501
            elif self.sam == 0x2:
                tmp = LINK_LOCAL_PREFIX[0:8] + b"\x00\x00\x00\xff\xfe\x00"
                tmp_ip = tmp + tmp_ip[16 - source_addr_size(self):16]
            elif self.sam == 0x3:
                # Taken from encapsulating header
                tmp_ip = _extract_upperaddress(self, source=True)
        else:  # self.sac == 1:
            if self.sam == 0x0:
                # Unspecified address ::
                pass
            elif self.sam == 0x1:
                # should use context IID
                pass
            elif self.sam == 0x2:
                # should use context IID
                tmp = LINK_LOCAL_PREFIX[0:8] + b"\x00\x00\x00\xff\xfe\x00"
                tmp_ip = tmp + tmp_ip[16 - source_addr_size(self):16]
            elif self.sam == 0x3:
                # should use context IID
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + b"\x00" * 8
        self.src = inet_ntop(socket.AF_INET6, tmp_ip)
        return self.src

    def guess_payload_class(self, payload):
        if self.nh:
            return LoWPAN_NHC
        u = self.underlayer
        if u and isinstance(u, (LoWPANFragmentationFirst,
                                LoWPANFragmentationSubsequent)):
            return Raw
        return IPv6

    def do_build(self):
        _cur = self
        if isinstance(_cur.payload, LoWPAN_NHC):
            _cur = _cur.payload
        if not isinstance(_cur.payload, IPv6):
            return Packet.do_build(self)
        ipv6 = _cur.payload

        self._reserved = 0x03

        # NEW COMPRESSION TECHNIQUE!
        # a ) Compression Techniques

        # 1. Set Traffic Class
        if self.tf == 0x0:
            self.tc_ecn = ipv6.tc >> 6
            self.tc_dscp = ipv6.tc & 0x3F
            self.flowlabel = ipv6.fl
        elif self.tf == 0x1:
            self.tc_ecn = ipv6.tc >> 6
            self.flowlabel = ipv6.fl
        elif self.tf == 0x2:
            self.tc_ecn = ipv6.tc >> 6
            self.tc_dscp = ipv6.tc & 0x3F
        else:  # self.tf == 0x3:
            pass  # no field is set

        # 2. Next Header
        if self.nh == 0x0:
            self.nhField = ipv6.nh
        elif self.nh == 1:
            # This will be handled in LoWPAN_NHC
            pass

        # 3. HLim
        if self.hlim == 0x0:
            self.hopLimit = ipv6.hlim
        else:  # if hlim is 1, 2 or 3, there are nothing to do!
            pass

        # 4. Context (which context to use...)
        if self.cid == 0x0:
            pass
        else:
            # TODO: Context Unimplemented yet
            pass

        # 5. Compress Source Addr
        self.compressSourceAddr(ipv6)
        self.compressDestAddr(ipv6)

        return Packet.do_build(self)

    def do_build_payload(self):
        # Elide the IPv6 payload
        if isinstance(self.payload, IPv6):
            return raw(self.payload.payload)
        return Packet.do_build_payload(self)

    def _getTrafficClassAndFlowLabel(self):
        """Page 6, draft feb 2011 """
        if self.tf == 0x0:
            return (self.tc_ecn << 6) + self.tc_dscp, self.flowlabel
        elif self.tf == 0x1:
            return (self.tc_ecn << 6), self.flowlabel
        elif self.tf == 0x2:
            return (self.tc_ecn << 6) + self.tc_dscp, 0
        else:
            return 0, 0

##############
# LOWPAN_NHC #
##############

# https://tools.ietf.org/html/rfc6282#section-4


class LoWPAN_NHC_Hdr(Packet):
    @classmethod
    def get_next_cls(cls, s):
        if s and len(s) >= 2:
            fb = ord(s[:1])
            if fb >> 3 == 0x1e:
                return LoWPAN_NHC_UDP
            if fb >> 4 == 0xe:
                return LoWPAN_NHC_IPv6Ext
        return None

    @classmethod
    def dispatch_hook(cls, _pkt=b"", *args, **kargs):
        return LoWPAN_NHC_Hdr.get_next_cls(_pkt) or LoWPAN_NHC_Hdr

    def extract_padding(self, s):
        return b"", s


class LoWPAN_NHC_UDP(LoWPAN_NHC_Hdr):
    fields_desc = [
        BitField("res", 0x1e, 5),
        BitField("C", 0, 1),
        BitField("P", 0, 2),
        MultipleTypeField(
            [(BitField("udpSourcePort", 0, 16),
                lambda pkt: pkt.P in [0, 1]),
             (BitField("udpSourcePort", 0, 8),
                 lambda pkt: pkt.P == 2),
             (BitField("udpSourcePort", 0, 4),
                 lambda pkt: pkt.P == 3)],
            BitField("udpSourcePort", 0x0, 16),
        ),
        MultipleTypeField(
            [(BitField("udpDestPort", 0, 16),
                lambda pkt: pkt.P in [0, 2]),
             (BitField("udpDestPort", 0, 8),
                 lambda pkt: pkt.P == 1),
             (BitField("udpDestPort", 0, 4),
                 lambda pkt: pkt.P == 3)],
            BitField("udpDestPort", 0x0, 16),
        ),
        ConditionalField(
            XShortField("udpChecksum", 0x0),
            lambda pkt: pkt.C == 0
        ),
    ]


_lowpan_nhc_ipv6ext_eid = {
    0: "Hop-by-hop Options Header",
    1: "IPv6 Routing Header",
    2: "IPv6 Fragment Header",
    3: "IPv6 Destination Options Header",
    4: "IPv6 Mobility Header",
    7: "IPv6 Header",
}


class LoWPAN_NHC_IPv6Ext(LoWPAN_NHC_Hdr):
    fields_desc = [
        BitField("res", 0xe, 4),
        BitEnumField("eid", 0, 3, _lowpan_nhc_ipv6ext_eid),
        BitField("nh", 0, 1),
        ConditionalField(
            ByteField("nhField", 0),
            lambda pkt: pkt.nh == 0
        ),
        FieldLenField("len", None, length_of="data", fmt="B"),
        StrFixedLenField("data", b"", length_from=lambda pkt: pkt.len)
    ]

    def post_build(self, p, pay):
        if self.len is None:
            offs = (not self.nh) + 1
            p = p[:offs] + struct.pack("!B", len(p) - offs) + p[offs + 1:]
        return p + pay


class LoWPAN_NHC(Packet):
    name = "LOWPAN_NHC"
    fields_desc = [
        PacketListField(
            "exts", [], pkt_cls=LoWPAN_NHC_Hdr,
            next_cls_cb=lambda *s: LoWPAN_NHC_Hdr.get_next_cls(s[3])
        )
    ]

    def post_dissect(self, data):
        if not self.underlayer or not hasattr(self.underlayer, "_ipv6"):
            return data
        if self.guess_payload_class(data) != IPv6:
            return data
        # Underlayer is LoWPAN_IPHC
        packet = self.underlayer._ipv6
        try:
            ipv6_hdr = next(
                x for x in self.exts if isinstance(x, LoWPAN_NHC_IPv6Ext)
            )
        except StopIteration:
            ipv6_hdr = None
        if ipv6_hdr:
            # XXX todo: implement: append the IPv6 extension
            # packet = packet / ipv6extension
            pass
        try:
            udp_hdr = next(
                x for x in self.exts if isinstance(x, LoWPAN_NHC_UDP)
            )
        except StopIteration:
            udp_hdr = None
        if udp_hdr:
            packet.nh = 0x11  # UDP
            udp = UDP()
            # https://tools.ietf.org/html/rfc6282#section-4.3.3
            if udp_hdr.C == 0:
                udp.chksum = udp_hdr.udpChecksum
            if udp_hdr.P == 0:
                udp.sport = udp_hdr.udpSourcePort
                udp.dport = udp_hdr.udpDestPort
            elif udp_hdr.P == 1:
                udp.sport = udp_hdr.udpSourcePort
                udp.dport = 0xF000 + udp_hdr.udpDestPort
            elif udp_hdr.P == 2:
                udp.sport = 0xF000 + udp_hdr.udpSourcePort
                udp.dport = udp_hdr.udpDestPort
            elif udp_hdr.P == 3:
                udp.sport = 0xF0B0 + udp_hdr.udpSourcePort
                udp.dport = 0xF0B0 + udp_hdr.udpDestPort
            packet.lastlayer().add_payload(udp / data)
        else:
            packet.lastlayer().add_payload(data)
        data = raw(packet)
        return Packet.post_dissect(self, data)

    def do_build(self):
        if not isinstance(self.payload, IPv6):
            return Packet.do_build(self)
        pay = self.payload.payload
        while pay and isinstance(pay.payload, _IPv6ExtHdr):
            # XXX todo: populate a LoWPAN_NHC_IPv6Ext
            pay = pay.payload
        if isinstance(pay, UDP):
            try:
                udp_hdr = next(
                    x for x in self.exts if isinstance(x, LoWPAN_NHC_UDP)
                )
            except StopIteration:
                udp_hdr = LoWPAN_NHC_UDP()
                # Guess best compression
                if pay.sport >> 4 == 0xf0b and pay.dport >> 4 == 0xf0b:
                    udp_hdr.P = 3
                elif pay.sport >> 8 == 0xf0:
                    udp_hdr.P = 2
                elif pay.dport >> 8 == 0xf0:
                    udp_hdr.P = 1
                self.exts.insert(0, udp_hdr)
            # https://tools.ietf.org/html/rfc6282#section-4.3.3
            if udp_hdr.P == 0:
                udp_hdr.udpSourcePort = pay.sport
                udp_hdr.udpDestPort = pay.dport
            elif udp_hdr.P == 1:
                udp_hdr.udpSourcePort = pay.sport
                udp_hdr.udpDestPort = pay.dport & 255
            elif udp_hdr.P == 2:
                udp_hdr.udpSourcePort = pay.sport & 255
                udp_hdr.udpDestPort = pay.dport
            elif udp_hdr.P == 3:
                udp_hdr.udpSourcePort = pay.sport & 15
                udp_hdr.udpDestPort = pay.dport & 15
            if udp_hdr.C == 0:
                if pay.chksum:
                    udp_hdr.udpChecksum = pay.chksum
                else:
                    udp_hdr.udpChecksum = UDP(raw(pay)).chksum
        return Packet.do_build(self)

    def do_build_payload(self):
        # Elide IPv6 payload, extensions and UDP
        if isinstance(self.payload, IPv6):
            cur = self.payload
            while cur and isinstance(cur, (IPv6, UDP)):
                cur = cur.payload
            return raw(cur)
        return Packet.do_build_payload(self)

    def guess_payload_class(self, payload):
        if self.underlayer:
            u = self.underlayer.underlayer
            if isinstance(u, (LoWPANFragmentationFirst,
                              LoWPANFragmentationSubsequent)):
                return Raw
        return IPv6


######################
# 6LowPan Dispatcher #
######################

# https://tools.ietf.org/html/rfc4944#section-5.1

class SixLoWPAN_ESC(Packet):
    name = "SixLoWPAN Dispatcher ESC"
    fields_desc = [ByteField("dispatch", 0)]


class SixLoWPAN(Packet):
    name = "SixLoWPAN Dispatcher"

    @classmethod
    def dispatch_hook(cls, _pkt=b"", *args, **kargs):
        """Depending on the payload content, the frame type we should interpretate"""  # noqa: E501
        if _pkt and len(_pkt) >= 1:
            fb = ord(_pkt[:1])
            if fb == 0x41:
                return LoWPANUncompressedIPv6
            if fb == 0x42:
                return LoWPAN_HC1
            if fb == 0x50:
                return LoWPANBroadcast
            if fb == 0x7f:
                return SixLoWPAN_ESC
            if fb >> 3 == 0x18:
                return LoWPANFragmentationFirst
            if fb >> 3 == 0x1C:
                return LoWPANFragmentationSubsequent
            if fb >> 6 == 0x02:
                return LoWPANMesh
            if fb >> 6 == 0x01:
                return LoWPAN_IPHC
        return cls


#################
# Fragmentation #
#################

# fragmentate IPv6
MAX_SIZE = 96


def sixlowpan_fragment(packet, datagram_tag=1):
    """Split a packet into different links to transmit as 6lowpan packets.
    Usage example::

      >>> ipv6 = ..... (very big packet)
      >>> pkts = sixlowpan_fragment(ipv6, datagram_tag=0x17)
      >>> send = [Dot15d4()/Dot15d4Data()/x for x in pkts]
      >>> wireshark(send)
    """
    if not packet.haslayer(IPv6):
        raise Exception("SixLoWPAN only fragments IPv6 packets !")

    str_packet = raw(packet[IPv6])

    if len(str_packet) <= MAX_SIZE:
        return [packet]

    def chunks(li, n):
        return [li[i:i + n] for i in range(0, len(li), n)]

    new_packet = chunks(str_packet, MAX_SIZE)

    new_packet[0] = LoWPANFragmentationFirst(datagramTag=datagram_tag, datagramSize=len(str_packet)) / new_packet[0]  # noqa: E501
    i = 1
    while i < len(new_packet):
        new_packet[i] = LoWPANFragmentationSubsequent(datagramTag=datagram_tag, datagramSize=len(str_packet), datagramOffset=MAX_SIZE // 8 * i) / new_packet[i]  # noqa: E501
        i += 1

    return new_packet


def sixlowpan_defragment(packet_list):
    results = {}
    for p in packet_list:
        cls = None
        if LoWPANFragmentationFirst in p:
            cls = LoWPANFragmentationFirst
        elif LoWPANFragmentationSubsequent in p:
            cls = LoWPANFragmentationSubsequent
        if cls:
            tag = p[cls].datagramTag
            results[tag] = results.get(tag, b"") + p[cls].payload.load  # noqa: E501
    return {tag: SixLoWPAN(x) for tag, x in results.items()}

############
# Bindings #
############


bind_layers(LoWPAN_HC1, IPv6)

bind_top_down(LoWPAN_IPHC, LoWPAN_NHC, nh=1)
bind_layers(LoWPANFragmentationFirst, SixLoWPAN)
bind_layers(LoWPANMesh, SixLoWPAN)
bind_layers(LoWPANBroadcast, SixLoWPAN)

bind_layers(Ether, SixLoWPAN, type=0xA0ED)
