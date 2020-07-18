# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Cesar A. Bernardini <mesarpe@gmail.com>
#               Intern at INRIA Grand Nancy Est
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license
"""
6LoWPAN Protocol Stack
======================

This implementation follows the next documents:

- Transmission of IPv6 Packets over IEEE 802.15.4 Networks
- Compression Format for IPv6 Datagrams in Low Power and Lossy
  networks (6LoWPAN): draft-ietf-6lowpan-hc-15
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
    * Next header compression techniques
    * Unimplemented LoWPANBroadcast

"""

import socket
import struct

from scapy.compat import chb, orb, raw
from scapy.data import ETHER_TYPES

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, BitEnumField, BitFieldLenField, \
    XShortField, FlagsField, ConditionalField, FieldLenField

from scapy.layers.dot15d4 import Dot15d4Data
from scapy.layers.inet6 import IPv6, IP6Field
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

from scapy.utils import lhex, mac2str
from scapy.config import conf
from scapy.error import warning

from scapy.packet import Raw
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.volatile import RandShort

ETHER_TYPES[0xA0ED] = "6LoWPAN"

LINK_LOCAL_PREFIX = b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # noqa: E501


class IP6FieldLenField(IP6Field):
    __slots__ = ["length_of"]

    def __init__(self, name, default, size, length_of=None):
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


class BitVarSizeField(BitField):
    __slots__ = ["length_f"]

    def __init__(self, name, default, calculate_length=None):
        BitField.__init__(self, name, default, 0)
        self.length_f = calculate_length

    def addfield(self, pkt, s, val):
        self.size = self.length_f(pkt)
        return BitField.addfield(self, pkt, s, val)

    def getfield(self, pkt, s):
        self.size = self.length_f(pkt)
        return BitField.getfield(self, pkt, s)


class SixLoWPANAddrField(FieldLenField):
    """Special field to store 6LoWPAN addresses

    6LoWPAN Addresses have a variable length depending on other parameters.
    This special field allows to save them, and encode/decode no matter which
    encoding parameters they have.
    """

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.length_of(pkt) == 8:
            return s + struct.pack(self.fmt[0] + "B", val)
        if self.length_of(pkt) == 16:
            return s + struct.pack(self.fmt[0] + "H", val)
        if self.length_of(pkt) == 32:
            return s + struct.pack(self.fmt[0] + "2H", val)  # TODO: fix!
        if self.length_of(pkt) == 48:
            return s + struct.pack(self.fmt[0] + "3H", val)  # TODO: fix!
        elif self.length_of(pkt) == 64:
            return s + struct.pack(self.fmt[0] + "Q", val)
        elif self.length_of(pkt) == 128:
            # TODO: FIX THE PACKING!!
            return s + struct.pack(self.fmt[0] + "16s", raw(val))
        else:
            return s

    def getfield(self, pkt, s):
        if self.length_of(pkt) == 8:
            return s[1:], self.m2i(pkt, struct.unpack(self.fmt[0] + "B", s[:1])[0])  # noqa: E501
        elif self.length_of(pkt) == 16:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0] + "H", s[:2])[0])  # noqa: E501
        elif self.length_of(pkt) == 32:
            return s[4:], self.m2i(pkt, struct.unpack(self.fmt[0] + "2H", s[:2], s[2:4])[0])  # noqa: E501
        elif self.length_of(pkt) == 48:
            return s[6:], self.m2i(pkt, struct.unpack(self.fmt[0] + "3H", s[:2], s[2:4], s[4:6])[0])  # noqa: E501
        elif self.length_of(pkt) == 64:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0] + "Q", s[:8])[0])  # noqa: E501
        elif self.length_of(pkt) == 128:
            return s[16:], self.m2i(pkt, struct.unpack(self.fmt[0] + "16s", s[:16])[0])  # noqa: E501


class LoWPANUncompressedIPv6(Packet):
    name = "6LoWPAN Uncompressed IPv6"
    fields_desc = [
        BitField("_type", 0x0, 8)
    ]

    def default_payload_class(self, pay):
        return IPv6


class LoWPANMesh(Packet):
    name = "6LoWPAN Mesh Packet"
    fields_desc = [
        BitField("reserved", 0x2, 2),
        BitEnumField("_v", 0x0, 1, [False, True]),
        BitEnumField("_f", 0x0, 1, [False, True]),
        BitField("_hopsLeft", 0x0, 4),
        SixLoWPANAddrField("_sourceAddr", 0x0, length_of=lambda pkt: pkt._v and 2 or 8),  # noqa: E501
        SixLoWPANAddrField("_destinyAddr", 0x0, length_of=lambda pkt: pkt._f and 2 or 8),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        # check first 2 bytes if they are ZERO it's not a 6LoWPAN packet
        pass

###############################################################################
# Fragmentation
#
# Section 5.3 - September 2007
###############################################################################


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


IPHC_DEFAULT_VERSION = 6
IPHC_DEFAULT_TF = 0
IPHC_DEFAULT_FL = 0


def source_addr_mode2(pkt):
    """source_addr_mode

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


def destiny_addr_mode(pkt):
    """destiny_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the destiny address.

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
            raise Exception('reserved')
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
            raise Exception('reserved')
        elif pkt.dam == 0x2:
            raise Exception('reserved')
        elif pkt.dam == 0x3:
            raise Exception('reserved')


def nhc_port(pkt):
    if not pkt.nh:
        return 0, 0
    if pkt.header_compression & 0x3 == 0x3:
        return 4, 4
    elif pkt.header_compression & 0x2 == 0x2:
        return 8, 16
    elif pkt.header_compression & 0x1 == 0x1:
        return 16, 8
    else:
        return 16, 16


def pad_trafficclass(pkt):
    """
    This function depending on the arguments returns the amount of bits to be
    used by the padding of the traffic class.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.tf == 0x0:
        return 4
    elif pkt.tf == 0x1:
        return 2
    elif pkt.tf == 0x2:
        return 0
    else:
        return 0


def flowlabel_len(pkt):
    """
    This function depending on the arguments returns the amount of bits to be
    used by the padding of the traffic class.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.tf == 0x0:
        return 20
    elif pkt.tf == 0x1:
        return 20
    else:
        return 0


def _tf_last_attempt(pkt):
    if pkt.tf == 0:
        return 2, 6, 4, 20
    elif pkt.tf == 1:
        return 2, 0, 2, 20
    elif pkt.tf == 2:
        return 2, 6, 0, 0
    else:
        return 0, 0, 0, 0


def _extract_upperaddress(pkt, source=True):
    """This function extracts the source/destination address of a 6LoWPAN
    from its upper layer.

    (Upper layer could be 802.15.4 data, Ethernet...)

    params:
     - source: if True, the address is the source one. Otherwise, it is the
               destination.
    returns: the packed & processed address
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
        raise Exception(
            'Unimplemented: Unsupported upper layer: %s' % type(underlayer)
        )


class LoWPAN_IPHC(Packet):
    """6LoWPAN IPv6 header compressed packets

    It follows the implementation of RFC6282
    """
    # the LOWPAN_IPHC encoding utilizes 13 bits, 5 dispatch type
    name = "LoWPAN IP Header Compression Packet"
    _address_modes = ["Unspecified", "1", "16-bits inline", "Compressed"]
    _state_mode = ["Stateless", "Stateful"]
    fields_desc = [
        # dispatch
        BitField("_reserved", 0x03, 3),
        BitField("tf", 0x0, 2),
        BitEnumField("nh", 0x0, 1, ["Inline", "Compressed"]),
        BitField("hlim", 0x0, 2),
        BitEnumField("cid", 0x0, 1, [False, True]),
        BitEnumField("sac", 0x0, 1, _state_mode),
        BitEnumField("sam", 0x0, 2, _address_modes),
        BitEnumField("m", 0x0, 1, [False, True]),
        BitEnumField("dac", 0x0, 1, _state_mode),
        BitEnumField("dam", 0x0, 2, _address_modes),
        ConditionalField(
            ByteField("_contextIdentifierExtension", 0x0),
            lambda pkt: pkt.cid == 0x1
        ),
        # TODO: THIS IS WRONG!!!!!
        BitVarSizeField("tc_ecn", 0, calculate_length=lambda pkt: _tf_last_attempt(pkt)[0]),  # noqa: E501
        BitVarSizeField("tc_dscp", 0, calculate_length=lambda pkt: _tf_last_attempt(pkt)[1]),  # noqa: E501
        BitVarSizeField("_padd", 0, calculate_length=lambda pkt: _tf_last_attempt(pkt)[2]),  # noqa: E501
        BitVarSizeField("flowlabel", 0, calculate_length=lambda pkt: _tf_last_attempt(pkt)[3]),  # noqa: E501

        # NH
        ConditionalField(
            ByteField("_nhField", 0x0),
            lambda pkt: not pkt.nh
        ),
        # HLIM: Hop Limit: if it's 0
        ConditionalField(
            ByteField("_hopLimit", 0x0),
            lambda pkt: pkt.hlim == 0x0
        ),
        IP6FieldLenField("sourceAddr", "::", 0, length_of=source_addr_mode2),
        IP6FieldLenField("destinyAddr", "::", 0, length_of=destiny_addr_mode),  # problem when it's 0  # noqa: E501

        # LoWPAN_UDP Header Compression ########################################  # noqa: E501
        # TODO: IMPROVE!!!!!
        ConditionalField(
            FlagsField("header_compression", 0, 8, ["A", "B", "C", "D", "E", "C", "PS", "PD"]),  # noqa: E501
            lambda pkt: pkt.nh
        ),
        ConditionalField(
            BitFieldLenField("udpSourcePort", 0x0, 16, length_of=lambda pkt: nhc_port(pkt)[0]),  # noqa: E501
            # ShortField("udpSourcePort", 0x0),
            lambda pkt: pkt.nh and pkt.header_compression & 0x2 == 0x0
        ),
        ConditionalField(
            BitFieldLenField("udpDestinyPort", 0x0, 16, length_of=lambda pkt: nhc_port(pkt)[1]),  # noqa: E501
            lambda pkt: pkt.nh and pkt.header_compression & 0x1 == 0x0
        ),
        ConditionalField(
            XShortField("udpChecksum", 0x0),
            lambda pkt: pkt.nh and pkt.header_compression & 0x4 == 0x0
        ),

    ]

    def post_dissect(self, data):
        """dissect the IPv6 package compressed into this IPHC packet.

        The packet payload needs to be decompressed and depending on the
        arguments, several conversions should be done.
        """

        # uncompress payload
        packet = IPv6()
        packet.version = IPHC_DEFAULT_VERSION
        packet.tc, packet.fl = self._getTrafficClassAndFlowLabel()
        if not self.nh:
            packet.nh = self._nhField
        # HLIM: Hop Limit
        if self.hlim == 0:
            packet.hlim = self._hopLimit
        elif self.hlim == 0x1:
            packet.hlim = 1
        elif self.hlim == 0x2:
            packet.hlim = 64
        else:
            packet.hlim = 255
        # TODO: Payload length can be inferred from lower layers from either the  # noqa: E501
        # 6LoWPAN Fragmentation header or the IEEE802.15.4 header

        packet.src = self.decompressSourceAddr(packet)
        packet.dst = self.decompressDestinyAddr(packet)

        if self.nh == 1:
            # The Next Header field is compressed and the next header is
            # encoded using LOWPAN_NHC

            packet.nh = 0x11  # UDP
            udp = UDP()
            if self.header_compression and \
               self.header_compression & 0x4 == 0x0:
                udp.chksum = self.udpChecksum

            s, d = nhc_port(self)
            if s == 16:
                udp.sport = self.udpSourcePort
            elif s == 8:
                udp.sport = 0xF000 + s
            elif s == 4:
                udp.sport = 0xF0B0 + s
            if d == 16:
                udp.dport = self.udpDestinyPort
            elif d == 8:
                udp.dport = 0xF000 + d
            elif d == 4:
                udp.dport = 0xF0B0 + d

            packet.payload = udp / data
            data = raw(packet)
        # else self.nh == 0 not necessary
        elif self._nhField & 0xE0 == 0xE0:  # IPv6 Extension Header Decompression  # noqa: E501
            warning('Unimplemented: IPv6 Extension Header decompression')  # noqa: E501
            packet.payload = conf.raw_layer(data)
            data = raw(packet)
        else:
            packet.payload = conf.raw_layer(data)
            data = raw(packet)

        return Packet.post_dissect(self, data)

    def decompressDestinyAddr(self, packet):
        try:
            tmp_ip = inet_pton(socket.AF_INET6, self.destinyAddr)
        except socket.error:
            tmp_ip = b"\x00" * 16

        if self.m == 0 and self.dac == 0:
            if self.dam == 0:
                pass
            elif self.dam == 1:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + tmp_ip[-8:]
            elif self.dam == 2:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + b"\x00\x00\x00\xff\xfe\x00" + tmp_ip[-2:]  # noqa: E501
            elif self.dam == 3:
                # TODO May need some extra changes, we are copying
                # (self.m == 0 and self.dac == 1)
                tmp_ip = _extract_upperaddress(self, source=False)

        elif self.m == 0 and self.dac == 1:
            if self.dam == 0:
                raise Exception('Reserved')
            elif self.dam == 0x3:
                tmp_ip = _extract_upperaddress(self, source=False)
            elif self.dam not in [0x1, 0x2]:
                warning("Unknown destiny address compression mode !")
        elif self.m == 1 and self.dac == 0:
            if self.dam == 0:
                raise Exception("unimplemented")
            elif self.dam == 1:
                tmp = b"\xff" + chb(tmp_ip[16 - destiny_addr_mode(self)])
                tmp_ip = tmp + b"\x00" * 9 + tmp_ip[-5:]
            elif self.dam == 2:
                tmp = b"\xff" + chb(tmp_ip[16 - destiny_addr_mode(self)])
                tmp_ip = tmp + b"\x00" * 11 + tmp_ip[-3:]
            else:  # self.dam == 3:
                tmp_ip = b"\xff\x02" + b"\x00" * 13 + tmp_ip[-1:]
        elif self.m == 1 and self.dac == 1:
            if self.dam == 0x0:
                # See https://tools.ietf.org/html/rfc6282#page-9
                raise Exception("Unimplemented: I didn't understand the 6lowpan specification")  # noqa: E501
            else:  # all the others values
                raise Exception("Reserved value by specification.")

        self.destinyAddr = inet_ntop(socket.AF_INET6, tmp_ip)
        return self.destinyAddr

    def compressSourceAddr(self, ipv6):
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

        self.sourceAddr = inet_ntop(socket.AF_INET6, b"\x00" * (16 - len(tmp_ip)) + tmp_ip)  # noqa: E501
        return self.sourceAddr

    def compressDestinyAddr(self, ipv6):
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
            if self.dam == 0x1:
                tmp_ip = b"\x00" * 10 + tmp_ip[1:2] + tmp_ip[11:16]
            elif self.dam == 0x2:
                tmp_ip = b"\x00" * 12 + tmp_ip[1:2] + tmp_ip[13:16]
            elif self.dam == 0x3:
                tmp_ip = b"\x00" * 15 + tmp_ip[15:16]
        elif self.m == 1 and self.dac == 1:
            raise Exception('Unimplemented')

        self.destinyAddr = inet_ntop(socket.AF_INET6, tmp_ip)

    def decompressSourceAddr(self, packet):
        try:
            tmp_ip = inet_pton(socket.AF_INET6, self.sourceAddr)
        except socket.error:
            tmp_ip = b"\x00" * 16

        if self.sac == 0:
            if self.sam == 0x0:
                pass
            elif self.sam == 0x1:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + tmp_ip[16 - source_addr_mode2(self):16]  # noqa: E501
            elif self.sam == 0x2:
                tmp = LINK_LOCAL_PREFIX[0:8] + b"\x00\x00\x00\xff\xfe\x00"
                tmp_ip = tmp + tmp_ip[16 - source_addr_mode2(self):16]
            elif self.sam == 0x3:  # EXTRACT ADDRESS FROM Dot15d4
                tmp_ip = _extract_upperaddress(self, source=True)
            else:
                warning("Unknown source address compression mode !")
        else:  # self.sac == 1:
            if self.sam == 0x0:
                pass
            elif self.sam == 0x2:
                # TODO: take context IID
                tmp = LINK_LOCAL_PREFIX[0:8] + b"\x00\x00\x00\xff\xfe\x00"
                tmp_ip = tmp + tmp_ip[16 - source_addr_mode2(self):16]
            elif self.sam == 0x3:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + b"\x00" * 8  # TODO: CONTEXT ID  # noqa: E501
            else:
                raise Exception('Unimplemented')
        self.sourceAddr = inet_ntop(socket.AF_INET6, tmp_ip)
        return self.sourceAddr

    def guess_payload_class(self, payload):
        if self.underlayer and isinstance(self.underlayer, (LoWPANFragmentationFirst, LoWPANFragmentationSubsequent)):  # noqa: E501
            return Raw
        return IPv6

    def do_build(self):
        if not isinstance(self.payload, IPv6):
            return Packet.do_build(self)
        ipv6 = self.payload

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
            self.nh = 0  # ipv6.nh
        elif self.nh == 0x1:
            self.nh = 0  # disable compression
            # The Next Header field is compressed and the next header is encoded using LOWPAN_NHC, which is discussed in Section 4.1.  # noqa: E501
            warning('Next header compression is not implemented yet ! Will be ignored')  # noqa: E501

        # 3. HLim
        if self.hlim == 0x0:
            self._hopLimit = ipv6.hlim
        else:  # if hlim is 1, 2 or 3, there are nothing to do!
            pass

        # 4. Context (which context to use...)
        if self.cid == 0x0:
            pass
        else:
            # TODO: Context Unimplemented yet in my class
            self._contextIdentifierExtension = 0

        # 5. Compress Source Addr
        self.compressSourceAddr(ipv6)
        self.compressDestinyAddr(ipv6)

        return Packet.do_build(self)

    def do_build_payload(self):
        if self.header_compression and\
           self.header_compression & 240 == 240:  # TODO: UDP header IMPROVE
            return raw(self.payload)[40 + 16:]
        else:
            return raw(self.payload)[40:]

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

# Old compression (deprecated)


class LoWPAN_HC1(Raw):
    name = "LoWPAN_HC1 Compressed IPv6 (Not supported)"


class SixLoWPAN(Packet):
    name = "SixLoWPAN(Packet)"

    @classmethod
    def dispatch_hook(cls, _pkt=b"", *args, **kargs):
        """Depending on the payload content, the frame type we should interpretate"""  # noqa: E501
        if _pkt and len(_pkt) >= 1:
            if orb(_pkt[0]) == 0x41:
                return LoWPANUncompressedIPv6
            if orb(_pkt[0]) == 0x42:
                return LoWPAN_HC1
            if orb(_pkt[0]) >> 3 == 0x18:
                return LoWPANFragmentationFirst
            elif orb(_pkt[0]) >> 3 == 0x1C:
                return LoWPANFragmentationSubsequent
            elif orb(_pkt[0]) >> 6 == 0x02:
                return LoWPANMesh
            elif orb(_pkt[0]) >> 6 == 0x01:
                return LoWPAN_IPHC
        return cls


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


bind_layers(SixLoWPAN, LoWPANFragmentationFirst,)
bind_layers(SixLoWPAN, LoWPANFragmentationSubsequent,)
bind_layers(SixLoWPAN, LoWPANMesh,)
bind_layers(SixLoWPAN, LoWPAN_IPHC,)
bind_layers(LoWPANMesh, LoWPANFragmentationFirst,)
bind_layers(LoWPANMesh, LoWPANFragmentationSubsequent,)

bind_layers(Ether, SixLoWPAN, type=0xA0ED)

# TODO: I have several doubts about the Broadcast LoWPAN
# bind_layers( LoWPANBroadcast,   LoWPANHC1CompressedIPv6,            )
# bind_layers( SixLoWPAN,         LoWPANBroadcast,                    )
# bind_layers( LoWPANMesh,        LoWPANBroadcast,                    )
# bind_layers( LoWPANBroadcast,   LoWPANFragmentationFirst,           )
# bind_layers( LoWPANBroadcast,   LoWPANFragmentationSubsequent,      )

# TODO: find a way to chose between ZigbeeNWK and SixLoWPAN (cf. dot15d4.py)
# Currently: use conf.dot15d4_protocol value
# bind_layers(Dot15d4Data, SixLoWPAN)
