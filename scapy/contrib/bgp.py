# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# scapy.contrib.description = BGP v0.1
# scapy.contrib.status = loads

"""
BGP (Border Gateway Protocol).
"""

import struct
import re
import socket

from scapy.packet import Packet, Packet_metaclass, bind_layers
from scapy.fields import (Field, BitField, BitEnumField, XBitField, ByteField,
                          ByteEnumField, ShortField, ShortEnumField, IntField,
                          IntEnumField, LongField, IEEEFloatField, StrField,
                          StrLenField, StrFixedLenField, FieldLenField,
                          FieldListField, PacketField, PacketListField,
                          IPField, FlagsField, ConditionalField,
                          MultiEnumField)
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IP6Field
from scapy.config import conf, ConfClass
from scapy.error import log_runtime


#
# Module configuration
#


class BGPConf(ConfClass):
    """
    BGP module configuration.
    """

    # By default, set to True in order to behave like an OLD speaker (RFC 6793)
    use_2_bytes_asn = True


bgp_module_conf = BGPConf()


#
# Constants
#

# RFC 4271: "The maximum message size is 4096 octets. All implementations are
# required to support this maximum message size."
BGP_MAXIMUM_MESSAGE_SIZE = 4096

# RFC 4271: "Each message has a fixed-size header." Marker (16 bytes) +
# Length (2 bytes) + Type (1 byte)
_BGP_HEADER_SIZE = 19

# Marker included in every message (RFC 4271: "This 16-octet field is
# included for compatibility; it MUST be set to all ones")
_BGP_HEADER_MARKER = "\xff" * 16

# extended-length flag (RFC 4271 4.3. UPDATE Message Format -
# Path Attributes)
_BGP_PA_EXTENDED_LENGTH = 0x10

# RFC 5492 (at least 2 bytes : code + length)
_BGP_CAPABILITY_MIN_SIZE = 2

# RFC 5492 (at least 3 bytes : type code + length)
_BGP_PATH_ATTRIBUTE_MIN_SIZE = 3


#
# Fields and utilities
#

def _bits_to_bytes_len(length_in_bits):
    """
    Helper function that returns the numbers of bytes necessary to store the
    given number of bits.
    """

    return (length_in_bits + 7) // 8


class BGPFieldIPv4(Field):
    """
    IPv4 Field (CIDR)
    """

    def mask2iplen(self, mask):
        """Get the IP field mask length (in bytes)."""
        return (mask + 7) // 8

    def h2i(self, pkt, h):
        """x.x.x.x/y to "internal" representation."""
        ip, mask = re.split("/", h)
        return int(mask), ip

    def i2h(self, pkt, i):
        """"Internal" representation to "human" representation
        (x.x.x.x/y)."""
        mask, ip = i
        return ip + "/" + str(mask)

    def i2repr(self, pkt, i):
        return self.i2h(pkt, i)

    def i2len(self, pkt, i):
        mask, ip = i
        return self.mask2iplen(mask) + 1

    def i2m(self, pkt, i):
        """"Internal" (IP as bytes, mask as int) to "machine"
        representation."""
        mask, ip = i
        ip = socket.inet_aton(ip)
        return struct.pack(">B", mask) + ip[:self.mask2iplen(mask)]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        length = self.mask2iplen(struct.unpack(">B", s[0])[0]) + 1
        return s[length:], self.m2i(pkt, s[:length])

    def m2i(self, pkt, m):
        mask = struct.unpack(">B", m[0])[0]
        mask2iplen_res = self.mask2iplen(mask)
        ip = "".join(
            [m[i + 1] if i < mask2iplen_res else "\x00" for i in range(4)])
        return (mask, socket.inet_ntoa(ip))


class BGPFieldIPv6(Field):
    """IPv6 Field (CIDR)"""

    def mask2iplen(self, mask):
        """Get the IP field mask length (in bytes)."""
        return (mask + 7) // 8

    def h2i(self, pkt, h):
        """x.x.x.x/y to internal representation."""
        ip, mask = re.split("/", h)
        return int(mask), ip

    def i2h(self, pkt, i):
        """"Internal" representation to "human" representation."""
        mask, ip = i
        return ip + "/" + str(mask)

    def i2repr(self, pkt, i):
        return self.i2h(pkt, i)

    def i2len(self, pkt, i):
        mask, ip = i
        return self.mask2iplen(mask) + 1

    def i2m(self, pkt, i):
        """"Internal" (IP as bytes, mask as int) to "machine" representation."""
        mask, ip = i
        ip = socket.inet_pton(socket.AF_INET6, ip)
        return struct.pack(">B", mask) + ip[:self.mask2iplen(mask)]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        length = self.mask2iplen(struct.unpack(">B", s[0])[0]) + 1
        return s[length:], self.m2i(pkt, s[:length])

    def m2i(self, pkt, m):
        mask = struct.unpack(">B", m[0])[0]
        ip = "".join(
            [m[i + 1] if i < self.mask2iplen(mask) else "\x00" for i in range(16)])
        return (mask, socket.inet_ntop(socket.AF_INET6, ip))


def has_extended_length(flags):
    """
    Used in BGPPathAttr to check if the extended-length flag is
    set.
    """

    return flags & _BGP_PA_EXTENDED_LENGTH == _BGP_PA_EXTENDED_LENGTH


class BGPNLRI_IPv4(Packet):
    """
    Packet handling IPv4 NLRI fields.
    """

    name = "IPv4 NLRI"
    fields_desc = [BGPFieldIPv4("prefix", "0.0.0.0/0")]


class BGPNLRI_IPv6(Packet):
    """
    Packet handling IPv6 NLRI fields.
    """

    name = "IPv6 NLRI"
    fields_desc = [BGPFieldIPv6("prefix", "::/0")]


class BGPNLRIPacketListField(PacketListField):
    """
    PacketListField handling NLRI fields.
    """

    def getfield(self, pkt, s):
        lst = []
        length = None
        ret = ""

        if self.length_from is not None:
            length = self.length_from(pkt)

        if length is not None:
            remain, ret = s[:length], s[length:]
        else:
            index = s.find(_BGP_HEADER_MARKER)
            if index != -1:
                remain = s[:index]
                ret = s[index:]
            else:
                remain = s

        while remain:
            mask_length_in_bits = struct.unpack("!B", remain[0])[0]
            mask_length_in_bytes = (mask_length_in_bits + 7) // 8
            current = remain[:mask_length_in_bytes + 1]
            remain = remain[mask_length_in_bytes + 1:]
            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain + ret, lst


class _BGPInvalidDataException(Exception):
    """
    Raised when it is not possible to instantiate a BGP packet with the given
    data.
    """

    def __init__(self, details):
        Exception.__init__(
            self,
            "Impossible to build packet from the given data" + details
        )


def _get_cls(name, fallback_cls=conf.raw_layer):
    """
    Returns class named "name" if it exists, fallback_cls otherwise.
    """

    return globals().get(name, fallback_cls)


#
# Common dictionaries
#

_bgp_message_types = {
    0: "NONE",
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
    5: "ROUTE-REFRESH"
}


#
# AFIs
#

address_family_identifiers = {
    0: "Reserved",
    1: "IP (IP version 4)",
    2: "IP6 (IP version 6)",
    3: "NSAP",
    4: "HDLC (8-bit multidrop)",
    5: "BBN 1822",
    6: "802 (includes all 802 media plus Ethernet \"canonical format\")",
    7: "E.163",
    8: "E.164 (SMDS, Frame Relay, ATM)",
    9: "F.69 (Telex)",
    10: "X.121 (X.25, Frame Relay)",
    11: "IPX",
    12: "Appletalk",
    13: "Decnet IV",
    14: "Banyan Vines",
    15: "E.164 with NSAP format subaddress",  # ANDY_MALIS
    16: "DNS (Domain Name System)",
    17: "Distinguished Name",  # CHARLES_LYNN
    18: "AS Number",  # CHARLES_LYNN
    19: "XTP over IP version 4",  # MIKE_SAUL
    20: "XTP over IP version 6",  # MIKE_SAUL
    21: "XTP native mode XTP",  # MIKE_SAUL
    22: "Fibre Channel World-Wide Port Name",  # MARK_BAKKE
    23: "Fibre Channel World-Wide Node Name",  # MARK_BAKKE
    24: "GWID",  # SUBRA_HEGDE
    25: "AFI for L2VPN information",  # RFC 6074
    26: "MPLS-TP Section Endpoint Identifier",  # RFC 7212
    27: "MPLS-TP LSP Endpoint Identifier",  # RFC 7212
    28: "MPLS-TP Pseudowire Endpoint Identifier",  # RFC 7212
    29: "MT IP: Multi-Topology IP version 4",  # RFC 7307
    30: "MT IPv6: Multi-Topology IP version 6",  # RFC 7307
    16384: "EIGRP Common Service Family",  # DONNIE_SAVAGE
    16385: "EIGRP IPv4 Service Family",  # DONNIE_SAVAGE
    16386: "EIGRP IPv6 Service Family",  # DONNIE_SAVAGE
    16387: "LISP Canonical Address Format (LCAF)",  # DAVID_MEYER
    16388: "BGP-LS",  # RFC 7752
    16389: "48-bit MAC",  # RFC 7042
    16390: "64-bit MAC",  # RFC 7042
    16391: "OUI",  # draft-ietf-trill-ia-appsubtlv
    16392: "MAC/24",  # draft-ietf-trill-ia-appsubtlv
    16393: "MAC/40",  # draft-ietf-trill-ia-appsubtlv
    16394: "IPv6/64",  # draft-ietf-trill-ia-appsubtlv
    16395: "RBridge Port ID",  # draft-ietf-trill-ia-appsubtlv
    16396: "TRILL Nickname",  # RFC 7455
    65535: "Reserved"
}


subsequent_afis = {
    0: "Reserved",  # RFC 4760
    1: "Network Layer Reachability Information used for unicast forwarding",  # RFC 4760
    2: "Network Layer Reachability Information used for multicast forwarding",  # RFC 4760
    3: "Reserved",  # RFC 4760
    4: "Network Layer Reachability Information (NLRI) with MPLS Labels",  # RFC 3107
    5: "MCAST-VPN",  # RFC 6514
    6: "Network Layer Reachability Information used for Dynamic Placement of\
        Multi-Segment Pseudowires", # RFC 7267
    7: "Encapsulation SAFI",  # RFC 5512
    8: "MCAST-VPLS",  # RFC 7117
    64: "Tunnel SAFI",  # DRAFT-NALAWADE-KAPOOR-TUNNEL-SAFI-01
    65: "Virtual Private LAN Service (VPLS)",  # RFC 6074
    66: "BGP MDT SAFI",  # RFC 6037
    67: "BGP 4over6 SAFI",  # RFC 5747
    68: "BGP 6over4 SAFI",  # YONG_CUI
    69: "Layer-1 VPN auto-discovery information",  # RFC 5195
    70: "BGP EVPNs",  # RFC 7432
    71: "BGP-LS",  # RFC 7752
    72: "BGP-LS-VPN",  # RFC 7752
    128: "MPLS-labeled VPN address",  # RFC 4364
    129: "Multicast for BGP/MPLS IP Virtual Private Networks (VPNs)",  # RFC 6514
    132: "Route Target constraint",  # RFC 4684
    133: "IPv4 dissemination of flow specification rules",  # RFC 5575
    134: "VPNv4 dissemination of flow specification rules",  # RFC 5575
    140: "VPN auto-discovery",  # draft-ietf-l3vpn-bgpvpn-auto
    255: "Reserved"  # RFC 4760
}


# Used by _bgp_dispatcher to instantiate the appropriate class
_bgp_cls_by_type = {
    1: "BGPOpen",
    2: "BGPUpdate",
    3: "BGPNotification",
    4: "BGPKeepAlive",
    5: "BGPRouteRefresh",
}


#
# Header
#

class BGPHeader(Packet):
    """
    The header of any BGP message.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # Each message has a fixed-size header. There may or may not be a data
    # portion following the header, depending on the message type. The
    # layout of these fields is shown below:
    #
    #
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                                                               +
    # |                                                               |
    # +                                                               +
    # |                           Marker                              |
    # +                                                               +
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Length               |      Type     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Marker:
    #       This 16-octet field is included for compatibility; it MUST be set
    #       to all ones.
    #
    # Length:
    #       This 2-octet unsigned integer indicates the total length of the
    #       message, including the header in octets.  Thus, it allows one to
    #       locate the (Marker field of the) next message in the TCP stream.
    #       The value of the Length field MUST always be at least 19 and no
    #       greater than 4096, and MAY be further constrained, depending on
    #       the message type.  "padding" of extra data after the message is
    #       not allowed.  Therefore, the Length field MUST have the smallest
    #       value required, given the rest of the message.
    #
    # Type:
    #       This 1-octet unsigned integer indicates the type code of the
    #       message. This document defines the following type codes:
    #               1 - OPEN
    #               2 - UPDATE
    #               3 - NOTIFICATION
    #               4 - KEEPALIVE
    #
    # [RFC2918] defines one more type code.
    #________________________________________________________________________
    #

    name = "HEADER"
    fields_desc = [
        XBitField(
            "marker",
            0xffffffffffffffffffffffffffffffff,
            0x80
        ),
        ShortField("len", None),
        ByteEnumField("type", 4, _bgp_message_types)
    ]

    def post_build(self, p, pay):
        if self.len is None:
            length = len(p)
            if pay:
                length = length + len(pay)
            p = p[:16] + struct.pack("!H", length) + p[18:]
        return p + pay

    def guess_payload_class(self, payload):
        return _get_cls(_bgp_cls_by_type.get(self.type, conf.raw_layer), conf.raw_layer)


def _bgp_dispatcher(payload):
    """
    Returns the right class for a given BGP message.
    """

    cls = conf.raw_layer

    # By default, calling BGP() will build a BGPHeader.
    if payload is None:
        cls = _get_cls("BGPHeader", conf.raw_layer)

    else:
        if len(payload) >= _BGP_HEADER_SIZE and\
                payload[:16] == _BGP_HEADER_MARKER:

            # Get BGP message type
            message_type = struct.unpack("!B", payload[18])[0]
            if message_type == 4:
                cls = _get_cls("BGPKeepAlive")
            else:
                cls = _get_cls("BGPHeader")

    return cls


class BGP(Packet):
    """
    Every BGP message inherits from this class.
    """

    #
    # BGP messages types

    OPEN_TYPE = 1
    UPDATE_TYPE = 2
    NOTIFICATION_TYPE = 3
    KEEPALIVE_TYPE = 4
    ROUTEREFRESH_TYPE = 5

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """

        return _bgp_dispatcher(_pkt)

    def guess_payload_class(self, p):
        cls = None
        if len(p) > 15 and p[:16] == _BGP_HEADER_MARKER:
            cls = BGPHeader
        return cls


#
# KEEPALIVE
#

class BGPKeepAlive(BGP, BGPHeader):

    """
    KEEPALIVE message.
    """

    name = "KEEPALIVE"


#
# OPEN
#

#
# Optional Parameters Codes
#

optional_parameter_codes = {
    0: "Reserved",
    1: "Authentication (deprecated)",
    2: "Capabilities"
}


#
# Capabilities
#

_capabilities = {
    0: "Reserved",  # RFC 5492
    1: "Multiprotocol Extensions for BGP-4",  # RFC 2858
    2: "Route Refresh Capability for BGP-4",  # RFC 2918
    3: "Outbound Route Filtering Capability",  # RFC 5291
    4: "Multiple routes to a destination capability",  # RFC 3107
    5: "Extended Next Hop Encoding",  # RFC 5549
    6: "BGP-Extended Message",  # (TEMPORARY - registered 2015-09-30, expires 2016-09-30),
    # draft-ietf-idr-bgp-extended-messages
    64: "Graceful Restart Capability",  # RFC 4724
    65: "Support for 4-octet AS number capability",  # RFC 6793
    66: "Deprecated (2003-03-06)",
    67: "Support for Dynamic Capability (capability specific)",  # draft-ietf-idr-dynamic-cap
    68: "Multisession BGP Capability",  # draft-ietf-idr-bgp-multisession
    69: "ADD-PATH Capability",  # RFC-ietf-idr-add-paths-15
    70: "Enhanced Route Refresh Capability",  # RFC 7313
    71: "Long-Lived Graceful Restart (LLGR) Capability",  # draft-uttaro-idr-bgp-persistence
    73: "FQDN Capability",  # draft-walton-bgp-hostname-capability
    128: "Route Refresh Capability for BGP-4 (Cisco)",  # Cisco also uses 128 for RR capability
    130: "Outbound Route Filtering Capability (Cisco)",  # Cisco also uses 130 for ORF capability
}


_capabilities_objects = {
    0x01: "BGPCapMultiprotocol",  # RFC 2858
    0x02: "BGPCapGeneric",  # RFC 2918
    0x03: "BGPCapORF",  # RFC 5291
    0x40: "BGPCapGracefulRestart",  # RFC 4724
    0x41: "BGPCapFourBytesASN",  # RFC 4893
    0x46: "BGPCapGeneric",  # Enhanced Route Refresh Capability, RFC 7313
    0x82: "BGPCapORF",  # ORF / RFC 5291 (Cisco)
}


def _register_cls(registry, cls):
    registry[cls.__name__] = cls
    return cls


_capabilities_registry = {}


def _bgp_capability_dispatcher(payload):
    """
    Returns the right class for a given BGP capability.
    """

    cls = _capabilities_registry["BGPCapGeneric"]

    # By default, calling BGPCapability() will build a "generic" capability.
    if payload is None:
        cls = _capabilities_registry["BGPCapGeneric"]

    else:
        length = len(payload)
        if length >= _BGP_CAPABILITY_MIN_SIZE:
            code = struct.unpack("!B", payload[0])[0]
            cls = _get_cls(_capabilities_objects.get(code, "BGPCapGeneric"))

    return cls


class _BGPCap_metaclass(type):
    def __new__(cls, clsname, bases, attrs):
        newclass = super(_BGPCap_metaclass, cls).__new__(
            cls, clsname, bases, attrs)
        _register_cls(_capabilities_registry, newclass)
        return newclass


class _BGPCapability_metaclass(Packet_metaclass, _BGPCap_metaclass):
    pass


class BGPCapability(Packet):
    """
    Generic BGP capability.
    """

    __metaclass__ = _BGPCapability_metaclass

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """

        return _bgp_capability_dispatcher(_pkt)

    def pre_dissect(self, s):
        """
        Check that the payload is long enough (at least 2 bytes).
        """
        length = len(s)
        if length < _BGP_CAPABILITY_MIN_SIZE:
            err = " ({}".format(length) + " is < _BGP_CAPABILITY_MIN_SIZE "
            err += "({})).".format(_BGP_CAPABILITY_MIN_SIZE)
            raise _BGPInvalidDataException(err)
        return s

    # Every BGP capability object inherits from BGPCapability.
    def haslayer(self, cls):
        ret = 0
        if cls == BGPCapability:
            # If cls is BGPCap (the parent class), check that the object is an
            # instance of an existing BGP capability class.
            for cap_class in _capabilities_registry:
                if isinstance(self, _capabilities_registry[cap_class]):
                    ret = 1
                    break
        elif cls in _capabilities_registry and isinstance(self, cls):
            ret = 1
        return ret

    def getlayer(self, cls, nb=1, _track=None):
        layer = None
        if cls == BGPCapability:
            for cap_class in _capabilities_registry:
                if isinstance(self, _capabilities_registry[cap_class]):
                    layer = self
                    break
        else:
            layer = Packet.getlayer(self, cls, nb, _track)
        return layer

    def post_build(self, p, pay):
        length = 0
        if self.length is None:
            # capability packet length - capability code (1 byte) -
            # capability length (1 byte)
            length = len(p) - 2
            p = p[0] + struct.pack("!B", length) + p[2:]
        return p + pay


class BGPCapGeneric(BGPCapability):
    """
    This class provides an implementation of a generic capability.
    """

    name = "BGP Capability"
    fields_desc = [
        ByteEnumField("code", 0, _capabilities),
        ByteField("length", 0),
        ConditionalField(
            StrLenField(
                "cap_data",
                '',
                length_from=lambda p: p.length
            ),
            lambda p: p.length > 0
        )
    ]


#
# Multiprotocol Extensions for BGP-4
#

class BGPCapMultiprotocol(BGPCapability):
    """
    This class provides an implementation of the Multiprotocol
    capability.
    """

    #________________________________________________________________________
    #
    # RFC 4760
    #________________________________________________________________________
    #
    # The Capability Code field is set to 1 (which indicates Multiprotocol
    # Extensions capabilities).  The Capability Length field is set to 4.
    # The Capability Value field is defined as:
    #
    #             0       7      15      23      31
    #             +-------+-------+-------+-------+
    #             |      AFI      | Res.  | SAFI  |
    #             +-------+-------+-------+-------+
    #
    # The use and meaning of this field is as follow:
    #       AFI  - Address Family Identifier (16 bit), encoded the same way
    #       as in the Multiprotocol Extensions
    #
    #       Res. - Reserved (8 bit) field. SHOULD be set to 0 by the sender
    #       and ignored by the receiver. Note that not setting the field
    #       value to 0 may create issues for a receiver not ignoring the
    #       field.  In addition, this definition is problematic if it is
    #       ever attempted to redefine the field.
    #
    #       SAFI - Subsequent Address Family Identifier (8 bit), encoded the
    #       same way as in the Multiprotocol Extensions.
    #
    # A speaker that supports multiple <AFI, SAFI> tuples includes them as
    # multiple Capabilities in the Capabilities Optional Parameter.
    #
    # To have a bi-directional exchange of routing information for a
    # particular <AFI, SAFI> between a pair of BGP speakers, each such
    # speaker MUST advertise to the other (via the Capability Advertisement
    # mechanism) the capability to support that particular <AFI, SAFI>
    # route.
    #________________________________________________________________________
    #

    name = "Multiprotocol Extensions for BGP-4"
    fields_desc = [
        ByteEnumField("code", 1, _capabilities),
        ByteField("length", 4),
        ShortEnumField("afi", 0, address_family_identifiers),
        ByteField("reserved", 0),
        ByteEnumField("safi", 0, subsequent_afis)
    ]


#
# Outbound Route Filtering Capability for BGP-4
#

_orf_types = {
    0: "Reserved",  # RFC 5291
    64: "Address Prefix ORF",  # RFC 5292
    65: "CP-ORF",  # RFC 7543
}


send_receive_values = {
    1: "receive",
    2: "send",
    3: "receive + send"
}


class BGPCapORFBlock(Packet):
    """
    The "ORFBlock" is made of <AFI, rsvd, SAFI, Number of ORFs, and
    <ORF Type, Send/Receive> entries.
    """

    class ORFTuple(Packet):
        """
        Packet handling <ORF Types, Send/Receive> tuples.
        """

        # (ORF Type (1 octet) / Send/Receive (1 octet)) ....
        name = "ORF Type"
        fields_desc = [
            ByteEnumField("orf_type", 0, _orf_types),
            ByteEnumField("send_receive", 0, send_receive_values)
        ]

    name = "ORF Capability Entry"
    fields_desc = [
        ShortEnumField("afi", 0, address_family_identifiers),
        ByteField("reserved", 0),
        ByteEnumField("safi", 0, subsequent_afis),
        FieldLenField(
            "orf_number",
            None,
            count_of="entries",
            fmt="!B"
        ),
        PacketListField(
            "entries",
            [],
            ORFTuple,
            count_from=lambda p: p.orf_number
        )
    ]

    def post_build(self, p, pay):
        count = None
        if self.orf_number is None:
            count = len(self.entries)  # orf_type (1 byte) + send_receive (1 byte)
            p = p[:4] + struct.pack("!B", count) + p[5:]
        return p + pay


class BGPCapORFBlockPacketListField(PacketListField):
    """
    Handles lists of BGPCapORFBlocks.
    """

    def getfield(self, pkt, s):
        lst = []
        length = None

        if self.length_from is not None:
            length = self.length_from(pkt)
        remain = s
        if length is not None:
            remain = s[:length]

        while remain:
            # block length: afi (2 bytes) + reserved (1 byte) + safi (1 byte) +
            # orf_number (1 byte) + entries (2 bytes * orf_number)
            orf_number = struct.unpack("!B", remain[4])[0]
            entries_length = orf_number * 2
            current = remain[:5 + entries_length]
            remain = remain[5 + entries_length:]
            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain, lst


class BGPCapORF(BGPCapability):
    """
    This class provides an implementation of the Outbound Route Filtering
    capability.
    """

    #________________________________________________________________________
    #
    # RFC 5291
    #________________________________________________________________________
    #
    # The Outbound Route Filtering Capability is a new BGP Capability defined
    # as follows:
    #       Capability code: 3
    #       Capability length: variable
    #       Capability value: one or more of the entries as shown in Figure
    #       3.
    #
    # +--------------------------------------------------+
    # | Address Family Identifier (2 octets)             |
    # +--------------------------------------------------+
    # | Reserved (1 octet)                               |
    # +--------------------------------------------------+
    # | Subsequent Address Family Identifier (1 octet)   |
    # +--------------------------------------------------+
    # | Number of ORFs (1 octet)                         |
    # +--------------------------------------------------+
    # | ORF Type (1 octet)                               |
    # +--------------------------------------------------+
    # | Send/Receive (1 octet)                           |
    # +--------------------------------------------------+
    # | ...                                              |
    # +--------------------------------------------------+
    # | ORF Type (1 octet)                               |
    # +--------------------------------------------------+
    # | Send/Receive (1 octet)                           |
    # +--------------------------------------------------+
    #
    # Figure 3: Outbound Route Filtering Capability Encoding
    #
    # The use and meaning of these fields are as follows:
    #       Address Family Identifier (AFI):
    #               This field is the same as the one used in RFC 4760.
    #
    #       Subsequent Address Family Identifier (SAFI):
    #               This field is the same as the one used in RFC 4760.
    #
    #       Number of ORF Types:
    #               This field contains the number of Filter Types to be
    #               listed in the following fields.
    #
    #       ORF Type:
    #               This field contains the value of an ORF Type.
    #
    #       Send/Receive:
    #               This field indicates whether the sender is (a) willing to
    #               receive ORF entries from its peer (value 1), (b) would
    #               like to send ORF entries to its peer (value 2), or (c)
    #               both (value 3) for the ORF Type.
    #________________________________________________________________________
    #

    name = "Outbound Route Filtering Capability"
    fields_desc = [
        ByteEnumField("code", 3, _capabilities),
        ByteField("length", None),
        BGPCapORFBlockPacketListField(
            "orf",
            [],
            BGPCapORFBlock,
            length_from=lambda p: p.length
        )
    ]


#
# Graceful Restart capability
#

gr_address_family_flags = {
    128: "Forwarding state preserved (0x80: F bit set)"
}


class BGPCapGracefulRestart(BGPCapability):
    """
    This class provides an implementation of the Graceful Restart
    capability.
    """

    #________________________________________________________________________
    #
    # RFC 4724
    #________________________________________________________________________
    #
    # The Graceful Restart Capability is a new BGP capability that can be
    # used by a BGP speaker to indicate its ability to preserve its
    # forwarding state during BGP restart. It can also be used to convey to
    # its peer its intention of generating the End-of-RIB marker upon the
    # completion of its initial routing updates.
    #
    # This capability is defined as follows:
    #       Capability code: 64
    #       Capability length: variable
    #       Capability value: Consists of the "Restart Flags" field,
    #       "Restart Time" field, and 0 to 63 of the tuples <AFI, SAFI,
    #       Flags for address family> as follows:
    #
    # +--------------------------------------------------+
    # | Restart Flags (4 bits)                           |
    # +--------------------------------------------------+
    # | Restart Time in seconds (12 bits)                |
    # +--------------------------------------------------+
    # | Address Family Identifier (16 bits)              |
    # +--------------------------------------------------+
    # | Subsequent Address Family Identifier (8 bits)    |
    # +--------------------------------------------------+
    # | Flags for Address Family (8 bits)                |
    # +--------------------------------------------------+
    # | ...                                              |
    # +--------------------------------------------------+
    # | Address Family Identifier (16 bits)              |
    # +--------------------------------------------------+
    # | Subsequent Address Family Identifier (8 bits)    |
    # +--------------------------------------------------+
    # | Flags for Address Family (8 bits)                |
    # +--------------------------------------------------+
    #
    # The use and meaning of the fields are as follows:
    #
    # Restart Flags:
    #   This field contains bit flags related to restart.
    #
    #       0 1 2 3
    #      +-+-+-+-+
    #      |R|Resv.|
    #      +-+-+-+-+
    #
    #   The most significant bit is defined as the Restart State (R) bit,
    #   which can be used to avoid possible deadlock caused by waiting for
    #   the End-of-RIB marker when multiple BGP speakers peering with each
    #   other restart. When set (value 1), this bit indicates that the BGP
    #   speaker has restarted, and its peer MUST NOT wait for the End-of-RIB
    #   marker from the speaker before advertising routing information to the
    #   speaker.
    #
    #   The remaining bits are reserved and MUST be set to zero by the sender
    #   and ignored by the receiver.
    #
    # Restart Time:
    #   This is the estimated time (in seconds) it will take for the BGP
    #   session to be re-established after a restart.  This can be used to
    #   speed up routing convergence by its peer in case that the BGP speaker
    #   does not come back after a restart.
    #
    # Address Family Identifier (AFI), Subsequent Address Family
    #   Identifier (SAFI):
    #
    #   The AFI and SAFI, taken in combination, indicate that Graceful
    #   Restart is supported for routes that are advertised with the same
    #   AFI and SAFI.  Routes may be explicitly associated with a particular
    #   AFI and SAFI using the encoding of [BGP-MP] or implicitly associated
    #   with <AFI=IPv4, SAFI=Unicast> if using the encoding of [BGP-4].
    #
    # Flags for Address Family:
    #
    #   This field contains bit flags relating to routes that were advertised
    #   with the given AFI and SAFI.
    #
    #    0 1 2 3 4 5 6 7
    #   +-+-+-+-+-+-+-+-+
    #   |F|   Reserved  |
    #   +-+-+-+-+-+-+-+-+
    #
    #   The most significant bit is defined as the Forwarding State (F) bit,
    #   which can be used to indicate whether the forwarding state for routes
    #   that were advertised with the given AFI and SAFI has indeed been
    #   preserved during the previous BGP restart. When set (value 1), the
    #   bit indicates that the forwarding state has been preserved.
    #
    #   The remaining bits are reserved and MUST be set to zero by the
    #   sender and ignored by the receiver.
    #________________________________________________________________________
    #

    class GRTuple(Packet):

        """Tuple <AFI, SAFI, Flags for address family>"""
        name = "<AFI, SAFI, Flags for address family>"
        fields_desc = [ShortEnumField("afi", 0, address_family_identifiers),
                       ByteEnumField("safi", 0, subsequent_afis),
                       ByteEnumField("flags", 0, gr_address_family_flags)]

    name = "Graceful Restart Capability"
    fields_desc = [ByteEnumField("code", 64, _capabilities),
                   ByteField("length", None),
                   BitField("restart_flags", 0, 4),
                   BitField("restart_time", 0, 12),
                   PacketListField("entries", [], GRTuple)]


#
# Support for 4-octet AS number capability
#

class BGPCapFourBytesASN(BGPCapability):
    """
    This class provides an implementation of the 4-octet AS number
    capability.
    """

    #________________________________________________________________________
    #
    # RFC 4893
    #________________________________________________________________________
    #
    # "The Capability that is used by a BGP speaker to convey to its BGP peer
    # the 4-octet Autonomous System number capability, also carries the
    # 4-octet Autonomous System number of the speaker in the Capability
    # Value field of the Capability Optional Parameter.  The Capability
    # Length field of the Capability is set to 4."
    #________________________________________________________________________
    #

    name = "Support for 4-octet AS number capability"
    fields_desc = [ByteEnumField("code", 65, _capabilities),
                   ByteField("length", 4),
                   IntField("asn", 0)]


#
# Authentication Information optional parameter.
#

class BGPAuthenticationInformation(Packet):

    """
    Provides an implementation of the Authentication Information optional
    parameter, which is now obsolete.
    """

    #________________________________________________________________________
    #
    # RFC 1771 (became an optional parameter in RFC 1771, was in the OPEN
    # message in RFC 1654)
    #________________________________________________________________________
    #
    # Authentication Information (Parameter Type 1):
    #       This optional parameter may be used to authenticate a BGP peer.
    #       The Parameter Value field contains a 1-octet Authentication Code
    #       followed by a variable length Authentication Data.
    #
    # 0 1 2 3 4 5 6 7 8
    # +-+-+-+-+-+-+-+-+
    # |  Auth. Code   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                     |
    # |              Authentication Data                    |
    # |                                                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Authentication Code:
    #       This 1-octet unsigned integer indicates the authentication
    #       mechanism being used.  Whenever an authentication mechanism is
    #       specified for use within BGP, three things must be included in
    #       the specification:
    #               - the value of the Authentication Code which indicates
    #               use of the mechanism,
    #               - the form and meaning of the Authentication Data, and
    #               - the algorithm for computing values of Marker fields.
    #
    #               Note that a separate authentication mechanism may be used
    #               in establishing the transport level connection.
    #
    # Authentication Data:
    #       The form and meaning of this field is a variable-length field
    #       depend on the Authentication Code.
    #
    #________________________________________________________________________
    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # Optional Parameter Type 1 (Authentication Information) has been
    # deprecated.
    #________________________________________________________________________
    #

    name = "BGP Authentication Data"
    fields_desc = [ByteField("authentication_code", 0),
                   StrField("authentication_data", None)]


#
# Optional Parameter.
#


class BGPOptParamPacketListField(PacketListField):
    """
    PacketListField handling the optional parameters (OPEN message).
    """

    def getfield(self, pkt, s):
        lst = []

        length = 0
        if self.length_from is not None:
            length = self.length_from(pkt)
        remain = s
        if length is not None:
            remain, ret = s[:length], s[length:]

        while remain:
            param_len = struct.unpack("!B", remain[1])[0]  # Get param length
            current = remain[:2 + param_len]
            remain = remain[2 + param_len:]
            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain + ret, lst


class BGPOptParam(Packet):
    """
    Provides an implementation the OPEN message optional parameters.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # Optional Parameters:
    #       This field contains a list of optional parameters, in which each
    #       parameter is encoded as a <Parameter Type, Parameter Length,
    #       Parameter Value> triplet.
    #
    # 0                   1
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
    # |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
    #
    # Parameter Type is a one octet field that unambiguously identifies
    # individual parameters.
    # Parameter Length is a one octet field that contains the length of the
    # Parameter Value field in octets.
    # Parameter Value is a variable length field that is interpreted
    # according to the value of the Parameter Type field.
    #________________________________________________________________________
    #

    name = "Optional parameter"
    fields_desc = [
        ByteEnumField("param_type", 2, optional_parameter_codes),
        ByteField("param_length", None),
        ConditionalField(
            PacketField(
                "param_value",
                None,
                BGPCapability
            ),
            lambda p: p.param_type == 2
        ),
        # It"s obsolete, but one can use it provided that
        # param_type == 1.
        ConditionalField(
            PacketField(
                "authentication_data",
                None,
                BGPAuthenticationInformation
            ),
            lambda p: p.param_type == 1
        )
    ]

    def post_build(self, p, pay):
        length = None
        packet = p
        if self.param_length is None:
            if self.param_value is None and self.authentication_data is None:
                length = 0
            else:
                length = len(p) - \
                    2  # parameter type (1 byte) - parameter length (1 byte)
            packet = p[0] + struct.pack("!B", length)
            if (self.param_type == 2 and self.param_value is not None) or\
                    (self.param_type == 1 and self.authentication_data is not None):
                packet = packet + p[2:]

        return packet + pay


#
# OPEN
#

class BGPOpen(BGP):
    """
    OPEN messages are exchanged in order to open a new BGP session.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # After a TCP connection is established, the first message sent by each
    # side is an OPEN message.  If the OPEN message is acceptable, a
    # KEEPALIVE message confirming the OPEN is sent back. In addition to the
    # fixed-size BGP header, the OPEN message contains the following fields:
    #
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+
    # |    Version    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     My Autonomous System      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Hold Time           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         BGP Identifier                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Opt Parm Len  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # |             Optional Parameters (variable)                    |
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Version:
    #       This 1-octet unsigned integer indicates the protocol version
    #       number of the message.  The current BGP version number is 4.
    #
    # My Autonomous System:
    #       This 2-octet unsigned integer indicates the Autonomous System
    #       number of the sender.
    #
    # Hold Time:
    #       This 2-octet unsigned integer indicates the number of seconds the
    #       sender proposes for the value of the Hold Timer.  Upon receipt of
    #       an OPEN message, a BGP speaker MUST calculate the value of the
    #       Hold Timer by using the smaller of its configured Hold Time and
    #       the Hold Time received in the OPEN message. The Hold Time MUST be
    #       either zero or at least three seconds.  An implementation MAY
    #       reject connections on the basis of the Hold Time. The calculated
    #       value indicates the maximum number of seconds that may elapse
    #       between the receipt of successive KEEPALIVE and/or UPDATE
    #       messages from the sender.
    #
    # BGP Identifier:
    #       This 4-octet unsigned integer indicates the BGP Identifier of the
    #       sender. A given BGP speaker sets the value of its BGP Identifier
    #       to an IP address that is assigned to that BGP speaker. The value
    #       of the BGP Identifier is determined upon startup and is the same
    #       for every local interface and BGP peer.
    #
    # Optional Parameters Length:
    #       This 1-octet unsigned integer indicates the total length of the
    #       Optional Parameters field in octets.  If the value of this field
    #       is zero, no Optional Parameters are present.
    #
    # Optional Parameters:
    #       [...]
    #
    # [RFC3392] defines the Capabilities Optional Parameter.
    #
    # The minimum length of the OPEN message is 29 octets (including the
    # message header).
    #________________________________________________________________________
    #

    name = "OPEN"
    fields_desc = [
        ByteField("version", 4),
        ShortField("my_as", 0),
        ShortField("hold_time", 0),
        IPField("bgp_id", "0.0.0.0"),
        FieldLenField(
            "opt_param_len",
            None,
            length_of="opt_params",
            fmt="!B"
        ),
        BGPOptParamPacketListField(
            "opt_params",
            [],
            BGPOptParam,
            length_from=lambda p: p.opt_param_len
        )
    ]

    def post_build(self, p, pay):
        if self.opt_param_len is None:
            length = len(p) - 10  # 10 is regular length with no additional
            # options
            p = p[:9] + struct.pack("!B", length) + p[10:]
        return p + pay


#
# UPDATE
#

#
# Path attributes
#

#
# Dictionaries

path_attributes = {
    0: "Reserved",
    1: "ORIGIN",  # RFC 4271
    2: "AS_PATH",  # RFC 4271
    3: "NEXT_HOP",  # RFC 4271
    4: "MULTI_EXIT_DISC",  # RFC 4271
    5: "LOCAL_PREF",  # RFC 4271
    6: "ATOMIC_AGGREGATE",  # RFC 4271
    7: "AGGREGATOR",  # RFC 4271
    8: "COMMUNITY",  # RFC 1997
    9: "ORIGINATOR_ID",  # RFC 4456
    10: "CLUSTER_LIST",  # RFC 4456
    11: "DPA (deprecated)",  # RFC 6938
    12: "ADVERTISER  (Historic) (deprecated)",  # RFC 4223, RFC 6938
    13: "RCID_PATH / CLUSTER_ID (Historic) (deprecated)",  # RFC 4223, RFC 6938
    14: "MP_REACH_NLRI",  # RFC 4760
    15: "MP_UNREACH_NLRI",  # RFC 4760
    16: "EXTENDED COMMUNITIES",  # RFC 4360
    17: "AS4_PATH",  # RFC 6793
    18: "AS4_AGGREGATOR",  # RFC 6793
    19: "SAFI Specific Attribute (SSA) (deprecated)",  # draft-kapoor-nalawade-idr-bgp-ssa-00,
    # draft-nalawade-idr-mdt-safi-00, draft-wijnands-mt-discovery-00
    20: "Connector Attribute (deprecated)",  # RFC 6037
    21: "AS_PATHLIMIT (deprecated)",  # draft-ietf-idr-as-pathlimit
    22: "PMSI_TUNNEL",  # RFC 6514
    23: "Tunnel Encapsulation Attribute",  # RFC 5512
    24: "Traffic Engineering",  # RFC 5543
    25: "IPv6 Address Specific Extended Community",  # RFC 5701
    26: "AIGP",  # RFC 7311
    27: "PE Distinguisher Labels",  # RFC 6514
    28: "BGP Entropy Label Capability Attribute (deprecated)",  # RFC 6790, RFC 7447
    29: "BGP-LS Attribute",  # RFC 7752
    40: "BGP Prefix-SID",  # (TEMPORARY - registered 2015-09-30, expires 2016-09-30)
    # draft-ietf-idr-bgp-prefix-sid
    128: "ATTR_SET",  # RFC 6368
    255: "Reserved for development"
}

# http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xml
attributes_flags = {
    1: 0x40,    # ORIGIN
    2: 0x40,    # AS_PATH
    3: 0x40,    # NEXT_HOP
    4: 0x80,    # MULTI_EXIT_DISC
    5: 0x40,    # LOCAL_PREF
    6: 0x40,    # ATOMIC_AGGREGATE
    7: 0xc0,    # AGGREGATOR
    8: 0xc0,    # COMMUNITIES (RFC 1997)
    9: 0x80,    # ORIGINATOR_ID (RFC 4456)
    10: 0x80,   # CLUSTER_LIST (RFC 4456)
    11: 0xc0,   # DPA (RFC 6938)
    12: 0x80,   # ADVERTISER (RFC 1863, RFC 4223)
    13: 0x80,   # RCID_PATH (RFC 1863, RFC 4223)
    14: 0x80,   # MP_REACH_NLRI (RFC 4760)
    15: 0x80,   # MP_UNREACH_NLRI (RFC 4760)
    16: 0xc0,   # EXTENDED_COMMUNITIES (RFC 4360)
    17: 0xc0,   # AS4_PATH (RFC 6793)
    18: 0xc0,   # AS4_AGGREGATOR (RFC 6793)
    19: 0xc0,   # SSA (draft-kapoor-nalawade-idr-bgp-ssa-00)
    20: 0xc0,   # Connector (RFC 6037)
    21: 0xc0,   # AS_PATHLIMIT (draft-ietf-idr-as-pathlimit)
    22: 0xc0,   # PMSI_TUNNEL (RFC 6514)
    23: 0xc0,   # Tunnel Encapsulation (RFC 5512)
    24: 0x80,   # Traffic Engineering (RFC 5543)
    25: 0xc0,   # IPv6 Address Specific Extended Community (RFC 5701)
    26: 0x80,   # AIGP (RFC 7311)
    27: 0xc0,   # PE Distinguisher Labels (RFC 6514)
    28: 0xc0,   # BGP Entropy Label Capability Attribute
    29: 0x80,   # BGP-LS Attribute
    40: 0xc0,   # BGP Prefix-SID
    128: 0xc0   # ATTR_SET (RFC 6368)
}


class BGPPathAttrPacketListField(PacketListField):
    """
    PacketListField handling the path attributes (UPDATE message).
    """

    def getfield(self, pkt, s):
        lst = []
        length = 0

        if self.length_from is not None:
            length = self.length_from(pkt)
        ret = ""
        remain = s
        if length is not None:
            remain, ret = s[:length], s[length:]

        while remain:
            #
            # Get the path attribute flags
            flags = struct.unpack("!B", remain[0])[0]

            attr_len = 0
            if has_extended_length(flags):
                attr_len = struct.unpack("!H", remain[2:4])[0]
                current = remain[:4 + attr_len]
                remain = remain[4 + attr_len:]
            else:
                attr_len = struct.unpack("!B", remain[2])[0]
                current = remain[:3 + attr_len]
                remain = remain[3 + attr_len:]

            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain + ret, lst


#
# ORIGIN
#

class BGPPAOrigin(Packet):

    """
    Packet handling the ORIGIN attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # ORIGIN (Type Code 1):
    #   ORIGIN is a well-known mandatory attribute that defines the origin of
    #   the path information. The data octet can assume the following values:
    #
    #  Value                Meaning
    #
    #       0               IGP - Network Layer Reachability Information is
    #                       interior to the originating AS
    #       1               EGP - Network Layer Reachability Information
    #                       learned via the EGP protocol [RFC904]
    #       2               INCOMPLETE - Network Layer Reachability
    #                       Information learned by some other means
    #________________________________________________________________________
    #

    name = "ORIGIN"
    fields_desc = [
        ByteEnumField("origin", 0, {0: "IGP", 1: "EGP", 2: "INCOMPLETE"})]


#
# AS_PATH (2 bytes and 4 bytes)
#

as_path_segment_types = {
    # RFC 4271
    1: "AS_SET",
    2: "AS_SEQUENCE",

    # RFC 5065
    3: "AS_CONFED_SEQUENCE",
    4: "AS_CONFED_SET"
}


class ASPathSegmentPacketListField(PacketListField):
    """
    PacketListField handling AS_PATH segments.
    """

    def getfield(self, pkt, s):
        lst = []
        remain = s

        while remain:
            #
            # Get the segment length
            segment_length = struct.unpack("!B", remain[1])[0]

            if bgp_module_conf.use_2_bytes_asn:
                current = remain[:2 + segment_length * 2]
                remain = remain[2 + segment_length * 2:]
            else:
                current = remain[:2 + segment_length * 4]
                remain = remain[2 + segment_length * 4:]

            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain, lst


class BGPPAASPath(Packet):
    """
    Packet handling the AS_PATH attribute value (2 bytes ASNs, for old
    speakers).
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # AS_PATH (Type Code 2):
    #   AS_PATH is a well-known mandatory attribute that is composed of a
    #   sequence of AS path segments.  Each AS path segment is represented by
    #   a triple <path segment type, path segment length,
    #   path segment value>.
    #
    #   The path segment type is a 1-octet length field with the following
    #   values defined:
    #       Value   Segment Type
    #           1         AS_SET: unordered set of ASes a route in the UPDATE
    #                     message has traversed
    #           2         AS_SEQUENCE: ordered set of ASes a route in the
    #                     UPDATE message has traversed
    #
    #   The path segment length is a 1-octet length field, containing the
    #   number of ASes (not the number of octets) in the path segment value
    #   field.
    #
    #   The path segment value field contains one or more AS numbers, each
    #   encoded as a 2-octet length field.
    #________________________________________________________________________
    #________________________________________________________________________
    #
    # RFC 5065
    #________________________________________________________________________
    #
    # This document specifies two additional segment types:
    #   3       AS_CONFED_SEQUENCE: ordered set of Member Autonomous Systems
    #           in the local confederation that the UPDATE message has
    #           traversed
    #   4       AS_CONFED_SET: unordered set of Member Autonomous Systems in
    #           the local confederation that the UPDATE message has traversed
    #________________________________________________________________________
    #

    AS_TRANS = 23456

    class ASPathSegment(Packet):
        """
        Provides an implementation for AS_PATH segments with 2 bytes ASNs.
        """

        fields_desc = [
            ByteEnumField("segment_type", 2, as_path_segment_types),
            ByteField("segment_length", None),
            FieldListField("segment_value", [], ShortField("asn", 0))
        ]

        def post_build(self, p, pay):
            segment_len = self.segment_length
            if segment_len is None:
                segment_len = len(self.segment_value)
                p = p[0] + struct.pack("!B", segment_len) + p[2:]

            return p + pay

    name = "AS_PATH (RFC 4271)"
    fields_desc = [
        ASPathSegmentPacketListField("segments", [], ASPathSegment)]


class BGPPAAS4BytesPath(Packet):
    """
    Packet handling the AS_PATH attribute value (4 bytes ASNs, for new
    speakers -> ASNs are encoded as IntFields).
    """

    #________________________________________________________________________
    #
    # RFC 4893
    #________________________________________________________________________
    #
    # 4.1. Interaction Between NEW BGP Speakers
    #
    # A BGP speaker that supports 4-octet Autonomous System numbers SHOULD
    # advertise this to its peers using the BGP Capability Advertisements.
    # A BGP speaker that advertises such capability to a particular peer, and
    # receives from that peer the advertisement of such capability MUST
    # encode Autonomous System numbers as 4-octet entities in both the
    # AS_PATH and the AGGREGATOR attributes in the updates it sends to the
    # peer, and MUST assume that these attributes in the updates received
    # from the peer encode Autonomous System numbers as 4-octet entities.
    #
    # The new attributes, AS4_PATH and AS4_AGGREGATOR SHOULD NOT be carried
    # in the UPDATE messages between NEW BGP peers. A NEW BGP speaker that
    # receives the AS4_PATH and AS4_AGGREGATOR path attributes in an UPDATE
    # message from a NEW BGP speaker SHOULD discard these path attributes
    # and continue processing the UPDATE message.
    #________________________________________________________________________
    #

    class ASPathSegment(Packet):
        """
        Provides an implementation for AS_PATH segments with 4 bytes ASNs.
        """

        fields_desc = [ByteEnumField("segment_type", 2, as_path_segment_types),
                       ByteField("segment_length", None),
                       FieldListField("segment_value", [], IntField("asn", 0))]

        def post_build(self, p, pay):
            segment_len = self.segment_length
            if segment_len is None:
                segment_len = len(self.segment_value)
                p = p[0] + struct.pack("!B", segment_len) + p[2:]

            return p + pay

    name = "AS_PATH (RFC 4893)"
    fields_desc = [
        ASPathSegmentPacketListField("segments", [], ASPathSegment)]


#
# NEXT_HOP
#

class BGPPANextHop(Packet):
    """
    Packet handling the NEXT_HOP attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # NEXT_HOP (Type Code 3):
    #
    # This is a well-known mandatory attribute that defines the (unicast) IP
    # address of the router that SHOULD be used as the next hop to the
    # destinations listed in the Network Layer Reachability Information field
    # of the UPDATE message.
    #________________________________________________________________________
    #

    name = "NEXT_HOP"
    fields_desc = [IPField("next_hop", "0.0.0.0")]


#
# MULTI_EXIT_DISC
#

class BGPPAMultiExitDisc(Packet):
    """
    Packet handling the MULTI_EXIT_DISC attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # MULTI_EXIT_DISC (Type Code 4):
    #
    # This is an optional non-transitive attribute that is a four-octet
    # unsigned integer. The value of this attribute MAY be used by a BGP
    # speaker"s Decision Process to discriminate among multiple entry points
    # to a neighboring autonomous system.
    #________________________________________________________________________
    #

    name = "MULTI_EXIT_DISC"
    fields_desc = [IntField("med", 0)]


#
# LOCAL_PREF
#

class BGPPALocalPref(Packet):
    """
    Packet handling the LOCAL_PREF attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # LOCAL_PREF (Type Code 5):
    #
    # LOCAL_PREF is a well-known attribute that is a four-octet unsigned
    # integer. A BGP speaker uses it to inform its other internal peers of
    # the advertising speaker"s degree of preference for an advertised route.
    #________________________________________________________________________
    #

    name = "LOCAL_PREF"
    fields_desc = [IntField("local_pref", 0)]


#
# ATOMIC_AGGREGATE
#

class BGPPAAtomicAggregate(Packet):
    """
    Packet handling the ATOMIC_AGGREGATE attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # ATOMIC_AGGREGATE (Type Code 6)
    #
    # ATOMIC_AGGREGATE is a well-known discretionary attribute of length 0.
    #
    # If an aggregate excludes at least some of the AS numbers present in the
    # AS_PATH of the routes that are aggregated as a result of dropping the
    # AS_SET, the aggregated route, when advertised to the peer, SHOULD
    # include the ATOMIC_AGGREGATE attribute.
    #________________________________________________________________________
    #

    name = "ATOMIC_AGGREGATE"


#
# AGGREGATOR
#

class BGPPAAggregator(Packet):
    """
    Packet handling the AGGREGATOR attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # AGGREGATOR (Type Code 7)
    #
    # AGGREGATOR is an optional transitive attribute of length 6. The
    # attribute contains the last AS number that formed the aggregate route
    # (encoded as 2 octets), followed by the IP address of the BGP speaker
    # that formed the aggregate route (encoded as 4 octets). This SHOULD be
    # the same address as the one used for the BGP Identifier of the
    # speaker.
    #________________________________________________________________________
    #

    name = "AGGREGATOR"
    fields_desc = [ShortField("aggregator_asn", 0),
                   IPField("speaker_address", "0.0.0.0")]


#
# COMMUNITIES
#

# http://www.iana.org/assignments/bgp-well-known-communities/bgp-well-known-communities.xml
well_known_communities = {
    0xFFFFFF01: "NO_EXPORT",  # RFC 1997
    0xFFFFFF02: "NO_ADVERTISE",  # RFC 1997
    0xFFFFFF03: "NO_EXPORT_SUBCONFED",  # RFC 1997
    0xFFFFFF04: "NOPEER",  # RFC 3765
    0xFFFF0000: "planned-shut",  # draft-francois-bgp-gshut
    0xFFFF0001: "ACCEPT-OWN",  # RFC 7611
    0xFFFF0002: "ROUTE_FILTER_TRANSLATED_v4",  # draft-l3vpn-legacy-rtc
    0xFFFF0003: "ROUTE_FILTER_v4",  # draft-l3vpn-legacy-rtc
    0xFFFF0004: "ROUTE_FILTER_TRANSLATED_v6",  # draft-l3vpn-legacy-rtc
    0xFFFF0005: "ROUTE_FILTER_v6",  # draft-l3vpn-legacy-rtc
    0xFFFF0006: "LLGR_STALE",  # draft-uttaro-idr-bgp-persistence
    0xFFFF0007: "NO_LLGR",  # draft-uttaro-idr-bgp-persistence
    0xFFFF0008: "accept-own-nexthop",  # Ashutosh_Grewal
}


class BGPPACommunity(Packet):
    """
    Packet handling the COMMUNITIES attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 1997
    #________________________________________________________________________
    #
    # The attribute consists of a set of four octet values, each of which
    # specify a community. All routes with this attribute belong to the
    # communities listed in the attribute.
    #
    # The COMMUNITIES attribute has Type Code 8.
    #________________________________________________________________________
    #

    name = "COMMUNITIES"
    fields_desc = [IntEnumField("community", 0, well_known_communities)]


#
# ORIGINATOR_ID
#

class BGPPAOriginatorID(Packet):
    """
    Packet handling the ORIGINATOR_ID attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4456
    #________________________________________________________________________
    #
    # ORIGINATOR_ID
    #
    # ORIGINATOR_ID is a new optional, non-transitive BGP attribute of Type
    # code 9. This attribute is 4 bytes long and it will be created by an RR
    # in reflecting a route. This attribute will carry the BGP Identifier of
    # the originator of the route in the local AS.  A BGP speaker SHOULD NOT
    # create an ORIGINATOR_ID attribute if one already exists. A router that
    # recognizes the ORIGINATOR_ID attribute SHOULD ignore a route received
    # with its BGP Identifier as the ORIGINATOR_ID.
    #________________________________________________________________________
    #

    name = "ORIGINATOR_ID"
    fields_desc = [IPField("originator_id", "0.0.0.0")]


#
# CLUSTER_LIST
#

class BGPPAClusterList(Packet):
    """
    Packet handling the CLUSTER_LIST attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4456
    #________________________________________________________________________
    #
    # CLUSTER_LIST
    #
    # CLUSTER_LIST is a new, optional, non-transitive BGP attribute of Type
    # code 10. It is a sequence of CLUSTER_ID values representing the
    # reflection path that the route has passed.
    #
    # When an RR reflects a route, it MUST prepend the local CLUSTER_ID to
    # the CLUSTER_LIST.  If the CLUSTER_LIST is empty, it MUST create a new
    # one.  Using this attribute an RR can identify if the routing
    # information has looped back to the same cluster due to
    # misconfiguration. If the local CLUSTER_ID is found in the CLUSTER_LIST,
    # the advertisement received SHOULD be ignored.
    #________________________________________________________________________
    #

    name = "CLUSTER_LIST"
    fields_desc = [
        FieldListField("cluster_list", [], IntField("cluster_id", 0))]


#
# EXTENDED COMMUNITIES (RFC 4360)
#

# BGP Transitive Extended Community Types
# http://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#transitive
_ext_comm_types = {
    0x00: "Transitive Two-Octet AS-Specific Extended Community",  # RFC 7153
    0x01: "Transitive IPv4-Address-Specific Extended Community",  # RFC 7153
    0x02: "Transitive Four-Octet AS-Specific Extended Community",  # RFC 7153
    0x03: "Transitive Opaque Extended Community",  # RFC 7153
    0x04: "QoS Marking",  # Thomas_Martin_Knoll
    0x05: "CoS Capability",  # Thomas_Martin_Knoll
    0x06: "EVPN",  # RFC 7153
    0x07: "Unassigned",
    0x08: "Flow spec redirect/mirror to IP next-hop",  # draft-simpson-idr-flowspec-redirect

    # BGP Non-Transitive Extended Community Types
    0x40: "Non-Transitive Two-Octet AS-Specific Extended Community",  # RFC 7153
    0x41: "Non-Transitive IPv4-Address-Specific Extended Community",  # RFC 7153
    0x42: "Non-Transitive Four-Octet AS-Specific Extended Community",  # RFC 7153
    0x43: "Non-Transitive Opaque Extended Community",  # RFC 7153
    0x44: "QoS Marking",  # Thomas_Martin_Knoll

    0x80: "Generic Transitive Experimental Use Extended Community",  # RFC 7153
    0x81: "Generic Transitive Experimental Use Extended Community Part 2",  # RFC 7674
    0x82: "Generic Transitive Experimental Use Extended Community Part 3",  # RFC 7674
}

# EVPN Extended Community Sub-Types
_ext_comm_evpn_subtypes = {
    0x00: "MAC Mobility",  # RFC 7432
    0x01: "ESI Label",  # RFC 7432
    0x02: "ES-Import Route Target",  # RFC 7432
    0x03: "EVPN Router\"s MAC Extended Community",
    # draft-sajassi-l2vpn-evpn-inter-subnet-forwarding
    0x04: "Layer 2 Extended Community",  # draft-ietf-bess-evpn-vpws
    0x05: "E-TREE Extended Community",  # draft-ietf-bess-evpn-etree
    0x06: "DF Election Extended Community",  # draft-ietf-bess-evpn-df-election
    0x07: "I-SID Extended Community",  # draft-sajassi-bess-evpn-virtual-eth-segment
}

# Transitive Two-Octet AS-Specific Extended Community Sub-Types
_ext_comm_trans_two_octets_as_specific_subtypes = {
    0x02: "Route Target",  # RFC 4360
    0x03: "Route Origin",  # RFC 4360
    0x04: "Unassigned",  # RFC 4360
    0x05: "OSPF Domain Identifier",  # RFC 4577
    0x08: "BGP Data Collection",  # RFC 4384
    0x09: "Source AS",  # RFC 6514
    0x0a: "L2VPN Identifier",  # RFC 6074
    0x0010: "Cisco VPN-Distinguisher",  # Eric_Rosen
}

# Non-Transitive Two-Octet AS-Specific Extended Community Sub-Types
_ext_comm_non_trans_two_octets_as_specific_subtypes = {
    0x04: "Link Bandwidth Extended Community",  # draft-ietf-idr-link-bandwidth-00
    0x80: "Virtual-Network Identifier Extended Community",
    # draft-drao-bgp-l3vpn-virtual-network-overlays
}

# Transitive Four-Octet AS-Specific Extended Community Sub-Types
_ext_comm_trans_four_octets_as_specific_subtypes = {
    0x02: "Route Target",  # RFC 5668
    0x03: "Route Origin",  # RFC 5668
    0x04: "Generic",  # draft-ietf-idr-as4octet-extcomm-generic-subtype
    0x05: "OSPF Domain Identifier",  # RFC 4577
    0x08: "BGP Data Collection",  # RFC 4384
    0x09: "Source AS",  # RFC 6514
    0x10: "Cisco VPN Identifier",  # Eric_Rosen
}

# Non-Transitive Four-Octet AS-Specific Extended Community Sub-Types
_ext_comm_non_trans_four_octets_as_specific_subtypes = {
    0x04: "Generic",  # draft-ietf-idr-as4octet-extcomm-generic-subtype
}

# Transitive IPv4-Address-Specific Extended Community Sub-Types
_ext_comm_trans_ipv4_addr_specific_subtypes = {
    0x02: "Route Target",  # RFC 4360
    0x03: "Route Origin",  # RFC 4360
    0x05: "OSPF Domain Identifier",  # RFC 4577
    0x07: "OSPF Route ID",  # RFC 4577
    0x0a: "L2VPN Identifier",  # RFC 6074
    0x0b: "VRF Route Import",  # RFC 6514
    0x0c: "Flow-spec Redirect to IPv4",  # draft-ietf-idr-flowspec-redirect
    0x10: "Cisco VPN-Distinguisher",  # Eric_Rosen
    0x12: "Inter-Area P2MP Segmented Next-Hop",  # RFC 7524
}

# Non-Transitive IPv4-Address-Specific Extended Community Sub-Types
_ext_comm_non_trans_ipv4_addr_specific_subtypes = {}

# Transitive Opaque Extended Community Sub-Types
_ext_comm_trans_opaque_subtypes = {
    0x01: "Cost Community",  # draft-ietf-idr-custom-decision
    0x03: "CP-ORF",  # RFC 7543
    0x04: "Extranet Source Extended Community",  # RFC 7900
    0x05: "Extranet Separation Extended Community",  # RFC 7900
    0x06: "OSPF Route Type",  # RFC 4577
    0x07: "Additional PMSI Tunnel Attribute Flags",  # RFC 7902
    0x0b: "Color Extended Community",  # RFC 5512
    0x0c: "Encapsulation Extended Community",  # RFC 5512
    0x0d: "Default Gateway",  # Yakov_Rekhter
    0x0e: "Point-to-Point-to-Multipoint (PPMP) Label",  # Rishabh_Parekh
    0x13: "Route-Target Record",  # draft-ietf-bess-service-chaining
    0x14: "Consistent Hash Sort Order",  # draft-ietf-bess-service-chaining
}

# Non-Transitive Opaque Extended Community Sub-Types
_ext_comm_non_trans_opaque_subtypes = {
    0x00: "BGP Origin Validation State",  # draft-ietf-sidr-origin-validation-signaling
    0x01: "Cost Community",  # draft-ietf-idr-custom-decision
}

# Generic Transitive Experimental Use Extended Community Sub-Types
_ext_comm_generic_transitive_exp_subtypes = {
    0x00: "OSPF Route Type (deprecated)",  # RFC 4577
    0x01: "OSPF Router ID (deprecated)",  # RFC 4577
    0x05: "OSPF Domain Identifier (deprecated)",  # RFC 4577
    0x06: "Flow spec traffic-rate",  # RFC 5575
    0x07: "Flow spec traffic-action",  # RFC 5575
    0x08: "Flow spec redirect AS-2byte format",  # RFC 5575, RFC 7674
    0x09: "Flow spec traffic-remarking",  # RFC 5575
    0x0a: "Layer2 Info Extended Community",  # RFC 4761
    0x0b: "E-Tree Info",  # RFC 7796
}

# Generic Transitive Experimental Use Extended Community Part 2 Sub-Types
_ext_comm_generic_transitive_exp_part2_subtypes = {
    0x08: "Flow spec redirect IPv4 format",  # RFC 7674
}

# Generic Transitive Experimental Use Extended Community Part 3 Sub-Types
_ext_comm_generic_transitive_exp_part3_subtypes = {
    0x08: "Flow spec redirect AS-4byte format",  # RFC 7674
}

# Traffic Action Fields
_ext_comm_traffic_action_fields = {
    47: "Terminal Action",  # RFC 5575
    46: "Sample",  # RFC 5575
}

# Transitive IPv6-Address-Specific Extended Community Types
_ext_comm_trans_ipv6_addr_specific_types = {
    0x0002: "Route Target",  # RFC 5701
    0x0003: "Route Origin",  # RFC 5701
    0x0004: "OSPFv3 Route Attributes (DEPRECATED)",  # RFC 6565
    0x000b: "VRF Route Import",  # RFC 6515, RFC 6514
    0x000c: "Flow-spec Redirect to IPv6",  # draft-ietf-idr-flowspec-redirect-ip
    0x0010: "Cisco VPN-Distinguisher",  # Eric_Rosen
    0x0011: "UUID-based Route Target",  # Dhananjaya_Rao
    0x0012: "Inter-Area P2MP Segmented Next-Hop",  # RFC 7524
}

# Non-Transitive IPv6-Address-Specific Extended Community Types
_ext_comm_non_trans_ipv6_addr_specific_types = {}


_ext_comm_subtypes_classes = {
    0x00: _ext_comm_trans_two_octets_as_specific_subtypes,
    0x01: _ext_comm_trans_ipv4_addr_specific_subtypes,
    0x02: _ext_comm_trans_four_octets_as_specific_subtypes,
    0x03: _ext_comm_trans_opaque_subtypes,
    0x06: _ext_comm_evpn_subtypes,
    0x40: _ext_comm_non_trans_two_octets_as_specific_subtypes,
    0x41: _ext_comm_non_trans_ipv4_addr_specific_subtypes,
    0x42: _ext_comm_non_trans_four_octets_as_specific_subtypes,
    0x43: _ext_comm_non_trans_opaque_subtypes,
    0x80: _ext_comm_generic_transitive_exp_subtypes,
    0x81: _ext_comm_generic_transitive_exp_part2_subtypes,
    0x82: _ext_comm_generic_transitive_exp_part3_subtypes,
}


#
# Extended Community "templates"
#

class BGPPAExtCommTwoOctetASSpecific(Packet):
    """
    Packet handling the Two-Octet AS Specific Extended Community attribute
    value.
    """

    #________________________________________________________________________
    #
    # RFC 4360
    #________________________________________________________________________
    #
    # The value of the high-order octet of this extended type is either 0x00
    # or 0x40. The low-order octet of this extended type is used to indicate
    # sub-types.
    #
    # The Value Field consists of two sub-fields:
    # Global Administrator sub-field: 2 octets
    # 	This sub-field contains an Autonomous System number assigned by IANA.
    #
    # Local Administrator sub-field: 4 octets
    # The organization identified by Autonomous System number in the Global
    # Administrator sub-field can encode any information in this sub-field.
    # The format and meaning of the value encoded in this sub-field should be
    # defined by the sub-type of the community.
    #________________________________________________________________________
    #

    name = "Two-Octet AS Specific Extended Community"
    fields_desc = [
        ShortField("global_administrator", 0), IntField("local_administrator", 0)]


class BGPPAExtCommFourOctetASSpecific(Packet):
    """
    Packet handling the Four-Octet AS Specific Extended Community
    attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 5668
    #________________________________________________________________________
    #
    # The Value field consists of 2 sub-fields:
    #   Global Administrator sub-field: 4 octets
    #       This sub-field contains a 4-octet Autonomous System number
    #       assigned by IANA.
    #
    #   Local Administrator sub-field: 2 octets
    #       The organization identified by the Autonomous System number in
    #       the Global Administrator sub-field can encode any information in
    #       this sub-field. The format and meaning of the value encoded in
    #       this sub-field should be defined by the sub-type of the
    #       community.
    #________________________________________________________________________
    #

    name = "Four-Octet AS Specific Extended Community"
    fields_desc = [
        IntField("global_administrator", 0), ShortField("local_administrator", 0)]


class BGPPAExtCommIPv4AddressSpecific(Packet):
    """
    Packet handling the IPv4 Address Specific Extended Community attribute
    value.
    """

    #________________________________________________________________________
    #
    # RFC 4360
    #________________________________________________________________________
    #
    # This is an extended type with Type Field composed of 2 octets and Value
    # Field composed of 6 octets.
    #
    # The value of the high-order octet of this extended type is either 0x01
    # or 0x41. The low-order octet of this extended type is used to indicate
    # sub-types.
    #
    # The Value field consists of two sub-fields:
    #
    # 	Global Administrator sub-field: 4 octets
    #		This sub-field contains an IPv4 unicast address assigned by one
    #       of  the Internet registries.
    #
    #	Local Administrator sub-field: 2 octets
    #		The organization that has been assigned the IPv4 address in the
    #       Global Administrator sub-field can encode any information in
    #       this sub-field. The format and meaning of this value encoded in
    #       this sub-field should be defined by the sub-type of the
    #       community.
    #________________________________________________________________________
    #

    name = "IPv4 Address Specific Extended Community"
    fields_desc = [
        IntField("global_administrator", 0), ShortField("local_administrator", 0)]


class BGPPAExtCommOpaque(Packet):
    """
    Packet handling the Opaque Extended Community attribute value.
    """

    #________________________________________________________________________
    #
    # RFC 4360
    #________________________________________________________________________
    #
    # This is an extended type with Type Field composed of 2 octets and Value
    # Field composed of 6 octets.
    #
    # The value of the high-order octet of this extended type is either 0x03
    # or 0x43. The low-order octet of this extended type is used to indicate
    # sub-types.
    #
    # This is a generic community of extended type. The value of the sub-type
    # that should define the Value Field is to be assigned by IANA.
    #________________________________________________________________________
    #

    name = "Opaque Extended Community"
    fields_desc = [StrFixedLenField("value", "", length=6)]


#
# FlowSpec related extended communities
#

class BGPPAExtCommTrafficRate(Packet):
    """
    Packet handling the (FlowSpec) "traffic-rate" extended community.
    """

    #________________________________________________________________________
    #
    # RFC 5575
    #________________________________________________________________________
    #
    #  Traffic-rate:  The traffic-rate extended community is a non-
    #  transitive extended community across the autonomous-system
    #  boundary and uses following extended community encoding:
    #
    #     The first two octets carry the 2-octet id, which can be
    #     assigned from a 2-byte AS number.  When a 4-byte AS number is
    #     locally present, the 2 least significant bytes of such an AS
    #     number can be used.  This value is purely informational and
    #     should not be interpreted by the implementation.
    #
    #     The remaining 4 octets carry the rate information in IEEE
    #     floating point [IEEE.754.1985] format, units being bytes per
    #     second.  A traffic-rate of 0 should result on all traffic for
    #     the particular flow to be discarded.
    #________________________________________________________________________
    #

    name = "FlowSpec traffic-rate extended community"
    fields_desc = [
        ShortField("id", 0),
        IEEEFloatField("rate", 0)
    ]


class BGPPAExtCommTrafficAction(Packet):
    """
    Packet handling the (FlowSpec) "traffic-action" extended community.
    """

    #________________________________________________________________________
    #
    # RFC 5575
    #________________________________________________________________________
    #
    # Traffic-action:  The traffic-action extended community consists of 6
    #   bytes of which only the 2 least significant bits of the 6th byte
    #   (from left to right) are currently defined.
    #
    #                    40  41  42  43  44  45  46  47
    #                  +---+---+---+---+---+---+---+---+
    #                  |        reserved       | S | T |
    #                  +---+---+---+---+---+---+---+---+
    #
    #   *  Terminal Action (bit 47): When this bit is set, the traffic
    #      filtering engine will apply any subsequent filtering rules (as
    #      defined by the ordering procedure).  If not set, the evaluation
    #      of the traffic filter stops when this rule is applied.
    #
    #   *  Sample (bit 46): Enables traffic sampling and logging for this
    #      flow specification.
    #________________________________________________________________________
    #

    name = "FlowSpec traffic-action extended community"
    fields_desc = [
        BitField("reserved", 0, 46),
        BitField("sample", 0, 1),
        BitField("terminal_action", 0, 1)
    ]


class BGPPAExtCommRedirectAS2Byte(Packet):
    """
    Packet handling the (FlowSpec) "redirect AS-2byte" extended community
    (RFC 7674).
    """

    #________________________________________________________________________
    #
    # RFC 7674
    #________________________________________________________________________
    #
    #   +--------+--------------------+-------------------------------------+
    #   | type   | extended community | encoding                            |
    #   +--------+--------------------+-------------------------------------+
    #   | 0x8008 | redirect AS-2byte  | 2-octet AS, 4-octet Value           |
    #   +--------+--------------------+-------------------------------------+
    #________________________________________________________________________
    #

    name = "FlowSpec redirect AS-2byte extended community"
    fields_desc = [
        ShortField("asn", 0),
        IntField("value", 0)
    ]


class BGPPAExtCommRedirectIPv4(Packet):
    """
    Packet handling the (FlowSpec) "redirect IPv4" extended community.
    (RFC 7674).
    """

    #________________________________________________________________________
    #
    # RFC 7674
    #________________________________________________________________________
    #
    #   +--------+--------------------+-------------------------------------+
    #   | type   | extended community | encoding                            |
    #   +--------+--------------------+-------------------------------------+
    #   | 0x8108 | redirect IPv4      | 4-octet IPv4 Address, 2-octet Value |
    #   +--------+--------------------+-------------------------------------+
    #________________________________________________________________________
    #

    name = "FlowSpec redirect IPv4 extended community"
    fields_desc = [
        IntField("ip_addr", 0),
        ShortField("value", 0)
    ]


class BGPPAExtCommRedirectAS4Byte(Packet):
    """
    Packet handling the (FlowSpec) "redirect AS-4byte" extended community.
    (RFC 7674).
    """

    #________________________________________________________________________
    #
    # RFC 7674
    #________________________________________________________________________
    #
    #   +--------+--------------------+-------------------------------------+
    #   | type   | extended community | encoding                            |
    #   +--------+--------------------+-------------------------------------+
    #   | 0x8208 | redirect AS-4byte  | 4-octet AS, 2-octet Value           |
    #   +--------+--------------------+-------------------------------------+
    #________________________________________________________________________
    #

    name = "FlowSpec redirect AS-4byte extended community"
    fields_desc = [
        IntField("asn", 0),
        ShortField("value", 0)
    ]


class BGPPAExtCommTrafficMarking(Packet):
    """
    Packet handling the (FlowSpec) "traffic-marking" extended community.
    """

    #________________________________________________________________________
    #
    # RFC 5575
    #________________________________________________________________________
    #
    # Traffic Marking:  The traffic marking extended community instructs a
    #   system to modify the DSCP bits of a transiting IP packet to the
    #   corresponding value.  This extended community is encoded as a
    #   sequence of 5 zero bytes followed by the DSCP value encoded in the
    #   6 least significant bits of 6th byte.
    #________________________________________________________________________
    #
    name = "FlowSpec traffic-marking extended community"
    fields_desc = [
        BitEnumField("dscp", 48, 48, _ext_comm_traffic_action_fields)
    ]


class _ExtCommValuePacketField(PacketField):
    """
    PacketField handling Extended Communities "value parts".
    """

    __slots__ = ["type_from"]

    def __init__(self, name, default, cls, remain=0, type_from=(0, 0)):
        PacketField.__init__(self, name, default, cls, remain)
        self.type_from = type_from

    def m2i(self, pkt, m):
        ret = None
        type_high, type_low = self.type_from(pkt)

        if type_high == 0x00 or type_high == 0x40:
            # Two-Octet AS Specific Extended Community
            ret = BGPPAExtCommTwoOctetASSpecific(m)

        elif type_high == 0x01 or type_high == 0x41:
            # IPv4 Address Specific
            ret = BGPPAExtCommIPv4AddressSpecific(m)

        elif type_high == 0x02 or type_high == 0x42:
            # Four-octet AS Specific Extended Community
            ret = BGPPAExtCommFourOctetASSpecific(m)

        elif type_high == 0x03 or type_high == 0x43:
            # Opaque
            ret = BGPPAExtCommOpaque(m)

        elif type_high == 0x80:
            # FlowSpec
            if type_low == 0x06:
                ret = BGPPAExtCommTrafficRate(m)
            elif type_low == 0x07:
                ret = BGPPAExtCommTrafficAction(m)
            elif type_low == 0x08:
                ret = BGPPAExtCommRedirectAS2Byte(m)
            elif type_low == 0x09:
                ret = BGPPAExtCommTrafficMarking(m)

        elif type_high == 0x81:
            # FlowSpec
            if type_low == 0x08:
                ret = BGPPAExtCommRedirectIPv4(m)

        elif type_high == 0x82:
            # FlowSpec
            if type_low == 0x08:
                ret = BGPPAExtCommRedirectAS4Byte(m)

        else:
            ret = conf.raw_layer(m)

        return ret


class BGPPAIPv6AddressSpecificExtComm(Packet):
    """
    Provides an implementation of the IPv6 Address Specific Extended
    Community attribute. This attribute is not defined using the existing
    BGP Extended Community attribute (see the RFC 5701 excerpt below).
    """

    #________________________________________________________________________
    #
    # RFC 5701
    #________________________________________________________________________
    #
    # Because the BGP Extended Community attribute defines each BGP Extended
    # Community as being 8 octets long, it is not possible to define the
    # IPv6 Specific Extended Community using the existing BGP Extended
    # Community attribute [RFC4360]. Therefore, this document defines a new
    # BGP attribute, the IPv6 Address Specific Extended Community, that has
    # a structure similar to the IPv4 Address Specific Extended Community,
    # and thus could be used in a pure IPv6 environment as a replacement of
    # the IPv4 Address Specific Extended Community.
    #
    # The first high-order octet indicates whether a particular sub-type of
    # this community is transitive across Autonomous Systems (ASes) (0x00),
    # or not (0x40). The second high-order octet of this extended type is
    # used to indicate sub-types. The sub-types are the same as for the IPv4
    # Address Specific Extended Community.
    #
    # Global Administrator field: 16 octets
    #   This field contains an IPv6 unicast address assigned by one of the
    #   Internet registries.
    #
    # Local Administrator field: 2 octets
    #   The organization that has been assigned the IPv6 address in the
    #   Global Administrator field can encode any information in this
    #   field.  The format and meaning of the value encoded in this field
    #   should be defined by the sub-type of the community.
    #________________________________________________________________________
    #

    name = "IPv6 Address Specific Extended Community"
    fields_desc = [
        IP6Field("global_administrator", "::"), ShortField("local_administrator", 0)]


def _get_ext_comm_subtype(type_high):
    """
    Returns a ByteEnumField with the right sub-types dict for a given community.
    http://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml
    """

    return _ext_comm_subtypes_classes.get(type_high, {})


class _TypeLowField(ByteField):
    """
    Field used to retrieve "dynamically" the right sub-type dict.
    """

    __slots__ = ["enum_from"]

    def __init__(self, name, default, enum_from=None):
        ByteField.__init__(self, name=name, default=default)
        self.enum_from = enum_from

    def i2repr(self, pkt, i):
        enum = self.enum_from(pkt)
        return enum.get(i, i)


class BGPPAExtCommunity(Packet):
    """
    Provides an implementation of the Extended Communities attribute.
    """

    #________________________________________________________________________
    #
    # RFC 4360
    #________________________________________________________________________
    #
    # The Extended Communities Attribute is a transitive optional BGP
    # attribute, with the Type Code 16.  The attribute consists of a set of
    # "extended communities".  All routes with the Extended Communities
    # attribute belong to the communities listed in the attribute. Each
    # Extended Community is encoded as an 8-octet quantity, as follows:
    #    Type Field  : 1 or 2 octets
    #    Value Field : Remaining octets
    #
    # Type Field:
    #    Two classes of Type Field are introduced: Regular type and Extended
    #    type.
    #
    #    The size of Type Field for Regular types is 1 octet, and the size of
    #    the Type Field for Extended types is 2 octets.
    #
    #    The value of the high-order octet of the Type Field determines if an
    #    extended community is a Regular type or an Extended type. The class
    #    of a type (Regular or Extended) is not encoded in the structure of
    #    the type itself. The class of a type is specified in the document
    #    that defines the type and the IANA registry.
    #
    # I - IANA authority bit
    #    Value 0: IANA-assignable type using the "First Come First Serve"
    #    policy
    #    Value 1: Part of this Type Field space is for IANA assignable types
    #    using either the Standard Action or the Early IANA Allocation
    #    policy. The rest of this Type Field space is for Experimental use.
    #
    # T - Transitive bit
    #    Value 0: The community is transitive across ASes
    #    Value 1: The community is non-transitive across ASes
    #
    # Remaining 6 bits: Indicates the structure of the community
    #
    # Value Field:
    # The encoding of the Value Field is dependent on the "type" of the
    # community as specified by the Type Field.
    #________________________________________________________________________
    #

    name = "EXTENDED_COMMUNITY"
    fields_desc = [
        ByteEnumField("type_high", 0, _ext_comm_types),
        _TypeLowField(
            "type_low",
            0,
            enum_from=lambda x: _get_ext_comm_subtype(x.type_high)
        ),
        _ExtCommValuePacketField(
            "value",
            None,
            Packet,
            type_from=lambda x: (x.type_high, x.type_low)
        )
    ]

    def post_build(self, p, pay):
        if self.value is None:
            p = p[:2]
        return p + pay


class _ExtCommsPacketListField(PacketListField):
    """
    PacketListField handling a list of extended communities.
    """

    def getfield(self, pkt, s):
        lst = []
        length = len(s)
        remain = s[:length]

        while remain:
            current = remain[:8]
            remain = remain[8:]
            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain, lst


class BGPPAExtComms(Packet):
    """
    Packet handling the multiple extended communities.
    """

    name = "EXTENDED_COMMUNITIES"
    fields_desc = [
        _ExtCommsPacketListField(
            "extended_communities",
            [],
            BGPPAExtCommunity
        )
    ]


class MPReachNLRIPacketListField(PacketListField):
    """
    PacketListField handling the AFI specific part (except for the length of
    Next Hop Network Address field, which is not AFI specific) of the
    MP_REACH_NLRI attribute.
    """

    def getfield(self, pkt, s):
        lst = []
        remain = s

        # IPv6
        if pkt.afi == 2:
            if pkt.safi == 1:
                # BGPNLRI_IPv6
                while remain:
                    mask = struct.unpack(">B", remain[0])[0]
                    length_in_bytes = (mask + 7) // 8
                    current = remain[:length_in_bytes + 1]
                    remain = remain[length_in_bytes + 1:]
                    prefix = BGPNLRI_IPv6(current)
                    lst.append(prefix)

        return remain, lst


class BGPPAMPReachNLRI(Packet):
    """
    Packet handling the MP_REACH_NLRI attribute value, for non IPv6
    AFI.
    """

    #________________________________________________________________________
    #
    # RFC 4760
    #________________________________________________________________________
    #
    # This is an optional non-transitive attribute that can be used for the
    # following purposes:
    #       (a) to advertise a feasible route to a peer
    #       (b) to permit a router to advertise the Network Layer address of
    #       the router that should be used as the next hop to the
    #       destinations listed in the Network Layer Reachability Information
    #       field of the MP_NLRI attribute.
    #
    # Address Family Identifier (AFI):
    #       This field in combination with the Subsequent Address Family
    #       Identifier field identifies the set of Network Layer protocols to
    #       which the address carried in the Next Hop field must belong, the
    #       way in which the address of the next hop is encoded, and the
    #       semantics of the Network Layer Reachability Information that
    #       follows.  If the Next Hop is allowed to be from more than one
    #       Network Layer protocol, the encoding of the Next Hop MUST provide
    #       a way to determine its Network Layer protocol.
    #
    #       Presently defined values for the Address Family Identifier field
    #       are specified in the IANA"s Address Family Numbers registry
    #       [IANA-AF].
    #
    # Subsequent Address Family Identifier (SAFI):
    #       This field in combination with the Address Family Identifier
    #       field identifies the set of Network Layer protocols to which the
    #       address carried in the Next Hop must belong, the way in which
    #       the address of the next hop is encoded, and the semantics of the
    #       Network Layer Reachability Information that follows. If the Next
    #       Hop is allowed to be from more than one Network Layer protocol,
    #       the encoding of the Next Hop MUST provide a way to determine its
    #       Network Layer protocol.
    #
    # Length of Next Hop Network Address:
    #       A 1-octet field whose value expresses the length of the "Network
    #       Address of Next Hop" field, measured in octets.
    #
    # Network Address of Next Hop:
    #       A variable-length field that contains the Network Address of the
    #       next router on the path to the destination system.  The Network
    #       Layer protocol associated with the Network Address of the Next
    #       Hop is identified by a combination of <AFI, SAFI> carried in the
    #       attribute.
    #
    # Reserved:
    #       A 1 octet field that MUST be set to 0, and SHOULD be ignored upon
    #       receipt.
    #
    # Network Layer Reachability Information (NLRI):
    #       A variable length field that lists NLRI for the feasible routes
    #       that are being advertised in this attribute.  The semantics of
    #       NLRI is identified by a combination of <AFI, SAFI> carried in the
    #       attribute. When the Subsequent Address Family Identifier field is
    #       set to one of the values defined in this document, each NLRI is
    #       encoded as specified in the "NLRI encoding" section of this
    #       document.
    #
    # The next hop information carried in the MP_REACH_NLRI path attribute
    # defines the Network Layer address of the router that SHOULD be used as
    # the next hop to the destinations listed in the MP_NLRI attribute in
    # the UPDATE message.
    #________________________________________________________________________
    #

    name = "MP_REACH_NLRI"
    fields_desc = [
        ShortEnumField("afi", 0, address_family_identifiers),
        ByteEnumField("safi", 0, subsequent_afis),
        ByteField("nh_addr_len", 0),
        ConditionalField(IPField("nh_v4_addr", "0.0.0.0"),
                         lambda x: x.afi == 1 and x.nh_addr_len == 4),
        ConditionalField(IP6Field("nh_v6_addr", "::"),
                         lambda x: x.afi == 2 and x.nh_addr_len == 16),
        ConditionalField(IP6Field("nh_v6_global", "::"),
                         lambda x: x.afi == 2 and x.nh_addr_len == 32),
        ConditionalField(IP6Field("nh_v6_link_local", "::"),
                         lambda x: x.afi == 2 and x.nh_addr_len == 32),
        ByteField("reserved", 0),
        MPReachNLRIPacketListField("nlri", [], Packet)]

    def post_build(self, p, pay):
        if self.nlri is None:
            p = p[:3]

        return p + pay


#
# MP_UNREACH_NLRI
#

class BGPPAMPUnreachNLRI_IPv6(Packet):
    """
    Packet handling the MP_UNREACH_NLRI attribute value, for IPv6 AFI.
    """

    name = "MP_UNREACH_NLRI (IPv6 NLRI)"
    fields_desc = [BGPNLRIPacketListField(
        "withdrawn_routes", [], BGPNLRI_IPv6)]


class MPUnreachNLRIPacketField(PacketField):
    """
    PacketField handling the AFI specific part of the MP_UNREACH_NLRI
    attribute.
    """

    def m2i(self, pkt, m):
        ret = None

        if pkt.afi == 2:
            ret = BGPPAMPUnreachNLRI_IPv6(m)
        else:
            ret = conf.raw_layer(m)

        return ret


class BGPPAMPUnreachNLRI(Packet):
    """
    Packet handling the MP_UNREACH_NLRI attribute value, for non IPv6
    AFI.
    """

    #________________________________________________________________________
    #
    # RFC 4760
    #________________________________________________________________________
    #
    # This is an optional non-transitive attribute that can be used for the
    # purpose of withdrawing multiple unfeasible routes from service.
    #
    # Withdrawn Routes Network Layer Reachability Information:
    #       A variable-length field that lists NLRI for the routes that are
    #       being
    #       withdrawn from service.  The semantics of NLRI is identified by a
    #       combination of <AFI, SAFI> carried in the attribute.
    #
    #       When the Subsequent Address Family Identifier field is set to one
    #       of the values defined in this document, each NLRI is encoded as
    #       specified in the "NLRI encoding" section of this document.
    #
    # An UPDATE message that contains the MP_UNREACH_NLRI is not required to
    # carry any other path attributes.
    #________________________________________________________________________
    #

    name = "MP_UNREACH_NLRI"
    fields_desc = [ShortEnumField("afi", 0, address_family_identifiers),
                   ByteEnumField("safi", 0, subsequent_afis),
                   MPUnreachNLRIPacketField("afi_safi_specific", None, Packet)]

    def post_build(self, p, pay):
        if self.afi_safi_specific is None:
            p = p[:3]

        return p + pay


#
# AS4_PATH
#

class BGPPAAS4Path(Packet):
    """
    Provides an implementation of the AS4_PATH attribute "value part".
    """

    #________________________________________________________________________
    #
    # RFC 4893
    #________________________________________________________________________
    #
    # When communicating with an OLD BGP speaker, a NEW speaker MUST send the
    # AS path information in the AS_PATH attribute encoded with 2-octet AS
    # numbers. The NEW speaker MUST also send the AS path information in the
    # AS4_PATH attribute (encoded with 4-octet AS numbers), except for the
    # case where the entire AS path information is composed of 2-octet AS
    # numbers only.  In this case, the NEW speaker SHOULD NOT send the
    # AS4_PATH attribute.
    #
    # In the AS_PATH attribute encoded with 2-octet AS numbers, non-mappable
    # 4-octet AS numbers are represented by the well-known 2-octet AS number,
    # AS_TRANS.  This will preserve the path length property of the AS path
    # information and also help in updating the AS path information received
    # on a NEW BGP speaker from an OLD speaker, as explained in the next
    # section. The NEW speaker constructs the AS4_PATH attribute from the
    # information carried in the AS_PATH attribute. In the case where the
    # AS_PATH attribute contains either AS_CONFED_SEQUENCE or AS_CONFED_SET
    # path segments, the NEW speaker, when constructing the AS4_PATH
    # attribute from the AS_PATH attribute, MUST exclude such path segments.
    # The AS4_PATH attribute will be carried across a series of OLD BGP
    # speakers without modification and will help preserve the truly 4-octet
    # AS numbers in the AS path information.
    #
    # Similarly, if the NEW speaker has to send the AGGREGATOR attribute, and
    # if the aggregating Autonomous System"s AS number is truly 4-octets, then
    # the speaker constructs the AS4_AGGREGATOR attributes by taking the
    # attribute length and attribute value from the AGGREGATOR attribute and
    # placing them into the attribute length and attribute value of the
    # AS4_AGGREGATOR attribute, and sets the AS number field in the existing
    # AGGREGATOR attribute to the reserved AS number, AS_TRANS. Note that if
    # the AS number is 2-octets only, then the AS4_AGGREGATOR attribute
    # SHOULD NOT be sent.
    #
    # Finally, this document introduces a reserved 2-octet AS number --
    # AS_TRANS.
    # The AS number 23456 has been assigned by the IANA for AS_TRANS.
    #________________________________________________________________________
    #

    name = "AS4_PATH"
    fields_desc = [
        ByteEnumField(
            "segment_type",
            2,
            {1: "AS_SET", 2: "AS_SEQUENCE"}
        ),
        ByteField("segment_length", None),
        FieldListField("segment_value", [], IntField("asn", 0))
    ]

    def post_build(self, p, pay):
        if self.segment_length is None:
            segment_len = len(self.segment_value)
            p = p[0] + struct.pack("!B", segment_len) + p[2:]

        return p + pay


#
# AS4_AGGREGATOR
#

class BGPPAAS4Aggregator(Packet):
    """
    Provides an implementation of the AS4_AGGREGATOR attribute
    "value part".
    """

    #________________________________________________________________________
    #
    # RFC 4893
    #________________________________________________________________________
    #
    # Similarly, this document defines a new aggregator attribute called
    # AS4_AGGREGATOR, which is optional transitive. The AS4_AGGREGATOR
    # attribute has the same semantics as the AGGREGATOR attribute, except
    # that it carries a 4-octet AS number.
    #________________________________________________________________________
    #

    name = "AS4_AGGREGATOR "
    fields_desc = [IntField("aggregator_asn", 0),
                   IPField("speaker_address", "0.0.0.0")]


_path_attr_objects = {
    0x01: "BGPPAOrigin",
    0x02: "BGPPAASPath",  # if bgp_module_conf.use_2_bytes_asn, BGPPAAS4BytesPath otherwise
    0x03: "BGPPANextHop",
    0x04: "BGPPAMultiExitDisc",
    0x05: "BGPPALocalPref",
    0x06: "BGPPAAtomicAggregate",
    0x07: "BGPPAAggregator",
    0x08: "BGPPACommunity",
    0x09: "BGPPAOriginatorID",
    0x0A: "BGPPAClusterList",
    0x0E: "BGPPAMPReachNLRI",
    0x0F: "BGPPAMPUnreachNLRI",
    0x10: "BGPPAExtComms",
    0x11: "BGPPAAS4Path",
    0x19: "BGPPAIPv6AddressSpecificExtComm"
}


class _PathAttrPacketField(PacketField):
    """
    PacketField handling path attribute value parts.
    """

    def m2i(self, pkt, m):
        ret = None
        type_code = pkt.type_code

        # Reserved
        if type_code == 0 or type_code == 255:
            ret = conf.raw_layer(m)
        # Unassigned
        elif (type_code >= 30 and type_code <= 39) or\
            (type_code >= 41 and type_code <= 127) or\
            (type_code >= 129 and type_code <= 254):
            ret = conf.raw_layer(m)
        # Known path attributes
        else:
            if type_code == 0x02 and not bgp_module_conf.use_2_bytes_asn:
                ret = BGPPAAS4BytesPath(m)
            else:
                ret = _get_cls(
                    _path_attr_objects.get(type_code, conf.raw_layer))(m)

        return ret


class BGPPathAttr(Packet):
    """
    Provides an implementation of the path attributes.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # Path Attributes:
    #       A variable-length sequence of path attributes is present in every
    #       UPDATE message, except for an UPDATE message that carries only
    #       the withdrawn routes. Each path attribute is a triple <attribute
    #       type, attribute length, attribute value> of variable length.
    #
    #       Attribute Type is a two-octet field that consists of the
    #       Attribute Flags octet, followed by the Attribute Type Code octet.
    #
    #       0                   1
    #       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    #       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #       |  Attr. Flags  |Attr. Type Code|
    #       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    #       The high-order bit (bit 0) of the Attribute Flags octet is the
    #       Optional bit.  It defines whether the attribute is optional
    #       (if set to 1) or well-known (if set to 0).
    #
    #       The second high-order bit (bit 1) of the Attribute Flags octet
    #       is the Transitive bit.  It defines whether an optional attribute
    #       is transitive (if set to 1) or non-transitive (if set to 0).
    #
    #       For well-known attributes, the Transitive bit MUST be set to 1.
    #       (See Section 5 for a discussion of transitive attributes.)
    #
    #       The third high-order bit (bit 2) of the Attribute Flags octet is
    #       the Partial bit.  It defines whether the information contained in
    #       the optional transitive attribute is partial (if set to 1) or
    #       complete (if set to 0).  For well-known attributes and for
    #       optional non-transitive attributes, the Partial bit MUST be set
    #       to 0.
    #
    #       The fourth high-order bit (bit 3) of the Attribute Flags octet is
    #       the Extended Length bit.  It defines whether the Attribute Length
    #       is one octet (if set to 0) or two octets (if set to 1).
    #
    #       The lower-order four bits of the Attribute Flags octet are unused.
    #       They MUST be zero when sent and MUST be ignored when received.
    #
    #       The Attribute Type Code octet contains the Attribute Type Code.
    #       Currently defined Attribute Type Codes are discussed in Section 5.
    #
    #       If the Extended Length bit of the Attribute Flags octet is set to
    #       0, the third octet of the Path Attribute contains the length of
    #       the attribute data in octets.
    #
    #       If the Extended Length bit of the Attribute Flags octet is set to
    #       1, the third and fourth octets of the path attribute contain the
    #       length of the attribute data in octets.
    #
    #       The remaining octets of the Path Attribute represent the
    #       attribute value and are interpreted according to the Attribute
    #       Flags and the Attribute Type Code.
    #________________________________________________________________________
    #

    name = "BGPPathAttr"
    fields_desc = [
        FlagsField("type_flags", 0x80, 8, [
            "NA0",
            "NA1",
            "NA2",
            "NA3",
            "Extended-Length",
            "Partial",
            "Transitive",
            "Optional"
        ]),
        ByteEnumField("type_code", 0, path_attributes),
        ConditionalField(
            ShortField("attr_ext_len", None),
            lambda x: x.type_flags != None and\
                has_extended_length(x.type_flags)
        ),
        ConditionalField(
            ByteField("attr_len", None),
            lambda x: x.type_flags != None and not\
                has_extended_length(x.type_flags)
        ),
        _PathAttrPacketField("attribute", None, Packet)
    ]

    def post_build(self, p, pay):
        flags_value = None
        length = None
        packet = None
        extended_length = False

        # Set default flags value ?
        if self.type_flags is None:
            # Set the standard value, if it is exists in attributes_flags.
            if attributes_flags.has_key(self.type_code):
                flags_value = attributes_flags.get(self.type_code)

            # Otherwise, set to optional, non-transitive.
            else:
                flags_value = 0x80

            extended_length = has_extended_length(flags_value)
        else:
            extended_length = has_extended_length(self.type_flags)

        # Set the flags
        if flags_value is None:
            packet = p[:2]
        else:
            packet = struct.pack("!B", flags_value) + p[1]

        # Add the length
        if self.attr_len is None:
            if self.attribute is None:
                length = 0
            else:
                if extended_length:
                    length = len(p) - 4  # Flags + Type + Length (2 bytes)
                else:
                    length = len(p) - 3  # Flags + Type + Length (1 byte)

        if length is None:
            if extended_length:
                packet = packet + p[2:4]
            else:
                packet = packet + p[2]
        else:
            if extended_length:
                packet = packet + struct.pack("!H", length)
            else:
                packet = packet + struct.pack("!B", length)

        # Append the rest of the message
        if extended_length:
            if self.attribute != None:
                packet = packet + p[4:]
        else:
            if self.attribute != None:
                packet = packet + p[3:]

        return packet + pay


#
# UPDATE
#

class BGPUpdate(BGP):
    """
    UPDATE messages allow peers to exchange routes.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # UPDATE messages are used to transfer routing information between BGP
    # peers.  The information in the UPDATE message can be used to construct
    # a graph that describes the relationships of the various Autonomous
    # Systems.  By applying rules to be discussed, routing information loops
    # and some other anomalies may be detected and removed from inter-AS
    # routing.
    #
    # An UPDATE message is used to advertise feasible routes that share
    # common path attributes to a peer, or to withdraw multiple unfeasible
    # routes from service (see 3.1). An UPDATE message MAY simultaneously
    # advertise a feasible route and withdraw multiple unfeasible routes
    # from service.  The UPDATE message always includes the fixed-size BGP
    # header, and also includes the other fields, as shown below (note, some
    # of the shown fields may not be present in every UPDATE message):
    #
    # +-----------------------------------------------------+
    # |   Withdrawn Routes Length (2 octets)                |
    # +-----------------------------------------------------+
    # |   Withdrawn Routes (variable)                       |
    # +-----------------------------------------------------+
    # |   Total Path Attribute Length (2 octets)            |
    # +-----------------------------------------------------+
    # |   Path Attributes (variable)                        |
    # +-----------------------------------------------------+
    # |   Network Layer Reachability Information (variable) |
    # +-----------------------------------------------------+
    #
    # Withdrawn Routes Length:
    #
    #       This 2-octets unsigned integer indicates the total length of the
    #       Withdrawn Routes field in octets.  Its value allows the length of
    #       the Network Layer Reachability Information field to be
    #       determined, as specified below.
    #
    #       A value of 0 indicates that no routes are being withdrawn from
    #       service, and that the WITHDRAWN ROUTES field is not present in
    #       this UPDATE message.
    #
    #
    # Withdrawn Routes:
    #
    #       This is a variable-length field that contains a list of IP
    #       address prefixes for the routes that are being withdrawn from
    #       service.  Each IP address prefix is encoded as a 2-tuple of
    #       the form <length, prefix>, whose fields are described below:
    #
    #       +---------------------------+
    #       |   Length (1 octet)        |
    #       +---------------------------+
    #       |   Prefix (variable)       |
    #       +---------------------------+
    #
    #
    #       The use and the meaning of these fields are as follows:
    #
    #               a) Length:
    #               The Length field indicates the length in bits of the IP
    #               address prefix.  A length of zero indicates a prefix that
    #               matches all IP addresses (with prefix, itself, of zero
    #               octets).
    #
    #               b) Prefix:
    #               The Prefix field contains an IP address prefix, followed
    #               by the minimum number of trailing bits needed to make the
    #               end of the field fall on an octet boundary.  Note that
    #               the value of trailing bits is irrelevant.
    #
    # Total Path Attribute Length:
    #
    #       This 2-octet unsigned integer indicates the total length of the
    #       Path Attributes field in octets.  Its value allows the length of
    #       the Network Layer Reachability field to be determined as
    #       specified below.
    #
    #       A value of 0 indicates that neither the Network Layer
    #       Reachability Information field nor the Path Attribute field is
    #       present in this UPDATE message.
    #
    #
    # Path Attributes: cf BGPPathAttrs and the attributes themselves.
    #
    #
    # Network Layer Reachability Information:
    #
    #       This variable length field contains a list of IP address
    #       prefixes.  The length, in octets, of the Network Layer
    #       Reachability Information is not encoded explicitly, but can be
    #       calculated as:
    #
    #               UPDATE message Length - 23 - Total Path Attributes
    #               Length - Withdrawn Routes Length
    #
    #       where UPDATE message Length is the value encoded in the
    #       fixed-size BGP header, Total Path Attribute Length, and Withdrawn
    #       Routes Length are the values encoded in the variable part of the
    #       UPDATE message, and 23 is a combined length of the fixed-size BGP
    #       header, the Total Path Attribute Length field, and the Withdrawn
    #       Routes Length field.
    #
    # Reachability information is encoded as one or more 2-tuples of the form
    # <length, prefix>, whose fields are described below:
    #
    #       +---------------------------+
    #       |   Length (1 octet)        |
    #       +---------------------------+
    #       |   Prefix (variable)       |
    #       +---------------------------+
    #
    # The use and the meaning of these fields are as follows:
    #
    #       a) Length:
    #               The Length field indicates the length in bits of the IP
    #               address prefix.  A length of zero indicates a prefix that
    #               matches all IP addresses (with prefix, itself, of zero
    #               octets).
    #       b) Prefix:
    #               The Prefix field contains an IP address prefix, followed
    #               by enough trailing bits to make the end of the field fall
    #               on an octet boundary.
    #               Note that the value of the trailing bits is irrelevant.
    #
    # The minimum length of the UPDATE message is 23 octets -- 19 octets for
    # the fixed header + 2 octets for the Withdrawn Routes Length + 2 octets
    # for the Total Path Attribute Length (the value of Withdrawn Routes
    # Length is 0 and the value of Total Path Attribute Length is 0).
    #________________________________________________________________________
    #

    name = "UPDATE"
    fields_desc = [
        FieldLenField(
            "withdrawn_routes_len",
            None,
            length_of="withdrawn_routes",
            fmt="!H"
        ),
        BGPNLRIPacketListField(
            "withdrawn_routes",
            [],
            BGPNLRI_IPv4,
            length_from=lambda p: p.withdrawn_routes_len
        ),
        FieldLenField(
            "path_attr_len",
            None,
            length_of="path_attr",
            fmt="!H"
        ),
        BGPPathAttrPacketListField(
            "path_attr",
            [],
            BGPPathAttr,
            length_from=lambda p: p.path_attr_len
        ),
        BGPNLRIPacketListField("nlri", [], BGPNLRI_IPv4)
    ]

    def post_build(self, p, pay):
        subpacklen = lambda p: len(p)
        packet = ""
        if self.withdrawn_routes_len is None:
            wl = sum(map(subpacklen, self.withdrawn_routes))
            packet = p[:0] + struct.pack("!H", wl) + p[2:]
        if self.path_attr_len is None:
            length = sum(map(subpacklen, self.path_attr))
            packet = p[:2 + wl] + struct.pack("!H", length) + p[4 + wl:]

        return packet + pay


#
# NOTIFICATION
#

#
# RFC 4271, RFC 7313
# http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-3
#
_error_codes = {
    0x01: "Message Header Error",
    0x02: "OPEN Message Error",
    0x03: "UPDATE Message Error",
    0x04: "Hold Timer Expired",
    0x05: "Finite State Machine Error",
    0x06: "Cease",
    0x07: "ROUTE-REFRESH Message Error",  # RFC 7313
}

#
# http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-4
#
_error_subcodes = {
    # Reserved
    0: {},

    # Header (RFC 4271)
    1:
    {
        0: "Unspecific",
        1: "Connection Not Synchronized",
        2: "Bad Message Length",
        3: "Bad Message Type"
    },

    # OPEN (RFC 4271, RFC 5492)
    2:
    {
        0: "Reserved",
        1: "Unsupported Version Number",
        2: "Bad Peer AS",
        3: "Bad BGP Identifier",
        4: "Unsupported Optional Parameter",
        5: "Authentication Failure - Deprecated (RFC 4271)",
        6: "Unacceptable Hold Time",
        7: "Unsupported Capability"
    },

    # UPDATE (RFC 4271)
    3:
    {
        0: "Reserved",
        1: "Malformed Attribute List",
        2: "Unrecognized Well-known Attribute",
        3: "Missing Well-known Attribute",
        4: "Attribute Flags Error",
        5: "Attribute Length Error",
        6: "Invalid ORIGIN Attribute",
        7: "AS Routing Loop - Deprecated (RFC 4271)",
        8: "Invalid NEXT_HOP Attribute",
        9: "Optional Attribute Error",
        10: "Invalid Network Field",
        11: "Malformed AS_PATH"
    },

    # Hold Timer Expired
    4: {},

    # Finite State Machine Error (RFC 6608)
    5:
    {
        0: "Unspecified Error",
        1: "Receive Unexpected Message in OpenSent State",
        2: "Receive Unexpected Message in OpenConfirm State",
        3: "Receive Unexpected Message in Established State"
    },

    # Cease (RFC 4486)
    6:
    {
        0: "Unspecified Error",
        1: "Maximum Number of Prefixes Reached",
        2: "Administrative Shutdown",
        3: "Peer De-configured",
        4: "Administrative Reset",
        5: "Connection Rejected",
        6: "Other Configuration Change",
        7: "Connection Collision Resolution",
        8: "Out of Resources",
    },

    # ROUTE-REFRESH (RFC 7313)
    7:
    {
        0: "Reserved",
        1: "Invalid Message Length"
    },
}


class BGPNotification(BGP):
    """
    NOTIFICATION messages end a BGP session.
    """

    #________________________________________________________________________
    #
    # RFC 4271
    #________________________________________________________________________
    #
    # A NOTIFICATION message is sent when an error condition is detected.
    # The BGP connection is closed immediately after it is sent. In addition
    # to the fixed-size BGP header, the NOTIFICATION message contains the
    # following fields:
    #
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Error code    | Error subcode |   Data (variable)             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Error Code:
    #       This 1-octet unsigned integer indicates the type of NOTIFICATION.
    #
    # Error subcode:
    #       This 1-octet unsigned integer provides more specific information
    #       about the nature of the reported error.  Each Error Code may have
    #       one or more Error Subcodes associated with it. If no appropriate
    #       Error Subcode is defined, then a zero (Unspecific) value is used
    #       for the Error Subcode field.
    #
    # Data:
    #       This variable-length field is used to diagnose the reason for the
    #       NOTIFICATION.  The contents of the Data field depend upon the
    #       Error Code and Error Subcode.  See Section 6 for more details.
    #________________________________________________________________________
    #

    name = "NOTIFICATION"
    fields_desc = [
        ByteEnumField("error_code", 0, _error_codes),
        MultiEnumField(
            "error_subcode",
            0,
            _error_subcodes,
            depends_on=lambda p: p.error_code,
            fmt="B"
        ),
        StrField(name="data", default=None)
    ]


#
# ROUTE_REFRESH
#

_orf_when_to_refresh = {
    0x01: "IMMEDIATE",
    0x02: "DEFER"
}


_orf_actions = {
    0: "ADD",
    1: "REMOVE",
    2: "REMOVE-ALL"
}


_orf_match = {
    0: "PERMIT",
    1: "DENY"
}


_orf_entry_afi = 1
_orf_entry_safi = 1


def _update_orf_afi_safi(afi, safi):
    """
    Helper function that sets the afi / safi values
    of ORP entries.
    """

    global _orf_entry_afi
    global _orf_entry_safi

    _orf_entry_afi = afi
    _orf_entry_safi = safi


class BGPORFEntry(Packet):
    """
    Provides an implementation of an ORF entry.
    """

    #________________________________________________________________________
    #
    # RFC 5291
    #________________________________________________________________________
    #
    # 4.  Carrying ORF Entries in BGP
    #
    #    [ ... ]
    #
    #    The rest of the components in the common part are encoded in the
    #    first octet of each ORF-entry (from the most significant to the least
    #    significant bit) as shown in Figure 2:
    #
    #       Action is a two-bit field.  The value of this field is 0 for ADD,
    #       1 for REMOVE, and 2 for REMOVE-ALL.
    #
    #       Match is a one-bit field.  The value of this field is 0 for PERMIT
    #       and 1 for DENY.  This field is significant only when the value of
    #       the Action field is either ADD or REMOVE.
    #
    #       Reserved is a 5-bit field.  It is set to 0 on transmit and ignored
    #       on receipt.
    #
    #          +---------------------------------+
    #          |   Action (2 bit)                |
    #          +---------------------------------+
    #          |   Match (1 bit)                 |
    #          +---------------------------------+
    #          |   Reserved (5 bits)             |
    #          +---------------------------------+
    #          |   Type specific part (variable) |
    #          +---------------------------------+
    #
    #              Figure 2: ORF Entry Encoding
    #
    #       When the Action component of an ORF entry specifies REMOVE-ALL,
    #       the entry consists of only the common part.
    #________________________________________________________________________
    #

    name = "ORF entry"
    fields_desc = [
        BitEnumField("action", 0, 2, _orf_actions),
        BitEnumField("match", 0, 1, _orf_match),
        BitField("reserved", 0, 5),
        StrField("value", "")
    ]


class _ORFNLRIPacketField(PacketField):
    """
    PacketField handling the ORF NLRI.
    """

    def m2i(self, pkt, m):
        ret = None

        if _orf_entry_afi == 1:
            # IPv4
            ret = BGPNLRI_IPv4(m)

        elif _orf_entry_afi == 2:
            # IPv6
            ret = BGPNLRI_IPv6(m)

        else:
            ret = conf.raw_layer(m)

        return ret


class BGPORFAddressPrefix(BGPORFEntry):
    """
    Provides an implementation of the Address Prefix ORF (RFC 5292).
    """

    name = "Address Prefix ORF"
    fields_desc = [
        BitEnumField("action", 0, 2, _orf_actions),
        BitEnumField("match", 0, 1, _orf_match),
        BitField("reserved", 0, 5),
        IntField("sequence", 0),
        ByteField("min_len", 0),
        ByteField("max_len", 0),
        _ORFNLRIPacketField("prefix", "", Packet),
    ]


class BGPORFCoveringPrefix(Packet):
    """
    Provides an implementation of the CP-ORF (RFC 7543).
    """

    name = "CP-ORF"
    fields_desc = [
        BitEnumField("action", 0, 2, _orf_actions),
        BitEnumField("match", 0, 1, _orf_match),
        BitField("reserved", 0, 5),
        IntField("sequence", 0),
        ByteField("min_len", 0),
        ByteField("max_len", 0),
        LongField("rt", 0),
        LongField("import_rt", 0),
        ByteField("route_type", 0),
        PacketField("host_addr", None, Packet)
    ]


class BGPORFEntryPacketListField(PacketListField):
    """
    PacketListField handling the ORF entries.
    """

    def m2i(self, pkt, m):
        ret = None

        # Cisco also uses 128
        if pkt.orf_type == 64 or pkt.orf_type == 128:
            ret = BGPORFAddressPrefix(m)

        elif pkt.orf_type == 65:
            ret = BGPORFCoveringPrefix(m)

        else:
            ret = conf.raw_layer(m)

        return ret

    def getfield(self, pkt, s):
        lst = []
        length = 0
        if self.length_from is not None:
            length = self.length_from(pkt)
        remain = s
        if length is not None:
            remain, ret = s[:length], s[length:]

        while remain:
            orf_len = 0

            # Get value length, depending on the ORF type
            if pkt.orf_type == 64 or pkt.orf_type == 128:
                # Address Prefix ORF
                # Get the length, in bits, of the prefix
                prefix_len = _bits_to_bytes_len(
                    struct.unpack("!B", remain[6])[0]
                )
                # flags (1 byte) + sequence (4 bytes) + min_len (1 byte) +
                # max_len (1 byte) + mask_len (1 byte) + prefix_len
                orf_len = 8 + prefix_len

            elif pkt.orf_type == 65:
                # Covering Prefix ORF

                if _orf_entry_afi == 1:
                    # IPv4
                    # sequence (4 bytes) + min_len (1 byte) + max_len (1 byte) +
                    # rt (8 bytes) + import_rt (8 bytes) + route_type (1 byte)
                    orf_len = 23 + 4

                elif _orf_entry_afi == 2:
                    # IPv6
                    # sequence (4 bytes) + min_len (1 byte) + max_len (1 byte) +
                    # rt (8 bytes) + import_rt (8 bytes) + route_type (1 byte)
                    orf_len = 23 + 16

                elif _orf_entry_afi == 25:
                    # sequence (4 bytes) + min_len (1 byte) + max_len (1 byte) +
                    # rt (8 bytes) + import_rt (8 bytes)
                    route_type = struct.unpack("!B", remain[22])[0]

                    if route_type == 2:
                        # MAC / IP Advertisement Route
                        orf_len = 23 + 6

                    else:
                        orf_len = 23

            current = remain[:orf_len]
            remain = remain[orf_len:]
            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain + ret, lst


class BGPORF(Packet):
    """
    Provides an implementation of ORFs carried in the RR message.
    """

    #________________________________________________________________________
    #
    # RFC 5291
    #________________________________________________________________________
    #
    # 4.  Carrying ORF Entries in BGP
    #
    #    ORF entries are carried in the BGP ROUTE-REFRESH message [BGP-RR].
    #
    #    A BGP speaker can distinguish an incoming ROUTE-REFRESH message that
    #    carries one or more ORF entries from an incoming plain ROUTE-REFRESH
    #    message by using the Message Length field in the BGP message header.
    #
    #    A single ROUTE-REFRESH message MAY carry multiple ORF entries in one
    #    or more ORFs, as long as all these entries share the same AFI/SAFI.
    #
    #    From the encoding point of view, each ORF entry consists of a common
    #    part and type-specific part, as shown in Figures 1 and 2.
    #
    #    The common part consists of <AFI/SAFI, ORF-Type, Action, Match>, and
    #    is encoded as follows:
    #
    #       The AFI/SAFI component of an ORF entry is encoded in the AFI/SAFI
    #       field of the ROUTE-REFRESH message.
    #
    #       Following the AFI/SAFI component is the one-octet When-to-refresh
    #       field.  The value of this field can be either IMMEDIATE (0x01) or
    #       DEFER (0x02).  The semantics of IMMEDIATE and DEFER are discussed
    #       in the "Operation" section of this document.
    #
    #       Following the When-to-refresh field is a collection of one or more
    #       ORFs, grouped by ORF-Type.
    #
    #       The ORF-Type component is encoded as a one-octet field.
    #
    #       The "Length of ORF entries" component is a two-octet field that
    #       contains the total length (in octets) of the ORF entries that
    #       follows for the specified ORF type.
    #
    #          +--------------------------------------------------+
    #          | Address Family Identifier (2 octets)             |
    #          +--------------------------------------------------+
    #          | Reserved (1 octet)                               |
    #          +--------------------------------------------------+
    #          | Subsequent Address Family Identifier (1 octet)   |
    #          +--------------------------------------------------+
    #          | When-to-refresh (1 octet)                        |
    #          +--------------------------------------------------+
    #          | ORF Type (1 octet)                               |
    #          +--------------------------------------------------+
    #          | Length of ORF entries (2 octets)                 |
    #          +--------------------------------------------------+
    #          | First ORF entry (variable)                       |
    #          +--------------------------------------------------+
    #          | Second ORF entry (variable)                      |
    #          +--------------------------------------------------+
    #          | ...                                              |
    #          +--------------------------------------------------+
    #          | N-th ORF entry (variable)                        |
    #          +--------------------------------------------------+
    #          | ORF Type (1 octet)                               |
    #          +--------------------------------------------------+
    #          | Length of ORF entries (2 octets)                 |
    #          +--------------------------------------------------+
    #          | First ORF entry (variable)                       |
    #          +--------------------------------------------------+
    #          | Second ORF entry (variable)                      |
    #          +--------------------------------------------------+
    #          | ...                                              |
    #          +--------------------------------------------------+
    #          | N-th ORF entry (variable)                        |
    #          +--------------------------------------------------+
    #          | ...                                              |
    #          +--------------------------------------------------+
    #
    #          Figure 1: Carrying ORF Entries in the ROUTE-REFRESH Message
    #
    #
    #    The rest of the components in the common part are encoded in the
    #    first octet of each ORF-entry (from the most significant to the least
    #    significant bit) as shown in Figure 2:
    #
    #       Action is a two-bit field.  The value of this field is 0 for ADD,
    #       1 for REMOVE, and 2 for REMOVE-ALL.
    #
    #       Match is a one-bit field.  The value of this field is 0 for PERMIT
    #       and 1 for DENY.  This field is significant only when the value of
    #       the Action field is either ADD or REMOVE.
    #
    #       Reserved is a 5-bit field.  It is set to 0 on transmit and ignored
    #       on receipt.
    #
    #          +---------------------------------+
    #          |   Action (2 bit)                |
    #          +---------------------------------+
    #          |   Match (1 bit)                 |
    #          +---------------------------------+
    #          |   Reserved (5 bits)             |
    #          +---------------------------------+
    #          |   Type specific part (variable) |
    #          +---------------------------------+
    #
    #              Figure 2: ORF Entry Encoding
    #
    #       When the Action component of an ORF entry specifies REMOVE-ALL,
    #       the entry consists of only the common part.
    #________________________________________________________________________
    #

    name = "ORF"
    fields_desc = [
        ByteEnumField("when_to_refresh", 0, _orf_when_to_refresh),
        ByteEnumField("orf_type", 0, _orf_types),
        FieldLenField("orf_len", None, length_of="entries", fmt="!H"),
        BGPORFEntryPacketListField(
            "entries",
            [],
            Packet,
            length_from=lambda p: p.orf_len,
        )
    ]


# RFC 7313
# http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#route-refresh-subcodes
rr_message_subtypes = {
    0: "Route-Refresh",
    1: "BoRR",
    2: "EoRR",
    255: "Reserved"
}


class BGPRouteRefresh(BGP):
    """
    Provides an implementation of the ROUTE-REFRESH message.
    """

    #________________________________________________________________________
    #
    # RFC 2918
    #________________________________________________________________________
    #
    # The ROUTE-REFRESH message is a new BGP message type defined as follows:
    #
    #   Type: 5 - ROUTE-REFRESH
    #
    #   Message Format: One <AFI, SAFI> encoded as
    #
    #       0       7      15      23      31
    #       +-------+-------+-------+-------+
    #       |      AFI      | Res.  | SAFI  |
    #       +-------+-------+-------+-------+
    #
    #   The meaning, use and encoding of this <AFI, SAFI> field is the
    #   same as defined in [BGP-MP, sect. 7]. More specifically,
    #
    #       AFI  - Address Family Identifier (16 bit).
    #
    #       Res. - Reserved (8 bit) field. Should be set to 0 by the
    #              sender and ignored by the receiver.
    #
    #       SAFI - Subsequent Address Family Identifier (8 bit).
    #________________________________________________________________________
    #

    #________________________________________________________________________
    #
    # RFC 7313
    #________________________________________________________________________
    #
    # 3.2.  Subtypes for ROUTE-REFRESH Message
    #
    # The "Reserved" field of the ROUTE-REFRESH message specified in
    # [RFC2918] is redefined as the "Message Subtype" with the following
    # values:
    #
    #   0 - Normal route refresh request [RFC2918]
    #       with/without Outbound Route Filtering (ORF) [RFC5291]
    #   1 - Demarcation of the beginning of a route refresh
    #       (BoRR) operation
    #   2 - Demarcation of the ending of a route refresh
    #       (EoRR) operation
    #   255 - Reserved
    #
    # The remaining values of the message subtypes are reserved for future
    # use; see Section 6 ("IANA Considerations").  The use of the new
    # message subtypes is described in Section 4 ("Operation").
    #________________________________________________________________________
    #

    name = "ROUTE-REFRESH"
    fields_desc = [
        ShortEnumField("afi", 1, address_family_identifiers),
        ByteEnumField("subtype", 0, rr_message_subtypes),
        ByteEnumField("safi", 1, subsequent_afis),
        PacketField(
            'orf_data',
            "", BGPORF,
            lambda p: _update_orf_afi_safi(p.afi, p.safi)
        )
    ]


#
# Layer bindings
#

bind_layers(TCP, BGP, dport=179)
bind_layers(TCP, BGP, sport=179)
bind_layers(BGPHeader, BGPOpen, {"type": 1})
bind_layers(BGPHeader, BGPUpdate, {"type": 2})
bind_layers(BGPHeader, BGPNotification, {"type": 3})
bind_layers(BGPHeader, BGPKeepAlive, {"type": 4})
bind_layers(BGPHeader, BGPRouteRefresh, {"type": 5})

# When loading the module, display the current module configuration.
log_runtime.warning(
    "[bgp.py] use_2_bytes_asn: %s", bgp_module_conf.use_2_bytes_asn)

