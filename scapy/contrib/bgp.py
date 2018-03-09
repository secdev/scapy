# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = BGP v0.1
# scapy.contrib.status = loads

"""
BGP (Border Gateway Protocol).
"""

from __future__ import absolute_import
import struct
import re
import socket

from scapy import pton_ntop
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
from scapy.utils import issubtype
from scapy.config import conf, ConfClass
from scapy.compat import *
from scapy.error import log_runtime
import scapy.modules.six as six


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
_BGP_HEADER_MARKER = b"\xff" * 16

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
        length = self.mask2iplen(orb(s[0])) + 1
        return s[length:], self.m2i(pkt, s[:length])

    def m2i(self, pkt, m):
        mask = orb(m[0])
        mask2iplen_res = self.mask2iplen(mask)
        ip = b"".join(m[i + 1:i + 2] if i < mask2iplen_res else b"\x00" for i in range(4))
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
        ip = pton_ntop.inet_pton(socket.AF_INET6, ip)
        return struct.pack(">B", mask) + ip[:self.mask2iplen(mask)]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        length = self.mask2iplen(orb(s[0])) + 1
        return s[length:], self.m2i(pkt, s[:length])

    def m2i(self, pkt, m):
        mask = orb(m[0])
        ip = b"".join(m[i + 1:i + 2] if i < self.mask2iplen(mask) else b"\x00" for i in range(16))
        return (mask, pton_ntop.inet_ntop(socket.AF_INET6, ip))


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
        ret = b""

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
            mask_length_in_bits = orb(remain[0])
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
    References: RFC 4271
    """

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

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """

        return _bgp_dispatcher(_pkt)

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
            message_type = orb(payload[18])
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
            code = orb(payload[0])
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


class BGPCapability(six.with_metaclass(_BGPCapability_metaclass, Packet)):
    """
    Generic BGP capability.
    """

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
        if cls == "BGPCapability":
            if isinstance(self, BGPCapability):
                return True
        elif issubtype(cls, BGPCapability):
            if isinstance(self, cls):
                return True
        return super(BGPCapability, self).haslayer(cls)

    def getlayer(self, cls, nb=1, _track=None, _subclass=True, **flt):
        return super(BGPCapability, self).getlayer(
            cls, nb=nb, _track=_track, _subclass=True, **flt
        )

    def post_build(self, p, pay):
        length = 0
        if self.length is None:
            # capability packet length - capability code (1 byte) -
            # capability length (1 byte)
            length = len(p) - 2
            p = chb(p[0]) + chb(length) + p[2:]
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
    References: RFC 4760
    """

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
            orf_number = orb(remain[4])
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
    References: RFC 5291
    """

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
    References: RFC 4724
    """

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
    References: RFC 4893
    """

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
    References: RFC 1771, RFC 1654, RFC 4271
    """

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
            param_len = orb(remain[1])  # Get param length
            current = remain[:2 + param_len]
            remain = remain[2 + param_len:]
            packet = self.m2i(pkt, current)
            lst.append(packet)

        return remain + ret, lst


class BGPOptParam(Packet):
    """
    Provides an implementation the OPEN message optional parameters.
    References: RFC 4271
    """

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
            packet = chb(p[0]) + chb(length)
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
    References: RFC 4271
    """

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
            flags = orb(remain[0])

            attr_len = 0
            if has_extended_length(flags):
                attr_len = struct.unpack("!H", remain[2:4])[0]
                current = remain[:4 + attr_len]
                remain = remain[4 + attr_len:]
            else:
                attr_len = orb(remain[2])
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
    References: RFC 4271
    """

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
            segment_length = orb(remain[1])

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
    References: RFC 4271, RFC 5065
    """

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
                p = chb(p[0]) + chb(segment_len) + p[2:]

            return p + pay

    name = "AS_PATH (RFC 4271)"
    fields_desc = [
        ASPathSegmentPacketListField("segments", [], ASPathSegment)]


class BGPPAAS4BytesPath(Packet):
    """
    Packet handling the AS_PATH attribute value (4 bytes ASNs, for new
    speakers -> ASNs are encoded as IntFields).
    References: RFC 4893
    """

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
                p = chb(p[0]) + chb(segment_len) + p[2:]

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
    References: RFC 4271
    """

    name = "NEXT_HOP"
    fields_desc = [IPField("next_hop", "0.0.0.0")]


#
# MULTI_EXIT_DISC
#

class BGPPAMultiExitDisc(Packet):
    """
    Packet handling the MULTI_EXIT_DISC attribute value.
    References: RFC 4271
    """

    name = "MULTI_EXIT_DISC"
    fields_desc = [IntField("med", 0)]


#
# LOCAL_PREF
#

class BGPPALocalPref(Packet):
    """
    Packet handling the LOCAL_PREF attribute value.
    References: RFC 4271
    """

    name = "LOCAL_PREF"
    fields_desc = [IntField("local_pref", 0)]


#
# ATOMIC_AGGREGATE
#

class BGPPAAtomicAggregate(Packet):
    """
    Packet handling the ATOMIC_AGGREGATE attribute value.
    References: RFC 4271
    """

    name = "ATOMIC_AGGREGATE"


#
# AGGREGATOR
#

class BGPPAAggregator(Packet):
    """
    Packet handling the AGGREGATOR attribute value.
    References: RFC 4271
    """

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
    References: RFC 1997
    """

    name = "COMMUNITIES"
    fields_desc = [IntEnumField("community", 0, well_known_communities)]


#
# ORIGINATOR_ID
#

class BGPPAOriginatorID(Packet):
    """
    Packet handling the ORIGINATOR_ID attribute value.
    References: RFC 4456
    """

    name = "ORIGINATOR_ID"
    fields_desc = [IPField("originator_id", "0.0.0.0")]


#
# CLUSTER_LIST
#

class BGPPAClusterList(Packet):
    """
    Packet handling the CLUSTER_LIST attribute value.
    References: RFC 4456
    """

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
    References: RFC 4360
    """

    name = "Two-Octet AS Specific Extended Community"
    fields_desc = [
        ShortField("global_administrator", 0), IntField("local_administrator", 0)]


class BGPPAExtCommFourOctetASSpecific(Packet):
    """
    Packet handling the Four-Octet AS Specific Extended Community
    attribute value.
    References: RFC 5668
    """

    name = "Four-Octet AS Specific Extended Community"
    fields_desc = [
        IntField("global_administrator", 0), ShortField("local_administrator", 0)]


class BGPPAExtCommIPv4AddressSpecific(Packet):
    """
    Packet handling the IPv4 Address Specific Extended Community attribute
    value.
    References: RFC 4360
    """

    name = "IPv4 Address Specific Extended Community"
    fields_desc = [
        IntField("global_administrator", 0), ShortField("local_administrator", 0)]


class BGPPAExtCommOpaque(Packet):
    """
    Packet handling the Opaque Extended Community attribute value.
    References: RFC 4360
    """

    name = "Opaque Extended Community"
    fields_desc = [StrFixedLenField("value", "", length=6)]


#
# FlowSpec related extended communities
#

class BGPPAExtCommTrafficRate(Packet):
    """
    Packet handling the (FlowSpec) "traffic-rate" extended community.
    References: RFC 5575
    """

    name = "FlowSpec traffic-rate extended community"
    fields_desc = [
        ShortField("id", 0),
        IEEEFloatField("rate", 0)
    ]


class BGPPAExtCommTrafficAction(Packet):
    """
    Packet handling the (FlowSpec) "traffic-action" extended community.
    References: RFC 5575
    """

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
    References: RFC 7674
    """

    name = "FlowSpec redirect AS-2byte extended community"
    fields_desc = [
        ShortField("asn", 0),
        IntField("value", 0)
    ]


class BGPPAExtCommRedirectIPv4(Packet):
    """
    Packet handling the (FlowSpec) "redirect IPv4" extended community.
    (RFC 7674).
    References: RFC 7674
    """

    name = "FlowSpec redirect IPv4 extended community"
    fields_desc = [
        IntField("ip_addr", 0),
        ShortField("value", 0)
    ]


class BGPPAExtCommRedirectAS4Byte(Packet):
    """
    Packet handling the (FlowSpec) "redirect AS-4byte" extended community.
    (RFC 7674).
    References: RFC 7674
    """

    name = "FlowSpec redirect AS-4byte extended community"
    fields_desc = [
        IntField("asn", 0),
        ShortField("value", 0)
    ]


class BGPPAExtCommTrafficMarking(Packet):
    """
    Packet handling the (FlowSpec) "traffic-marking" extended community.
    References: RFC 5575
    """

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
    References: RFC 5701
    """

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
    References: RFC 4360
    """

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
                    mask = orb(remain[0])
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
    References: RFC 4760
    """

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
    References: RFC 4760
    """

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
    References: RFC 4893
    """

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
            p = chb(p[0]) + chb(segment_len) + p[2:]

        return p + pay


#
# AS4_AGGREGATOR
#

class BGPPAAS4Aggregator(Packet):
    """
    Provides an implementation of the AS4_AGGREGATOR attribute
    "value part".
    References: RFC 4893
    """

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
    References: RFC 4271
    """

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
            if self.type_code in attributes_flags:
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
    References: RFC 4271
    """

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
    References: RFC 4271
    """

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
    References: RFC 5291
    """

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
                    orb(remain[6])
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
                    route_type = orb(remain[22])

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
    References: RFC 5291
    """

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
    References: RFC 2918, RFC 7313
    """

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

