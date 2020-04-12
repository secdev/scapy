# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Vincent Mauge   <vmauge.nospam@nospam.gmail.com>
# This program is published under a GPLv2 license

"""
RADIUS (Remote Authentication Dial In User Service)
"""

import struct
import hashlib
import hmac
from scapy.compat import orb, raw
from scapy.packet import Packet, Padding, bind_layers, bind_bottom_up
from scapy.fields import ByteField, ByteEnumField, IntField, StrLenField,\
    XStrLenField, XStrFixedLenField, FieldLenField, PacketLenField,\
    PacketListField, IPField, MultiEnumField
from scapy.layers.inet import UDP
from scapy.layers.eap import EAP
from scapy.config import conf
from scapy.error import Scapy_Exception


# https://www.iana.org/assignments/radius-types/radius-types.xhtml
_radius_attribute_types = {
    1: "User-Name",
    2: "User-Password",
    3: "CHAP-Password",
    4: "NAS-IP-Address",
    5: "NAS-Port",
    6: "Service-Type",
    7: "Framed-Protocol",
    8: "Framed-IP-Address",
    9: "Framed-IP-Netmask",
    10: "Framed-Routing",
    11: "Filter-Id",
    12: "Framed-MTU",
    13: "Framed-Compression",
    14: "Login-IP-Host",
    15: "Login-Service",
    16: "Login-TCP-Port",
    17: "Unassigned",
    18: "Reply-Message",
    19: "Callback-Number",
    20: "Callback-Id",
    21: "Unassigned",
    22: "Framed-Route",
    23: "Framed-IPX-Network",
    24: "State",
    25: "Class",
    26: "Vendor-Specific",
    27: "Session-Timeout",
    28: "Idle-Timeout",
    29: "Termination-Action",
    30: "Called-Station-Id",
    31: "Calling-Station-Id",
    32: "NAS-Identifier",
    33: "Proxy-State",
    34: "Login-LAT-Service",
    35: "Login-LAT-Node",
    36: "Login-LAT-Group",
    37: "Framed-AppleTalk-Link",
    38: "Framed-AppleTalk-Network",
    39: "Framed-AppleTalk-Zone",
    40: "Acct-Status-Type",
    41: "Acct-Delay-Time",
    42: "Acct-Input-Octets",
    43: "Acct-Output-Octets",
    44: "Acct-Session-Id",
    45: "Acct-Authentic",
    46: "Acct-Session-Time",
    47: "Acct-Input-Packets",
    48: "Acct-Output-Packets",
    49: "Acct-Terminate-Cause",
    50: "Acct-Multi-Session-Id",
    51: "Acct-Link-Count",
    52: "Acct-Input-Gigawords",
    53: "Acct-Output-Gigawords",
    54: "Unassigned",
    55: "Event-Timestamp",
    56: "Egress-VLANID",
    57: "Ingress-Filters",
    58: "Egress-VLAN-Name",
    59: "User-Priority-Table",
    60: "CHAP-Challenge",
    61: "NAS-Port-Type",
    62: "Port-Limit",
    63: "Login-LAT-Port",
    64: "Tunnel-Type",
    65: "Tunnel-Medium-Type",
    66: "Tunnel-Client-Endpoint",
    67: "Tunnel-Server-Endpoint",
    68: "Acct-Tunnel-Connection",
    69: "Tunnel-Password",
    70: "ARAP-Password",
    71: "ARAP-Features",
    72: "ARAP-Zone-Access",
    73: "ARAP-Security",
    74: "ARAP-Security-Data",
    75: "Password-Retry",
    76: "Prompt",
    77: "Connect-Info",
    78: "Configuration-Token",
    79: "EAP-Message",
    80: "Message-Authenticator",
    81: "Tunnel-Private-Group-ID",
    82: "Tunnel-Assignment-ID",
    83: "Tunnel-Preference",
    84: "ARAP-Challenge-Response",
    85: "Acct-Interim-Interval",
    86: "Acct-Tunnel-Packets-Lost",
    87: "NAS-Port-Id",
    88: "Framed-Pool",
    89: "CUI",
    90: "Tunnel-Client-Auth-ID",
    91: "Tunnel-Server-Auth-ID",
    92: "NAS-Filter-Rule",
    93: "Unassigned",
    94: "Originating-Line-Info",
    95: "NAS-IPv6-Address",
    96: "Framed-Interface-Id",
    97: "Framed-IPv6-Prefix",
    98: "Login-IPv6-Host",
    99: "Framed-IPv6-Route",
    100: "Framed-IPv6-Pool",
    101: "Error-Cause",
    102: "EAP-Key-Name",
    103: "Digest-Response",
    104: "Digest-Realm",
    105: "Digest-Nonce",
    106: "Digest-Response-Auth",
    107: "Digest-Nextnonce",
    108: "Digest-Method",
    109: "Digest-URI",
    110: "Digest-Qop",
    111: "Digest-Algorithm",
    112: "Digest-Entity-Body-Hash",
    113: "Digest-CNonce",
    114: "Digest-Nonce-Count",
    115: "Digest-Username",
    116: "Digest-Opaque",
    117: "Digest-Auth-Param",
    118: "Digest-AKA-Auts",
    119: "Digest-Domain",
    120: "Digest-Stale",
    121: "Digest-HA1",
    122: "SIP-AOR",
    123: "Delegated-IPv6-Prefix",
    124: "MIP6-Feature-Vector",
    125: "MIP6-Home-Link-Prefix",
    126: "Operator-Name",
    127: "Location-Information",
    128: "Location-Data",
    129: "Basic-Location-Policy-Rules",
    130: "Extended-Location-Policy-Rules",
    131: "Location-Capable",
    132: "Requested-Location-Info",
    133: "Framed-Management-Protocol",
    134: "Management-Transport-Protection",
    135: "Management-Policy-Id",
    136: "Management-Privilege-Level",
    137: "PKM-SS-Cert",
    138: "PKM-CA-Cert",
    139: "PKM-Config-Settings",
    140: "PKM-Cryptosuite-List",
    141: "PKM-SAID",
    142: "PKM-SA-Descriptor",
    143: "PKM-Auth-Key",
    144: "DS-Lite-Tunnel-Name",
    145: "Mobile-Node-Identifier",
    146: "Service-Selection",
    147: "PMIP6-Home-LMA-IPv6-Address",
    148: "PMIP6-Visited-LMA-IPv6-Address",
    149: "PMIP6-Home-LMA-IPv4-Address",
    150: "PMIP6-Visited-LMA-IPv4-Address",
    151: "PMIP6-Home-HN-Prefix",
    152: "PMIP6-Visited-HN-Prefix",
    153: "PMIP6-Home-Interface-ID",
    154: "PMIP6-Visited-Interface-ID",
    155: "PMIP6-Home-IPv4-HoA",
    156: "PMIP6-Visited-IPv4-HoA",
    157: "PMIP6-Home-DHCP4-Server-Address",
    158: "PMIP6-Visited-DHCP4-Server-Address",
    159: "PMIP6-Home-DHCP6-Server-Address",
    160: "PMIP6-Visited-DHCP6-Server-Address",
    161: "PMIP6-Home-IPv4-Gateway",
    162: "PMIP6-Visited-IPv4-Gateway",
    163: "EAP-Lower-Layer",
    164: "GSS-Acceptor-Service-Name",
    165: "GSS-Acceptor-Host-Name",
    166: "GSS-Acceptor-Service-Specifics",
    167: "GSS-Acceptor-Realm-Name",
    168: "Framed-IPv6-Address",
    169: "DNS-Server-IPv6-Address",
    170: "Route-IPv6-Information",
    171: "Delegated-IPv6-Prefix-Pool",
    172: "Stateful-IPv6-Address-Pool",
    173: "IPv6-6rd-Configuration",
    174: "Allowed-Called-Station-Id",
    175: "EAP-Peer-Id",
    176: "EAP-Server-Id",
    177: "Mobility-Domain-Id",
    178: "Preauth-Timeout",
    179: "Network-Id-Name",
    180: "EAPoL-Announcement",
    181: "WLAN-HESSID",
    182: "WLAN-Venue-Info",
    183: "WLAN-Venue-Language",
    184: "WLAN-Venue-Name",
    185: "WLAN-Reason-Code",
    186: "WLAN-Pairwise-Cipher",
    187: "WLAN-Group-Cipher",
    188: "WLAN-AKM-Suite",
    189: "WLAN-Group-Mgmt-Cipher",
    190: "WLAN-RF-Band",
    191: "Unassigned",
}


class RadiusAttribute(Packet):
    """
    Implements a RADIUS attribute (RFC 2865). Every specific RADIUS attribute
    class should inherit from this one.
    """

    name = "Radius Attribute"
    fields_desc = [
        ByteEnumField("type", 1, _radius_attribute_types),
        FieldLenField("len", None, "value", "B",
                      adjust=lambda pkt, x: len(pkt.value) + 2),
        StrLenField("value", "", length_from=lambda pkt: pkt.len - 2)
    ]

    registered_attributes = {}

    @classmethod
    def register_variant(cls):
        """
        Registers the RADIUS attributes defined in this module.
        """

        if hasattr(cls, "val"):
            cls.registered_attributes[cls.val] = cls
        else:
            cls.registered_attributes[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right RadiusAttribute class for the given data.
        """

        if _pkt:
            attr_type = orb(_pkt[0])
            return cls.registered_attributes.get(attr_type, cls)
        return cls

    def post_build(self, p, pay):
        length = self.len
        if length is None:
            length = len(p)
            p = p[:1] + struct.pack("!B", length) + p[2:]
        return p

    def guess_payload_class(self, _):
        return Padding


class _SpecificRadiusAttr(RadiusAttribute):
    """
    Class from which every "specific" RADIUS attribute defined in this module
    inherits.
    """

    __slots__ = ["val"]
    match_subclass = True

    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):  # noqa: E501
        super(_SpecificRadiusAttr, self).__init__(
            _pkt,
            post_transform,
            _internal,
            _underlayer,
            **fields
        )
        self.fields["type"] = self.val
        name_parts = self.__class__.__name__.split('RadiusAttr_')
        if len(name_parts) < 2:
            raise Scapy_Exception(
                "Invalid class name: {}".format(self.__class__.__name__)
            )
        self.name = name_parts[1].replace('_', '-')


#
# RADIUS attributes which values are 4 bytes integers
#

class _RadiusAttrIntValue(_SpecificRadiusAttr):
    """
    Implements a RADIUS attribute which value field is 4 bytes long integer.
    """

    fields_desc = [
        ByteEnumField("type", 5, _radius_attribute_types),
        ByteField("len", 6),
        IntField("value", 0)
    ]


class RadiusAttr_User_Name(_SpecificRadiusAttr):
    """RFC 2865"""
    val = 1


class RadiusAttr_NAS_Port(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 5


class RadiusAttr_Framed_MTU(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 12


class RadiusAttr_Login_TCP_Port(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 16


class RadiusAttr_Session_Timeout(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 27


class RadiusAttr_Idle_Timeout(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 28


class RadiusAttr_Framed_AppleTalk_Link(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 37


class RadiusAttr_Framed_AppleTalk_Network(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 38


class RadiusAttr_Acct_Delay_Time(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 41


class RadiusAttr_Acct_Input_Octets(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 42


class RadiusAttr_Acct_Output_Octets(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 43


class RadiusAttr_Acct_Session_Time(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 46


class RadiusAttr_Acct_Input_Packets(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 47


class RadiusAttr_Acct_Output_Packets(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 48


class RadiusAttr_Acct_Link_Count(_RadiusAttrIntValue):
    """RFC 2866"""
    val = 51


class RadiusAttr_Acct_Input_Gigawords(_RadiusAttrIntValue):
    """RFC 2869"""
    val = 52


class RadiusAttr_Acct_Output_Gigawords(_RadiusAttrIntValue):
    """RFC 2869"""
    val = 53


class RadiusAttr_Egress_VLANID(_RadiusAttrIntValue):
    """RFC 4675"""
    val = 56


class RadiusAttr_Port_Limit(_RadiusAttrIntValue):
    """RFC 2865"""
    val = 62


class RadiusAttr_ARAP_Security(_RadiusAttrIntValue):
    """RFC 2869"""
    val = 73


class RadiusAttr_Password_Retry(_RadiusAttrIntValue):
    """RFC 2869"""
    val = 75


class RadiusAttr_Tunnel_Preference(_RadiusAttrIntValue):
    """RFC 2868"""
    val = 83


class RadiusAttr_Acct_Interim_Interval(_RadiusAttrIntValue):
    """RFC 2869"""
    val = 85


class RadiusAttr_Acct_Tunnel_Packets_Lost(_RadiusAttrIntValue):
    """RFC 2867"""
    val = 86


class RadiusAttr_Management_Privilege_Level(_RadiusAttrIntValue):
    """RFC 5607"""
    val = 136


class RadiusAttr_Mobility_Domain_Id(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 177


class RadiusAttr_Preauth_Timeout(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 178


class RadiusAttr_WLAN_Venue_Info(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 182


class RadiusAttr_WLAN_Reason_Code(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 185


class RadiusAttr_WLAN_Pairwise_Cipher(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 186


class RadiusAttr_WLAN_Group_Cipher(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 187


class RadiusAttr_WLAN_AKM_Suite(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 188


class RadiusAttr_WLAN_Group_Mgmt_Cipher(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 189


class RadiusAttr_WLAN_RF_Band(_RadiusAttrIntValue):
    """RFC 7268"""
    val = 190


#
# RADIUS attributes which values are string (displayed as hex)
#

class _RadiusAttrHexStringVal(_SpecificRadiusAttr):
    """
    Implements a RADIUS attribute which value field is a string that will be
    as a hex string.
    """

    __slots__ = ["val"]

    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):  # noqa: E501
        super(_RadiusAttrHexStringVal, self).__init__(
            _pkt,
            post_transform,
            _internal,
            _underlayer,
            **fields
        )
        self.fields["type"] = self.val
        name_parts = self.__class__.__name__.split('RadiusAttr_')
        if len(name_parts) < 2:
            raise Scapy_Exception(
                "Invalid class name: {}".format(self.__class__.__name__)
            )
        self.name = name_parts[1].replace('_', '-')

    fields_desc = [
        ByteEnumField("type", 24, _radius_attribute_types),
        FieldLenField(
            "len",
            None,
            "value",
            "B",
            adjust=lambda p, x: len(p.value) + 2
        ),
        XStrLenField("value", "", length_from=lambda p: p.len - 2 if p.len else 0)  # noqa: E501
    ]


class RadiusAttr_User_Password(_RadiusAttrHexStringVal):
    """RFC 2865"""
    val = 2


class RadiusAttr_State(_RadiusAttrHexStringVal):
    """RFC 2865"""
    val = 24


def prepare_packed_data(radius_packet, packed_req_authenticator):
    """
    Pack RADIUS data prior computing the authentication MAC
    """

    packed_hdr = struct.pack("!B", radius_packet.code)
    packed_hdr += struct.pack("!B", radius_packet.id)
    packed_hdr += struct.pack("!H", radius_packet.len)

    packed_attrs = b''
    for attr in radius_packet.attributes:
        packed_attrs += raw(attr)

    return packed_hdr + packed_req_authenticator + packed_attrs


class RadiusAttr_Message_Authenticator(_RadiusAttrHexStringVal):
    """RFC 2869"""
    val = 80

    fields_desc = [
        ByteEnumField("type", 24, _radius_attribute_types),
        FieldLenField(
            "len",
            18,
            "value",
            "B",
        ),
        XStrFixedLenField("value", "\x00" * 16, length=16)
    ]

    @staticmethod
    def compute_message_authenticator(radius_packet, packed_req_authenticator,
                                      shared_secret):
        """
        Computes the "Message-Authenticator" of a given RADIUS packet.
        (RFC 2869 - Page 33)
        """

        attr = radius_packet[RadiusAttr_Message_Authenticator]
        attr.value = bytearray(attr.len - 2)
        data = prepare_packed_data(radius_packet, packed_req_authenticator)
        radius_hmac = hmac.new(shared_secret, data, hashlib.md5)

        return radius_hmac.digest()

#
# RADIUS attributes which values are IPv4 prefixes
#


class _RadiusAttrIPv4AddrVal(_SpecificRadiusAttr):
    """
    Implements a RADIUS attribute which value field is an IPv4 address.
    """

    __slots__ = ["val"]

    fields_desc = [
        ByteEnumField("type", 4, _radius_attribute_types),
        ByteField("len", 6),
        IPField("value", "0.0.0.0")
    ]


class RadiusAttr_NAS_IP_Address(_RadiusAttrIPv4AddrVal):
    """RFC 2865"""
    val = 4


class RadiusAttr_Framed_IP_Address(_RadiusAttrIPv4AddrVal):
    """RFC 2865"""
    val = 8


class RadiusAttr_Framed_IP_Netmask(_RadiusAttrIPv4AddrVal):
    """RFC 2865"""
    val = 9


class RadiusAttr_Login_IP_Host(_RadiusAttrIPv4AddrVal):
    """RFC 2865"""
    val = 14


class RadiusAttr_Framed_IPX_Network(_RadiusAttrIPv4AddrVal):
    """RFC 2865"""
    val = 23


class RadiusAttr_PMIP6_Home_LMA_IPv4_Address(_RadiusAttrIPv4AddrVal):
    """RFC 6572"""
    val = 149


class RadiusAttr_PMIP6_Visited_LMA_IPv4_Address(_RadiusAttrIPv4AddrVal):
    """RFC 6572"""
    val = 150


class RadiusAttr_PMIP6_Home_DHCP4_Server_Address(_RadiusAttrIPv4AddrVal):
    """RFC 6572"""
    val = 157


class RadiusAttr_PMIP6_Visited_DHCP4_Server_Address(_RadiusAttrIPv4AddrVal):
    """RFC 6572"""
    val = 158


class RadiusAttr_PMIP6_Home_IPv4_Gateway(_RadiusAttrIPv4AddrVal):
    """RFC 6572"""
    val = 161


class RadiusAttr_PMIP6_Visited_IPv4_Gateway(_RadiusAttrIPv4AddrVal):
    """RFC 6572"""
    val = 162


# See IANA registry "RADIUS Types"
_radius_attrs_values = {
    # Service-Type
    6:
    {
        1: "Login",
        2: "Framed",
        3: "Callback Login",
        4: "Callback Framed",
        5: "Outbound",
        6: "Administrative",
        7: "NAS Prompt",
        8: "Authenticate Only",
        9: "Callback NAS Prompt",
        10: "Call Check",
        11: "Callback Administrative",
        12: "Voice",
        13: "Fax",
        14: "Modem Relay",
        15: "IAPP-Register",
        16: "IAPP-AP-Check",
        17: "Authorize Only",
        18: "Framed-Management",
        19: "Additional-Authorization"
    },

    # Framed-Protocol
    7:
    {
        1: "PPP",
        2: "SLIP",
        3: "AppleTalk Remote Access Protocol (ARAP)",
        4: "Gandalf proprietary SingleLink/MultiLink protocol",
        5: "Xylogics proprietary IPX/SLIP",
        6: "X.75 Synchronous",
        7: "GPRS PDP Context"
    },

    # Framed-Routing
    10:
    {
        0: "None",
        1: "Send routing packets",
        2: "Listen for routing packets",
        3: "Send and Listen"
    },

    # Framed-Compression
    13:
    {
        0: "None",
        1: "VJ TCP/IP header compression",
        2: "IPX header compression",
        3: "Stac-LZS compression"
    },

    # Login-Service
    15:
    {
        0: "Telnet",
        1: "Rlogin",
        2: "TCP Clear",
        3: "PortMaster (proprietary)",
        4: "LAT",
        5: "X25-PAD",
        6: "X25-T3POS",
        7: "Unassigned",
        8: "TCP Clear Quiet (suppresses any NAS-generated connect string)"
    },

    # Termination-Action
    29:
    {
        0: "Default",
        1: "RADIUS-Request"
    },

    # Acct-Status-Type
    40:
    {
        1: "Start",
        2: "Stop",
        3: "Interim-Update",
        4: "Unassigned",
        5: "Unassigned",
        6: "Unassigned",
        7: "Accounting-On",
        8: "Accounting-Off",
        9: "Tunnel-Start",
        10: "Tunnel-Stop",
        11: "Tunnel-Reject",
        12: "Tunnel-Link-Start",
        13: "Tunnel-Link-Stop",
        14: "Tunnel-Link-Reject",
        15: "Failed"
    },

    # Acct-Authentic
    45:
    {
        1: "RADIUS",
        2: "Local",
        3: "Remote",
        4: "Diameter"
    },

    # Acct-Terminate-Cause
    49:
    {
        1: "User Request",
        2: "Lost Carrier",
        3: "Lost Service",
        4: "Idle Timeout",
        5: "Session Timeout",
        6: "Admin Reset",
        7: "Admin Reboot",
        8: "Port Error",
        9: "NAS Error",
        10: "NAS Request",
        11: "NAS Reboot",
        12: "Port Unneeded",
        13: "Port Preempted",
        14: "Port Suspended",
        15: "Service Unavailable",
        16: "Callback",
        17: "User Error",
        18: "Host Request",
        19: "Supplicant Restart",
        20: "Reauthentication Failure",
        21: "Port Reinitialized",
        22: "Port Administratively Disabled",
        23: "Lost Power",
    },

    # NAS-Port-Type
    61:
    {
        0: "Async",
        1: "Sync",
        2: "ISDN Sync",
        3: "ISDN Async V.120",
        4: "ISDN Async V.110",
        5: "Virtual",
        6: "PIAFS",
        7: "HDLC Clear Channel",
        8: "X.25",
        9: "X.75",
        10: "G.3 Fax",
        11: "SDSL - Symmetric DSL",
        12: "ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase Modulation",  # noqa: E501
        13: "ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone",
        14: "IDSL - ISDN Digital Subscriber Line",
        15: "Ethernet",
        16: "xDSL - Digital Subscriber Line of unknown type",
        17: "Cable",
        18: "Wireles - Other",
        19: "Wireless - IEEE 802.11",
        20: "Token-Ring",
        21: "FDDI",
        22: "Wireless - CDMA2000",
        23: "Wireless - UMTS",
        24: "Wireless - 1X-EV",
        25: "IAPP",
        26: "FTTP - Fiber to the Premises",
        27: "Wireless - IEEE 802.16",
        28: "Wireless - IEEE 802.20",
        29: "Wireless - IEEE 802.22",
        30: "PPPoA - PPP over ATM",
        31: "PPPoEoA - PPP over Ethernet over ATM",
        32: "PPPoEoE - PPP over Ethernet over Ethernet",
        33: "PPPoEoVLAN - PPP over Ethernet over VLAN",
        34: "PPPoEoQinQ - PPP over Ethernet over IEEE 802.1QinQ",
        35: "xPON - Passive Optical Network",
        36: "Wireless - XGP",
        37: "WiMAX Pre-Release 8 IWK Function",
        38: "WIMAX-WIFI-IWK: WiMAX WIFI Interworking",
        39: "WIMAX-SFF: Signaling Forwarding Function for LTE/3GPP2",
        40: "WIMAX-HA-LMA: WiMAX HA and or LMA function",
        41: "WIMAX-DHCP: WIMAX DHCP service",
        42: "WIMAX-LBS: WiMAX location based service",
        43: "WIMAX-WVS: WiMAX voice service"
    },

    # Tunnel-Type
    64:
    {
        1: "Point-to-Point Tunneling Protocol (PPTP)",
        2: "Layer Two Forwarding (L2F)",
        3: "Layer Two Tunneling Protocol (L2TP)",
        4: "Ascend Tunnel Management Protocol (ATMP)",
        5: "Virtual Tunneling Protocol (VTP)",
        6: "IP Authentication Header in the Tunnel-mode (AH)",
        7: "IP-in-IP Encapsulation (IP-IP)",
        8: "Minimal IP-in-IP Encapsulation (MIN-IP-IP)",
        9: "IP Encapsulating Security Payload in the Tunnel-mode (ESP)",
        10: "Generic Route Encapsulation (GRE)",
        11: "Bay Dial Virtual Services (DVS)",
        12: "IP-in-IP Tunneling",
        13: "Virtual LANs (VLAN)"
    },

    # Tunnel-Medium-Type
    65:
    {
        1: "IPv4 (IP version 4)",
        2: "IPv6 (IP version 6)",
        3: "NSAP",
        4: "HDLC (8-bit multidrop)",
        5: "BBN 1822",
        6: "802",
        7: "E.163 (POTS)",
        8: "E.164 (SMDS, Frame Relay, ATM)",
        9: "F.69 (Telex)",
        10: "X.121 (X.25, Frame Relay)",
        11: "IPX",
        12: "Appletalk",
        13: "Decnet IV",
        14: "Banyan Vine",
        15: "E.164 with NSAP format subaddress"
    },

    # ARAP-Zone-Access
    72:
    {
        1: "Only allow access to default zone",
        2: "Use zone filter inclusively",
        3: "Not used",
        4: "Use zone filter exclusively"
    },

    # Prompt
    76:
    {
        0: "No Echo",
        1: "Echo"
    },

    # Error-Cause Attribute
    101:
    {
        201: "Residual Session Context Removed",
        202: "Invalid EAP Packet (Ignored)",
        401: "Unsupported Attribute",
        402: "Missing Attribute",
        403: "NAS Identification Mismatch",
        404: "Invalid Request",
        405: "Unsupported Service",
        406: "Unsupported Extension",
        407: "Invalid Attribute Value",
        501: "Administratively Prohibited",
        502: "Request Not Routable (Proxy)",
        503: "Session Context Not Found",
        504: "Session Context Not Removable",
        505: "Other Proxy Processing Error",
        506: "Resources Unavailable",
        507: "Request Initiated",
        508: "Multiple Session Selection Unsupported",
        509: "Location-Info-Required",
        601: "Response Too Big"
    },

    # Operator Namespace Identifier - Attribute 126
    126:
    {
        0x30: "TADIG",
        0x31: "REALM",
        0x32: "E212",
        0x33: "ICC",
        0xFF: "Reserved"
    },

    # Basic-Location-Policy-Rules
    129:
    {
        0: "Retransmission allowed",
    },

    # Location-Capable
    131:
    {
        1: "CIVIC_LOCATION",
        2: "GEO_LOCATION",
        4: "USERS_LOCATION",
        8: "NAS_LOCATION"
    },

    # Framed-Management-Protocol
    133:
    {
        1: "SNMP",
        2: "Web-based",
        3: "NETCONF",
        4: "FTP",
        5: "TFTP",
        6: "SFTP",
        7: "RCP",
        8: "SCP"
    },

    # Management-Transport-Protection
    134:
    {
        1: "No-Protection",
        2: "Integrity-Protection",
        3: "Integrity-Confidentiality-Protection",
    },
}


class _RadiusAttrIntEnumVal(_SpecificRadiusAttr):
    """
    Implements a RADIUS attribute which value field is 4 bytes long integer.
    """

    __slots__ = ["val"]

    fields_desc = [
        ByteEnumField("type", 6, _radius_attribute_types),
        ByteField("len", 6),
        MultiEnumField(
            "value",
            0,
            _radius_attrs_values,
            depends_on=lambda p: p.type,
            fmt="I"
        )
    ]


class RadiusAttr_Service_Type(_RadiusAttrIntEnumVal):
    """RFC 2865"""
    val = 6


class RadiusAttr_Framed_Protocol(_RadiusAttrIntEnumVal):
    """RFC 2865"""
    val = 7


class RadiusAttr_NAS_Port_Type(_RadiusAttrIntEnumVal):
    """RFC 2865"""
    val = 61


class _EAPPacketField(PacketLenField):

    """
    Handles EAP-Message attribute value (the actual EAP packet).
    """

    def m2i(self, pkt, m):
        ret = None
        eap_packet_len = struct.unpack("!H", m[2:4])[0]
        if eap_packet_len < 254:
            # If the EAP packet has not been fragmented, build a Scapy EAP
            # packet from the data.
            ret = EAP(m)
        else:
            ret = conf.raw_layer(m)
        return ret


class RadiusAttr_EAP_Message(RadiusAttribute):
    """
    Implements the "EAP-Message" attribute (RFC 3579).
    """

    name = "EAP-Message"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 79, _radius_attribute_types),
        FieldLenField(
            "len",
            None,
            "value",
            "B",
            adjust=lambda pkt, x: len(pkt.value) + 2
        ),
        _EAPPacketField("value", "", EAP, length_from=lambda p: p.len - 2)
    ]


class RadiusAttr_Vendor_Specific(RadiusAttribute):
    """
    Implements the "Vendor-Specific" attribute, as described in RFC 2865.
    """

    name = "Vendor-Specific"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 26, _radius_attribute_types),
        FieldLenField(
            "len",
            None,
            "value",
            "B",
            adjust=lambda pkt, x: len(pkt.value) + 8
        ),
        IntField("vendor_id", 0),
        ByteField("vendor_type", 0),
        FieldLenField(
            "vendor_len",
            None,
            "value",
            "B",
            adjust=lambda p, x: len(p.value) + 2
        ),
        StrLenField("value", "", length_from=lambda p: p.vendor_len - 2)
    ]


# See IANA RADIUS Packet Type Codes registry
_packet_codes = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    6: "Accounting-Status (now Interim Accounting)",
    7: "Password-Request",
    8: "Password-Ack",
    9: "Password-Reject",
    10: "Accounting-Message",
    11: "Access-Challenge",
    12: "Status-Server (experimental)",
    13: "Status-Client (experimental)",
    21: "Resource-Free-Request",
    22: "Resource-Free-Response",
    23: "Resource-Query-Request",
    24: "Resource-Query-Response",
    25: "Alternate-Resource-Reclaim-Request",
    26: "NAS-Reboot-Request",
    27: "NAS-Reboot-Response",
    28: "Reserved",
    29: "Next-Passcode",
    30: "New-Pin",
    31: "Terminate-Session",
    32: "Password-Expired",
    33: "Event-Request",
    34: "Event-Response",
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
    50: "IP-Address-Allocate",
    51: "IP-Address-Release",
    52: "Protocol-Error",
    250: "Experimental Use",
    251: "Experimental Use",
    252: "Experimental Use",
    253: "Experimental Use",
    254: "Reserved",
    255: "Reserved"
}


class Radius(Packet):
    """
    Implements a RADIUS packet (RFC 2865).
    """

    name = "RADIUS"
    fields_desc = [
        ByteEnumField("code", 1, _packet_codes),
        ByteField("id", 0),
        FieldLenField(
            "len",
            None,
            "attributes",
            "H",
            adjust=lambda pkt, x: len(pkt.attributes) + 20
        ),
        XStrFixedLenField("authenticator", "", 16),
        PacketListField(
            "attributes",
            [],
            RadiusAttribute,
            length_from=lambda pkt: pkt.len - 20
        )
    ]

    def compute_authenticator(self, packed_request_auth, shared_secret):
        """
        Computes the authenticator field (RFC 2865 - Section 3)
        """

        data = prepare_packed_data(self, packed_request_auth)
        radius_mac = hashlib.md5(data + shared_secret)
        return radius_mac.digest()

    def post_build(self, p, pay):
        p += pay
        length = self.len
        if length is None:
            length = len(p)
            p = p[:2] + struct.pack("!H", length) + p[4:]
        return p


bind_bottom_up(UDP, Radius, sport=1812)
bind_bottom_up(UDP, Radius, dport=1812)
bind_bottom_up(UDP, Radius, sport=1813)
bind_bottom_up(UDP, Radius, dport=1813)
bind_bottom_up(UDP, Radius, sport=3799)
bind_bottom_up(UDP, Radius, dport=3799)
bind_layers(UDP, Radius, sport=1812, dport=1812)
