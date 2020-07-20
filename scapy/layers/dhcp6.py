# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# Copyright (C) 2005  Guillaume Valadon <guedou@hongo.wide.ad.jp>
#                     Arnaud Ebalard <arnaud.ebalard@eads.net>

"""
DHCPv6: Dynamic Host Configuration Protocol for IPv6. [RFC 3315,8415]
"""

from __future__ import print_function
import socket
import struct
import time

from scapy.ansmachine import AnsweringMachine
from scapy.arch import get_if_raw_hwaddr, in6_getifaddr
from scapy.config import conf
from scapy.data import EPOCH, ETHER_ANY
from scapy.compat import raw, orb
from scapy.error import warning
from scapy.fields import BitField, ByteEnumField, ByteField, FieldLenField, \
    FlagsField, IntEnumField, IntField, MACField, PacketField, \
    PacketListField, ShortEnumField, ShortField, StrField, StrFixedLenField, \
    StrLenField, UTCTimeField, X3BytesField, XIntField, XShortEnumField, \
    PacketLenField, UUIDField, FieldListField
from scapy.data import IANA_ENTERPRISE_NUMBERS
from scapy.layers.dns import DNSStrField
from scapy.layers.inet import UDP
from scapy.layers.inet6 import DomainNameListField, IP6Field, IP6ListField, \
    IPv6
from scapy.packet import Packet, bind_bottom_up
from scapy.pton_ntop import inet_pton
from scapy.sendrecv import send
from scapy.themes import Color
from scapy.utils6 import in6_addrtovendor, in6_islladdr
import scapy.modules.six as six

#############################################################################
# Helpers                                                                  ##
#############################################################################


def get_cls(name, fallback_cls):
    return globals().get(name, fallback_cls)


dhcp6_cls_by_type = {1: "DHCP6_Solicit",
                     2: "DHCP6_Advertise",
                     3: "DHCP6_Request",
                     4: "DHCP6_Confirm",
                     5: "DHCP6_Renew",
                     6: "DHCP6_Rebind",
                     7: "DHCP6_Reply",
                     8: "DHCP6_Release",
                     9: "DHCP6_Decline",
                     10: "DHCP6_Reconf",
                     11: "DHCP6_InfoRequest",
                     12: "DHCP6_RelayForward",
                     13: "DHCP6_RelayReply"}


def _dhcp6_dispatcher(x, *args, **kargs):
    cls = conf.raw_layer
    if len(x) >= 2:
        cls = get_cls(dhcp6_cls_by_type.get(orb(x[0]), "Raw"), conf.raw_layer)
    return cls(x, *args, **kargs)

#############################################################################
#############################################################################
#                                  DHCPv6                                   #
#############################################################################
#############################################################################


All_DHCP_Relay_Agents_and_Servers = "ff02::1:2"
All_DHCP_Servers = "ff05::1:3"  # Site-Local scope : deprecated by 3879

dhcp6opts = {1: "CLIENTID",
             2: "SERVERID",
             3: "IA_NA",
             4: "IA_TA",
             5: "IAADDR",
             6: "ORO",
             7: "PREFERENCE",
             8: "ELAPSED_TIME",
             9: "RELAY_MSG",
             11: "AUTH",
             12: "UNICAST",
             13: "STATUS_CODE",
             14: "RAPID_COMMIT",
             15: "USER_CLASS",
             16: "VENDOR_CLASS",
             17: "VENDOR_OPTS",
             18: "INTERFACE_ID",
             19: "RECONF_MSG",
             20: "RECONF_ACCEPT",
             21: "SIP Servers Domain Name List",  # RFC3319
             22: "SIP Servers IPv6 Address List",  # RFC3319
             23: "DNS Recursive Name Server Option",  # RFC3646
             24: "Domain Search List option",  # RFC3646
             25: "OPTION_IA_PD",  # RFC3633
             26: "OPTION_IAPREFIX",  # RFC3633
             27: "OPTION_NIS_SERVERS",  # RFC3898
             28: "OPTION_NISP_SERVERS",  # RFC3898
             29: "OPTION_NIS_DOMAIN_NAME",  # RFC3898
             30: "OPTION_NISP_DOMAIN_NAME",  # RFC3898
             31: "OPTION_SNTP_SERVERS",  # RFC4075
             32: "OPTION_INFORMATION_REFRESH_TIME",  # RFC4242
             33: "OPTION_BCMCS_SERVER_D",  # RFC4280
             34: "OPTION_BCMCS_SERVER_A",  # RFC4280
             36: "OPTION_GEOCONF_CIVIC",  # RFC-ietf-geopriv-dhcp-civil-09.txt
             37: "OPTION_REMOTE_ID",  # RFC4649
             38: "OPTION_SUBSCRIBER_ID",  # RFC4580
             39: "OPTION_CLIENT_FQDN",  # RFC4704
             40: "OPTION_PANA_AGENT",  # RFC5192
             41: "OPTION_NEW_POSIX_TIMEZONE",  # RFC4833
             42: "OPTION_NEW_TZDB_TIMEZONE",  # RFC4833
             48: "OPTION_LQ_CLIENT_LINK",  # RFC5007
             59: "OPT_BOOTFILE_URL",  # RFC5970
             60: "OPT_BOOTFILE_PARAM",  # RFC5970
             61: "OPTION_CLIENT_ARCH_TYPE",  # RFC5970
             62: "OPTION_NII",  # RFC5970
             65: "OPTION_ERP_LOCAL_DOMAIN_NAME",  # RFC6440
             66: "OPTION_RELAY_SUPPLIED_OPTIONS",  # RFC6422
             68: "OPTION_VSS",  # RFC6607
             79: "OPTION_CLIENT_LINKLAYER_ADDR"}  # RFC6939

dhcp6opts_by_code = {1: "DHCP6OptClientId",
                     2: "DHCP6OptServerId",
                     3: "DHCP6OptIA_NA",
                     4: "DHCP6OptIA_TA",
                     5: "DHCP6OptIAAddress",
                     6: "DHCP6OptOptReq",
                     7: "DHCP6OptPref",
                     8: "DHCP6OptElapsedTime",
                     9: "DHCP6OptRelayMsg",
                     11: "DHCP6OptAuth",
                     12: "DHCP6OptServerUnicast",
                     13: "DHCP6OptStatusCode",
                     14: "DHCP6OptRapidCommit",
                     15: "DHCP6OptUserClass",
                     16: "DHCP6OptVendorClass",
                     17: "DHCP6OptVendorSpecificInfo",
                     18: "DHCP6OptIfaceId",
                     19: "DHCP6OptReconfMsg",
                     20: "DHCP6OptReconfAccept",
                     21: "DHCP6OptSIPDomains",  # RFC3319
                     22: "DHCP6OptSIPServers",  # RFC3319
                     23: "DHCP6OptDNSServers",  # RFC3646
                     24: "DHCP6OptDNSDomains",  # RFC3646
                     25: "DHCP6OptIA_PD",  # RFC3633
                     26: "DHCP6OptIAPrefix",  # RFC3633
                     27: "DHCP6OptNISServers",  # RFC3898
                     28: "DHCP6OptNISPServers",  # RFC3898
                     29: "DHCP6OptNISDomain",  # RFC3898
                     30: "DHCP6OptNISPDomain",  # RFC3898
                     31: "DHCP6OptSNTPServers",  # RFC4075
                     32: "DHCP6OptInfoRefreshTime",  # RFC4242
                     33: "DHCP6OptBCMCSDomains",  # RFC4280
                     34: "DHCP6OptBCMCSServers",  # RFC4280
                     # 36: "DHCP6OptGeoConf",            #RFC-ietf-geopriv-dhcp-civil-09.txt  # noqa: E501
                     37: "DHCP6OptRemoteID",  # RFC4649
                     38: "DHCP6OptSubscriberID",  # RFC4580
                     39: "DHCP6OptClientFQDN",  # RFC4704
                     40: "DHCP6OptPanaAuthAgent",  # RFC-ietf-dhc-paa-option-05.txt  # noqa: E501
                     41: "DHCP6OptNewPOSIXTimeZone",  # RFC4833
                     42: "DHCP6OptNewTZDBTimeZone",  # RFC4833
                     43: "DHCP6OptRelayAgentERO",  # RFC4994
                     # 44: "DHCP6OptLQQuery",            #RFC5007
                     # 45: "DHCP6OptLQClientData",       #RFC5007
                     # 46: "DHCP6OptLQClientTime",       #RFC5007
                     # 47: "DHCP6OptLQRelayData",        #RFC5007
                     48: "DHCP6OptLQClientLink",  # RFC5007
                     59: "DHCP6OptBootFileUrl",  # RFC5790
                     60: "DHCP6OptBootFileParam",  # RFC5970
                     61: "DHCP6OptClientArchType",  # RFC5970
                     62: "DHCP6OptClientNetworkInterId",  # RFC5970
                     65: "DHCP6OptERPDomain",  # RFC6440
                     66: "DHCP6OptRelaySuppliedOpt",  # RFC6422
                     68: "DHCP6OptVSS",  # RFC6607
                     79: "DHCP6OptClientLinkLayerAddr",  # RFC6939
                     }


# sect 7.3 RFC 8415 : DHCP6 Messages types
dhcp6types = {1: "SOLICIT",
                 2: "ADVERTISE",
                 3: "REQUEST",
                 4: "CONFIRM",
                 5: "RENEW",
                 6: "REBIND",
                 7: "REPLY",
                 8: "RELEASE",
                 9: "DECLINE",
              10: "RECONFIGURE",
              11: "INFORMATION-REQUEST",
              12: "RELAY-FORW",
              13: "RELAY-REPL"}


#####################################################################
#                    DHCPv6 DUID related stuff                      #
#####################################################################

duidtypes = {1: "Link-layer address plus time",
             2: "Vendor-assigned unique ID based on Enterprise Number",
             3: "Link-layer Address",
             4: "UUID"}

# DUID hardware types - RFC 826 - Extracted from
# http://www.iana.org/assignments/arp-parameters on 31/10/06
# We should add the length of every kind of address.
duidhwtypes = {0: "NET/ROM pseudo",  # Not referenced by IANA
               1: "Ethernet (10Mb)",
               2: "Experimental Ethernet (3Mb)",
               3: "Amateur Radio AX.25",
               4: "Proteon ProNET Token Ring",
               5: "Chaos",
               6: "IEEE 802 Networks",
               7: "ARCNET",
               8: "Hyperchannel",
               9: "Lanstar",
               10: "Autonet Short Address",
               11: "LocalTalk",
               12: "LocalNet (IBM PCNet or SYTEK LocalNET)",
               13: "Ultra link",
               14: "SMDS",
               15: "Frame Relay",
               16: "Asynchronous Transmission Mode (ATM)",
               17: "HDLC",
               18: "Fibre Channel",
               19: "Asynchronous Transmission Mode (ATM)",
               20: "Serial Line",
               21: "Asynchronous Transmission Mode (ATM)",
               22: "MIL-STD-188-220",
               23: "Metricom",
               24: "IEEE 1394.1995",
               25: "MAPOS",
               26: "Twinaxial",
               27: "EUI-64",
               28: "HIPARP",
               29: "IP and ARP over ISO 7816-3",
               30: "ARPSec",
               31: "IPsec tunnel",
               32: "InfiniBand (TM)",
               33: "TIA-102 Project 25 Common Air Interface (CAI)"}


class _UTCTimeField(UTCTimeField):
    def __init__(self, *args, **kargs):
        epoch_2000 = (2000, 1, 1, 0, 0, 0, 5, 1, 0)  # required Epoch
        UTCTimeField.__init__(self, epoch=epoch_2000, *args, **kargs)


class _LLAddrField(MACField):
    pass

# XXX We only support Ethernet addresses at the moment. _LLAddrField
#     will be modified when needed. Ask us. --arno


class DUID_LLT(Packet):  # sect 9.2 RFC 3315
    name = "DUID - Link-layer address plus time"
    fields_desc = [ShortEnumField("type", 1, duidtypes),
                   XShortEnumField("hwtype", 1, duidhwtypes),
                   _UTCTimeField("timeval", 0),  # i.e. 01 Jan 2000
                   _LLAddrField("lladdr", ETHER_ANY)]


class DUID_EN(Packet):  # sect 9.3 RFC 3315
    name = "DUID - Assigned by Vendor Based on Enterprise Number"
    fields_desc = [ShortEnumField("type", 2, duidtypes),
                   IntEnumField("enterprisenum", 311, IANA_ENTERPRISE_NUMBERS),
                   StrField("id", "")]


class DUID_LL(Packet):  # sect 9.4 RFC 3315
    name = "DUID - Based on Link-layer Address"
    fields_desc = [ShortEnumField("type", 3, duidtypes),
                   XShortEnumField("hwtype", 1, duidhwtypes),
                   _LLAddrField("lladdr", ETHER_ANY)]


class DUID_UUID(Packet):  # RFC 6355
    name = "DUID - Based on UUID"
    fields_desc = [ShortEnumField("type", 4, duidtypes),
                   UUIDField("uuid", None, uuid_fmt=UUIDField.FORMAT_BE)]


duid_cls = {1: "DUID_LLT",
            2: "DUID_EN",
            3: "DUID_LL",
            4: "DUID_UUID"}

#####################################################################
#                     DHCPv6 Options classes                        #
#####################################################################


class _DHCP6OptGuessPayload(Packet):
    @staticmethod
    def _just_guess_payload_class(cls, payload):
        # try to guess what option is in the payload
        if len(payload) <= 2:
            return conf.raw_layer
        opt = struct.unpack("!H", payload[:2])[0]
        clsname = dhcp6opts_by_code.get(opt, None)
        if clsname is None:
            return cls
        return get_cls(clsname, cls)

    def guess_payload_class(self, payload):
        # this method is used in case of all derived classes
        # from _DHCP6OptGuessPayload in this file
        return _DHCP6OptGuessPayload._just_guess_payload_class(
            DHCP6OptUnknown,
            payload
        )


class _DHCP6OptGuessPayloadElt(_DHCP6OptGuessPayload):
    """
    Same than _DHCP6OptGuessPayload but made for lists
    in case of list of different suboptions
    e.g. in ianaopts in DHCP6OptIA_NA
    """
    @classmethod
    def dispatch_hook(cls, payload=None, *args, **kargs):
        return cls._just_guess_payload_class(conf.raw_layer, payload)

    def extract_padding(self, s):
        return b"", s


class DHCP6OptUnknown(_DHCP6OptGuessPayload):  # A generic DHCPv6 Option
    name = "Unknown DHCPv6 Option"
    fields_desc = [ShortEnumField("optcode", 0, dhcp6opts),
                   FieldLenField("optlen", None, length_of="data", fmt="!H"),
                   StrLenField("data", "",
                               length_from=lambda pkt: pkt.optlen)]


class _DUIDField(PacketField):
    __slots__ = ["length_from"]

    def __init__(self, name, default, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from

    def i2m(self, pkt, i):
        return raw(i)

    def m2i(self, pkt, x):
        cls = conf.raw_layer
        if len(x) > 4:
            o = struct.unpack("!H", x[:2])[0]
            cls = get_cls(duid_cls.get(o, conf.raw_layer), conf.raw_layer)
        return cls(x)

    def getfield(self, pkt, s):
        tmp_len = self.length_from(pkt)
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


class DHCP6OptClientId(_DHCP6OptGuessPayload):     # RFC 8415 sect 21.2
    name = "DHCP6 Client Identifier Option"
    fields_desc = [ShortEnumField("optcode", 1, dhcp6opts),
                   FieldLenField("optlen", None, length_of="duid", fmt="!H"),
                   _DUIDField("duid", "",
                              length_from=lambda pkt: pkt.optlen)]


class DHCP6OptServerId(DHCP6OptClientId):     # RFC 8415 sect 21.3
    name = "DHCP6 Server Identifier Option"
    optcode = 2

# Should be encapsulated in the option field of IA_NA or IA_TA options
# Can only appear at that location.


class DHCP6OptIAAddress(_DHCP6OptGuessPayload):    # RFC 8415 sect 21.6
    name = "DHCP6 IA Address Option (IA_TA or IA_NA suboption)"
    fields_desc = [ShortEnumField("optcode", 5, dhcp6opts),
                   FieldLenField("optlen", None, length_of="iaaddropts",
                                 fmt="!H", adjust=lambda pkt, x: x + 24),
                   IP6Field("addr", "::"),
                   IntEnumField("preflft", 0, {0xffffffff: "infinity"}),
                   IntEnumField("validlft", 0, {0xffffffff: "infinity"}),
                   # last field IAaddr-options is not defined in the
                   # reference document. We copy what wireshark does: read
                   # more dhcp6 options and excpect failures
                   PacketListField("iaaddropts", [],
                                   _DHCP6OptGuessPayloadElt,
                                   length_from=lambda pkt: pkt.optlen - 24)]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class DHCP6OptIA_NA(_DHCP6OptGuessPayload):         # RFC 8415 sect 21.4
    name = "DHCP6 Identity Association for Non-temporary Addresses Option"
    fields_desc = [ShortEnumField("optcode", 3, dhcp6opts),
                   FieldLenField("optlen", None, length_of="ianaopts",
                                 fmt="!H", adjust=lambda pkt, x: x + 12),
                   XIntField("iaid", None),
                   IntField("T1", None),
                   IntField("T2", None),
                   PacketListField("ianaopts", [], _DHCP6OptGuessPayloadElt,
                                   length_from=lambda pkt: pkt.optlen - 12)]


class DHCP6OptIA_TA(_DHCP6OptGuessPayload):         # RFC 8415 sect 21.5
    name = "DHCP6 Identity Association for Temporary Addresses Option"
    fields_desc = [ShortEnumField("optcode", 4, dhcp6opts),
                   FieldLenField("optlen", None, length_of="iataopts",
                                 fmt="!H", adjust=lambda pkt, x: x + 4),
                   XIntField("iaid", None),
                   PacketListField("iataopts", [], _DHCP6OptGuessPayloadElt,
                                   length_from=lambda pkt: pkt.optlen - 4)]


#    DHCPv6 Option Request Option                                   #

class _OptReqListField(StrLenField):
    islist = 1

    def i2h(self, pkt, x):
        if x is None:
            return []
        return x

    def i2len(self, pkt, x):
        return 2 * len(x)

    def any2i(self, pkt, x):
        return x

    def i2repr(self, pkt, x):
        s = []
        for y in self.i2h(pkt, x):
            if y in dhcp6opts:
                s.append(dhcp6opts[y])
            else:
                s.append("%d" % y)
        return "[%s]" % ", ".join(s)

    def m2i(self, pkt, x):
        r = []
        while len(x) != 0:
            if len(x) < 2:
                warning("Odd length for requested option field. Rejecting last byte")  # noqa: E501
                return r
            r.append(struct.unpack("!H", x[:2])[0])
            x = x[2:]
        return r

    def i2m(self, pkt, x):
        return b"".join(struct.pack('!H', y) for y in x)

# A client may include an ORO in a solicit, Request, Renew, Rebind,
# Confirm or Information-request


class DHCP6OptOptReq(_DHCP6OptGuessPayload):       # RFC 8415 sect 21.7
    name = "DHCP6 Option Request Option"
    fields_desc = [ShortEnumField("optcode", 6, dhcp6opts),
                   FieldLenField("optlen", None, length_of="reqopts", fmt="!H"),  # noqa: E501
                   _OptReqListField("reqopts", [23, 24],
                                    length_from=lambda pkt: pkt.optlen)]


#    DHCPv6 Preference Option                                       #

# emise par un serveur pour affecter le choix fait par le client. Dans
# les messages Advertise, a priori
class DHCP6OptPref(_DHCP6OptGuessPayload):       # RFC 8415 sect 21.8
    name = "DHCP6 Preference Option"
    fields_desc = [ShortEnumField("optcode", 7, dhcp6opts),
                   ShortField("optlen", 1),
                   ByteField("prefval", 255)]


#    DHCPv6 Elapsed Time Option                                     #

class _ElapsedTimeField(ShortField):
    def i2repr(self, pkt, x):
        if x == 0xffff:
            return "infinity (0xffff)"
        return "%.2f sec" % (self.i2h(pkt, x) / 100.)


class DHCP6OptElapsedTime(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.9
    name = "DHCP6 Elapsed Time Option"
    fields_desc = [ShortEnumField("optcode", 8, dhcp6opts),
                   ShortField("optlen", 2),
                   _ElapsedTimeField("elapsedtime", 0)]


#    DHCPv6 Authentication Option                                   #

#    The following fields are set in an Authentication option for the
#    Reconfigure Key Authentication Protocol:
#
#       protocol    3
#
#       algorithm   1
#
#       RDM         0
#
#    The format of the Authentication information for the Reconfigure Key
#    Authentication Protocol is:
#
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |     Type      |                 Value (128 bits)              |
#     +-+-+-+-+-+-+-+-+                                               |
#     .                                                               .
#     .                                                               .
#     .                                               +-+-+-+-+-+-+-+-+
#     |                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#       Type    Type of data in Value field carried in this option:
#
#                  1   Reconfigure Key value (used in Reply message).
#
#                  2   HMAC-MD5 digest of the message (used in Reconfigure
#                      message).
#
#       Value   Data as defined by field.

# https://www.iana.org/assignments/auth-namespaces
_dhcp6_auth_proto = {
    0: "configuration token",
    1: "delayed authentication",
    2: "delayed authentication (obsolete)",
    3: "reconfigure key",
}
_dhcp6_auth_alg = {
    0: "configuration token",
    1: "HMAC-MD5",
}
_dhcp6_auth_rdm = {
    0: "use of a monotonically increasing value"
}


class DHCP6OptAuth(_DHCP6OptGuessPayload):    # RFC 8415 sect 21.11
    name = "DHCP6 Option - Authentication"
    fields_desc = [ShortEnumField("optcode", 11, dhcp6opts),
                   FieldLenField("optlen", None, length_of="authinfo",
                                 fmt="!H", adjust=lambda pkt, x: x + 11),
                   ByteEnumField("proto", 3, _dhcp6_auth_proto),
                   ByteEnumField("alg", 1, _dhcp6_auth_alg),
                   ByteEnumField("rdm", 0, _dhcp6_auth_rdm),
                   StrFixedLenField("replay", b"\x00" * 8, 8),
                   StrLenField("authinfo", "",
                               length_from=lambda pkt: pkt.optlen - 11)]

#    DHCPv6 Server Unicast Option                                   #


class _SrvAddrField(IP6Field):
    def i2h(self, pkt, x):
        if x is None:
            return "::"
        return x

    def i2m(self, pkt, x):
        return inet_pton(socket.AF_INET6, self.i2h(pkt, x))


class DHCP6OptServerUnicast(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.12
    name = "DHCP6 Server Unicast Option"
    fields_desc = [ShortEnumField("optcode", 12, dhcp6opts),
                   ShortField("optlen", 16),
                   _SrvAddrField("srvaddr", None)]


#    DHCPv6 Status Code Option                                      #

dhcp6statuscodes = {0: "Success",      # RFC 8415 sect 21.13
                    1: "UnspecFail",
                    2: "NoAddrsAvail",
                    3: "NoBinding",
                    4: "NotOnLink",
                    5: "UseMulticast",
                    6: "NoPrefixAvail"}  # From RFC3633


class DHCP6OptStatusCode(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.13
    name = "DHCP6 Status Code Option"
    fields_desc = [ShortEnumField("optcode", 13, dhcp6opts),
                   FieldLenField("optlen", None, length_of="statusmsg",
                                 fmt="!H", adjust=lambda pkt, x:x + 2),
                   ShortEnumField("statuscode", None, dhcp6statuscodes),
                   StrLenField("statusmsg", "",
                               length_from=lambda pkt: pkt.optlen - 2)]


#    DHCPv6 Rapid Commit Option                                     #

class DHCP6OptRapidCommit(_DHCP6OptGuessPayload):   # RFC 8415 sect 21.14
    name = "DHCP6 Rapid Commit Option"
    fields_desc = [ShortEnumField("optcode", 14, dhcp6opts),
                   ShortField("optlen", 0)]


#    DHCPv6 User Class Option                                       #

class _UserClassDataField(PacketListField):
    def i2len(self, pkt, z):
        if z is None or z == []:
            return 0
        return sum(len(raw(x)) for x in z)

    def getfield(self, pkt, s):
        tmp_len = self.length_from(pkt)
        lst = []
        remain, payl = s[:tmp_len], s[tmp_len:]
        while len(remain) > 0:
            p = self.m2i(pkt, remain)
            if conf.padding_layer in p:
                pad = p[conf.padding_layer]
                remain = pad.load
                del(pad.underlayer.payload)
            else:
                remain = ""
            lst.append(p)
        return payl, lst


class USER_CLASS_DATA(Packet):
    name = "user class data"
    fields_desc = [FieldLenField("len", None, length_of="data"),
                   StrLenField("data", "",
                               length_from=lambda pkt: pkt.len)]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class DHCP6OptUserClass(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.15
    name = "DHCP6 User Class Option"
    fields_desc = [ShortEnumField("optcode", 15, dhcp6opts),
                   FieldLenField("optlen", None, fmt="!H",
                                 length_of="userclassdata"),
                   _UserClassDataField("userclassdata", [], USER_CLASS_DATA,
                                       length_from=lambda pkt: pkt.optlen)]


#    DHCPv6 Vendor Class Option                                     #

class _VendorClassDataField(_UserClassDataField):
    pass


class VENDOR_CLASS_DATA(USER_CLASS_DATA):
    name = "vendor class data"


class DHCP6OptVendorClass(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.16
    name = "DHCP6 Vendor Class Option"
    fields_desc = [ShortEnumField("optcode", 16, dhcp6opts),
                   FieldLenField("optlen", None, length_of="vcdata", fmt="!H",
                                 adjust=lambda pkt, x: x + 4),
                   IntEnumField("enterprisenum", None,
                                IANA_ENTERPRISE_NUMBERS),
                   _VendorClassDataField("vcdata", [], VENDOR_CLASS_DATA,
                                         length_from=lambda pkt: pkt.optlen - 4)]  # noqa: E501

#    DHCPv6 Vendor-Specific Information Option                      #


class VENDOR_SPECIFIC_OPTION(_DHCP6OptGuessPayload):
    name = "vendor specific option data"
    fields_desc = [ShortField("optcode", None),
                   FieldLenField("optlen", None, length_of="optdata"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]

    def guess_payload_class(self, payload):
        return conf.padding_layer

# The third one that will be used for nothing interesting


class DHCP6OptVendorSpecificInfo(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.17
    name = "DHCP6 Vendor-specific Information Option"
    fields_desc = [ShortEnumField("optcode", 17, dhcp6opts),
                   FieldLenField("optlen", None, length_of="vso", fmt="!H",
                                 adjust=lambda pkt, x: x + 4),
                   IntEnumField("enterprisenum", None,
                                IANA_ENTERPRISE_NUMBERS),
                   _VendorClassDataField("vso", [], VENDOR_SPECIFIC_OPTION,
                                         length_from=lambda pkt: pkt.optlen - 4)]  # noqa: E501

#    DHCPv6 Interface-ID Option                                     #

# Repasser sur cette option a la fin. Elle a pas l'air d'etre des
# masses critique.


class DHCP6OptIfaceId(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.18
    name = "DHCP6 Interface-Id Option"
    fields_desc = [ShortEnumField("optcode", 18, dhcp6opts),
                   FieldLenField("optlen", None, fmt="!H",
                                 length_of="ifaceid"),
                   StrLenField("ifaceid", "",
                               length_from=lambda pkt: pkt.optlen)]


#    DHCPv6 Reconfigure Message Option                              #

# A server includes a Reconfigure Message option in a Reconfigure
# message to indicate to the client whether the client responds with a
# renew message or an Information-request message.
class DHCP6OptReconfMsg(_DHCP6OptGuessPayload):       # RFC 8415 sect 21.19
    name = "DHCP6 Reconfigure Message Option"
    fields_desc = [ShortEnumField("optcode", 19, dhcp6opts),
                   ShortField("optlen", 1),
                   ByteEnumField("msgtype", 11, {5: "Renew Message",
                                                 11: "Information Request"})]


#    DHCPv6 Reconfigure Accept Option                               #

# A client uses the Reconfigure Accept option to announce to the
# server whether the client is willing to accept Recoonfigure
# messages, and a server uses this option to tell the client whether
# or not to accept Reconfigure messages. The default behavior in the
# absence of this option, means unwillingness to accept reconfigure
# messages, or instruction not to accept Reconfigure messages, for the
# client and server messages, respectively.
class DHCP6OptReconfAccept(_DHCP6OptGuessPayload):   # RFC 8415 sect 21.20
    name = "DHCP6 Reconfigure Accept Option"
    fields_desc = [ShortEnumField("optcode", 20, dhcp6opts),
                   ShortField("optlen", 0)]


class DHCP6OptSIPDomains(_DHCP6OptGuessPayload):  # RFC3319
    name = "DHCP6 Option - SIP Servers Domain Name List"
    fields_desc = [ShortEnumField("optcode", 21, dhcp6opts),
                   FieldLenField("optlen", None, length_of="sipdomains"),
                   DomainNameListField("sipdomains", [],
                                       length_from=lambda pkt: pkt.optlen)]


class DHCP6OptSIPServers(_DHCP6OptGuessPayload):  # RFC3319
    name = "DHCP6 Option - SIP Servers IPv6 Address List"
    fields_desc = [ShortEnumField("optcode", 22, dhcp6opts),
                   FieldLenField("optlen", None, length_of="sipservers"),
                   IP6ListField("sipservers", [],
                                length_from=lambda pkt: pkt.optlen)]


class DHCP6OptDNSServers(_DHCP6OptGuessPayload):  # RFC3646
    name = "DHCP6 Option - DNS Recursive Name Server"
    fields_desc = [ShortEnumField("optcode", 23, dhcp6opts),
                   FieldLenField("optlen", None, length_of="dnsservers"),
                   IP6ListField("dnsservers", [],
                                length_from=lambda pkt: pkt.optlen)]


class DHCP6OptDNSDomains(_DHCP6OptGuessPayload):  # RFC3646
    name = "DHCP6 Option - Domain Search List option"
    fields_desc = [ShortEnumField("optcode", 24, dhcp6opts),
                   FieldLenField("optlen", None, length_of="dnsdomains"),
                   DomainNameListField("dnsdomains", [],
                                       length_from=lambda pkt: pkt.optlen)]


class DHCP6OptIAPrefix(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.22
    name = "DHCP6 Option - IA Prefix option"
    fields_desc = [ShortEnumField("optcode", 26, dhcp6opts),
                   FieldLenField("optlen", None, length_of="iaprefopts",
                                 adjust=lambda pkt, x: x + 25),
                   IntEnumField("preflft", 0, {0xffffffff: "infinity"}),
                   IntEnumField("validlft", 0, {0xffffffff: "infinity"}),
                   ByteField("plen", 48),  # TODO: Challenge that default value
                                           # See RFC 8168
                   IP6Field("prefix", "2001:db8::"),  # At least, global and won't hurt  # noqa: E501
                   # We copy what wireshark does: read more dhcp6 options and
                   # expect failures
                   PacketListField("iaprefopts", [],
                                   _DHCP6OptGuessPayloadElt,
                                   length_from=lambda pkt: pkt.optlen - 25)]


class DHCP6OptIA_PD(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.21
    name = "DHCP6 Option - Identity Association for Prefix Delegation"
    fields_desc = [ShortEnumField("optcode", 25, dhcp6opts),
                   FieldLenField("optlen", None, length_of="iapdopt",
                                 fmt="!H", adjust=lambda pkt, x: x + 12),
                   XIntField("iaid", None),
                   IntField("T1", None),
                   IntField("T2", None),
                   PacketListField("iapdopt", [], _DHCP6OptGuessPayloadElt,
                                   length_from=lambda pkt: pkt.optlen - 12)]


class DHCP6OptNISServers(_DHCP6OptGuessPayload):  # RFC3898
    name = "DHCP6 Option - NIS Servers"
    fields_desc = [ShortEnumField("optcode", 27, dhcp6opts),
                   FieldLenField("optlen", None, length_of="nisservers"),
                   IP6ListField("nisservers", [],
                                length_from=lambda pkt: pkt.optlen)]


class DHCP6OptNISPServers(_DHCP6OptGuessPayload):  # RFC3898
    name = "DHCP6 Option - NIS+ Servers"
    fields_desc = [ShortEnumField("optcode", 28, dhcp6opts),
                   FieldLenField("optlen", None, length_of="nispservers"),
                   IP6ListField("nispservers", [],
                                length_from=lambda pkt: pkt.optlen)]


class DHCP6OptNISDomain(_DHCP6OptGuessPayload):  # RFC3898
    name = "DHCP6 Option - NIS Domain Name"
    fields_desc = [ShortEnumField("optcode", 29, dhcp6opts),
                   FieldLenField("optlen", None, length_of="nisdomain"),
                   DNSStrField("nisdomain", "",
                               length_from=lambda pkt: pkt.optlen)]


class DHCP6OptNISPDomain(_DHCP6OptGuessPayload):  # RFC3898
    name = "DHCP6 Option - NIS+ Domain Name"
    fields_desc = [ShortEnumField("optcode", 30, dhcp6opts),
                   FieldLenField("optlen", None, length_of="nispdomain"),
                   DNSStrField("nispdomain", "",
                               length_from=lambda pkt: pkt.optlen)]


class DHCP6OptSNTPServers(_DHCP6OptGuessPayload):  # RFC4075
    name = "DHCP6 option - SNTP Servers"
    fields_desc = [ShortEnumField("optcode", 31, dhcp6opts),
                   FieldLenField("optlen", None, length_of="sntpservers"),
                   IP6ListField("sntpservers", [],
                                length_from=lambda pkt: pkt.optlen)]


IRT_DEFAULT = 86400
IRT_MINIMUM = 600


class DHCP6OptInfoRefreshTime(_DHCP6OptGuessPayload):  # RFC4242
    name = "DHCP6 Option - Information Refresh Time"
    fields_desc = [ShortEnumField("optcode", 32, dhcp6opts),
                   ShortField("optlen", 4),
                   IntField("reftime", IRT_DEFAULT)]  # One day


class DHCP6OptBCMCSDomains(_DHCP6OptGuessPayload):  # RFC4280
    name = "DHCP6 Option - BCMCS Domain Name List"
    fields_desc = [ShortEnumField("optcode", 33, dhcp6opts),
                   FieldLenField("optlen", None, length_of="bcmcsdomains"),
                   DomainNameListField("bcmcsdomains", [],
                                       length_from=lambda pkt: pkt.optlen)]


class DHCP6OptBCMCSServers(_DHCP6OptGuessPayload):  # RFC4280
    name = "DHCP6 Option - BCMCS Addresses List"
    fields_desc = [ShortEnumField("optcode", 34, dhcp6opts),
                   FieldLenField("optlen", None, length_of="bcmcsservers"),
                   IP6ListField("bcmcsservers", [],
                                length_from=lambda pkt: pkt.optlen)]


_dhcp6_geoconf_what = {
    0: "DHCP server",
    1: "closest network element",
    2: "client"
}


class DHCP6OptGeoConfElement(Packet):
    fields_desc = [ByteField("CAtype", 0),
                   FieldLenField("CAlength", None, length_of="CAvalue"),
                   StrLenField("CAvalue", "",
                               length_from=lambda pkt: pkt.CAlength)]


class DHCP6OptGeoConf(_DHCP6OptGuessPayload):  # RFC 4776
    name = "DHCP6 Option - Civic Location"
    fields_desc = [ShortEnumField("optcode", 36, dhcp6opts),
                   FieldLenField("optlen", None, length_of="ca_elts",
                                 adjust=lambda x: x + 3),
                   ByteEnumField("what", 2, _dhcp6_geoconf_what),
                   StrFixedLenField("country_code", "FR", 2),
                   PacketListField("ca_elts", [], DHCP6OptGeoConfElement,
                                   length_from=lambda pkt: pkt.optlen - 3)]

# TODO: see if we encounter opaque values from vendor devices


class DHCP6OptRemoteID(_DHCP6OptGuessPayload):  # RFC4649
    name = "DHCP6 Option - Relay Agent Remote-ID"
    fields_desc = [ShortEnumField("optcode", 37, dhcp6opts),
                   FieldLenField("optlen", None, length_of="remoteid",
                                 adjust=lambda pkt, x: x + 4),
                   IntEnumField("enterprisenum", None,
                                IANA_ENTERPRISE_NUMBERS),
                   StrLenField("remoteid", "",
                               length_from=lambda pkt: pkt.optlen - 4)]


class DHCP6OptSubscriberID(_DHCP6OptGuessPayload):  # RFC4580
    name = "DHCP6 Option - Subscriber ID"
    fields_desc = [ShortEnumField("optcode", 38, dhcp6opts),
                   FieldLenField("optlen", None, length_of="subscriberid"),
                   # subscriberid default value should be at least 1 byte long
                   # but we don't really care
                   StrLenField("subscriberid", "",
                               length_from=lambda pkt: pkt.optlen)]


class DHCP6OptClientFQDN(_DHCP6OptGuessPayload):  # RFC4704
    name = "DHCP6 Option - Client FQDN"
    fields_desc = [ShortEnumField("optcode", 39, dhcp6opts),
                   FieldLenField("optlen", None, length_of="fqdn",
                                 adjust=lambda pkt, x: x + 1),
                   BitField("res", 0, 5),
                   FlagsField("flags", 0, 3, "SON"),
                   DNSStrField("fqdn", "",
                               length_from=lambda pkt: pkt.optlen - 1)]


class DHCP6OptPanaAuthAgent(_DHCP6OptGuessPayload):  # RFC5192
    name = "DHCP6 PANA Authentication Agent Option"
    fields_desc = [ShortEnumField("optcode", 40, dhcp6opts),
                   FieldLenField("optlen", None, length_of="paaaddr"),
                   IP6ListField("paaaddr", [],
                                length_from=lambda pkt: pkt.optlen)]


class DHCP6OptNewPOSIXTimeZone(_DHCP6OptGuessPayload):  # RFC4833
    name = "DHCP6 POSIX Timezone Option"
    fields_desc = [ShortEnumField("optcode", 41, dhcp6opts),
                   FieldLenField("optlen", None, length_of="optdata"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]


class DHCP6OptNewTZDBTimeZone(_DHCP6OptGuessPayload):  # RFC4833
    name = "DHCP6 TZDB Timezone Option"
    fields_desc = [ShortEnumField("optcode", 42, dhcp6opts),
                   FieldLenField("optlen", None, length_of="optdata"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]


class DHCP6OptRelayAgentERO(_DHCP6OptGuessPayload):  # RFC4994
    name = "DHCP6 Option - RelayRequest Option"
    fields_desc = [ShortEnumField("optcode", 43, dhcp6opts),
                   FieldLenField("optlen", None, length_of="reqopts",
                                 fmt="!H"),
                   _OptReqListField("reqopts", [23, 24],
                                    length_from=lambda pkt: pkt.optlen)]


class DHCP6OptLQClientLink(_DHCP6OptGuessPayload):  # RFC5007
    name = "DHCP6 Client Link Option"
    fields_desc = [ShortEnumField("optcode", 48, dhcp6opts),
                   FieldLenField("optlen", None, length_of="linkaddress"),
                   IP6ListField("linkaddress", [],
                                length_from=lambda pkt: pkt.optlen)]


class DHCP6OptBootFileUrl(_DHCP6OptGuessPayload):  # RFC5970
    name = "DHCP6 Boot File URL Option"
    fields_desc = [ShortEnumField("optcode", 59, dhcp6opts),
                   FieldLenField("optlen", None, length_of="optdata"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]


class DHCP6OptClientArchType(_DHCP6OptGuessPayload):  # RFC5970
    name = "DHCP6 Client System Architecture Type Option"
    fields_desc = [ShortEnumField("optcode", 61, dhcp6opts),
                   FieldLenField("optlen", None, length_of="archtypes",
                                 fmt="!H"),
                   FieldListField("archtypes", [],
                                  ShortField("archtype", 0),
                                  length_from=lambda pkt: pkt.optlen)]


class DHCP6OptClientNetworkInterId(_DHCP6OptGuessPayload):  # RFC5970
    name = "DHCP6 Client Network Interface Identifier Option"
    fields_desc = [ShortEnumField("optcode", 62, dhcp6opts),
                   ShortField("optlen", 3),
                   ByteField("iitype", 0),
                   ByteField("iimajor", 0),
                   ByteField("iiminor", 0)]


class DHCP6OptERPDomain(_DHCP6OptGuessPayload):  # RFC6440
    name = "DHCP6 Option - ERP Domain Name List"
    fields_desc = [ShortEnumField("optcode", 65, dhcp6opts),
                   FieldLenField("optlen", None, length_of="erpdomain"),
                   DomainNameListField("erpdomain", [],
                                       length_from=lambda pkt: pkt.optlen)]


class DHCP6OptRelaySuppliedOpt(_DHCP6OptGuessPayload):  # RFC6422
    name = "DHCP6 Relay-Supplied Options Option"
    fields_desc = [ShortEnumField("optcode", 66, dhcp6opts),
                   FieldLenField("optlen", None, length_of="relaysupplied",
                                 fmt="!H"),
                   PacketListField("relaysupplied", [],
                                   _DHCP6OptGuessPayloadElt,
                                   length_from=lambda pkt: pkt.optlen)]


# Virtual Subnet selection
class DHCP6OptVSS(_DHCP6OptGuessPayload):  # RFC6607
    name = "DHCP6 Option - Virtual Subnet Selection"
    fields_desc = [ShortEnumField("optcode", 68, dhcp6opts),
                   FieldLenField("optlen", None, length_of="data",
                                 adjust=lambda pkt, x: x + 1),
                   ByteField("type", 255),  # Default Global/default table
                   StrLenField("data", "",
                               length_from=lambda pkt: pkt.optlen)]


# "Client link-layer address type.  The link-layer type MUST be a valid hardware  # noqa: E501
# type assigned by the IANA, as described in [RFC0826]
class DHCP6OptClientLinkLayerAddr(_DHCP6OptGuessPayload):  # RFC6939
    name = "DHCP6 Option - Client Link Layer address"
    fields_desc = [ShortEnumField("optcode", 79, dhcp6opts),
                   FieldLenField("optlen", None, length_of="clladdr",
                                 adjust=lambda pkt, x: x + 2),
                   ShortField("lltype", 1),  # ethernet
                   _LLAddrField("clladdr", ETHER_ANY)]


#####################################################################
#                          DHCPv6 messages                          #
#####################################################################

# Some state parameters of the protocols that should probably be
# useful to have in the configuration (and keep up-to-date)
DHCP6RelayAgentUnicastAddr = ""
DHCP6RelayHopCount = ""
DHCP6ServerUnicastAddr = ""
DHCP6ClientUnicastAddr = ""
DHCP6ClientIA_TA = ""
DHCP6ClientIA_NA = ""
DHCP6ClientIAID = ""
T1 = ""  # Voir 2462
T2 = ""  # Voir 2462
DHCP6ServerDUID = ""
DHCP6CurrentTransactionID = ""  # devrait etre utilise pour matcher une
# reponse et mis a jour en mode client par une valeur aleatoire pour
# laquelle on attend un retour de la part d'un serveur.
DHCP6PrefVal = ""  # la valeur de preference a utiliser dans
# les options preference

# Emitted by :
# - server : ADVERTISE, REPLY, RECONFIGURE, RELAY-REPL (vers relay)
# - client : SOLICIT, REQUEST, CONFIRM, RENEW, REBIND, RELEASE, DECLINE,
#            INFORMATION REQUEST
# - relay  : RELAY-FORW (toward server)

#####################################################################
# DHCPv6 messages sent between Clients and Servers (types 1 to 11)
# Comme specifie en section 15.1 de la RFC 3315, les valeurs de
# transaction id sont selectionnees de maniere aleatoire par le client
# a chaque emission et doivent matcher dans les reponses faites par
# les clients


class DHCP6(_DHCP6OptGuessPayload):
    name = "DHCPv6 Generic Message"
    fields_desc = [ByteEnumField("msgtype", None, dhcp6types),
                   X3BytesField("trid", 0x000000)]
    overload_fields = {UDP: {"sport": 546, "dport": 547}}

    def hashret(self):
        return struct.pack("!I", self.trid)[1:4]

#    DHCPv6 Relay Message Option                                    #

# Relayed message is seen as a payload.


class DHCP6OptRelayMsg(_DHCP6OptGuessPayload):  # RFC 8415 sect 21.10
    name = "DHCP6 Relay Message Option"
    fields_desc = [ShortEnumField("optcode", 9, dhcp6opts),
                   FieldLenField("optlen", None, fmt="!H",
                                 length_of="message"),
                   PacketLenField("message", DHCP6(), _dhcp6_dispatcher,
                                  length_from=lambda p: p.optlen)]

#####################################################################
# Solicit Message : sect 17.1.1 RFC3315
# - sent by client
# - must include a client identifier option
# - the client may include IA options for any IAs to which it wants the
#   server to assign address
# - The client use IA_NA options to request the assignment of
#   non-temporary addresses and uses IA_TA options to request the
#   assignment of temporary addresses
# - The client should include an Option Request option to indicate the
#   options the client is interested in receiving (eventually
#   including hints)
# - The client includes a Reconfigure Accept option if is willing to
#   accept Reconfigure messages from the server.
# Le cas du send and reply est assez particulier car suivant la
# presence d'une option rapid commit dans le solicit, l'attente
# s'arrete au premier message de reponse recu ou alors apres un
# timeout. De la meme maniere, si un message Advertise arrive avec une
# valeur de preference de 255, il arrete l'attente et envoie une
# Request.
# - The client announces its intention to use DHCP authentication by
# including an Authentication option in its solicit message. The
# server selects a key for the client based on the client's DUID. The
# client and server use that key to authenticate all DHCP messages
# exchanged during the session


class DHCP6_Solicit(DHCP6):
    name = "DHCPv6 Solicit Message"
    msgtype = 1
    overload_fields = {UDP: {"sport": 546, "dport": 547}}

#####################################################################
# Advertise Message
# - sent by server
# - Includes a server identifier option
# - Includes a client identifier option
# - the client identifier option must match the client's DUID
# - transaction ID must match


class DHCP6_Advertise(DHCP6):
    name = "DHCPv6 Advertise Message"
    msgtype = 2
    overload_fields = {UDP: {"sport": 547, "dport": 546}}

    def answers(self, other):
        return (isinstance(other, DHCP6_Solicit) and
                other.msgtype == 1 and
                self.trid == other.trid)

#####################################################################
# Request Message
# - sent by clients
# - includes a server identifier option
# - the content of Server Identifier option must match server's DUID
# - includes a client identifier option
# - must include an ORO Option (even with hints) p40
# - can includes a reconfigure Accept option indicating whether or
#   not the client is willing to accept Reconfigure messages from
#   the server (p40)
# - When the server receives a Request message via unicast from a
# client to which the server has not sent a unicast option, the server
# discards the Request message and responds with a Reply message
# containing Status Code option with the value UseMulticast, a Server
# Identifier Option containing the server's DUID, the client
# Identifier option from the client message and no other option.


class DHCP6_Request(DHCP6):
    name = "DHCPv6 Request Message"
    msgtype = 3

#####################################################################
# Confirm Message
# - sent by clients
# - must include a client identifier option
# - When the server receives a Confirm Message, the server determines
# whether the addresses in the Confirm message are appropriate for the
# link to which the client is attached. cf p50


class DHCP6_Confirm(DHCP6):
    name = "DHCPv6 Confirm Message"
    msgtype = 4

#####################################################################
# Renew Message
# - sent by clients
# - must include a server identifier option
# - content of server identifier option must match the server's identifier
# - must include a client identifier option
# - the clients includes any IA assigned to the interface that may
# have moved to a new link, along with the addresses associated with
# those IAs in its confirm messages
# - When the server receives a Renew message that contains an IA
# option from a client, it locates the client's binding and verifies
# that the information in the IA from the client matches the
# information for that client. If the server cannot find a client
# entry for the IA the server returns the IA containing no addresses
# with a status code option est to NoBinding in the Reply message. cf
# p51 pour le reste.


class DHCP6_Renew(DHCP6):
    name = "DHCPv6 Renew Message"
    msgtype = 5

#####################################################################
# Rebind Message
# - sent by clients
# - must include a client identifier option
# cf p52


class DHCP6_Rebind(DHCP6):
    name = "DHCPv6 Rebind Message"
    msgtype = 6

#####################################################################
# Reply Message
# - sent by servers
# - the message must include a server identifier option
# - transaction-id field must match the value of original message
# The server includes a Rapid Commit option in the Reply message to
# indicate that the reply is in response to a solicit message
# - if the client receives a reply message with a Status code option
# with the value UseMulticast, the client records the receipt of the
# message and sends subsequent messages to the server through the
# interface on which the message was received using multicast. The
# client resends the original message using multicast
# - When the client receives a NotOnLink status from the server in
# response to a Confirm message, the client performs DHCP server
# solicitation as described in section 17 and client-initiated
# configuration as descrribed in section 18 (RFC 3315)
# - when the client receives a NotOnLink status from the server in
# response to a Request, the client can either re-issue the Request
# without specifying any addresses or restart the DHCP server
# discovery process.
# - the server must include a server identifier option containing the
# server's DUID in the Reply message


class DHCP6_Reply(DHCP6):
    name = "DHCPv6 Reply Message"
    msgtype = 7

    overload_fields = {UDP: {"sport": 547, "dport": 546}}

    def answers(self, other):

        types = (DHCP6_Solicit, DHCP6_InfoRequest, DHCP6_Confirm, DHCP6_Rebind,
                 DHCP6_Decline, DHCP6_Request, DHCP6_Release, DHCP6_Renew)

        return (isinstance(other, types) and self.trid == other.trid)

#####################################################################
# Release Message
# - sent by clients
# - must include a server identifier option
# cf p53


class DHCP6_Release(DHCP6):
    name = "DHCPv6 Release Message"
    msgtype = 8

#####################################################################
# Decline Message
# - sent by clients
# - must include a client identifier option
# - Server identifier option must match server identifier
# - The addresses to be declined must be included in the IAs. Any
# addresses for the IAs the client wishes to continue to use should
# not be in added to the IAs.
# - cf p54


class DHCP6_Decline(DHCP6):
    name = "DHCPv6 Decline Message"
    msgtype = 9

#####################################################################
# Reconfigure Message
# - sent by servers
# - must be unicast to the client
# - must include a server identifier option
# - must include a client identifier option that contains the client DUID
# - must contain a Reconfigure Message Option and the message type
#   must be a valid value
# - the server sets the transaction-id to 0
# - The server must use DHCP Authentication in the Reconfigure
# message. Autant dire que ca va pas etre le type de message qu'on va
# voir le plus souvent.


class DHCP6_Reconf(DHCP6):
    name = "DHCPv6 Reconfigure Message"
    msgtype = 10
    overload_fields = {UDP: {"sport": 547, "dport": 546}}


#####################################################################
# Information-Request Message
# - sent by clients when needs configuration information but no
# addresses.
# - client should include a client identifier option to identify
# itself. If it doesn't the server is not able to return client
# specific options or the server can choose to not respond to the
# message at all. The client must include a client identifier option
# if the message will be authenticated.
# - client must include an ORO of option she's interested in receiving
# (can include hints)

class DHCP6_InfoRequest(DHCP6):
    name = "DHCPv6 Information Request Message"
    msgtype = 11

#####################################################################
# sent between Relay Agents and Servers
#
# Normalement, doit inclure une option "Relay Message Option"
# peut en inclure d'autres.
# voir section 7.1 de la 3315

# Relay-Forward Message
# - sent by relay agents to servers
# If the relay agent relays messages to the All_DHCP_Servers multicast
# address or other multicast addresses, it sets the Hop Limit field to
# 32.


class DHCP6_RelayForward(_DHCP6OptGuessPayload, Packet):
    name = "DHCPv6 Relay Forward Message (Relay Agent/Server Message)"
    fields_desc = [ByteEnumField("msgtype", 12, dhcp6types),
                   ByteField("hopcount", None),
                   IP6Field("linkaddr", "::"),
                   IP6Field("peeraddr", "::")]
    overload_fields = {UDP: {"sport": 547, "dport": 547}}

    def hashret(self):  # we filter on peer address field
        return inet_pton(socket.AF_INET6, self.peeraddr)

#####################################################################
# sent between Relay Agents and Servers
# Normalement, doit inclure une option "Relay Message Option"
# peut en inclure d'autres.
# Les valeurs des champs hop-count, link-addr et peer-addr
# sont copiees du message Forward associe. POur le suivi de session.
# Pour le moment, comme decrit dans le commentaire, le hashret
# se limite au contenu du champ peer address.
# Voir section 7.2 de la 3315.

# Relay-Reply Message
# - sent by servers to relay agents
# - if the solicit message was received in a Relay-Forward message,
# the server constructs a relay-reply message with the Advertise
# message in the payload of a relay-message. cf page 37/101. Envoie de
# ce message en unicast au relay-agent. utilisation de l'adresse ip
# presente en ip source du paquet recu


class DHCP6_RelayReply(DHCP6_RelayForward):
    name = "DHCPv6 Relay Reply Message (Relay Agent/Server Message)"
    msgtype = 13

    def hashret(self):  # We filter on peer address field.
        return inet_pton(socket.AF_INET6, self.peeraddr)

    def answers(self, other):
        return (isinstance(other, DHCP6_RelayForward) and
                self.hopcount == other.hopcount and
                self.linkaddr == other.linkaddr and
                self.peeraddr == other.peeraddr)


bind_bottom_up(UDP, _dhcp6_dispatcher, {"dport": 547})
bind_bottom_up(UDP, _dhcp6_dispatcher, {"dport": 546})


class DHCPv6_am(AnsweringMachine):
    function_name = "dhcp6d"
    filter = "udp and port 546 and port 547"
    send_function = staticmethod(send)

    def usage(self):
        msg = """
DHCPv6_am.parse_options( dns="2001:500::1035", domain="localdomain, local",
        duid=None, iface=conf.iface, advpref=255, sntpservers=None,
        sipdomains=None, sipservers=None,
        nisdomain=None, nisservers=None,
        nispdomain=None, nispservers=None,
        bcmcsdomains=None, bcmcsservers=None)

   debug : When set, additional debugging information is printed.

   duid   : some DUID class (DUID_LLT, DUID_LL or DUID_EN). If none
            is provided a DUID_LLT is constructed based on the MAC
            address of the sending interface and launch time of dhcp6d
            answering machine.

   iface : the interface to listen/reply on if you do not want to use
           conf.iface.

   advpref : Value in [0,255] given to Advertise preference field.
             By default, 255 is used. Be aware that this specific
             value makes clients stops waiting for further Advertise
             messages from other servers.

   dns : list of recursive DNS servers addresses (as a string or list).
         By default, it is set empty and the associated DHCP6OptDNSServers
         option is inactive. See RFC 3646 for details.
   domain : a list of DNS search domain (as a string or list). By default,
         it is empty and the associated DHCP6OptDomains option is inactive.
         See RFC 3646 for details.

   sntpservers : a list of SNTP servers IPv6 addresses. By default,
         it is empty and the associated DHCP6OptSNTPServers option
         is inactive.

   sipdomains : a list of SIP domains. By default, it is empty and the
         associated DHCP6OptSIPDomains option is inactive. See RFC 3319
         for details.
   sipservers : a list of SIP servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptSIPDomains option is inactive.
         See RFC 3319 for details.

   nisdomain : a list of NIS domains. By default, it is empty and the
         associated DHCP6OptNISDomains option is inactive. See RFC 3898
         for details. See RFC 3646 for details.
   nisservers : a list of NIS servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptNISServers option is inactive.
         See RFC 3646 for details.

   nispdomain : a list of NIS+ domains. By default, it is empty and the
         associated DHCP6OptNISPDomains option is inactive. See RFC 3898
         for details.
   nispservers : a list of NIS+ servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptNISServers option is inactive.
         See RFC 3898 for details.

   bcmcsdomain : a list of BCMCS domains. By default, it is empty and the
         associated DHCP6OptBCMCSDomains option is inactive. See RFC 4280
         for details.
   bcmcsservers : a list of BCMCS servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptBCMCSServers option is inactive.
         See RFC 4280 for details.

   If you have a need for others, just ask ... or provide a patch."""
        print(msg)

    def parse_options(self, dns="2001:500::1035", domain="localdomain, local",
                      startip="2001:db8::1", endip="2001:db8::20", duid=None,
                      sntpservers=None, sipdomains=None, sipservers=None,
                      nisdomain=None, nisservers=None, nispdomain=None,
                      nispservers=None, bcmcsservers=None, bcmcsdomains=None,
                      iface=None, debug=0, advpref=255):
        def norm_list(val, param_name):
            if val is None:
                return None
            if isinstance(val, list):
                return val
            elif isinstance(val, str):
                tmp_len = val.split(',')
                return [x.strip() for x in tmp_len]
            else:
                print("Bad '%s' parameter provided." % param_name)
                self.usage()
                return -1

        if iface is None:
            iface = conf.iface

        self.debug = debug

        # Dictionary of provided DHCPv6 options, keyed by option type
        self.dhcpv6_options = {}

        for o in [(dns, "dns", 23, lambda x: DHCP6OptDNSServers(dnsservers=x)),
                  (domain, "domain", 24, lambda x: DHCP6OptDNSDomains(dnsdomains=x)),  # noqa: E501
                  (sntpservers, "sntpservers", 31, lambda x: DHCP6OptSNTPServers(sntpservers=x)),  # noqa: E501
                  (sipservers, "sipservers", 22, lambda x: DHCP6OptSIPServers(sipservers=x)),  # noqa: E501
                  (sipdomains, "sipdomains", 21, lambda x: DHCP6OptSIPDomains(sipdomains=x)),  # noqa: E501
                  (nisservers, "nisservers", 27, lambda x: DHCP6OptNISServers(nisservers=x)),  # noqa: E501
                  (nisdomain, "nisdomain", 29, lambda x: DHCP6OptNISDomain(nisdomain=(x + [""])[0])),  # noqa: E501
                  (nispservers, "nispservers", 28, lambda x: DHCP6OptNISPServers(nispservers=x)),  # noqa: E501
                  (nispdomain, "nispdomain", 30, lambda x: DHCP6OptNISPDomain(nispdomain=(x + [""])[0])),  # noqa: E501
                  (bcmcsservers, "bcmcsservers", 33, lambda x: DHCP6OptBCMCSServers(bcmcsservers=x)),  # noqa: E501
                  (bcmcsdomains, "bcmcsdomains", 34, lambda x: DHCP6OptBCMCSDomains(bcmcsdomains=x))]:  # noqa: E501

            opt = norm_list(o[0], o[1])
            if opt == -1:  # Usage() was triggered
                return False
            elif opt is None:  # We won't return that option
                pass
            else:
                self.dhcpv6_options[o[2]] = o[3](opt)

        if self.debug:
            print("\n[+] List of active DHCPv6 options:")
            opts = sorted(self.dhcpv6_options)
            for i in opts:
                print("    %d: %s" % (i, repr(self.dhcpv6_options[i])))

        # Preference value used in Advertise.
        self.advpref = advpref

        # IP Pool
        self.startip = startip
        self.endip = endip
        # XXX TODO Check IPs are in same subnet

        ####
        # The interface we are listening/replying on
        self.iface = iface

        ####
        # Generate a server DUID
        if duid is not None:
            self.duid = duid
        else:
            # Timeval
            epoch = (2000, 1, 1, 0, 0, 0, 5, 1, 0)
            delta = time.mktime(epoch) - EPOCH
            timeval = time.time() - delta

            # Mac Address
            rawmac = get_if_raw_hwaddr(iface)[1]
            mac = ":".join("%.02x" % orb(x) for x in rawmac)

            self.duid = DUID_LLT(timeval=timeval, lladdr=mac)

        if self.debug:
            print("\n[+] Our server DUID:")
            self.duid.show(label_lvl=" " * 4)

        ####
        # Find the source address we will use
        self.src_addr = None
        try:
            addr = next(x for x in in6_getifaddr() if x[2] == iface and in6_islladdr(x[0]))  # noqa: E501
        except (StopIteration, RuntimeError):
            warning("Unable to get a Link-Local address")
            return
        else:
            self.src_addr = addr[0]

        ####
        # Our leases
        self.leases = {}

        if self.debug:
            print("\n[+] Starting DHCPv6 service on %s:" % self.iface)

    def is_request(self, p):
        if IPv6 not in p:
            return False

        src = p[IPv6].src

        p = p[IPv6].payload
        if not isinstance(p, UDP) or p.sport != 546 or p.dport != 547:
            return False

        p = p.payload
        if not isinstance(p, DHCP6):
            return False

        # Message we considered client messages :
        # Solicit (1), Request (3), Confirm (4), Renew (5), Rebind (6)
        # Decline (9), Release (8), Information-request (11),
        if not (p.msgtype in [1, 3, 4, 5, 6, 8, 9, 11]):
            return False

        # Message validation following section 15 of RFC 3315

        if ((p.msgtype == 1) or  # Solicit
            (p.msgtype == 6) or  # Rebind
                (p.msgtype == 4)):  # Confirm
            if ((DHCP6OptClientId not in p) or
                    DHCP6OptServerId in p):
                return False

            if (p.msgtype == 6 or  # Rebind
                    p.msgtype == 4):  # Confirm
                # XXX We do not reply to Confirm or Rebind as we
                # XXX do not support address assignment
                return False

        elif (p.msgtype == 3 or  # Request
              p.msgtype == 5 or  # Renew
              p.msgtype == 8):  # Release

            # Both options must be present
            if ((DHCP6OptServerId not in p) or
                    (DHCP6OptClientId not in p)):
                return False
            # provided server DUID must match ours
            duid = p[DHCP6OptServerId].duid
            if not isinstance(duid, type(self.duid)):
                return False
            if raw(duid) != raw(self.duid):
                return False

            if (p.msgtype == 5 or  # Renew
                    p.msgtype == 8):  # Release
                # XXX We do not reply to Renew or Release as we
                # XXX do not support address assignment
                return False

        elif p.msgtype == 9:  # Decline
            # XXX We should check if we are tracking that client
            if not self.debug:
                return False

            bo = Color.bold
            g = Color.green + bo
            b = Color.blue + bo
            n = Color.normal
            r = Color.red

            vendor = in6_addrtovendor(src)
            if (vendor and vendor != "UNKNOWN"):
                vendor = " [" + b + vendor + n + "]"
            else:
                vendor = ""
            src = bo + src + n

            it = p
            addrs = []
            while it:
                lst = []
                if isinstance(it, DHCP6OptIA_NA):
                    lst = it.ianaopts
                elif isinstance(it, DHCP6OptIA_TA):
                    lst = it.iataopts

                addrs += [x.addr for x in lst if isinstance(x, DHCP6OptIAAddress)]  # noqa: E501
                it = it.payload

            addrs = [bo + x + n for x in addrs]
            if self.debug:
                msg = r + "[DEBUG]" + n + " Received " + g + "Decline" + n
                msg += " from " + bo + src + vendor + " for "
                msg += ", ".join(addrs) + n
                print(msg)

            # See RFC 3315 sect 18.1.7

            # Sent by a client to warn us she has determined
            # one or more addresses assigned to her is already
            # used on the link.
            # We should simply log that fact. No messaged should
            # be sent in return.

            # - Message must include a Server identifier option
            # - the content of the Server identifier option must
            #   match the server's identifier
            # - the message must include a Client Identifier option
            return False

        elif p.msgtype == 11:  # Information-Request
            if DHCP6OptServerId in p:
                duid = p[DHCP6OptServerId].duid
                if not isinstance(duid, type(self.duid)):
                    return False
                if raw(duid) != raw(self.duid):
                    return False
            if ((DHCP6OptIA_NA in p) or
                (DHCP6OptIA_TA in p) or
                    (DHCP6OptIA_PD in p)):
                return False
        else:
            return False

        return True

    def print_reply(self, req, reply):
        def norm(s):
            if s.startswith("DHCPv6 "):
                s = s[7:]
            if s.endswith(" Message"):
                s = s[:-8]
            return s

        if reply is None:
            return

        bo = Color.bold
        g = Color.green + bo
        b = Color.blue + bo
        n = Color.normal
        reqtype = g + norm(req.getlayer(UDP).payload.name) + n
        reqsrc = req.getlayer(IPv6).src
        vendor = in6_addrtovendor(reqsrc)
        if (vendor and vendor != "UNKNOWN"):
            vendor = " [" + b + vendor + n + "]"
        else:
            vendor = ""
        reqsrc = bo + reqsrc + n
        reptype = g + norm(reply.getlayer(UDP).payload.name) + n

        print("Sent %s answering to %s from %s%s" % (reptype, reqtype, reqsrc, vendor))  # noqa: E501

    def make_reply(self, req):
        p = req[IPv6]
        req_src = p.src

        p = p.payload.payload

        msgtype = p.msgtype
        trid = p.trid

        def _include_options(query, answer):
            """
            Include options from the DHCPv6 query
            """

            # See which options should be included
            reqopts = []
            if query.haslayer(DHCP6OptOptReq):  # add only asked ones
                reqopts = query[DHCP6OptOptReq].reqopts
                for o, opt in six.iteritems(self.dhcpv6_options):
                    if o in reqopts:
                        answer /= opt
            else:
                # advertise everything we have available
                # Should not happen has clients MUST include
                # and ORO in requests (sec 18.1.1)   -- arno
                for o, opt in six.iteritems(self.dhcpv6_options):
                    answer /= opt

        if msgtype == 1:  # SOLICIT (See Sect 17.1 and 17.2 of RFC 3315)

            # XXX We don't support address or prefix assignment
            # XXX We also do not support relay function           --arno

            client_duid = p[DHCP6OptClientId].duid
            resp = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)

            if p.haslayer(DHCP6OptRapidCommit):
                # construct a Reply packet
                resp /= DHCP6_Reply(trid=trid)
                resp /= DHCP6OptRapidCommit()  # See 17.1.2
                resp /= DHCP6OptServerId(duid=self.duid)
                resp /= DHCP6OptClientId(duid=client_duid)

            else:  # No Rapid Commit in the packet. Reply with an Advertise

                if (p.haslayer(DHCP6OptIA_NA) or
                        p.haslayer(DHCP6OptIA_TA)):
                    # XXX We don't assign addresses at the moment
                    msg = "Scapy6 dhcp6d does not support address assignment"
                    resp /= DHCP6_Advertise(trid=trid)
                    resp /= DHCP6OptStatusCode(statuscode=2, statusmsg=msg)
                    resp /= DHCP6OptServerId(duid=self.duid)
                    resp /= DHCP6OptClientId(duid=client_duid)

                elif p.haslayer(DHCP6OptIA_PD):
                    # XXX We don't assign prefixes at the moment
                    msg = "Scapy6 dhcp6d does not support prefix assignment"
                    resp /= DHCP6_Advertise(trid=trid)
                    resp /= DHCP6OptStatusCode(statuscode=6, statusmsg=msg)
                    resp /= DHCP6OptServerId(duid=self.duid)
                    resp /= DHCP6OptClientId(duid=client_duid)

                else:  # Usual case, no request for prefixes or addresse
                    resp /= DHCP6_Advertise(trid=trid)
                    resp /= DHCP6OptPref(prefval=self.advpref)
                    resp /= DHCP6OptServerId(duid=self.duid)
                    resp /= DHCP6OptClientId(duid=client_duid)
                    resp /= DHCP6OptReconfAccept()

                    _include_options(p, resp)

            return resp

        elif msgtype == 3:  # REQUEST (INFO-REQUEST is further below)
            client_duid = p[DHCP6OptClientId].duid
            resp = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            resp /= DHCP6_Solicit(trid=trid)
            resp /= DHCP6OptServerId(duid=self.duid)
            resp /= DHCP6OptClientId(duid=client_duid)

            _include_options(p, resp)

            return resp

        elif msgtype == 4:  # CONFIRM
            # see Sect 18.1.2

            # Client want to check if addresses it was assigned
            # are still appropriate

            # Server must discard any Confirm messages that
            # do not include a Client Identifier option OR
            # THAT DO INCLUDE a Server Identifier Option

            # XXX we must discard the SOLICIT if it is received with
            #     a unicast destination address

            pass

        elif msgtype == 5:  # RENEW
            # see Sect 18.1.3

            # Clients want to extend lifetime of assigned addresses
            # and update configuration parameters. This message is sent
            # specifically to the server that provided her the info

            # - Received message must include a Server Identifier
            #   option.
            # - the content of server identifier option must match
            #   the server's identifier.
            # - the message must include a Client identifier option

            pass

        elif msgtype == 6:  # REBIND
            # see Sect 18.1.4

            # Same purpose as the Renew message but sent to any
            # available server after he received no response
            # to its previous Renew message.

            # - Message must include a Client Identifier Option
            # - Message can't include a Server identifier option

            # XXX we must discard the SOLICIT if it is received with
            #     a unicast destination address

            pass

        elif msgtype == 8:  # RELEASE
            # See RFC 3315 section 18.1.6

            # Message is sent to the server to indicate that
            # she will no longer use the addresses that was assigned
            # We should parse the message and verify our dictionary
            # to log that fact.

            # - The message must include a server identifier option
            # - The content of the Server Identifier option must
            #   match the server's identifier
            # - the message must include a Client Identifier option

            pass

        elif msgtype == 9:  # DECLINE
            # See RFC 3315 section 18.1.7
            pass

        elif msgtype == 11:  # INFO-REQUEST
            client_duid = None
            if not p.haslayer(DHCP6OptClientId):
                if self.debug:
                    warning("Received Info Request message without Client Id option")  # noqa: E501
            else:
                client_duid = p[DHCP6OptClientId].duid

            resp = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            resp /= DHCP6_Reply(trid=trid)
            resp /= DHCP6OptServerId(duid=self.duid)

            if client_duid:
                resp /= DHCP6OptClientId(duid=client_duid)

            # Stack requested options if available
            for o, opt in six.iteritems(self.dhcpv6_options):
                resp /= opt

            return resp

        else:
            # what else ?
            pass

        # - We won't support reemission
        # - We won't support relay role, nor relay forwarded messages
        #   at the beginning
