# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Extensible Authentication Protocol (EAP)
"""

from __future__ import absolute_import
from __future__ import print_function

import struct

from scapy.fields import BitField, ByteField, XByteField,\
    ShortField, IntField, XIntField, ByteEnumField, StrLenField, XStrField,\
    XStrLenField, XStrFixedLenField, LenField, FieldLenField, FieldListField,\
    PacketField, PacketListField, ConditionalField, PadField
from scapy.packet import Packet, Padding, bind_layers
from scapy.layers.l2 import SourceMACField, Ether, CookedLinux, GRE, SNAP
from scapy.config import conf
from scapy.compat import orb, chb

#
# EAPOL
#

#########################################################################
#
# EAPOL protocol version
# IEEE Std 802.1X-2010 - Section 11.3.1
#########################################################################
#

eapol_versions = {
    0x1: "802.1X-2001",
    0x2: "802.1X-2004",
    0x3: "802.1X-2010",
}

#########################################################################
#
# EAPOL Packet Types
# IEEE Std 802.1X-2010 - Table 11.3
#########################################################################
#

eapol_types = {
    0x0: "EAP-Packet",  # "EAPOL-EAP" in 801.1X-2010
    0x1: "EAPOL-Start",
    0x2: "EAPOL-Logoff",
    0x3: "EAPOL-Key",
    0x4: "EAPOL-Encapsulated-ASF-Alert",
    0x5: "EAPOL-MKA",
    0x6: "EAPOL-Announcement (Generic)",
    0x7: "EAPOL-Announcement (Specific)",
    0x8: "EAPOL-Announcement-Req"
}


class EAPOL(Packet):
    """
    EAPOL - IEEE Std 802.1X-2010
    """

    name = "EAPOL"
    fields_desc = [
        ByteEnumField("version", 1, eapol_versions),
        ByteEnumField("type", 0, eapol_types),
        LenField("len", None, "H")
    ]

    EAP_PACKET = 0
    START = 1
    LOGOFF = 2
    KEY = 3
    ASF = 4

    def extract_padding(self, s):
        tmp_len = self.len
        return s[:tmp_len], s[tmp_len:]

    def hashret(self):
        return chb(self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, EAPOL):
            if ((self.type == self.EAP_PACKET) and
                    (other.type == self.EAP_PACKET)):
                return self.payload.answers(other.payload)
        return 0

    def mysummary(self):
        return self.sprintf("EAPOL %EAPOL.type%")


#
# EAP
#


#########################################################################
#
# EAP methods types
# http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4
#########################################################################
#

eap_types = {
    0: "Reserved",
    1: "Identity",
    2: "Notification",
    3: "Legacy Nak",
    4: "MD5-Challenge",
    5: "One-Time Password (OTP)",
    6: "Generic Token Card (GTC)",
    7: "Allocated - RFC3748",
    8: "Allocated - RFC3748",
    9: "RSA Public Key Authentication",
    10: "DSS Unilateral",
    11: "KEA",
    12: "KEA-VALIDATE",
    13: "EAP-TLS",
    14: "Defender Token (AXENT)",
    15: "RSA Security SecurID EAP",
    16: "Arcot Systems EAP",
    17: "EAP-Cisco Wireless",
    18: "GSM Subscriber Identity Modules (EAP-SIM)",
    19: "SRP-SHA1",
    20: "Unassigned",
    21: "EAP-TTLS",
    22: "Remote Access Service",
    23: "EAP-AKA Authentication",
    24: "EAP-3Com Wireless",
    25: "PEAP",
    26: "MS-EAP-Authentication",
    27: "Mutual Authentication w/Key Exchange (MAKE)",
    28: "CRYPTOCard",
    29: "EAP-MSCHAP-V2",
    30: "DynamID",
    31: "Rob EAP",
    32: "Protected One-Time Password",
    33: "MS-Authentication-TLV",
    34: "SentriNET",
    35: "EAP-Actiontec Wireless",
    36: "Cogent Systems Biometrics Authentication EAP",
    37: "AirFortress EAP",
    38: "EAP-HTTP Digest",
    39: "SecureSuite EAP",
    40: "DeviceConnect EAP",
    41: "EAP-SPEKE",
    42: "EAP-MOBAC",
    43: "EAP-FAST",
    44: "ZoneLabs EAP (ZLXEAP)",
    45: "EAP-Link",
    46: "EAP-PAX",
    47: "EAP-PSK",
    48: "EAP-SAKE",
    49: "EAP-IKEv2",
    50: "EAP-AKA",
    51: "EAP-GPSK",
    52: "EAP-pwd",
    53: "EAP-EKE Version 1",
    54: "EAP Method Type for PT-EAP",
    55: "TEAP",
    254: "Reserved for the Expanded Type",
    255: "Experimental",
}


#########################################################################
#
# EAP codes
# http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-1
#########################################################################
#

eap_codes = {
    1: "Request",
    2: "Response",
    3: "Success",
    4: "Failure",
    5: "Initiate",
    6: "Finish"
}


class EAP(Packet):
    """
    RFC 3748 - Extensible Authentication Protocol (EAP)
    """

    name = "EAP"
    fields_desc = [
        ByteEnumField("code", 4, eap_codes),
        ByteField("id", 0),
        ShortField("len", None),
        ConditionalField(ByteEnumField("type", 0, eap_types),
                         lambda pkt:pkt.code not in [
                             EAP.SUCCESS, EAP.FAILURE]),
        ConditionalField(
            FieldListField("desired_auth_types", [],
                           ByteEnumField("auth_type", 0, eap_types),
                           length_from=lambda pkt: pkt.len - 4),
            lambda pkt:pkt.code == EAP.RESPONSE and pkt.type == 3),
        ConditionalField(
            StrLenField("identity", '', length_from=lambda pkt: pkt.len - 5),
            lambda pkt: pkt.code == EAP.RESPONSE and hasattr(pkt, 'type') and pkt.type == 1),  # noqa: E501
        ConditionalField(
            StrLenField("message", '', length_from=lambda pkt: pkt.len - 5),
            lambda pkt: pkt.code == EAP.REQUEST and hasattr(pkt, 'type') and pkt.type == 1)  # noqa: E501
    ]

    #########################################################################
    #
    # EAP codes
    # http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-1
    #########################################################################
    #

    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    INITIATE = 5
    FINISH = 6

    registered_methods = {}

    @classmethod
    def register_variant(cls):
        cls.registered_methods[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            c = orb(_pkt[0])
            if c in [1, 2] and len(_pkt) >= 5:
                t = orb(_pkt[4])
                return cls.registered_methods.get(t, cls)
        return cls

    def answers(self, other):
        if isinstance(other, EAP):
            if self.code == self.REQUEST:
                return 0
            elif self.code == self.RESPONSE:
                if ((other.code == self.REQUEST) and
                        (other.type == self.type)):
                    return 1
            elif other.code == self.RESPONSE:
                return 1
        return 0

    def mysummary(self):
        summary_str = "EAP %{eap_class}.code% %{eap_class}.type%".format(
            eap_class=self.__class__.__name__
        )
        if self.type == 1 and self.code == EAP.RESPONSE:
            summary_str += " %{eap_class}.identity%".format(
                eap_class=self.__class__.__name__
            )
        return self.sprintf(summary_str)

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) + len(pay)
            tmp_p = p[:2] + chb((tmp_len >> 8) & 0xff) + chb(tmp_len & 0xff)
            p = tmp_p + p[4:]
        return p + pay

    def guess_payload_class(self, _):
        return Padding


class EAP_MD5(EAP):
    """
    RFC 3748 - "Extensible Authentication Protocol (EAP)"
    """

    name = "EAP-MD5"
    match_subclass = True
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="optional_name",
                      adjust=lambda p, x: x + 6 + (p.value_size or 0)),
        ByteEnumField("type", 4, eap_types),
        FieldLenField("value_size", None, fmt="B", length_of="value"),
        XStrLenField("value", '', length_from=lambda p: p.value_size),
        XStrLenField("optional_name", '', length_from=lambda p: 0 if p.len is None or p.value_size is None else (p.len - p.value_size - 6))  # noqa: E501
    ]


class EAP_TLS(EAP):
    """
    RFC 5216 - "The EAP-TLS Authentication Protocol"
    """

    name = "EAP-TLS"
    match_subclass = True
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="tls_data",
                      adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
        ByteEnumField("type", 13, eap_types),
        BitField('L', 0, 1),
        BitField('M', 0, 1),
        BitField('S', 0, 1),
        BitField('reserved', 0, 5),
        ConditionalField(IntField('tls_message_len', 0), lambda pkt: pkt.L == 1),  # noqa: E501
        XStrLenField('tls_data', '', length_from=lambda pkt: 0 if pkt.len is None else pkt.len - (6 + 4 * pkt.L))  # noqa: E501
    ]


class EAP_TTLS(EAP):
    """
    RFC 5281 - "Extensible Authentication Protocol Tunneled Transport Layer
    Security Authenticated Protocol Version 0 (EAP-TTLSv0)"
    """

    name = "EAP-TTLS"
    match_subclass = True
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="data",
                      adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
        ByteEnumField("type", 21, eap_types),
        BitField("L", 0, 1),
        BitField("M", 0, 1),
        BitField("S", 0, 1),
        BitField("reserved", 0, 2),
        BitField("version", 0, 3),
        ConditionalField(IntField("message_len", 0), lambda pkt: pkt.L == 1),
        XStrLenField("data", "", length_from=lambda pkt: 0 if pkt.len is None else pkt.len - (6 + 4 * pkt.L))  # noqa: E501
    ]


class EAP_PEAP(EAP):
    """
    draft-josefsson-pppext-eap-tls-eap-05.txt - "Protected EAP Protocol (PEAP)"
    """

    name = "PEAP"
    match_subclass = True
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="tls_data",
                      adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
        ByteEnumField("type", 25, eap_types),
        BitField("L", 0, 1),
        BitField("M", 0, 1),
        BitField("S", 0, 1),
        BitField("reserved", 0, 3),
        BitField("version", 1, 2),
        ConditionalField(IntField("tls_message_len", 0), lambda pkt: pkt.L == 1),  # noqa: E501
        XStrLenField("tls_data", "", length_from=lambda pkt: 0 if pkt.len is None else pkt.len - (6 + 4 * pkt.L))  # noqa: E501
    ]


class EAP_FAST(EAP):
    """
    RFC 4851 - "The Flexible Authentication via Secure Tunneling
    Extensible Authentication Protocol Method (EAP-FAST)"
    """

    name = "EAP-FAST"
    match_subclass = True
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="data",
                      adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
        ByteEnumField("type", 43, eap_types),
        BitField('L', 0, 1),
        BitField('M', 0, 1),
        BitField('S', 0, 1),
        BitField('reserved', 0, 2),
        BitField('version', 0, 3),
        ConditionalField(IntField('message_len', 0), lambda pkt: pkt.L == 1),
        XStrLenField('data', '', length_from=lambda pkt: 0 if pkt.len is None else pkt.len - (6 + 4 * pkt.L))  # noqa: E501
    ]


class LEAP(EAP):
    """
    Cisco LEAP (Lightweight EAP)
    https://freeradius.org/rfc/leap.txt
    """

    name = "Cisco LEAP"
    match_subclass = True
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        ShortField("len", None),
        ByteEnumField("type", 17, eap_types),
        ByteField('version', 1),
        XByteField('unused', 0),
        FieldLenField("count", None, "challenge_response", "B", adjust=lambda p, x: len(p.challenge_response)),  # noqa: E501
        XStrLenField("challenge_response", "", length_from=lambda p: 0 or p.count),  # noqa: E501
        StrLenField("username", "", length_from=lambda p: p.len - (8 + (0 or p.count)))  # noqa: E501
    ]


#############################################################################
# IEEE 802.1X-2010 - MACsec Key Agreement (MKA) protocol
#############################################################################

#########################################################################
#
# IEEE 802.1X-2010 standard
# Section 11.11.1
#########################################################################
#

_parameter_set_types = {
    1: "Live Peer List",
    2: "Potential Peer List",
    3: "MACsec SAK Use",
    4: "Distributed SAK",
    5: "Distributed CAK",
    6: "KMD",
    7: "Announcement",
    255: "ICV Indicator"
}


# Used by MKAParamSet::dispatch_hook() to instantiate the appropriate class
_param_set_cls = {
    1: "MKALivePeerListParamSet",
    2: "MKAPotentialPeerListParamSet",
    3: "MKASAKUseParamSet",
    4: "MKADistributedSAKParamSet",
    255: "MKAICVSet",
}


class MACsecSCI(Packet):
    """
    Secure Channel Identifier.
    """

    #########################################################################
    #
    # IEEE 802.1AE-2006 standard
    # Section 9.9
    #########################################################################
    #

    name = "SCI"
    fields_desc = [
        SourceMACField("system_identifier"),
        ShortField("port_identifier", 0)
    ]

    def extract_padding(self, s):
        return "", s


class MKAParamSet(Packet):
    """
    Class from which every parameter set class inherits (except
    MKABasicParamSet, which has no "Parameter set type" field, and must
    come first in the list of parameter sets).
    """

    MACSEC_DEFAULT_ICV_LEN = 16
    EAPOL_MKA_DEFAULT_KEY_WRAP_LEN = 24

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right parameter set class.
        """

        cls = conf.raw_layer
        if _pkt is not None:
            ptype = orb(_pkt[0])
            return globals().get(_param_set_cls.get(ptype), conf.raw_layer)

        return cls


class MKABasicParamSet(Packet):
    """
    Basic Parameter Set (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "Basic Parameter Set"
    fields_desc = [
        ByteField("mka_version_id", 0),
        ByteField("key_server_priority", 0),
        BitField("key_server", 0, 1),
        BitField("macsec_desired", 0, 1),
        BitField("macsec_capability", 0, 2),
        BitField("param_set_body_len", 0, 12),
        PacketField("SCI", MACsecSCI(), MACsecSCI),
        XStrFixedLenField("actor_member_id", "", length=12),
        XIntField("actor_message_number", 0),
        XIntField("algorithm_agility", 0),
        PadField(
            XStrLenField(
                "cak_name",
                "",
                length_from=lambda pkt: (pkt.param_set_body_len - 28)
            ),
            4,
            padwith=b"\x00"
        )
    ]

    def extract_padding(self, s):
        return "", s


class MKAPeerListTuple(Packet):
    """
    Live / Potential Peer List parameter sets tuples (802.1X-2010, section 11.11).  # noqa: E501
    """

    name = "Peer List Tuple"
    fields_desc = [
        XStrFixedLenField("member_id", "", length=12),
        XStrFixedLenField("message_number", "", length=4),
    ]


class MKALivePeerListParamSet(MKAParamSet):
    """
    Live Peer List parameter sets (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "Live Peer List Parameter Set"
    fields_desc = [
        PadField(
            ByteEnumField(
                "param_set_type",
                1,
                _parameter_set_types
            ),
            2,
            padwith=b"\x00"
        ),
        ShortField("param_set_body_len", 0),
        PacketListField("member_id_message_num", [], MKAPeerListTuple)
    ]


class MKAPotentialPeerListParamSet(MKAParamSet):
    """
    Potential Peer List parameter sets (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "Potential Peer List Parameter Set"
    fields_desc = [
        PadField(
            ByteEnumField(
                "param_set_type",
                2,
                _parameter_set_types
            ),
            2,
            padwith=b"\x00"
        ),
        ShortField("param_set_body_len", 0),
        PacketListField("member_id_message_num", [], MKAPeerListTuple)
    ]


class MKASAKUseParamSet(MKAParamSet):
    """
    SAK Use Parameter Set (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "SAK Use Parameter Set"
    fields_desc = [
        ByteEnumField("param_set_type", 3, _parameter_set_types),
        BitField("latest_key_an", 0, 2),
        BitField("latest_key_tx", 0, 1),
        BitField("latest_key_rx", 0, 1),
        BitField("old_key_an", 0, 2),
        BitField("old_key_tx", 0, 1),
        BitField("old_key_rx", 0, 1),
        BitField("plain_tx", 0, 1),
        BitField("plain_rx", 0, 1),
        BitField("X", 0, 1),
        BitField("delay_protect", 0, 1),
        BitField("param_set_body_len", 0, 12),
        XStrFixedLenField("latest_key_key_server_member_id", "", length=12),
        XStrFixedLenField("latest_key_key_number", "", length=4),
        XStrFixedLenField("latest_key_lowest_acceptable_pn", "", length=4),
        XStrFixedLenField("old_key_key_server_member_id", "", length=12),
        XStrFixedLenField("old_key_key_number", "", length=4),
        XStrFixedLenField("old_key_lowest_acceptable_pn", "", length=4)
    ]


class MKADistributedSAKParamSet(MKAParamSet):
    """
    Distributed SAK parameter set (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "Distributed SAK parameter set"
    fields_desc = [
        ByteEnumField("param_set_type", 4, _parameter_set_types),
        BitField("distributed_an", 0, 2),
        BitField("confidentiality_offset", 0, 2),
        BitField("unused", 0, 4),
        ShortField("param_set_body_len", 0),
        XStrFixedLenField("key_number", "", length=4),
        ConditionalField(
            XStrFixedLenField("macsec_cipher_suite", "", length=8),
            lambda pkt: pkt.param_set_body_len > 28
        ),
        XStrFixedLenField(
            "sak_aes_key_wrap",
            "",
            length=MKAParamSet.EAPOL_MKA_DEFAULT_KEY_WRAP_LEN
        )
    ]


class MKADistributedCAKParamSet(MKAParamSet):
    """
    Distributed CAK Parameter Set (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "Distributed CAK parameter set"
    fields_desc = [
        PadField(
            ByteEnumField(
                "param_set_type",
                5,
                _parameter_set_types
            ),
            2,
            padwith=b"\x00"
        ),
        ShortField("param_set_body_len", 0),
        XStrFixedLenField(
            "cak_aes_key_wrap",
            "",
            length=MKAParamSet.EAPOL_MKA_DEFAULT_KEY_WRAP_LEN
        ),
        XStrField("cak_key_name", "")
    ]


class MKAICVSet(MKAParamSet):
    """
    ICV (802.1X-2010, section 11.11).
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "ICV"
    fields_desc = [
        PadField(
            ByteEnumField(
                "param_set_type",
                255,
                _parameter_set_types
            ),
            2,
            padwith=b"\x00"
        ),
        ShortField("param_set_body_len", 0),
        XStrFixedLenField("icv", "", length=MKAParamSet.MACSEC_DEFAULT_ICV_LEN)
    ]


class MKAParamSetPacketListField(PacketListField):
    """
    PacketListField that handles the parameter sets.
    """

    PARAM_SET_LEN_MASK = 0b0000111111111111

    def m2i(self, pkt, m):
        return MKAParamSet(m)

    def getfield(self, pkt, s):
        lst = []
        remain = s

        while remain:
            len_bytes = struct.unpack("!H", remain[2:4])[0]
            param_set_len = self.__class__.PARAM_SET_LEN_MASK & len_bytes
            current = remain[:4 + param_set_len]
            remain = remain[4 + param_set_len:]
            current_packet = self.m2i(pkt, current)
            lst.append(current_packet)

        return remain, lst


class MKAPDU(Packet):
    """
    MACsec Key Agreement Protocol Data Unit.
    """

    #########################################################################
    #
    # IEEE 802.1X-2010 standard
    # Section 11.11
    #########################################################################
    #

    name = "MKPDU"
    fields_desc = [
        PacketField("basic_param_set", "", MKABasicParamSet),
        MKAParamSetPacketListField("parameter_sets", [], MKAParamSet),
    ]

    def extract_padding(self, s):
        return "", s


bind_layers(Ether, EAPOL, type=34958)
bind_layers(Ether, EAPOL, dst='01:80:c2:00:00:03', type=34958)
bind_layers(CookedLinux, EAPOL, proto=34958)
bind_layers(GRE, EAPOL, proto=34958)
bind_layers(EAPOL, EAP, type=0)
bind_layers(SNAP, EAPOL, code=34958)
bind_layers(EAPOL, MKAPDU, type=5)
