# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
LDAP

RFC 1777 - LDAP v2
RFC 4511 - LDAP v3

Note: to mimic Microsoft Windows LDAP packets, you must set::

    conf.ASN1_default_long_size = 4

.. note::
    You will find more complete documentation for this layer over at
    `LDAP <https://scapy.readthedocs.io/en/latest/layers/ldap.html>`_
"""

import collections
import ssl
import socket
import struct
import uuid

from enum import Enum

from scapy.arch import get_if_addr
from scapy.ansmachine import AnsweringMachine
from scapy.asn1.asn1 import (
    ASN1_STRING,
    ASN1_Class,
    ASN1_Codecs,
)
from scapy.asn1.ber import (
    BERcodec_STRING,
    BER_id_dec,
    BER_len_dec,
)
from scapy.asn1fields import (
    ASN1F_badsequence,
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_INTEGER,
    ASN1F_NULL,
    ASN1F_optional,
    ASN1F_PACKET,
    ASN1F_SEQUENCE_OF,
    ASN1F_SEQUENCE,
    ASN1F_SET_OF,
    ASN1F_STRING,
    ASN1F_STRING_PacketField,
)
from scapy.asn1packet import ASN1_Packet
from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import (
    FieldLenField,
    FlagsField,
    ThreeBytesField,
)
from scapy.packet import (
    Packet,
    bind_bottom_up,
    bind_layers,
)
from scapy.sendrecv import send
from scapy.supersocket import (
    SimpleSocket,
    StreamSocket,
    SSLStreamSocket,
)

from scapy.layers.dns import dns_resolve
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.gssapi import (
    _GSSAPI_Field,
    GSS_C_FLAGS,
    GSS_S_COMPLETE,
    GSSAPI_BLOB_SIGNATURE,
    GSSAPI_BLOB,
    SSP,
)
from scapy.layers.netbios import NBTDatagram
from scapy.layers.smb import (
    NETLOGON,
    NETLOGON_SAM_LOGON_RESPONSE_EX,
)


# Elements of protocol
# https://datatracker.ietf.org/doc/html/rfc1777#section-4

LDAPString = ASN1F_STRING
LDAPOID = ASN1F_STRING
LDAPDN = LDAPString
RelativeLDAPDN = LDAPString
AttributeType = LDAPString
AttributeValue = ASN1F_STRING
URI = LDAPString


class AttributeValueAssertion(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        AttributeType("attributeType", "organizationName"),
        AttributeValue("attributeValue", ""),
    )


class LDAPReferral(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("uri", "")


LDAPResult = (
    ASN1F_ENUMERATED(
        "resultCode",
        0,
        {
            0: "success",
            1: "operationsError",
            2: "protocolError",
            3: "timeLimitExceeded",
            4: "sizeLimitExceeded",
            5: "compareFalse",
            6: "compareTrue",
            7: "authMethodNotSupported",
            8: "strongAuthRequired",
            10: "referral",
            11: "adminLimitExceeded",
            14: "saslBindInProgress",
            16: "noSuchAttribute",
            17: "undefinedAttributeType",
            18: "inappropriateMatching",
            19: "constraintViolation",
            20: "attributeOrValueExists",
            21: "invalidAttributeSyntax",
            32: "noSuchObject",
            33: "aliasProblem",
            34: "invalidDNSyntax",
            35: "isLeaf",
            36: "aliasDereferencingProblem",
            48: "inappropriateAuthentication",
            49: "invalidCredentials",
            50: "insufficientAccessRights",
            51: "busy",
            52: "unavailable",
            53: "unwillingToPerform",
            54: "loopDetect",
            64: "namingViolation",
            65: "objectClassViolation",
            66: "notAllowedOnNonLeaf",
            67: "notAllowedOnRDN",
            68: "entryAlreadyExists",
            69: "objectClassModsProhibited",
            70: "resultsTooLarge",  # CLDAP
            80: "other",
        },
    ),
    LDAPDN("matchedDN", ""),
    LDAPString("diagnosticMessage", ""),
    # LDAP v3 only
    ASN1F_optional(ASN1F_SEQUENCE_OF("referral", [], LDAPReferral, implicit_tag=0xA3)),
)


# ldap APPLICATION


class ASN1_Class_LDAP(ASN1_Class):
    name = "LDAP"
    # APPLICATION + CONSTRUCTED = 0x40 | 0x20
    BindRequest = 0x60
    BindResponse = 0x61
    UnbindRequest = 0x42  # not constructed
    SearchRequest = 0x63
    SearchResultEntry = 0x64
    SearchResultDone = 0x65
    ModifyRequest = 0x66
    ModifyResponse = 0x67
    AddRequest = 0x68
    AddResponse = 0x69
    DelRequest = 0x4A  # not constructed
    DelResponse = 0x6B
    ModifyDNRequest = 0x6C
    ModifyDNResponse = 0x6D
    CompareRequest = 0x6E
    CompareResponse = 0x7F
    AbandonRequest = 0x50  # application + primitive
    SearchResultReference = 0x73
    ExtendedRequest = 0x77
    ExtendedResponse = 0x78


# Bind operation
# https://datatracker.ietf.org/doc/html/rfc1777#section-4.1


class ASN1_Class_LDAP_Authentication(ASN1_Class):
    name = "LDAP Authentication"
    # CONTEXT-SPECIFIC = 0x80
    simple = 0x80
    krbv42LDAP = 0x81
    krbv42DSA = 0x82
    sasl = 0xA3  # CONTEXT-SPECIFIC | CONSTRUCTED
    # [MS-ADTS] sect 5.1.1.1
    sicilyPackageDiscovery = 0x89
    sicilyNegotiate = 0x8A
    sicilyResponse = 0x8B


# simple
class LDAP_Authentication_simple(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.simple


class BERcodec_LDAP_Authentication_simple(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.simple


class ASN1F_LDAP_Authentication_simple(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.simple


# krbv42LDAP
class LDAP_Authentication_krbv42LDAP(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class BERcodec_LDAP_Authentication_krbv42LDAP(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class ASN1F_LDAP_Authentication_krbv42LDAP(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


# krbv42DSA
class LDAP_Authentication_krbv42DSA(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42DSA


class BERcodec_LDAP_Authentication_krbv42DSA(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42DSA


class ASN1F_LDAP_Authentication_krbv42DSA(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.krbv42DSA


# sicilyPackageDiscovery
class LDAP_Authentication_sicilyPackageDiscovery(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyPackageDiscovery


class BERcodec_LDAP_Authentication_sicilyPackageDiscovery(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyPackageDiscovery


class ASN1F_LDAP_Authentication_sicilyPackageDiscovery(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.sicilyPackageDiscovery


# sicilyNegotiate
class LDAP_Authentication_sicilyNegotiate(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyNegotiate


class BERcodec_LDAP_Authentication_sicilyNegotiate(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyNegotiate


class ASN1F_LDAP_Authentication_sicilyNegotiate(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.sicilyNegotiate


# sicilyResponse
class LDAP_Authentication_sicilyResponse(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyResponse


class BERcodec_LDAP_Authentication_sicilyResponse(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyResponse


class ASN1F_LDAP_Authentication_sicilyResponse(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.sicilyResponse


_SASL_MECHANISMS = {b"GSS-SPNEGO": GSSAPI_BLOB, b"GSSAPI": GSSAPI_BLOB}


class _SaslCredentialsField(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_SaslCredentialsField, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.mechanism.val in _SASL_MECHANISMS:
            return (
                _SASL_MECHANISMS[pkt.mechanism.val](val[0].val, _underlayer=pkt),
                val[1],
            )
        return val


class LDAP_Authentication_SaslCredentials(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPString("mechanism", ""),
        ASN1F_optional(
            _SaslCredentialsField("credentials", ""),
        ),
        implicit_tag=ASN1_Class_LDAP_Authentication.sasl,
    )


class LDAP_BindRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("version", 3),
        LDAPDN("bind_name", ""),
        ASN1F_CHOICE(
            "authentication",
            None,
            ASN1F_LDAP_Authentication_simple,
            ASN1F_LDAP_Authentication_krbv42LDAP,
            ASN1F_LDAP_Authentication_krbv42DSA,
            LDAP_Authentication_SaslCredentials,
        ),
        implicit_tag=ASN1_Class_LDAP.BindRequest,
    )


class LDAP_BindResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *(
            LDAPResult
            + (
                ASN1F_optional(
                    # For GSSAPI, the response is wrapped in
                    # LDAP_Authentication_SaslCredentials
                    ASN1F_STRING("serverSaslCredsWrap", "", implicit_tag=0xA7),
                ),
                ASN1F_optional(
                    ASN1F_STRING("serverSaslCreds", "", implicit_tag=0x87),
                ),
            )
        ),
        implicit_tag=ASN1_Class_LDAP.BindResponse,
    )

    @property
    def serverCreds(self):
        """
        serverCreds field in SicilyBindResponse
        """
        return self.matchedDN.val

    @serverCreds.setter
    def serverCreds(self, val):
        """
        serverCreds field in SicilyBindResponse
        """
        self.matchedDN = ASN1_STRING(val)

    @property
    def serverSaslCredsData(self):
        """
        Get serverSaslCreds or serverSaslCredsWrap depending on what's available
        """
        if self.serverSaslCredsWrap and self.serverSaslCredsWrap.val:
            wrap = LDAP_Authentication_SaslCredentials(self.serverSaslCredsWrap.val)
            val = wrap.credentials
            if isinstance(val, ASN1_STRING):
                return val.val
            return bytes(val)
        elif self.serverSaslCreds and self.serverSaslCreds.val:
            return self.serverSaslCreds.val
        else:
            return None


# Unbind operation
# https://datatracker.ietf.org/doc/html/rfc1777#section-4.2


class LDAP_UnbindRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_NULL("info", 0),
        implicit_tag=ASN1_Class_LDAP.UnbindRequest,
    )


# Search operation
# https://datatracker.ietf.org/doc/html/rfc1777#section-4.3


class LDAP_SubstringFilterInitial(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("initial", "")


class LDAP_SubstringFilterAny(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("any", "")


class LDAP_SubstringFilterFinal(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("final", "")


class LDAP_SubstringFilterStr(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "str",
        ASN1_STRING(""),
        ASN1F_PACKET(
            "initial",
            LDAP_SubstringFilterInitial(),
            LDAP_SubstringFilterInitial,
            implicit_tag=0x80,
        ),
        ASN1F_PACKET(
            "any", LDAP_SubstringFilterAny(), LDAP_SubstringFilterAny, implicit_tag=0x81
        ),
        ASN1F_PACKET(
            "final",
            LDAP_SubstringFilterFinal(),
            LDAP_SubstringFilterFinal,
            implicit_tag=0x82,
        ),
    )


class LDAP_SubstringFilter(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        AttributeType("type", ""),
        ASN1F_SEQUENCE_OF("filters", [], LDAP_SubstringFilterStr),
    )


_LDAP_Filter = lambda *args, **kwargs: LDAP_Filter(*args, **kwargs)


class LDAP_FilterAnd(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF("and_", [], _LDAP_Filter)


class LDAP_FilterOr(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF("or_", [], _LDAP_Filter)


class LDAP_FilterPresent(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeType("present", "objectClass")


class LDAP_FilterEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterGreaterOrEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterLesserOrEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterLessOrEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterApproxMatch(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class ASN1_Class_LDAP_Filter(ASN1_Class):
    name = "LDAP Filter"
    # CONTEXT-SPECIFIC + CONSTRUCTED = 0x80 | 0x20
    And = 0xA0
    Or = 0xA1
    Not = 0xA2
    EqualityMatch = 0xA3
    Substrings = 0xA4
    GreaterOrEqual = 0xA5
    LessOrEqual = 0xA6
    Present = 0x87  # not constructed
    ApproxMatch = 0xA8


class LDAP_Filter(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "filter",
        LDAP_FilterPresent(),
        ASN1F_PACKET(
            "and_", None, LDAP_FilterAnd, implicit_tag=ASN1_Class_LDAP_Filter.And
        ),
        ASN1F_PACKET(
            "or_", None, LDAP_FilterOr, implicit_tag=ASN1_Class_LDAP_Filter.Or
        ),
        ASN1F_PACKET(
            "not_", None, _LDAP_Filter, implicit_tag=ASN1_Class_LDAP_Filter.Not
        ),
        ASN1F_PACKET(
            "equalityMatch",
            None,
            LDAP_FilterEqual,
            implicit_tag=ASN1_Class_LDAP_Filter.EqualityMatch,
        ),
        ASN1F_PACKET(
            "substrings",
            None,
            LDAP_SubstringFilter,
            implicit_tag=ASN1_Class_LDAP_Filter.Substrings,
        ),
        ASN1F_PACKET(
            "greaterOrEqual",
            None,
            LDAP_FilterGreaterOrEqual,
            implicit_tag=ASN1_Class_LDAP_Filter.GreaterOrEqual,
        ),
        ASN1F_PACKET(
            "lessOrEqual",
            None,
            LDAP_FilterLessOrEqual,
            implicit_tag=ASN1_Class_LDAP_Filter.LessOrEqual,
        ),
        ASN1F_PACKET(
            "present",
            None,
            LDAP_FilterPresent,
            implicit_tag=ASN1_Class_LDAP_Filter.Present,
        ),
        ASN1F_PACKET(
            "approxMatch",
            None,
            LDAP_FilterApproxMatch,
            implicit_tag=ASN1_Class_LDAP_Filter.ApproxMatch,
        ),
    )


class LDAP_SearchRequestAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeType("type", "")


class LDAP_SearchRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("baseObject", ""),
        ASN1F_ENUMERATED(
            "scope", 0, {0: "baseObject", 1: "singleLevel", 2: "wholeSubtree"}
        ),
        ASN1F_ENUMERATED(
            "derefAliases",
            0,
            {
                0: "neverDerefAliases",
                1: "derefInSearching",
                2: "derefFindingBaseObj",
                3: "derefAlways",
            },
        ),
        ASN1F_INTEGER("sizeLimit", 0),
        ASN1F_INTEGER("timeLimit", 0),
        ASN1F_BOOLEAN("attrsOnly", False),
        ASN1F_PACKET("filter", LDAP_Filter(), LDAP_Filter),
        ASN1F_SEQUENCE_OF("attributes", [], LDAP_SearchRequestAttribute),
        implicit_tag=ASN1_Class_LDAP.SearchRequest,
    )


class LDAP_SearchResponseEntryAttributeValue(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValue("value", "")


class LDAP_SearchResponseEntryAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        AttributeType("type", ""),
        ASN1F_SET_OF("values", [], LDAP_SearchResponseEntryAttributeValue),
    )


class LDAP_SearchResponseEntry(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("objectName", ""),
        ASN1F_SEQUENCE_OF(
            "attributes",
            LDAP_SearchResponseEntryAttribute(),
            LDAP_SearchResponseEntryAttribute,
        ),
        implicit_tag=ASN1_Class_LDAP.SearchResultEntry,
    )


class LDAP_SearchResponseResultDone(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *LDAPResult,
        implicit_tag=ASN1_Class_LDAP.SearchResultDone,
    )


class LDAP_AbandonRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("messageID", 0),
        implicit_tag=ASN1_Class_LDAP.AbandonRequest,
    )


# LDAP v3

# RFC 4511 sect 4.1.11


class LDAP_Control(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPOID("controlType", ""),
        ASN1F_optional(
            ASN1F_BOOLEAN("criticality", False),
        ),
        ASN1F_optional(ASN1F_STRING("controlValue", "")),
    )


# RFC 4511 sect 4.12 - Extended Operation


class LDAP_ExtendedResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *(
            LDAPResult
            + (
                ASN1F_optional(LDAPOID("responseName", None, implicit_tag=0x8A)),
                ASN1F_optional(ASN1F_STRING("responseValue", None, implicit_tag=0x8B)),
            )
        ),
        implicit_tag=ASN1_Class_LDAP.ExtendedResponse,
    )

    def do_dissect(self, x):
        # Note: Windows builds this packet with a buggy sequence size, that does not
        # include the optional fields. Do another pass of dissection on the optionals.
        s = super(LDAP_ExtendedResponse, self).do_dissect(x)
        if not s:
            return s
        for obj in self.ASN1_root.seq[-2:]:  # only on the 2 optional fields
            try:
                s = obj.dissect(self, s)
            except ASN1F_badsequence:
                break
        return s


# LDAP main class


class LDAP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("messageID", 0),
        ASN1F_CHOICE(
            "protocolOp",
            LDAP_SearchRequest(),
            LDAP_BindRequest,
            LDAP_BindResponse,
            LDAP_SearchRequest,
            LDAP_SearchResponseEntry,
            LDAP_SearchResponseResultDone,
            LDAP_AbandonRequest,
            LDAP_UnbindRequest,
            LDAP_ExtendedResponse,
        ),
        # LDAP v3 only
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("Controls", None, LDAP_Control, implicit_tag=0xA0)
        ),
    )

    show_indent = 0

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 4:
            # Heuristic to detect SASL_Buffer
            if _pkt[0] != 0x30:
                if struct.unpack("!I", _pkt[:4])[0] + 4 == len(_pkt):
                    return LDAP_SASL_Buffer
                return conf.raw_layer
        return cls

    def hashret(self):
        return b"ldap"

    @property
    def unsolicited(self):
        # RFC4511 sect 4.4. - Unsolicited Notification
        return self.messageID == 0 and isinstance(
            self.protocolOp, LDAP_ExtendedResponse
        )

    def answers(self, other):
        if self.unsolicited:
            return True
        return isinstance(other, LDAP) and other.messageID == self.messageID

    def mysummary(self):
        return (
            "%s(%s)"
            % (
                self.protocolOp.__class__.__name__.replace("_", " "),
                self.messageID.val,
            ),
            [LDAP],
        )


bind_layers(LDAP, LDAP)

bind_bottom_up(TCP, LDAP, dport=389)
bind_bottom_up(TCP, LDAP, sport=389)
bind_bottom_up(TCP, LDAP, dport=3268)
bind_bottom_up(TCP, LDAP, sport=3268)
bind_layers(TCP, LDAP, sport=389, dport=389)

# CLDAP - rfc1798


class CLDAP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAP.ASN1_root.seq[0],  # messageID
        ASN1F_optional(
            LDAPDN("user", ""),
        ),
        LDAP.ASN1_root.seq[1],  # protocolOp
    )

    def answers(self, other):
        return isinstance(other, CLDAP) and other.messageID == self.messageID


bind_layers(CLDAP, CLDAP)

bind_bottom_up(UDP, CLDAP, dport=389)
bind_bottom_up(UDP, CLDAP, sport=389)
bind_layers(UDP, CLDAP, sport=389, dport=389)


# Small CLDAP Answering machine: [MS-ADTS] 6.3.3 - Ldap ping


class LdapPing_am(AnsweringMachine):
    function_name = "ldappingd"
    filter = "udp port 389 or 138"
    send_function = staticmethod(send)

    def parse_options(
        self,
        NetbiosDomainName="DOMAIN",
        DomainGuid=uuid.UUID("192bc4b3-0085-4521-83fe-062913ef59f2"),
        DcSiteName="Default-First-Site-Name",
        NetbiosComputerName="SRV1",
        DnsForestName=None,
        DnsHostName=None,
        src_ip=None,
        src_ip6=None,
    ):
        self.NetbiosDomainName = NetbiosDomainName
        self.DnsForestName = DnsForestName or (NetbiosDomainName + ".LOCAL")
        self.DomainGuid = DomainGuid
        self.DcSiteName = DcSiteName
        self.NetbiosComputerName = NetbiosComputerName
        self.DnsHostName = DnsHostName or (
            NetbiosComputerName + "." + self.DnsForestName
        )
        self.src_ip = src_ip
        self.src_ip6 = src_ip6

    def is_request(self, req):
        # [MS-ADTS] 6.3.3 - Example:
        # (&(DnsDomain=abcde.corp.microsoft.com)(Host=abcdefgh-dev)(User=abcdefgh-
        # dev$)(AAC=\80\00\00\00)(DomainGuid=\3b\b0\21\ca\d3\6d\d1\11\8a\7d\b8\df\b1\56\87\1f)(NtVer
        # =\06\00\00\00))
        if NBTDatagram in req:
            # special case: mailslot ping
            from scapy.layers.smb import SMBMailslot_Write, NETLOGON_SAM_LOGON_REQUEST

            try:
                return (
                    SMBMailslot_Write in req and NETLOGON_SAM_LOGON_REQUEST in req.Data
                )
            except AttributeError:
                return False
        if CLDAP not in req or not isinstance(req.protocolOp, LDAP_SearchRequest):
            return False
        req = req.protocolOp
        return (
            req.attributes
            and req.attributes[0].type.val.lower() == b"netlogon"
            and req.filter
            and isinstance(req.filter.filter, LDAP_FilterAnd)
            and any(
                x.filter.attributeType.val == b"NtVer" for x in req.filter.filter.and_
            )
        )

    def make_reply(self, req):
        if NBTDatagram in req:
            # Special case
            return self.make_mailslot_ping_reply(req)
        if IPv6 in req:
            resp = IPv6(dst=req[IPv6].src, src=self.src_ip6 or req[IPv6].dst)
        else:
            resp = IP(dst=req[IP].src, src=self.src_ip or req[IP].dst)
        resp /= UDP(sport=req.dport, dport=req.sport)
        # get the DnsDomainName from the request
        try:
            DnsDomainName = next(
                x.filter.attributeValue.val
                for x in req.protocolOp.filter.filter.and_
                if x.filter.attributeType.val == b"DnsDomain"
            )
        except StopIteration:
            return
        return (
            resp
            / CLDAP(
                protocolOp=LDAP_SearchResponseEntry(
                    attributes=[
                        LDAP_SearchResponseEntryAttribute(
                            values=[
                                LDAP_SearchResponseEntryAttributeValue(
                                    value=ASN1_STRING(
                                        val=bytes(
                                            NETLOGON_SAM_LOGON_RESPONSE_EX(
                                                # Mandatory fields
                                                DnsDomainName=DnsDomainName,
                                                NtVersion="V1+V5",
                                                LmNtToken=65535,
                                                Lm20Token=65535,
                                                # Below can be customized
                                                Flags=0x3F3FD,
                                                DomainGuid=self.DomainGuid,
                                                DnsForestName=self.DnsForestName,
                                                DnsHostName=self.DnsHostName,
                                                NetbiosDomainName=self.NetbiosDomainName,  # noqa: E501
                                                NetbiosComputerName=self.NetbiosComputerName,  # noqa: E501
                                                UserName=b".",
                                                DcSiteName=self.DcSiteName,
                                                ClientSiteName=self.DcSiteName,
                                            )
                                        )
                                    )
                                )
                            ],
                            type=ASN1_STRING(b"Netlogon"),
                        )
                    ],
                ),
                messageID=req.messageID,
                user=None,
            )
            / CLDAP(
                protocolOp=LDAP_SearchResponseResultDone(
                    referral=None,
                    resultCode=0,
                ),
                messageID=req.messageID,
                user=None,
            )
        )

    def make_mailslot_ping_reply(self, req):
        # type: (Packet) -> Packet
        from scapy.layers.smb import (
            SMBMailslot_Write,
            SMB_Header,
            DcSockAddr,
            NETLOGON_SAM_LOGON_RESPONSE_EX,
        )

        resp = IP(dst=req[IP].src) / UDP(
            sport=req.dport,
            dport=req.sport,
        )
        address = self.src_ip or get_if_addr(self.optsniff.get("iface", conf.iface))
        resp /= (
            NBTDatagram(
                SourceName=req.DestinationName,
                SUFFIX1=req.SUFFIX2,
                DestinationName=req.SourceName,
                SUFFIX2=req.SUFFIX1,
                SourceIP=address,
            )
            / SMB_Header()
            / SMBMailslot_Write(
                Name=req.Data.MailslotName,
            )
        )
        NetbiosDomainName = req.DestinationName.strip()
        resp.Data = NETLOGON_SAM_LOGON_RESPONSE_EX(
            # Mandatory fields
            NetbiosDomainName=NetbiosDomainName,
            DcSockAddr=DcSockAddr(
                sin_addr=address,
            ),
            NtVersion="V1+V5EX+V5EX_WITH_IP",
            LmNtToken=65535,
            Lm20Token=65535,
            # Below can be customized
            Flags=0x3F3FD,
            DomainGuid=self.DomainGuid,
            DnsForestName=self.DnsForestName,
            DnsDomainName=self.DnsForestName,
            DnsHostName=self.DnsHostName,
            NetbiosComputerName=self.NetbiosComputerName,
            DcSiteName=self.DcSiteName,
            ClientSiteName=self.DcSiteName,
        )
        return resp


_located_dc = collections.namedtuple("LocatedDC", ["ip", "samlogon"])
_dclocatorcache = conf.netcache.new_cache("dclocator", 600)


@conf.commands.register
def dclocator(
    realm, qtype="A", mode="ldap", port=None, timeout=1, NtVersion=None, debug=0
):
    """
    Perform a DC Locator as per [MS-ADTS] sect 6.3.6 or RFC4120.

    :param realm: the kerberos realm to locate
    :param mode: Detect if a server is up and joinable thanks to one of:

    - 'nocheck': Do not check that servers are online.
    - 'ldap': Use the LDAP ping (CLDAP) per [MS-ADTS]. Default.
              This will however not work with MIT Kerberos servers.
    - 'connect': connect to specified port to test the connection.

    :param mode: in connect mode, the port to connect to. (e.g. 88)
    :param debug: print debug logs

    This is cached in conf.netcache.dclocator.
    """
    if NtVersion is None:
        # Windows' default
        NtVersion = (
            0x00000002  # V5
            | 0x00000004  # V5EX
            | 0x00000010  # V5EX_WITH_CLOSEST_SITE
            | 0x01000000  # AVOID_NT4EMUL
            | 0x20000000  # IP
        )
    # Check cache
    cache_ident = ";".join([realm, qtype, mode, str(NtVersion)]).lower()
    if cache_ident in _dclocatorcache:
        return _dclocatorcache[cache_ident]
    # Perform DNS-Based discovery (6.3.6.1)
    # 1. SRV records
    qname = "_kerberos._tcp.dc._msdcs.%s" % realm.lower()
    if debug:
        log_runtime.info("DC Locator: requesting SRV for '%s' ..." % qname)
    try:
        hosts = [
            x.target
            for x in dns_resolve(
                qname=qname,
                qtype="SRV",
                timeout=timeout,
            )
        ]
    except TimeoutError:
        raise TimeoutError("Resolution of %s timed out" % qname)
    if not hosts:
        raise ValueError("No DNS record found for %s" % qname)
    elif debug:
        log_runtime.info(
            "DC Locator: got %s. Resolving %s records ..." % (hosts, qtype)
        )
    # 2. A records
    ips = []
    for host in hosts:
        arec = dns_resolve(
            qname=host,
            qtype=qtype,
            timeout=timeout,
        )
        if arec:
            ips.extend(x.rdata for x in arec)
    if not ips:
        raise ValueError("Could not get any %s records for %s" % (qtype, hosts))
    elif debug:
        log_runtime.info("DC Locator: got %s . Mode: %s" % (ips, mode))
    # Pick first online host. We have three options
    if mode == "nocheck":
        # Don't check anything. Not recommended
        return _located_dc(ips[0], None)
    elif mode == "connect":
        assert port is not None, "Must provide a port in connect mode !"
        # Compatibility with MIT Kerberos servers
        for ip in ips:  # TODO: "addresses in weighted random order [RFC2782]"
            if debug:
                log_runtime.info("DC Locator: connecting to %s on %s ..." % (ip, port))
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                # Success
                result = _located_dc(ip, None)
                # Cache
                _dclocatorcache[cache_ident] = result
                return result
            except OSError:
                # Host timed out, No route to host, etc.
                if debug:
                    log_runtime.info("DC Locator: %s timed out." % ip)
                continue
            finally:
                sock.close()
        raise ValueError("No host was reachable on port %s among %s" % (port, ips))
    elif mode == "ldap":
        # Real 'LDAP Ping' per [MS-ADTS]
        for ip in ips:  # TODO: "addresses in weighted random order [RFC2782]"
            if debug:
                log_runtime.info("DC Locator: LDAP Ping %s on ..." % ip)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.connect((ip, 389))
                sock = SimpleSocket(sock, CLDAP)
                pkt = sock.sr1(
                    CLDAP(
                        protocolOp=LDAP_SearchRequest(
                            filter=LDAP_Filter(
                                filter=LDAP_FilterAnd(
                                    and_=[
                                        LDAP_Filter(
                                            filter=LDAP_FilterEqual(
                                                attributeType=ASN1_STRING(b"DnsDomain"),
                                                attributeValue=ASN1_STRING(realm),
                                            )
                                        ),
                                        LDAP_Filter(
                                            filter=LDAP_FilterEqual(
                                                attributeType=ASN1_STRING(b"NtVer"),
                                                attributeValue=ASN1_STRING(
                                                    struct.pack("<I", NtVersion)
                                                ),
                                            )
                                        ),
                                    ]
                                )
                            ),
                            attributes=[
                                LDAP_SearchRequestAttribute(
                                    type=ASN1_STRING(b"Netlogon")
                                )
                            ],
                        ),
                        user=None,
                    ),
                    timeout=timeout,
                    verbose=0,
                )
                if pkt:
                    # Check if we have a search response
                    response = None
                    if isinstance(pkt.protocolOp, LDAP_SearchResponseEntry):
                        try:
                            response = next(
                                NETLOGON(x.values[0].value.val)
                                for x in pkt.protocolOp.attributes
                                if x.type.val == b"Netlogon"
                            )
                        except StopIteration:
                            pass
                    result = _located_dc(ip, response)
                    # Cache
                    _dclocatorcache[cache_ident] = result
                    return result
            except OSError:
                # Host timed out, No route to host, etc.
                if debug:
                    log_runtime.info("DC Locator: %s timed out." % ip)
                continue
            finally:
                sock.close()
        raise ValueError("No LDAP ping succeeded on any of %s. Try another mode?" % ips)


#####################
# Basic LDAP client #
#####################


class LDAP_BIND_MECHS(Enum):
    NONE = "UNAUTHENTICATED"
    SIMPLE = "SIMPLE"
    SASL_GSSAPI = "GSSAPI"
    SASL_GSS_SPNEGO = "GSS-SPNEGO"
    SASL_EXTERNAL = "EXTERNAL"
    SASL_DIGEST_MD5 = "DIGEST-MD5"
    # [MS-ADTS] extension
    SICILY = "SICILY"


class LDAP_SASL_GSSAPI_SsfCap(Packet):
    """
    RFC2222 sect 7.2.1 and 7.2.2 negotiate token
    """

    fields_desc = [
        FlagsField(
            "supported_security_layers",
            0,
            -8,
            {
                # https://github.com/cyrusimap/cyrus-sasl/blob/7e2feaeeb2e37d38cb5fa957d0e8a599ced22612/plugins/gssapi.c#L221
                0x01: "NONE",
                0x02: "INTEGRITY",
                0x04: "CONFIDENTIALITY",
            },
        ),
        ThreeBytesField("max_output_token_size", 0),
    ]


class LDAP_SASL_Buffer(Packet):
    """
    RFC 4422 sect 3.7
    """

    # "Each buffer of protected data is transferred over the underlying
    # transport connection as a sequence of octets prepended with a four-
    # octet field in network byte order that represents the length of the
    # buffer."

    fields_desc = [
        FieldLenField("BufferLength", None,
                      fmt="!I", length_of="Buffer"),
        _GSSAPI_Field("Buffer", LDAP),
    ]

    def hashret(self):
        return b"ldap"

    def answers(self, other):
        return isinstance(other, LDAP_SASL_Buffer)

    @classmethod
    def tcp_reassemble(cls, data, *args, **kwargs):
        if len(data) < 4:
            return None
        if data[0] == 0x30:
            # Add a heuristic to detect LDAP errors
            xlen, x = BER_len_dec(BER_id_dec(data)[1])
            if xlen and xlen == len(x):
                return LDAP(data)
        # Check BufferLength
        length = struct.unpack("!I", data[:4])[0] + 4
        if len(data) >= length:
            return cls(data)


class LDAP_Client(object):
    """
    A basic LDAP client

    The complete documentation is available at
    https://scapy.readthedocs.io/en/latest/layers/ldap.html

    Example 1 - SICILY - NTLM (with encryption)::

        client = LDAP_Client()
        client.connect("192.168.0.100")
        ssp = NTLMSSP(UPN="Administrator", PASSWORD="Password1!")
        client.bind(
            LDAP_BIND_MECHS.SICILY,
            ssp=ssp,
            encrypt=True,
        )

    Example 2 - SASL_GSSAPI - Kerberos (with signing)::

        client = LDAP_Client()
        client.connect("192.168.0.100")
        ssp = KerberosSSP(UPN="Administrator@domain.local", PASSWORD="Password1!",
                          SPN="ldap/dc1.domain.local")
        client.bind(
            LDAP_BIND_MECHS.SASL_GSSAPI,
            ssp=ssp,
            sign=True,
        )

    Example 3 - SASL_GSS_SPNEGO - NTLM / Kerberos::

        client = LDAP_Client()
        client.connect("192.168.0.100")
        ssp = SPNEGOSSP([
            NTLMSSP(UPN="Administrator", PASSWORD="Password1!"),
            KerberosSSP(UPN="Administrator@domain.local", PASSWORD="Password1!",
                          SPN="ldap/dc1.domain.local"),
        ])
        client.bind(
            LDAP_BIND_MECHS.SASL_GSS_SPNEGO,
            ssp=ssp,
        )

    Example 4 - Simple bind over TLS::

        client = LDAP_Client()
        client.connect("192.168.0.100", use_ssl=True)
        client.bind(
            LDAP_BIND_MECHS.SIMPLE,
            simple_username="Administrator",
            simple_password="Password1!",
        )
    """

    def __init__(
        self,
        verb=True,
    ):
        self.sock = None
        self.verb = verb
        self.ssl = False
        self.sslcontext = None
        self.ssp = None
        self.sspcontext = None
        self.encrypt = False
        self.sign = False
        # Session status
        self.sasl_wrap = False
        self.messageID = 0

    def connect(self, ip, port=None, use_ssl=False, sslcontext=None, timeout=5):
        """
        Initiate a connection

        :param ip: the IP to connect to.
        :param port: the port to connect to. (Default: 389 or 636)

        :param use_ssl: whether to use LDAPS or not. (Default: False)
        :param sslcontext: an optional SSLContext to use.
        """
        self.ssl = use_ssl
        self.sslcontext = sslcontext

        if port is None:
            if self.ssl:
                port = 636
            else:
                port = 389
        sock = socket.socket()
        sock.settimeout(timeout)
        if self.verb:
            print(
                "\u2503 Connecting to %s on port %s%s..."
                % (
                    ip,
                    port,
                    " with SSL" if self.ssl else "",
                )
            )
        sock.connect((ip, port))
        if self.verb:
            print(
                conf.color_theme.green(
                    "\u2514 Connected from %s" % repr(sock.getsockname())
                )
            )
        if self.ssl:
            if self.sslcontext is None:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                # Hm, this is insecure.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = self.sslcontext
            sock = context.wrap_socket(sock)
        if self.ssl:
            self.sock = SSLStreamSocket(sock, LDAP)
        else:
            self.sock = StreamSocket(sock, LDAP)

    def sr1(self, protocolOp, controls=None, **kwargs):
        self.messageID += 1
        if self.verb:
            print(conf.color_theme.opening(">> %s" % protocolOp.__class__.__name__))
        # Build packet
        pkt = LDAP(
            messageID=self.messageID,
            protocolOp=protocolOp,
            Controls=controls,
        )
        # If signing / encryption is used, apply
        if self.sasl_wrap:
            pkt = LDAP_SASL_Buffer(
                Buffer=self.ssp.GSS_Wrap(
                    self.sspcontext,
                    bytes(pkt),
                    conf_req_flag=self.encrypt,
                )
            )
        # Send / Receive
        resp = self.sock.sr1(
            pkt,
            verbose=0,
            **kwargs,
        )
        # Check for unsolicited notification
        if resp and LDAP in resp and resp[LDAP].unsolicited:
            resp.show()
            if self.verb:
                print(conf.color_theme.fail("! Got unsolicited notification."))
                return resp
        # If signing / encryption is used, unpack
        if self.sasl_wrap:
            if resp.Buffer:
                resp = LDAP(
                    self.ssp.GSS_Unwrap(
                        self.sspcontext,
                        resp.Buffer,
                    )
                )
            else:
                resp = None
        if self.verb:
            if not resp:
                print(conf.color_theme.fail("! Bad response."))
            else:
                print(
                    conf.color_theme.success(
                        "<< %s"
                        % (
                            resp.protocolOp.__class__.__name__
                            if LDAP in resp
                            else resp.__class__.__name__
                        )
                    )
                )
        return resp

    def bind(
        self,
        mech,
        ssp=None,
        sign=False,
        encrypt=False,
        simple_username=None,
        simple_password=None,
    ):
        """
        Send Bind request.

        :param mech: one of LDAP_BIND_MECHS
        :param ssp: the SSP object to use for binding

        :param sign: request signing when binding
        :param encrypt: request encryption when binding

        :
        This acts differently based on the :mech: provided during initialization.
        """
        # Store and check consistency
        self.mech = mech
        self.ssp = ssp  # type: SSP
        self.sign = sign
        self.encrypt = encrypt

        assert isinstance(mech, LDAP_BIND_MECHS)
        if mech == LDAP_BIND_MECHS.SASL_GSSAPI:
            from scapy.layers.kerberos import KerberosSSP

            if not isinstance(self.ssp, KerberosSSP):
                raise ValueError("Only raw KerberosSSP is supported with SASL_GSSAPI !")
        elif mech == LDAP_BIND_MECHS.SASL_GSS_SPNEGO:
            from scapy.layers.spnego import SPNEGOSSP

            if not isinstance(self.ssp, SPNEGOSSP):
                raise ValueError("Only SPNEGOSSP is supported with SASL_GSS_SPNEGO !")
        elif mech == LDAP_BIND_MECHS.SICILY:
            from scapy.layers.ntlm import NTLMSSP

            if not isinstance(self.ssp, NTLMSSP):
                raise ValueError("Only raw NTLMSSP is supported with SICILY !")
            if self.sign and not self.encrypt:
                raise ValueError(
                    "NTLM on LDAP does not support signing without encryption !"
                )
        elif mech == LDAP_BIND_MECHS.NONE:
            if self.sign or self.encrypt:
                raise ValueError(
                    "Cannot use 'sign' or 'encrypt' with unauthenticated (NONE) !"
                )
        if self.ssp is not None and mech in [
            LDAP_BIND_MECHS.NONE,
            LDAP_BIND_MECHS.SIMPLE,
        ]:
            raise ValueError("%s cannot be used with a ssp !" % mech.value)

        # Now perform the bind, depending on the mech
        if self.mech == LDAP_BIND_MECHS.SIMPLE:
            # Simple binding
            resp = self.sr1(
                LDAP_BindRequest(
                    bind_name=ASN1_STRING(simple_username or ""),
                    authentication=LDAP_Authentication_simple(
                        simple_password or "",
                    ),
                )
            )
            if (
                LDAP not in resp
                or not isinstance(resp.protocolOp, LDAP_BindResponse)
                or resp.protocolOp.resultCode != 0
            ):
                if self.verb:
                    resp.show()
                raise RuntimeError("LDAP simple bind failed !")
        elif self.mech == LDAP_BIND_MECHS.SICILY:
            # [MS-ADTS] sect 5.1.1.1.3
            # 1. Package Discovery
            resp = self.sr1(
                LDAP_BindRequest(
                    bind_name=ASN1_STRING(b""),
                    authentication=LDAP_Authentication_sicilyPackageDiscovery(b""),
                )
            )
            if resp.protocolOp.resultCode != 0:
                resp.show()
                raise RuntimeError("Sicily package discovery failed !")
            # 2. First exchange: Negotiate
            self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                self.sspcontext,
                req_flags=(
                    GSS_C_FLAGS.GSS_C_REPLAY_FLAG
                    | GSS_C_FLAGS.GSS_C_SEQUENCE_FLAG
                    | GSS_C_FLAGS.GSS_C_MUTUAL_FLAG
                    | (GSS_C_FLAGS.GSS_C_INTEG_FLAG if self.sign else 0)
                    | (GSS_C_FLAGS.GSS_C_CONF_FLAG if self.encrypt else 0)
                ),
            )
            resp = self.sr1(
                LDAP_BindRequest(
                    bind_name=ASN1_STRING(b"NTLM"),
                    authentication=LDAP_Authentication_sicilyNegotiate(
                        bytes(token),
                    ),
                )
            )
            val = resp.protocolOp.serverCreds
            if not val:
                resp.show()
                raise RuntimeError("Sicily negotiate failed !")
            # 3. Second exchange: Response
            self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                self.sspcontext, GSSAPI_BLOB(val)
            )
            resp = self.sr1(
                LDAP_BindRequest(
                    bind_name=ASN1_STRING(b"NTLM"),
                    authentication=LDAP_Authentication_sicilyResponse(
                        bytes(token),
                    ),
                )
            )
            if resp.protocolOp.resultCode != 0:
                resp.show()
                raise RuntimeError("Sicily response failed !")
        elif self.mech in [
            LDAP_BIND_MECHS.SASL_GSS_SPNEGO,
            LDAP_BIND_MECHS.SASL_GSSAPI,
        ]:
            # GSSAPI or SPNEGO
            self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                self.sspcontext,
                req_flags=(
                    # Required flags for GSSAPI: RFC4752 sect 3.1
                    GSS_C_FLAGS.GSS_C_REPLAY_FLAG
                    | GSS_C_FLAGS.GSS_C_SEQUENCE_FLAG
                    | GSS_C_FLAGS.GSS_C_MUTUAL_FLAG
                    | (GSS_C_FLAGS.GSS_C_INTEG_FLAG if self.sign else 0)
                    | (GSS_C_FLAGS.GSS_C_CONF_FLAG if self.encrypt else 0)
                ),
            )
            while token:
                resp = self.sr1(
                    LDAP_BindRequest(
                        bind_name=ASN1_STRING(b""),
                        authentication=LDAP_Authentication_SaslCredentials(
                            mechanism=ASN1_STRING(self.mech.value),
                            credentials=ASN1_STRING(bytes(token)),
                        ),
                    )
                )
                if not isinstance(resp.protocolOp, LDAP_BindResponse):
                    if self.verb:
                        print("%s bind failed !" % self.mech.name)
                        resp.show()
                    return
                val = resp.protocolOp.serverSaslCredsData
                if not val:
                    status = resp.protocolOp.resultCode
                    break
                self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                    self.sspcontext, GSSAPI_BLOB(val)
                )
        else:
            status = GSS_S_COMPLETE
        if status != GSS_S_COMPLETE:
            resp.show()
            raise RuntimeError("%s bind failed !" % self.mech.name)
        elif self.mech == LDAP_BIND_MECHS.SASL_GSSAPI:
            # GSSAPI has 2 extra exchanges
            # https://datatracker.ietf.org/doc/html/rfc2222#section-7.2.1
            resp = self.sr1(
                LDAP_BindRequest(
                    bind_name=ASN1_STRING(b""),
                    authentication=LDAP_Authentication_SaslCredentials(
                        mechanism=ASN1_STRING(self.mech.value),
                        credentials=None,
                    ),
                )
            )
            # Parse server-supported layers
            saslOptions = LDAP_SASL_GSSAPI_SsfCap(
                self.ssp.GSS_Unwrap(
                    self.sspcontext,
                    GSSAPI_BLOB_SIGNATURE(resp.protocolOp.serverSaslCredsData),
                )
            )
            if self.sign and not saslOptions.supported_security_layers.INTEGRITY:
                raise RuntimeError("GSSAPI SASL failed to negotiate INTEGRITY !")
            if (
                self.encrypt
                and not saslOptions.supported_security_layers.CONFIDENTIALITY
            ):
                raise RuntimeError("GSSAPI SASL failed to negotiate CONFIDENTIALITY !")
            # Announce client-supported layers
            saslOptions = LDAP_SASL_GSSAPI_SsfCap(
                supported_security_layers="+".join(
                    (["INTEGRITY"] if self.sign else [])
                    + (["CONFIDENTIALITY"] if self.encrypt else [])
                )
                if (self.sign or self.encrypt)
                else "NONE",
                # Same as server
                max_output_token_size=saslOptions.max_output_token_size,
            )
            resp = self.sr1(
                LDAP_BindRequest(
                    bind_name=ASN1_STRING(b""),
                    authentication=LDAP_Authentication_SaslCredentials(
                        mechanism=ASN1_STRING(self.mech.value),
                        credentials=self.ssp.GSS_Wrap(
                            self.sspcontext,
                            bytes(saslOptions),
                            # We still haven't finished negotiating
                            conf_req_flag=False,
                        ),
                    ),
                )
            )
            if resp.protocolOp.resultCode != 0:
                resp.show()
                raise RuntimeError(
                    "GSSAPI SASL failed to negotiate client security flags !"
                )
        # SASL wrapping is now available.
        self.sasl_wrap = self.encrypt or self.sign
        if self.sasl_wrap:
            self.sock.closed = True  # prevent closing by marking it as already closed.
            self.sock = StreamSocket(self.sock.ins, LDAP_SASL_Buffer)
        # Success.
        if self.verb:
            print("%s bind succeeded !" % self.mech.name)

    def close(self):
        if self.verb:
            print("X Connection closed\n")
        self.sock.close()
