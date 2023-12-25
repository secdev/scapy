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
"""

import collections
import socket
import uuid

from scapy.ansmachine import AnsweringMachine
from scapy.asn1.asn1 import (
    ASN1_STRING,
    ASN1_SEQUENCE,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
)
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.asn1fields import (
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_INTEGER,
    ASN1F_NULL,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_SET_OF,
    ASN1F_STRING,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.config import conf
from scapy.error import log_runtime
from scapy.packet import bind_bottom_up, bind_layers
from scapy.supersocket import SimpleSocket

from scapy.layers.dns import dns_resolve
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.kerberos import _ASN1FString_PacketField
from scapy.layers.smb import (
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


class ASN1_Class_LDAP(ASN1_Class_UNIVERSAL):
    name = "LDAP"
    APPLICATION = 0x60


class ASN1_LDAP_APPLICATION(ASN1_SEQUENCE):
    tag = ASN1_Class_LDAP.APPLICATION


class BERcodec_LDAP_APPLICATION(BERcodec_SEQUENCE):
    tag = ASN1_Class_LDAP.APPLICATION


class ASN1F_LDAP_APPLICATION(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_LDAP.APPLICATION


# Bind operation
# https://datatracker.ietf.org/doc/html/rfc1777#section-4.1


class ASN1_Class_LDAP_Authentication(ASN1_Class_UNIVERSAL):
    name = "LDAP Authentication"
    simple = 0xA0
    krbv42LDAP = 0xA1
    krbv42DSA = 0xA2
    sasl = 0xA3


class ASN1_LDAP_Authentication_simple(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.simple


class BERcodec_LDAP_Authentication_simple(BERcodec_SEQUENCE):
    tag = ASN1_Class_LDAP_Authentication.simple


class ASN1F_LDAP_Authentication_simple(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.simple


class ASN1_LDAP_Authentication_krbv42LDAP(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class BERcodec_LDAP_Authentication_krbv42LDAP(BERcodec_SEQUENCE):
    tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class ASN1F_LDAP_Authentication_krbv42LDAP(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class ASN1_LDAP_Authentication_krbv42DSA(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42DSA


class BERcodec_LDAP_Authentication_krbv42DSA(BERcodec_SEQUENCE):
    tag = ASN1_Class_LDAP_Authentication.krbv42DSA


class ASN1F_LDAP_Authentication_krbv42DSA(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.krbv42DSA


_SASL_MECHANISMS = {b"GSS-SPNEGO": GSSAPI_BLOB}


class _SaslCredentialsField(_ASN1FString_PacketField):
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


class LDAP_SaslCredentials(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPString("mechanism", ""), _SaslCredentialsField("credentials", "")
    )


class LDAP_BindRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_LDAP_APPLICATION(
        ASN1F_INTEGER("version", 2),
        LDAPDN("bind_name", ""),
        ASN1F_CHOICE(
            "authentication",
            None,
            ASN1F_LDAP_Authentication_simple,
            ASN1F_LDAP_Authentication_krbv42LDAP,
            ASN1F_LDAP_Authentication_krbv42DSA,
            ASN1F_PACKET(
                "sasl", LDAP_SaslCredentials(), LDAP_SaslCredentials, implicit_tag=0xA3
            ),
        ),
        implicit_tag=0,
    )


class LDAP_BindResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_LDAP_APPLICATION(
        *(
            LDAPResult
            + (ASN1F_optional(ASN1F_STRING("serverSaslCreds", "", implicit_tag=0x87)),)
        ),
        implicit_tag=1,
    )


# Unbind operation
# https://datatracker.ietf.org/doc/html/rfc1777#section-4.2


class LDAP_UnbindRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_NULL("info", 0)


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
            implicit_tag=0x0,
        ),
        ASN1F_PACKET(
            "any", LDAP_SubstringFilterAny(), LDAP_SubstringFilterAny, implicit_tag=0x1
        ),
        ASN1F_PACKET(
            "final",
            LDAP_SubstringFilterFinal(),
            LDAP_SubstringFilterFinal,
            implicit_tag=0x2,
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
    ASN1_root = AttributeType("present", "")


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


class LDAP_Filter(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "filter",
        LDAP_FilterPresent(),
        ASN1F_PACKET("and_", None, LDAP_FilterAnd, implicit_tag=0xA0),
        ASN1F_PACKET("or_", None, LDAP_FilterOr, implicit_tag=0xA1),
        ASN1F_PACKET("not_", None, _LDAP_Filter, implicit_tag=0xA2),
        ASN1F_PACKET("equalityMatch", None, LDAP_FilterEqual, implicit_tag=0xA3),
        ASN1F_PACKET("substrings", None, LDAP_SubstringFilter, implicit_tag=0xA4),
        ASN1F_PACKET(
            "greaterOrEqual", None, LDAP_FilterGreaterOrEqual, implicit_tag=0xA5
        ),
        ASN1F_PACKET("lessOrEqual", None, LDAP_FilterLessOrEqual, implicit_tag=0xA6),
        ASN1F_PACKET("present", None, LDAP_FilterPresent, implicit_tag=0xA7),
        ASN1F_PACKET("approxMatch", None, LDAP_FilterApproxMatch, implicit_tag=0xA8),
    )


class LDAP_SearchRequestAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeType("type", "")


class LDAP_SearchRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_LDAP_APPLICATION(
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
        implicit_tag=3,
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
    ASN1_root = ASN1F_LDAP_APPLICATION(
        LDAPDN("objectName", ""),
        ASN1F_SEQUENCE_OF(
            "attributes",
            LDAP_SearchResponseEntryAttribute(),
            LDAP_SearchResponseEntryAttribute,
        ),
        implicit_tag=4,
    )


class LDAP_SearchResponseResultDone(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_LDAP_APPLICATION(
        *LDAPResult,
        implicit_tag=5,
    )


class LDAP_AbandonRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_LDAP_APPLICATION(
        ASN1F_INTEGER("messageID", 0),
        implicit_tag=0x10,
    )


# LDAP v3


class LDAP_Control(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPOID("controlType", ""),
        ASN1F_optional(
            ASN1F_BOOLEAN("criticality", False),
        ),
        ASN1F_optional(ASN1F_STRING("controlValue", "")),
    )


# LDAP


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
            # For some reason the unbind request is under the 0x40
            ASN1F_PACKET(
                "unbindRequest",
                LDAP_UnbindRequest(),
                LDAP_UnbindRequest,
                implicit_tag=0x42,
            ),
        ),
        # LDAP v3 only
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("Controls", None, LDAP_Control, implicit_tag=0xA0)
        ),
    )

    def answers(self, other):
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
    filter = "udp port 389"

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
        if CLDAP not in req or not isinstance(req.protocolOp, LDAP_SearchRequest):
            return False
        req = req.protocolOp
        return (
            req.attributes
            and req.attributes[0].type.val == b"Netlogon"
            and req.filter
            and isinstance(req.filter.filter, LDAP_FilterAnd)
            and any(
                x.filter.attributeType.val == b"NtVer" for x in req.filter.filter.and_
            )
        )

    def make_reply(self, req):
        if IPv6 in req:
            resp = IPv6(dst=req[IPv6].src, src=self.src_ip6)
        else:
            resp = IP(dst=req[IP].src, src=self.src_ip)
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
                                                NtVersion=5,
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


_located_dc = collections.namedtuple("LocatedDC", ["ip", "samlogon"])
_dclocatorcache = conf.netcache.new_cache("dclocator", 600)


@conf.commands.register
def dclocator(realm, qtype="A", mode="ldap", port=None, timeout=1, debug=0):
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
    # Check cache
    cache_ident = ";".join([realm, qtype, mode])
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
                                                    b"\x16\x00\x00!"
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
                                NETLOGON_SAM_LOGON_RESPONSE_EX(x.values[0].value.val)
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
