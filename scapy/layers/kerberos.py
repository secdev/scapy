# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter
# This program is published under a GPLv2 license

"""
Kerberos V5

Implements parts of
- Kerberos Version 5 GSS-API: RFC1964
"""

from scapy.asn1.asn1 import ASN1_SEQUENCE, ASN1_Class_UNIVERSAL, ASN1_Codecs
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.asn1fields import (
    ASN1F_CHOICE,
    ASN1F_FLAGS,
    ASN1F_GENERAL_STRING,
    ASN1F_GENERALIZED_TIME,
    ASN1F_INTEGER,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_enum_INTEGER,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import bind_bottom_up, bind_layers
from scapy.volatile import GeneralizedTime

from scapy.layers.inet import UDP

# kerberos APPLICATION


class ASN1_Class_KRB(ASN1_Class_UNIVERSAL):
    name = "KERBEROS"
    APPLICATION = 0x60


class ASN1_GSSAPI_APPLICATION(ASN1_SEQUENCE):
    tag = ASN1_Class_KRB.APPLICATION


class BERcodec_GSSAPI_APPLICATION(BERcodec_SEQUENCE):
    tag = ASN1_Class_KRB.APPLICATION


class ASN1F_KRB_APPLICATION(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_KRB.APPLICATION

# sect 5.2


KerberosString = ASN1F_GENERAL_STRING
Realm = KerberosString
Int32 = ASN1F_INTEGER
UInt32 = ASN1F_INTEGER


class PrincipalName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("nameType", 0, explicit_tag=0xa0),
        ASN1F_SEQUENCE_OF(
            "nameString",
            [],
            KerberosString,
            explicit_tag=0xa1
        )
    )


KerberosTime = ASN1F_GENERALIZED_TIME
Microseconds = ASN1F_INTEGER


class HostAddress(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("addrType", 0, explicit_tag=0xa0),
        ASN1F_STRING("address", "", explicit_tag=0xa1)
    )


HostAddresses = lambda name, **kwargs: ASN1F_SEQUENCE_OF(
    name,
    [],
    HostAddress,
    **kwargs
)


class AuthorizationDataItem(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("adType", 0, explicit_tag=0xa0),
        ASN1F_STRING("adData", "", explicit_tag=0xa1)
    )


AuthorizationData = lambda name, **kwargs: ASN1F_SEQUENCE_OF(
    name,
    [],
    AuthorizationDataItem,
    **kwargs
)
ADIFRELEVANT = AuthorizationData
Checksum = lambda **kwargs: ASN1F_SEQUENCE(
    Int32("chksumtype", 0, explicit_tag=0xa0),
    ASN1F_STRING("checksum", "", explicit_tag=0xa1),
    **kwargs
)
ADKDCIssued = ASN1F_SEQUENCE(
    Checksum(explicit_tag=0xa0),
    ASN1F_optional(
        Realm("iRealm", "", explicit_tag=0xa1),
    ),
    ASN1F_optional(
        ASN1F_PACKET("iSname", None, PrincipalName,
                     explicit_tag=0xa2)
    ),
    AuthorizationData("elements", explicit_tag=0xa3)
)
ASANDOR = ASN1F_SEQUENCE(
    Int32("conditionCount", 0, explicit_tag=0xa1),
    AuthorizationData("elements", explicit_tag=0xa1)
)
ADMANDATORYFORKDC = AuthorizationData


class PADATA(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("padataType", 0, explicit_tag=0xa1),
        ASN1F_STRING("padataValue", "", explicit_tag=0xa2)
    )


class EncryptedData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("etype", 0, explicit_tag=0xa0),
        ASN1F_optional(
            UInt32("kvno", 0, explicit_tag=0xa1)
        ),
        ASN1F_STRING("cipher", "", explicit_tag=0xa2)
    )


EncryptionKey = ASN1F_SEQUENCE(
    Int32("keytype", 0, explicit_tag=0x0),
    ASN1F_STRING("keyvalue", "", explicit_tag=0x1),
)
PAENCTIMESTAMP = EncryptedData
KerberosFlags = ASN1F_FLAGS

# sect 5.10

KRB_MSG_TYPES = {
    1: "Ticket",
    2: "Authenticator",
    3: "EncTicketPart",
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    20: "KRB-SAFE",
    21: "KRB-PRIV",
    22: "KRB-CRED",
    25: "EncASRepPart",
    26: "EncTGSRepPart",
    27: "EncApRepPart",
    28: "EncKrbPrivPart",
    29: "EnvKrbCredPart",
    30: "KRB-ERROR",
}

# sect 5.3


class KRB_Ticket(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("tktVno", 0, explicit_tag=0xa0),
            Realm("realm", "", explicit_tag=0xa1),
            ASN1F_PACKET("sname", None, PrincipalName,
                         explicit_tag=0xa2),
            ASN1F_PACKET("encPart", None, EncryptedData,
                         explicit_tag=0xa3),
        ),
        implicit_tag=1
    )

# sect 5.4.1


class KRB_KDC_REQ_BODY(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KerberosFlags("kdcOptions", "", [
            "reserved",
            "forwardable",
            "forwarded",
            "proxiable",
            "proxy",
            "allow-postdate",
            "postdated",
            "unused7",
            "renewable",
            "unused9",
            "unused10",
            "opt-hardware-auth",
            "unused12",
            "unused13",
            "constrained-delegation",
            "canonicalize",
            "request-anonymous",
        ] + ["unused%d" % i for i in range(17, 26)] + [
            "disable-transited-check",
            "renewable-ok",
            "enc-tkt-in-skey",
            "unused29",
            "renew",
            "validate"
        ],
            explicit_tag=0xa0),
        ASN1F_optional(
            ASN1F_PACKET("cname", None, PrincipalName,
                         explicit_tag=0xa1)
        ),
        Realm("realm", "", explicit_tag=0xa2),
        ASN1F_optional(
            ASN1F_PACKET("sname", None, PrincipalName,
                         explicit_tag=0xa3),
        ),
        ASN1F_optional(
            KerberosTime("from", GeneralizedTime(), explicit_tag=0xa4)
        ),
        KerberosTime("till", GeneralizedTime(), explicit_tag=0xa5),
        ASN1F_optional(
            KerberosTime("rtime", GeneralizedTime(), explicit_tag=0xa6)
        ),
        UInt32("nonce", 0, explicit_tag=0xa7),
        ASN1F_SEQUENCE_OF(
            "etype",
            [],
            Int32,
            explicit_tag=0xa8
        ),
        ASN1F_optional(
            HostAddresses("addresses", explicit_tag=0xa9),
        ),
        ASN1F_optional(
            ASN1F_PACKET("encAuthorizationData", None, EncryptedData,
                         explicit_tag=0xaa),
        ),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF(
                "additionalTickets",
                [],
                KRB_Ticket,
                explicit_tag=0xab
            )
        )
    )


KRB_KDC_REQ = ASN1F_SEQUENCE(
    ASN1F_INTEGER("pvno", 5, explicit_tag=0xa1),
    ASN1F_enum_INTEGER("msgType", 10, KRB_MSG_TYPES,
                       explicit_tag=0xa2),
    ASN1F_optional(
        ASN1F_SEQUENCE_OF("padata", [], PADATA,
                          explicit_tag=0xa3)
    ),
    ASN1F_PACKET("reqBody",
                 KRB_KDC_REQ_BODY(),
                 KRB_KDC_REQ_BODY,
                 explicit_tag=0xa4)
)


class KRB_AS_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        KRB_KDC_REQ,
        implicit_tag=10,
    )


class KRB_TGS_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        KRB_KDC_REQ,
        implicit_tag=12,
    )


# sect 5.4.2

KRB_KDC_REP = ASN1F_SEQUENCE(
    ASN1F_INTEGER("pvno", 5, explicit_tag=0xa0),
    ASN1F_enum_INTEGER("msgType", 11, KRB_MSG_TYPES,
                       explicit_tag=0xa1),
    ASN1F_optional(
        ASN1F_SEQUENCE_OF("padata", [], PADATA,
                          explicit_tag=0xa2),
    ),
    Realm("crealm", "", explicit_tag=0xa3),
    ASN1F_PACKET("cname", None, PrincipalName,
                 explicit_tag=0xa4),
    ASN1F_PACKET("ticket", None, KRB_Ticket,
                 explicit_tag=0xa5),
    ASN1F_PACKET("encPart", None, EncryptedData,
                 explicit_tag=0xa6),
)


class KRB_AS_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        KRB_KDC_REP,
        implicit_tag=11,
    )


class KRB_TGS_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        KRB_KDC_REP,
        implicit_tag=13,
    )


# sect 5.9.1

class KRB_ERROR(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xa0),
            ASN1F_enum_INTEGER("msgType", 30, KRB_MSG_TYPES,
                               explicit_tag=0xa1),
            ASN1F_optional(
                KerberosTime("ctime", 0, explicit_tag=0xa2),
            ),
            ASN1F_optional(
                Microseconds("cusec", 0, explicit_tag=0xa3),
            ),
            KerberosTime("stime", 0, explicit_tag=0xa4),
            Microseconds("susec", 0, explicit_tag=0xa5),
            ASN1F_INTEGER("errorCode", 0, explicit_tag=0xa6),
            ASN1F_optional(
                Realm("crealm", "", explicit_tag=0xa7)
            ),
            ASN1F_optional(
                ASN1F_PACKET("cname", None, PrincipalName,
                             explicit_tag=0xa8),
            ),
            Realm("realm", "", explicit_tag=0xa9),
            ASN1F_PACKET("sname", None, PrincipalName,
                         explicit_tag=0xaa),
            ASN1F_optional(
                KerberosString("eText", "", explicit_tag=0xab)
            ),
            ASN1F_optional(
                ASN1F_STRING("eData", "", explicit_tag=0xac)
            ),
        ),
        implicit_tag=30,
    )

# Entry class

# sect 5.10


class Kerberos(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "root",
        None,
        KRB_Ticket,  # [APPLICATION 1]
        KRB_AS_REQ,  # [APPLICATION 10]
        KRB_AS_REP,  # [APPLICATION 11]
        KRB_TGS_REQ,  # [APPLICATION 12]
        KRB_TGS_REP,  # [APPLICATION 13]
        KRB_ERROR,  # [APPLICATION 30]
    )


bind_bottom_up(UDP, Kerberos, sport=88)
bind_bottom_up(UDP, Kerberos, dport=88)
bind_layers(UDP, Kerberos, sport=88, dport=88)
