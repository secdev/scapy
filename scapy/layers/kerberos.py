# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter
# This program is published under a GPLv2 license

"""
Kerberos V5

Implements parts of
- Kerberos Network Authentication Service (V5): RFC4120
- Kerberos Version 5 GSS-API: RFC1964, RFC4121
- Kerberos Pre-Authentication: RFC6113 (FAST)
"""

import scapy.asn1.mib  # noqa: F401
from scapy.asn1.asn1 import (
    ASN1_SEQUENCE,
    ASN1_STRING,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
)
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.asn1fields import (
    ASN1F_CHOICE,
    ASN1F_FLAGS,
    ASN1F_GENERAL_STRING,
    ASN1F_GENERALIZED_TIME,
    ASN1F_INTEGER,
    ASN1F_OID,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_enum_INTEGER,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.fields import (
    ByteField,
    FlagsField,
    LEIntField,
    LenField,
    LEShortEnumField,
    LEShortField,
    PadField,
    ShortField,
    StrFixedLenEnumField,
    XStrFixedLenField,
)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_bottom_up, bind_layers
from scapy.volatile import GeneralizedTime

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
        Int32("nameType", 0, explicit_tag=0xA0),
        ASN1F_SEQUENCE_OF("nameString", [], KerberosString, explicit_tag=0xA1),
    )


KerberosTime = ASN1F_GENERALIZED_TIME
Microseconds = ASN1F_INTEGER


class HostAddress(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("addrType", 0, explicit_tag=0xA0),
        ASN1F_STRING("address", "", explicit_tag=0xA1),
    )


HostAddresses = lambda name, **kwargs: ASN1F_SEQUENCE_OF(
    name, [], HostAddress, **kwargs
)


class AuthorizationDataItem(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("adType", 0, explicit_tag=0xA0),
        ASN1F_STRING("adData", "", explicit_tag=0xA1),
    )


AuthorizationData = lambda name, **kwargs: ASN1F_SEQUENCE_OF(
    name, [], AuthorizationDataItem, **kwargs
)
ADIFRELEVANT = AuthorizationData
Checksum = lambda **kwargs: ASN1F_SEQUENCE(
    Int32("chksumtype", 0, explicit_tag=0xA0),
    ASN1F_STRING("checksum", "", explicit_tag=0xA1),
    **kwargs
)
ADKDCIssued = ASN1F_SEQUENCE(
    Checksum(explicit_tag=0xA0),
    ASN1F_optional(
        Realm("iRealm", "", explicit_tag=0xA1),
    ),
    ASN1F_optional(ASN1F_PACKET("iSname", None, PrincipalName, explicit_tag=0xA2)),
    AuthorizationData("elements", explicit_tag=0xA3),
)
ASANDOR = ASN1F_SEQUENCE(
    Int32("conditionCount", 0, explicit_tag=0xA1),
    AuthorizationData("elements", explicit_tag=0xA1),
)
ADMANDATORYFORKDC = AuthorizationData


_KRB_E_TYPES = {
    0x1: "DES",
    0x10: "3DES",
    0x11: "AES-128",
    0x12: "AES-256",
    0x17: "RC4",
}


class EncryptedData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("etype", 0x1, _KRB_E_TYPES, explicit_tag=0xA0),
        ASN1F_optional(UInt32("kvno", 0, explicit_tag=0xA1)),
        ASN1F_STRING("cipher", "", explicit_tag=0xA2),
    )


EncryptionKey = lambda **kwargs: ASN1F_SEQUENCE(
    Int32("keytype", 0, explicit_tag=0x0),
    ASN1F_STRING("keyvalue", "", explicit_tag=0x1),
    **kwargs
)
PAENCTIMESTAMP = EncryptedData
KerberosFlags = ASN1F_FLAGS


_PADATA_TYPES = {
    1: "PA-TGS-REQ",
    2: "PA-ENC-TIMESTAMP",
    3: "PA-PW-SALT",
    11: "PA-ETYPE-INFO",
    16: "PA-PK-AS-REQ",
    17: "PA-PK-AS-REP",
    19: "PA-ETYPE-INFO2",
    133: "PA-FX-COOKIE",
    134: "PA-AUTHENTICATION-SET",
    135: "PA-AUTH-SET-SELECTED",
    136: "PA-FX-FAST",
    137: "PA-FX-ERROR",
}

_PADATA_CLASSES = {
    # Filled elsewhere in this file
}


# RFC4120


class _PADATA_value_Field(ASN1F_STRING):
    """
    A special field that properly dispatches PA-DATA values according to
    padata-type and if the paquet is a request or a response.
    """

    holds_packets = 1

    def m2i(self, pkt, s):
        val = super(_PADATA_value_Field, self).m2i(pkt, s)
        if pkt.padataType.val in _PADATA_CLASSES:
            cls = _PADATA_CLASSES[pkt.padataType.val]
            if isinstance(cls, tuple):
                is_reply = isinstance(pkt.underlayer, (KRB_AS_REP, KRB_TGS_REP))
                cls = cls[is_reply]
            return cls(val[0].val), b""
        return val

    def i2m(self, pkt, val):
        if isinstance(val, ASN1_Packet):
            val = ASN1_STRING(bytes(val))
        return super(_PADATA_value_Field, self).i2m(pkt, val)


class PADATA(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("padataType", 0, _PADATA_TYPES, explicit_tag=0xA1),
        _PADATA_value_Field(
            "padataValue",
            "",
            explicit_tag=0xA2,
        ),
    )


# PADATA Extended with RFC6113

# RFC6113 sect


class PA_AUTHENTICATION_SET_ELEM(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("paType", 0, explicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_STRING("paHint", "", explicit_tag=0xA1),
        ),
        ASN1F_optional(
            ASN1F_STRING("paValue", "", explicit_tag=0xA2),
        ),
    )


class PA_AUTHENTICATION_SET(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "elems", [PA_AUTHENTICATION_SET_ELEM()], PA_AUTHENTICATION_SET_ELEM
    )


_PADATA_CLASSES[134] = PA_AUTHENTICATION_SET


# RFC6113 sect 5.4.1


class KrbFastArmor(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("armorType", 0, explicit_tag=0xA0),
        ASN1F_STRING("armorValue", "", explicit_tag=0xA1),
    )


# RFC6113 sect 5.4.2


class KrbFastArmoredReq(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_optional(
                ASN1F_PACKET("armor", KrbFastArmor(), KrbFastArmor, explicit_tag=0xA0)
            ),
            Checksum(explicit_tag=0xA1),
            ASN1F_PACKET("encFastReq", None, EncryptedData, explicit_tag=0xA2),
        )
    )


class PA_FX_FAST_REQUEST(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "armoredData",
        ASN1_STRING(""),
        ASN1F_PACKET("req", KrbFastArmoredReq, KrbFastArmoredReq, implicit_tag=0xA0),
    )


class KrbFastReq(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KerberosFlags(
            "fastOptions",
            "",
            [
                "RESERVED",
                "hide-client-names",
            ] +
            ["res%d" % i for i in range(2, 16)] +
            ["kdc-follow-referrals"],
            explicit_tag=0xA0,
        ),
        ASN1F_SEQUENCE_OF("padata", [PADATA()], PADATA, explicit_tag=0xA1),
        ASN1F_PACKET("reqBody", None, EncryptedData, explicit_tag=0xA2),
    )


# RFC6113 sect 5.4.3


class KrbFastArmoredRep(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_PACKET("encFastRep", None, EncryptedData, explicit_tag=0xA0),
        )
    )


class PA_FX_FAST_REPLY(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "armoredData",
        ASN1_STRING(""),
        ASN1F_PACKET("req", KrbFastArmoredRep, KrbFastArmoredRep, implicit_tag=0xA0),
    )


class KrbFastFinished(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Microseconds("timestamp", 0, explicit_tag=0xA0),
        KerberosTime("usec", GeneralizedTime(), explicit_tag=0xA1),
        Realm("crealm", "", explicit_tag=0xA2),
        ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA3),
        Checksum(explicit_tag=0xA4),
    )


class KrbFastResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE_OF("padata", [PADATA()], PADATA, explicit_tag=0xA0),
        ASN1F_optional(EncryptionKey(explicit_tag=0xA1)),
        ASN1F_optional(
            ASN1F_PACKET(
                "finished", KrbFastFinished(), KrbFastFinished, explicit_tag=0xA2
            )
        ),
        UInt32("nonce", 0, explicit_tag=0xA3),
    )


_PADATA_CLASSES[136] = (PA_FX_FAST_REQUEST, PA_FX_FAST_REPLY)

# RFC 4556


# sect 3.2.1


class ExternalPrincipalIdentifier(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_STRING("subjectName", "", implicit_tag=0xA0),
        ),
        ASN1F_optional(
            ASN1F_STRING("issuerAndSerialNumber", "", implicit_tag=0xA1),
        ),
        ASN1F_optional(
            ASN1F_STRING("subjectKeyIdentifier", "", implicit_tag=0xA2),
        ),
    )


class PA_PK_AS_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING("signedAuthpack", "", implicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF(
                "trustedCertifiers",
                [ExternalPrincipalIdentifier()],
                ExternalPrincipalIdentifier,
                explicit_tag=0xA1,
            ),
        ),
        ASN1F_optional(
            ASN1F_STRING("kdcPkId", "", implicit_tag=0xA2),
        ),
    )


_PADATA_CLASSES[16] = PA_PK_AS_REQ

# sect 3.2.3


class DHRepInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING("dhSignedData", "", implicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_STRING("serverDHNonce", "", explicit_tag=0xA1),
        ),
    )


class EncKeyPack(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING("encKeyPack", "")


class PA_PK_AS_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "rep",
        ASN1_STRING(""),
        ASN1F_PACKET("dhInfo", DHRepInfo(), DHRepInfo, explicit_tag=0xA0),
        ASN1F_PACKET("encKeyPack", EncKeyPack(), EncKeyPack, explicit_tag=0xA1),
    )


_PADATA_CLASSES[17] = PA_PK_AS_REP

# Back to RFC4120

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
            ASN1F_INTEGER("tktVno", 0, explicit_tag=0xA0),
            Realm("realm", "", explicit_tag=0xA1),
            ASN1F_PACKET("sname", None, PrincipalName, explicit_tag=0xA2),
            ASN1F_PACKET("encPart", None, EncryptedData, explicit_tag=0xA3),
        ),
        implicit_tag=1,
    )


# sect 5.4.1


class KRB_KDC_REQ_BODY(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KerberosFlags(
            "kdcOptions",
            "",
            [
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
            ] +
            ["unused%d" % i for i in range(17, 26)] +
            [
                "disable-transited-check",
                "renewable-ok",
                "enc-tkt-in-skey",
                "unused29",
                "renew",
                "validate",
            ],
            explicit_tag=0xA0,
        ),
        ASN1F_optional(ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA1)),
        Realm("realm", "", explicit_tag=0xA2),
        ASN1F_optional(
            ASN1F_PACKET("sname", None, PrincipalName, explicit_tag=0xA3),
        ),
        ASN1F_optional(KerberosTime("from", GeneralizedTime(), explicit_tag=0xA4)),
        KerberosTime("till", GeneralizedTime(), explicit_tag=0xA5),
        ASN1F_optional(KerberosTime("rtime", GeneralizedTime(), explicit_tag=0xA6)),
        UInt32("nonce", 0, explicit_tag=0xA7),
        ASN1F_SEQUENCE_OF("etype", [], Int32, explicit_tag=0xA8),
        ASN1F_optional(
            HostAddresses("addresses", explicit_tag=0xA9),
        ),
        ASN1F_optional(
            ASN1F_PACKET(
                "encAuthorizationData", None, EncryptedData, explicit_tag=0xAA
            ),
        ),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("additionalTickets", [], KRB_Ticket, explicit_tag=0xAB)
        ),
    )


KRB_KDC_REQ = ASN1F_SEQUENCE(
    ASN1F_INTEGER("pvno", 5, explicit_tag=0xA1),
    ASN1F_enum_INTEGER("msgType", 10, KRB_MSG_TYPES, explicit_tag=0xA2),
    ASN1F_optional(ASN1F_SEQUENCE_OF("padata", [], PADATA, explicit_tag=0xA3)),
    ASN1F_PACKET("reqBody", KRB_KDC_REQ_BODY(), KRB_KDC_REQ_BODY, explicit_tag=0xA4),
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
    ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
    ASN1F_enum_INTEGER("msgType", 11, KRB_MSG_TYPES, explicit_tag=0xA1),
    ASN1F_optional(
        ASN1F_SEQUENCE_OF("padata", [], PADATA, explicit_tag=0xA2),
    ),
    Realm("crealm", "", explicit_tag=0xA3),
    ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA4),
    ASN1F_PACKET("ticket", None, KRB_Ticket, explicit_tag=0xA5),
    ASN1F_PACKET("encPart", None, EncryptedData, explicit_tag=0xA6),
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


# sect 5.5.1


class KRB_AP_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 14, KRB_MSG_TYPES, explicit_tag=0xA1),
            KerberosFlags(
                "apOptions",
                "",
                [
                    "reserved",
                    "use-session-key",
                    "mutual-required",
                ],
                explicit_tag=0xA2,
            ),
            ASN1F_PACKET("ticket", None, KRB_Ticket, explicit_tag=0xA3),
            ASN1F_PACKET("authenticator", None, EncryptedData, explicit_tag=0xA4),
        ),
        implicit_tag=14,
    )


_PADATA_CLASSES[1] = KRB_AP_REQ


class KRB_Authenticator(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("authenticatorPvno", 5, explicit_tag=0xA0),
            Realm("crealm", "", explicit_tag=0xA1),
            ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA2),
            ASN1F_optional(Checksum(explicit_tag=0x3)),
            Microseconds("cusec", 0, explicit_tag=0xA4),
            KerberosTime("ctime", GeneralizedTime(), explicit_tag=0xA5),
            ASN1F_optional(
                EncryptionKey(explicit_tag=0xA6),
            ),
            ASN1F_optional(
                UInt32("seqNumber", 0, explicit_tag=0xA7),
            ),
            ASN1F_optional(AuthorizationData("authorizationData", explicit_tag=0xA8)),
        ),
        implicit_tag=2,
    )


# sect 5.5.2


class KRB_AP_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 15, KRB_MSG_TYPES, explicit_tag=0xA1),
            ASN1F_PACKET("encPart", None, EncryptedData, explicit_tag=0xA2),
        ),
        implicit_tag=15,
    )


# sect 5.9.1


class KRB_ERROR(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 30, KRB_MSG_TYPES, explicit_tag=0xA1),
            ASN1F_optional(
                KerberosTime("ctime", GeneralizedTime(), explicit_tag=0xA2),
            ),
            ASN1F_optional(
                Microseconds("cusec", 0, explicit_tag=0xA3),
            ),
            KerberosTime("stime", GeneralizedTime(), explicit_tag=0xA4),
            Microseconds("susec", 0, explicit_tag=0xA5),
            ASN1F_INTEGER("errorCode", 0, explicit_tag=0xA6),
            ASN1F_optional(Realm("crealm", "", explicit_tag=0xA7)),
            ASN1F_optional(
                ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA8),
            ),
            Realm("realm", "", explicit_tag=0xA9),
            ASN1F_PACKET("sname", None, PrincipalName, explicit_tag=0xAA),
            ASN1F_optional(KerberosString("eText", "", explicit_tag=0xAB)),
            ASN1F_optional(ASN1F_STRING("eData", "", explicit_tag=0xAC)),
        ),
        implicit_tag=30,
    )


# Kerberos V5 GSS-API - RFC1964 and RFC4121

_TOK_IDS = {
    # RFC 1964
    b"\x01\x00": "GSS_InitialContextToken_1964 (AP-REQ)",
    b"\x02\x00": "GSS_InitialContextToken_1964 (AP-REP)",
    b"\x03\x00": "GSS_InitialContextToken_1964 (ERROR)",
    b"\x01\x01": "GSS_GetMIC-RFC1964",
    b"\x02\x01": "GSS_Wrap-RFC1964",
    b"\x01\x02": "GSS_Delete_sec_context-RFC1964",
    # RFC 4121
    b"\x04\x04": "GSS_GetMIC",
    b"\x05\x04": "GSS_Wrap",
}
_SGN_ALGS = {
    0: "DES MAC MD5",
    1: "MD2.5",
    2: "DES MAC",
}
_SEAL_ALGS = {
    0: "DES",
    0xFFFF: "none",
}


# RFC 1964 - sect 1.1


class KRB5_InitialContextToken_innerContextToken(Packet):
    name = "Kerberos v5 InitialContextToken innerContextToken (RFC1964)"
    fields_desc = [
        StrFixedLenEnumField("TOK_ID", b"\x01\x01", _TOK_IDS, length=2),
    ]


# RFC 1964 - sect 1.1


class KRB_InitialContextToken(ASN1_Packet):
    name = "Kerberos v5 InitialContextToken (RFC1964)"
    # It's funny how useless this wrapping is
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_OID("MechType", "1.2.840.113554.1.2.2"),
        ASN1F_PACKET(
            "innerContextToken",
            KRB5_InitialContextToken_innerContextToken(),
            KRB5_InitialContextToken_innerContextToken,
            implicit_tag=0x0,
        ),
        implicit_tag=0,
    )


# RFC 1964 - sect 1.2.1


class KRB5_GSS_GetMIC_RFC1964(Packet):
    name = "Kerberos v5 GSS_GetMIC (RFC1964)"
    fields_desc = [
        StrFixedLenEnumField("TOK_ID", b"\x01\x01", _TOK_IDS, length=2),
        LEShortEnumField("SGN_ALG", 0, _SGN_ALGS),
        LEIntField("reserved", 0xFFFFFFFF),
        XStrFixedLenField("SND_SEQ", b"", length=8),
        PadField(  # sect 1.2.2.3
            XStrFixedLenField("SGN_CKSUM", b"", length=8),
            align=8,
            padwith=b"\x04",
        ),
    ]


# RFC 1964 - sect 1.2.2


class KRB5_GSS_Wrap_RFC1964(Packet):
    name = "Kerberos v5 GSS_Wrap (RFC1964)"
    fields_desc = [
        StrFixedLenEnumField("TOK_ID", b"\x02\x01", _TOK_IDS, length=2),
        LEShortEnumField("SGN_ALG", 0, _SGN_ALGS),
        LEShortEnumField("SEAL_ALG", 0, _SEAL_ALGS),
        LEShortField("reserved", 0xFFFF),
        XStrFixedLenField("SND_SEQ", b"", length=8),
        PadField(  # sect 1.2.2.3
            XStrFixedLenField("SGN_CKSUM", b"", length=8),
            align=8,
            padwith=b"\x04",
        ),
        # sect 1.2.2.3
        XStrFixedLenField("CONFOUNDER", b"", length=8),
    ]


# RFC 1964 - sect 1.2.2


class KRB5_GSS_Delete_sec_context_RFC1964(Packet):
    name = "Kerberos v5 GSS_Delete_sec_context (RFC1964)"
    TOK_ID = b"\x01\x02"
    fields_desc = KRB5_GSS_GetMIC_RFC1964.fields_desc


# RFC 4121 - sect 4.2.2
_KRB5_GSS_Flags = [
    "SentByAcceptor",
    "Sealed",
    "AcceptorSubkey",
]


# RFC 4121 - sect 4.2.6.1


class KRB5_GSS_GetMIC(Packet):
    name = "Kerberos v5 GSS_GetMIC"
    fields_desc = [
        StrFixedLenEnumField("TOK_ID", b"\x04\x04", _TOK_IDS, length=2),
        FlagsField("Flags", 8, 0, _KRB5_GSS_Flags),
        LEIntField("reserved", 0xFFFFFFFF),
        XStrFixedLenField("SND_SEQ", b"", length=8),
        PadField(
            XStrFixedLenField("SGN_CKSUM", b"", length=8),
            align=8,
            padwith=b"\x04",
        ),
    ]


# RFC 4121 - sect 4.2.6.2


class KRB5_GSS_Wrap(Packet):
    name = "Kerberos v5 GSS_Wrap"
    fields_desc = [
        StrFixedLenEnumField("TOK_ID", b"\x05\x04", _TOK_IDS, length=2),
        FlagsField("Flags", 8, 0, _KRB5_GSS_Flags),
        ByteField("reserved", 0xFF),
        ShortField("EC", 0),  # Big endian
        ShortField("RRC", 0),  # Big endian
        XStrFixedLenField("SND_SEQ", b"", length=8),
        PadField(
            XStrFixedLenField("SGN_CKSUM", b"", length=8),
            align=8,
            padwith=b"\x04",
        ),
    ]


# Main classes


class KRB5_GSS(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            if _pkt[:2] == b"\x01\x01":
                return KRB5_GSS_GetMIC_RFC1964
            elif _pkt[:2] == b"\x02\x01":
                return KRB5_GSS_Wrap_RFC1964
            elif _pkt[:2] == b"\x01\x02":
                return KRB5_GSS_Delete_sec_context_RFC1964
            elif _pkt[:2] in [b"\x01\x00", "\x02\x00", "\x03\x00"]:
                return KRB5_InitialContextToken_innerContextToken
            elif _pkt[:2] == b"\x04\x04":
                return KRB5_GSS_GetMIC
            elif _pkt[:2] == b"\x05\x04":
                return KRB5_GSS_Wrap
        return KRB5_GSS_Wrap


# Entry class

# RFC4120 sect 5.10


class Kerberos(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "root",
        None,
        KRB_InitialContextToken,  # [APPLICATION 0]
        KRB_Ticket,  # [APPLICATION 1]
        KRB_Authenticator,  # [APPLICATION 2]
        KRB_AS_REQ,  # [APPLICATION 10]
        KRB_AS_REP,  # [APPLICATION 11]
        KRB_TGS_REQ,  # [APPLICATION 12]
        KRB_TGS_REP,  # [APPLICATION 13]
        KRB_AP_REQ,  # [APPLICATION 14]
        KRB_AP_REP,  # [APPLICATION 15]
        KRB_ERROR,  # [APPLICATION 30]
    )


bind_bottom_up(UDP, Kerberos, sport=88)
bind_bottom_up(UDP, Kerberos, dport=88)
bind_layers(UDP, Kerberos, sport=88, dport=88)

bind_layers(KRB5_InitialContextToken_innerContextToken, Kerberos)
bind_layers(KRB5_GSS_GetMIC_RFC1964, Kerberos)
bind_layers(KRB5_GSS_Wrap_RFC1964, Kerberos)
bind_layers(KRB5_GSS_Wrap_RFC1964, Kerberos)


# RFC4120 sect 7.2.2


class KerberosTCPHeader(Packet):
    fields_desc = [LenField("len", None, fmt="!I")]


bind_layers(KerberosTCPHeader, Kerberos)

bind_bottom_up(TCP, KerberosTCPHeader, sport=88)
bind_layers(TCP, KerberosTCPHeader, dport=88)
