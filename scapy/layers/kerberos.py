# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

r"""
Kerberos V5

Implements parts of:

- Kerberos Network Authentication Service (V5): RFC4120
- Kerberos Version 5 GSS-API: RFC1964, RFC4121
- Kerberos Pre-Authentication: RFC6113 (FAST)

You will find more complete documentation for this layer over
`Kerberos <https://scapy.readthedocs.io/en/latest/layers/kerberos.html>`_

Example decryption:

>>> from scapy.libs.rfc3961 import Key, EncryptionType
>>> pkt = Ether(hex_bytes("525400695813525400216c2b08004500015da71840008006dc\
83c0a87a9cc0a87a11c209005854f6ab2392c25bd650182014b6e00000000001316a8201\
2d30820129a103020105a20302010aa3633061304ca103020102a24504433041a0030201\
12a23a043848484decb01c9b62a1cabfbc3f2d1ed85aa5e093ba8358a8cea34d4393af93\
bf211e274fa58e814878db9f0d7a28d94e7327660db4f3704b3011a10402020080a20904\
073005a0030101ffa481b73081b4a00703050040810010a1123010a003020101a1093007\
1b0577696e3124a20e1b0c444f4d41494e2e4c4f43414ca321301fa003020102a1183016\
1b066b72627467741b0c444f4d41494e2e4c4f43414ca511180f32303337303931333032\
343830355aa611180f32303337303931333032343830355aa7060204701cc5d1a8153013\
0201120201110201170201180202ff79020103a91d301b3019a003020114a11204105749\
4e31202020202020202020202020"))
>>> enc = pkt[Kerberos].root.padata[0].padataValue
>>> k = Key(enc.etype.val, key=hex_bytes("7fada4e566ae4fb270e2800a23a\
e87127a819d42e69b5e22de0ddc63da80096d"))
>>> enc.decrypt(k)
"""

from collections import namedtuple
from datetime import datetime, timedelta
import re
import socket
import struct

import scapy.asn1.mib  # noqa: F401
from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_GENERAL_STRING,
    ASN1_GENERALIZED_TIME,
    ASN1_INTEGER,
    ASN1_SEQUENCE,
    ASN1_STRING,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
)
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.asn1fields import (
    ASN1F_BOOLEAN,
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
from scapy.automaton import Automaton, ATMT
from scapy.compat import bytes_encode
from scapy.error import log_runtime
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
from scapy.packet import Packet, bind_bottom_up, bind_layers
from scapy.supersocket import StreamSocket
from scapy.volatile import GeneralizedTime, RandNum

from scapy.layers.inet import TCP, UDP

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


# RFC4120 sect 5.2


KerberosString = ASN1F_GENERAL_STRING
Realm = KerberosString
Int32 = ASN1F_INTEGER
UInt32 = ASN1F_INTEGER


class PrincipalName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "nameType",
            0,
            {
                0: "NT-UNKNOWN",
                1: "NT-PRINCIPAL",
                2: "NT-SRV-INST",
                3: "NT-SRV-HST",
                4: "NT-SRV-XHST",
                5: "NT-UID",
                6: "NT-X500-PRINCIPAL",
                7: "NT-SMTP-NAME",
                10: "NT-ENTERPRISE",
            },
            explicit_tag=0xA0,
        ),
        ASN1F_SEQUENCE_OF("nameString", [], KerberosString, explicit_tag=0xA1),
    )


KerberosTime = ASN1F_GENERALIZED_TIME
Microseconds = ASN1F_INTEGER


class HostAddress(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "addrType",
            0,
            {
                # RFC4120 sect 7.5.3
                2: "IPv4",
                3: "Directional",
                5: "ChaosNet",
                6: "XNS",
                7: "ISO",
                12: "DECNET Phase IV",
                16: "AppleTalk DDP",
                20: "NetBios",
                24: "IPv6",
            },
            explicit_tag=0xA0,
        ),
        ASN1F_STRING("address", "", explicit_tag=0xA1),
    )


HostAddresses = lambda name, **kwargs: ASN1F_SEQUENCE_OF(
    name, [], HostAddress, **kwargs
)

Checksum = lambda **kwargs: ASN1F_SEQUENCE(
    ASN1F_enum_INTEGER(
        "checksumtype",
        0,
        {
            # RFC3961 sect 8
            1: "CRC32",
            2: "RSA-MD4",
            3: "RSA-MD4-DES",
            4: "DES-MAC",
            5: "DES-MAC-K",
            6: "RSA-MD4-DES-K",
            7: "RSA-MD5",
            8: "RSA-MD5-DES",
            9: "RSA-MD5-DES3",
            10: "SHA1",
            12: "HMAC-SHA1-DES3-KD",
            13: "HMAC-SHA1-DES3",
            14: "SHA1",
            15: "HMAC-SHA1-96-AES128",
            16: "HMAC-SHA1-96-AES256",
        },
        explicit_tag=0xA0,
    ),
    ASN1F_STRING("checksum", "", explicit_tag=0xA1),
    **kwargs
)

_AUTHORIZATIONDATA_VALUES = {
    # Filled below
}


class _ASN1FString_PacketField(ASN1F_STRING):
    holds_packets = 1

    def i2m(self, pkt, val):
        if isinstance(val, ASN1_Packet):
            val = ASN1_STRING(bytes(val))
        return super(_ASN1FString_PacketField, self).i2m(pkt, val)

    def any2i(self, pkt, x):
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return super(_ASN1FString_PacketField, self).any2i(pkt, x)


class _AuthorizationData_value_Field(_ASN1FString_PacketField):
    def m2i(self, pkt, s):
        val = super(_AuthorizationData_value_Field, self).m2i(pkt, s)
        if pkt.adType.val in _PADATA_CLASSES:
            cls = _AUTHORIZATIONDATA_VALUES.get(pkt.adType.val, None)
            if not val[0].val:
                return val
            if cls:
                return cls(val[0].val, _underlayer=pkt), val[1]
        return val


class AuthorizationDataItem(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "adType",
            0,
            {
                # RFC4120 sect 7.5.4
                1: "AD-IF-RELEVANT",
                2: "AD-INTENDED-FOR-SERVER",
                3: "AD-INTENDED-FOR-APPLICATION-CLASS",
                4: "AD-KDC-ISSUED",
                5: "AD-AND-OR",
                6: "AD-MANDATORY-TICKET-EXTENSIONS",
                7: "AD-IN-TICKET-EXTENSIONS",
                8: "AD-MANDATORY-FOR-KDC",
                64: "OSF-DCE",
                65: "SESAME",
                66: "AD-OSD-DCE-PKI-CERTID",
                128: "AD-WIN2K-PAC",
                129: "AD-ETYPE-NEGOTIATION",
            },
            explicit_tag=0xA0,
        ),
        _AuthorizationData_value_Field("adData", "", explicit_tag=0xA1),
    )


class AuthorizationData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "seq", [AuthorizationDataItem()], AuthorizationDataItem
    )


AD_IF_RELEVANT = AuthorizationData
_AUTHORIZATIONDATA_VALUES[1] = AD_IF_RELEVANT


class AD_KDCIssued(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Checksum(explicit_tag=0xA0),
        ASN1F_optional(
            Realm("iRealm", "", explicit_tag=0xA1),
        ),
        ASN1F_optional(ASN1F_PACKET("iSname", None, PrincipalName, explicit_tag=0xA2)),
        ASN1F_PACKET("elements", None, AuthorizationData, explicit_tag=0xA3),
    )


_AUTHORIZATIONDATA_VALUES[4] = AD_KDCIssued


class AD_AND_OR(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("conditionCount", 0, explicit_tag=0xA0),
        ASN1F_PACKET("elements", None, AuthorizationData, explicit_tag=0xA1),
    )


_AUTHORIZATIONDATA_VALUES[5] = AD_AND_OR

ADMANDATORYFORKDC = AuthorizationData
_AUTHORIZATIONDATA_VALUES[8] = ADMANDATORYFORKDC


# back to RFC4120


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

    def get_usage(self):
        """
        Get current key usage number and encrypted class
        """
        # RFC 4120 sect 7.5.1
        if self.underlayer:
            if isinstance(self.underlayer, PADATA):
                patype = self.underlayer.padataType
                if patype == 2:
                    # AS-REQ PA-ENC-TIMESTAMP padata timestamp
                    return 1, PA_ENC_TS_ENC
            elif isinstance(self.underlayer, KRB_Ticket):
                # AS-REP Ticket and TGS-REP Ticket
                return 2, EncTicketPart
            elif isinstance(self.underlayer, KRB_AS_REP):
                # AS-REP encrypted part
                return 3, EncASRepPart
            elif isinstance(self.underlayer, KRB_AP_REQ):
                # AP-REQ Authenticator
                return 11, KRB_Authenticator
            elif isinstance(self.underlayer, KrbFastArmoredReq):
                # KEY_USAGE_FAST_ENC
                return 51, KrbFastReq
        raise ValueError(
            "Could not guess key usage number. Please specify key_usage_number"
        )

    def decrypt(self, key, key_usage_number=None, cls=None):
        """
        Decrypt and return the data contained in cipher.

        :param key: the key to use for decryption
        :param key_usage_number: (optional) specify the key usage number.
                                 Guessed otherwise
        :param cls: (optional) the class of the decrypted payload
                               Guessed otherwise (or bytes)
        """
        if key_usage_number is None:
            key_usage_number, cls = self.get_usage()
        d = key.decrypt(key_usage_number, self.cipher.val)
        if cls:
            return cls(d)
        return d

    def encrypt(self, key, text, confounder=None, key_usage_number=None):
        """
        Encrypt text and set it into cipher.

        :param key: the key to use for encryption
        :param text: the bytes value to encode
        :param confounder: (optional) specify the confounder bytes. Random otherwise
        :param key_usage_number: (optional) specify the key usage number.
                                 Guessed otherwise
        """
        if key_usage_number is None:
            key_usage_number = self.get_usage()[0]
        self.etype = key.eptype
        self.cipher = key.encrypt(key_usage_number, text, confounder=confounder)


class EncryptionKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("keytype", 0, _KRB_E_TYPES, explicit_tag=0xA0),
        ASN1F_STRING("keyvalue", "", explicit_tag=0xA1),
    )

    def toKey(self):
        from scapy.libs.rfc3961 import Key

        return Key(self.keytype.val, key=self.keyvalue.val)


KerberosFlags = ASN1F_FLAGS


_PADATA_TYPES = {
    1: "PA-TGS-REQ",
    2: "PA-ENC-TIMESTAMP",
    3: "PA-PW-SALT",
    11: "PA-ETYPE-INFO",
    14: "PA-PK-AS-REQ-OLD",
    15: "PA-PK-AS-REP-OLD",
    16: "PA-PK-AS-REQ",
    17: "PA-PK-AS-REP",
    19: "PA-ETYPE-INFO2",
    20: "PA-SVR-REFERRAL-INFO",
    128: "PA-PAC-REQUEST",
    133: "PA-FX-COOKIE",
    134: "PA-AUTHENTICATION-SET",
    135: "PA-AUTH-SET-SELECTED",
    136: "PA-FX-FAST",
    137: "PA-FX-ERROR",
    165: "PA-SUPPORTED-ENCTYPES",
    167: "PA-PAC-OPTIONS",
}

_PADATA_CLASSES = {
    # Filled elsewhere in this file
}


# RFC4120


class _PADATA_value_Field(_ASN1FString_PacketField):
    """
    A special field that properly dispatches PA-DATA values according to
    padata-type and if the paquet is a request or a response.
    """

    def m2i(self, pkt, s):
        val = super(_PADATA_value_Field, self).m2i(pkt, s)
        if pkt.padataType.val in _PADATA_CLASSES:
            cls = _PADATA_CLASSES[pkt.padataType.val]
            if isinstance(cls, tuple):
                is_reply = (
                    pkt.underlayer.underlayer is not None and
                    isinstance(pkt.underlayer.underlayer, KRB_ERROR)
                ) or isinstance(pkt.underlayer, (KRB_AS_REP, KRB_TGS_REP))
                cls = cls[is_reply]
            if not val[0].val:
                return val
            return cls(val[0].val, _underlayer=pkt), val[1]
        return val


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


# RFC 4120 sect 5.2.7.2


class PA_ENC_TS_ENC(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KerberosTime("patimestamp", GeneralizedTime(), explicit_tag=0xA0),
        ASN1F_optional(Microseconds("pausec", 0, explicit_tag=0xA1)),
    )


_PADATA_CLASSES[2] = EncryptedData


# RFC 4120 sect 5.2.7.4


class ETYPE_INFO_ENTRY(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("etype", 0x1, _KRB_E_TYPES, explicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_STRING("salt", "", explicit_tag=0xA1),
        ),
    )


class ETYPE_INFO(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("seq", [ETYPE_INFO_ENTRY()], ETYPE_INFO_ENTRY)


_PADATA_CLASSES[11] = ETYPE_INFO

# RFC 4120 sect 5.2.7.5


class ETYPE_INFO_ENTRY2(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("etype", 0x1, _KRB_E_TYPES, explicit_tag=0xA0),
        ASN1F_optional(
            KerberosString("salt", "", explicit_tag=0xA1),
        ),
        ASN1F_optional(
            ASN1F_STRING("s2kparams", "", explicit_tag=0xA2),
        ),
    )


class ETYPE_INFO2(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("seq", [ETYPE_INFO_ENTRY2()], ETYPE_INFO_ENTRY2)


_PADATA_CLASSES[19] = ETYPE_INFO2

# PADATA Extended with RFC6113


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

# [MS-KILE] sect 2.2.3


class PA_PAC_REQUEST(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_BOOLEAN("includePac", True, explicit_tag=0xA0),
    )


_PADATA_CLASSES[128] = PA_PAC_REQUEST


# [MS-KILE] sect 2.2.8


class PA_SUPPORTED_ENCTYPES(Packet):
    fields_desc = [
        FlagsField(
            "flags",
            0,
            -32,
            [
                "DES-CBC-CRC",
                "DES-CBC-MD5",
                "RC4-HMAC",
                "AES128-CTS-HMAC-SHA1-96",
                "AES256-CTS-HMAC-SHA1-96",
            ] +
            ["bit_%d" % i for i in range(11)] +
            [
                "FAST-supported",
                "Compount-identity-supported",
                "Claims-supported",
                "Resource-SID-compression-disabled",
            ],
        )
    ]


_PADATA_CLASSES[165] = PA_SUPPORTED_ENCTYPES

# [MS-KILE] sect 2.2.10


class PA_PAC_OPTIONS(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KerberosFlags(
            "options",
            0,
            [
                "Claims",
                "Branch-Aware",
                "Forward-to-Full-DC",
            ],
            explicit_tag=0xA0,
        )
    )


_PADATA_CLASSES[167] = PA_PAC_OPTIONS


# RFC6113 sect 5.4.1


class _KrbFastArmor_value_Field(_ASN1FString_PacketField):
    def m2i(self, pkt, s):
        val = super(_KrbFastArmor_value_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.armorType.val == 1:  # FX_FAST_ARMOR_AP_REQUEST
            return KRB_AP_REQ(val[0].val, _underlayer=pkt), val[1]
        return val


class KrbFastArmor(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "armorType", 1, {1: "FX_FAST_ARMOR_AP_REQUEST"}, explicit_tag=0xA0
        ),
        _KrbFastArmor_value_Field("armorValue", "", explicit_tag=0xA1),
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
        ASN1F_optional(
            ASN1F_PACKET("stengthenKey", None, EncryptionKey, explicit_tag=0xA1)
        ),
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


class TransitedEncoding(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("trType", 0, explicit_tag=0xA0),
        ASN1F_STRING("contents", "", explicit_tag=0xA1),
    )


_TICKET_FLAGS = [
    "reserved",
    "forwardable",
    "forwarded",
    "proxiable",
    "proxy",
    "may-postdate",
    "postdated",
    "invalid",
    "renewable",
    "initial",
    "pre-authent",
    "hw-authent",
    "transited-since-policy-checked",
    "ok-as-delegate",
]


class EncTicketPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        ASN1F_SEQUENCE(
            KerberosFlags(
                "flags",
                0,
                _TICKET_FLAGS,
                explicit_tag=0xA0,
            ),
            ASN1F_PACKET("key", None, EncryptionKey, explicit_tag=0xA1),
            Realm("crealm", "", explicit_tag=0xA2),
            ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA3),
            ASN1F_PACKET(
                "transited", TransitedEncoding(), TransitedEncoding, explicit_tag=0xA4
            ),
            KerberosTime("authtime", GeneralizedTime(), explicit_tag=0xA5),
            ASN1F_optional(
                KerberosTime("starttime", GeneralizedTime(), explicit_tag=0xA6)
            ),
            KerberosTime("endtime", GeneralizedTime(), explicit_tag=0xA7),
            ASN1F_optional(
                KerberosTime("renewTill", GeneralizedTime(), explicit_tag=0xA8),
            ),
            ASN1F_optional(
                HostAddresses("addresses", explicit_tag=0xA9),
            ),
            ASN1F_optional(
                ASN1F_PACKET(
                    "authorizationData", None, AuthorizationData, explicit_tag=0xAA
                ),
            ),
        ),
        implicit_tag=3,
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
        ASN1F_optional(KerberosTime("from_", None, explicit_tag=0xA4)),
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


class KrbFastReq(ASN1_Packet):
    # RFC6113 sect 5.4.2
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
        ASN1F_PACKET("reqBody", None, KRB_KDC_REQ_BODY, explicit_tag=0xA2),
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


class LastReqItem(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Int32("lrType", 0, explicit_tag=0xA0),
        KerberosTime("lrValue", GeneralizedTime(), explicit_tag=0xA1),
    )


EncKDCRepPart = ASN1F_SEQUENCE(
    ASN1F_PACKET("key", None, EncryptionKey, explicit_tag=0xA0),
    ASN1F_SEQUENCE_OF("lastReq", [], LastReqItem, explicit_tag=0xA1),
    UInt32("nonce", 0, explicit_tag=0xA2),
    ASN1F_optional(
        KerberosTime("keyExpiration", GeneralizedTime(), explicit_tag=0xA3),
    ),
    KerberosFlags(
        "flags",
        0,
        _TICKET_FLAGS,
        explicit_tag=0xA4,
    ),
    KerberosTime("authtime", GeneralizedTime(), explicit_tag=0xA5),
    ASN1F_optional(
        KerberosTime("starttime", GeneralizedTime(), explicit_tag=0xA6),
    ),
    KerberosTime("endtime", GeneralizedTime(), explicit_tag=0xA7),
    ASN1F_optional(
        KerberosTime("renewTill", GeneralizedTime(), explicit_tag=0xA8),
    ),
    Realm("srealm", "", explicit_tag=0xA9),
    ASN1F_PACKET("sname", PrincipalName(), PrincipalName, explicit_tag=0xAA),
    ASN1F_optional(
        HostAddresses("caddr", explicit_tag=0xAB),
    ),
    # RFC6806 sect 11
    # ASN1F_optional(
    ASN1F_SEQUENCE_OF("encryptedPaData", [], PADATA, explicit_tag=0xAC),
    # ),
)


class EncASRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        EncKDCRepPart,
        implicit_tag=25,
    )


class EncTGSRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_KRB_APPLICATION(
        EncKDCRepPart,
        implicit_tag=26,
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
                ASN1F_PACKET("subkey", None, EncryptionKey, explicit_tag=0xA6),
            ),
            ASN1F_optional(
                UInt32("seqNumber", 0, explicit_tag=0xA7),
            ),
            ASN1F_optional(
                ASN1F_PACKET(
                    "encAuthorizationData", None, AuthorizationData, explicit_tag=0xA8
                ),
            ),
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


class MethodData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("seq", [PADATA()], PADATA)


class _KRBERROR_data_Field(_ASN1FString_PacketField):
    def m2i(self, pkt, s):
        val = super(_KRBERROR_data_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.errorCode.val in [24, 25]:
            # 24: KDC_ERR_PREAUTH_FAILED
            # 25: KDC_ERR_PREAUTH_REQUIRED
            return MethodData(val[0].val, _underlayer=pkt), val[1]
        return val


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
            ASN1F_enum_INTEGER(
                "errorCode",
                0,
                {
                    # RFC4120 sect 7.5.9
                    0: "KDC_ERR_NONE",
                    1: "KDC_ERR_NAME_EXP",
                    2: "KDC_ERR_SERVICE_EXP",
                    3: "KDC_ERR_BAD_PVNO",
                    4: "KDC_ERR_C_OLD_MAST_KVNO",
                    5: "KDC_ERR_S_OLD_MAST_KVNO",
                    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
                    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
                    8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
                    9: "KDC_ERR_NULL_KEY",
                    10: "KDC_ERR_CANNOT_POSTDATE",
                    11: "KDC_ERR_NEVER_VALID",
                    12: "KDC_ERR_POLICY",
                    13: "KDC_ERR_BADOPTION",
                    14: "KDC_ERR_ETYPE_NOSUPP",
                    15: "KDC_ERR_SUMTYPE_NOSUPP",
                    16: "KDC_ERR_PADATA_TYPE_NOSUPP",
                    17: "KDC_ERR_TRTYPE_NOSUPP",
                    18: "KDC_ERR_CLIENT_REVOKED",
                    19: "KDC_ERR_SERVICE_REVOKED",
                    20: "KDC_ERR_TGT_REVOKED",
                    21: "KDC_ERR_CLIENT_NOTYET",
                    22: "KDC_ERR_SERVICE_NOTYET",
                    23: "KDC_ERR_KEY_EXPIRED",
                    24: "KDC_ERR_PREAUTH_FAILED",
                    25: "KDC_ERR_PREAUTH_REQUIRED",
                    26: "KDC_ERR_SERVER_NOMATCH",
                    27: "KDC_ERR_MUST_USE_USER2USER",
                    28: "KDC_ERR_PATH_NOT_ACCEPTED",
                    29: "KDC_ERR_SVC_UNAVAILABLE",
                    31: "KRB_AP_ERR_BAD_INTEGRITY",
                    32: "KRB_AP_ERR_TKT_EXPIRED",
                    33: "KRB_AP_ERR_TKT_NYV",
                    34: "KRB_AP_ERR_REPEAT",
                    35: "KRB_AP_ERR_NOT_US",
                    36: "KRB_AP_ERR_BADMATCH",
                    37: "KRB_AP_ERR_SKEW",
                    38: "KRB_AP_ERR_BADADDR",
                    39: "KRB_AP_ERR_BADVERSION",
                    40: "KRB_AP_ERR_MSG_TYPE",
                    41: "KRB_AP_ERR_MODIFIED",
                    42: "KRB_AP_ERR_BADORDER",
                    44: "KRB_AP_ERR_BADKEYVER",
                    45: "KRB_AP_ERR_NOKEY",
                    46: "KRB_AP_ERR_MUT_FAIL",
                    47: "KRB_AP_ERR_BADDIRECTION",
                    48: "KRB_AP_ERR_METHOD",
                    49: "KRB_AP_ERR_BADSEQ",
                    50: "KRB_AP_ERR_INAPP_CKSUM",
                    51: "KRB_AP_PATH_NOT_ACCEPTED",
                    52: "KRB_ERR_RESPONSE_TOO_BIG",
                    60: "KRB_ERR_GENERIC",
                    61: "KRB_ERR_FIELD_TOOLONG",
                    62: "KDC_ERROR_CLIENT_NOT_TRUSTED",
                    63: "KDC_ERROR_KDC_NOT_TRUSTED",
                    64: "KDC_ERROR_INVALID_SIG",
                    65: "KDC_ERR_KEY_TOO_WEAK",
                    66: "KDC_ERR_CERTIFICATE_MISMATCH",
                    67: "KRB_AP_ERR_NO_TGT",
                    68: "KDC_ERR_WRONG_REALM",
                    69: "KRB_AP_ERR_USER_TO_USER_REQUIRED",
                    70: "KDC_ERR_CANT_VERIFY_CERTIFICATE",
                    71: "KDC_ERR_INVALID_CERTIFICATE",
                    72: "KDC_ERR_REVOKED_CERTIFICATE",
                    73: "KDC_ERR_REVOCATION_STATUS_UNKNOWN",
                    74: "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
                    75: "KDC_ERR_CLIENT_NAME_MISMATCH",
                    76: "KDC_ERR_KDC_NAME_MISMATCH",
                },
                explicit_tag=0xA6,
            ),
            ASN1F_optional(Realm("crealm", "", explicit_tag=0xA7)),
            ASN1F_optional(
                ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA8),
            ),
            Realm("realm", "", explicit_tag=0xA9),
            ASN1F_PACKET("sname", None, PrincipalName, explicit_tag=0xAA),
            ASN1F_optional(KerberosString("eText", "", explicit_tag=0xAB)),
            ASN1F_optional(_KRBERROR_data_Field("eData", "", explicit_tag=0xAC)),
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
    0x00: "DES MAC MD5",
    0x01: "MD2.5",
    0x02: "DES MAC",
    # RFC 4757
    0x11: "HMAC",
}
_SEAL_ALGS = {
    0: "DES",
    0xFFFF: "none",
    # RFC 4757
    0x10: "RC4",
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

    def mysummary(self):
        return self.root.summary()


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

    @classmethod
    def tcp_reassemble(cls, data, *args, **kwargs):
        if len(data) < 4:
            return None
        length = struct.unpack("!I", data[:4])[0]
        if len(data) == length + 4:
            return cls(data)


bind_layers(KerberosTCPHeader, Kerberos)

bind_bottom_up(TCP, KerberosTCPHeader, sport=88)
bind_layers(TCP, KerberosTCPHeader, dport=88)


# Util functions


class KerberosClient(Automaton):
    RES = namedtuple("AS_Result", ["asrep", "sessionkey"])

    def __init__(
        self, ip=None, host=None, user=None, domain=None, key=None, port=88, **kwargs
    ):
        import scapy.libs.rfc3961  # Trigger error if any  # noqa: F401

        if not ip:
            raise ValueError("Invalid IP")
        if not host:
            raise ValueError("Invalid host")
        if not user:
            raise ValueError("Invalid user")
        if not domain:
            raise ValueError("Invalid domain")

        self.result = None  # Result

        sock = socket.socket()
        sock.settimeout(5.0)
        sock.connect((ip, port))
        sock = StreamSocket(sock, KerberosTCPHeader)

        self.host = bytes_encode(host).upper()
        self.user = bytes_encode(user)
        self.domain = bytes_encode(domain).upper()
        self.key = key
        self.pre_auth = False
        super(KerberosClient, self).__init__(
            recvsock=lambda **_: sock, ll=lambda **_: sock, **kwargs
        )

    def send(self, pkt):
        super(KerberosClient, self).send(KerberosTCPHeader() / pkt)

    def ap_req(self):
        from scapy.libs.rfc3961 import EncryptionType

        now_time = datetime.utcnow().replace(microsecond=0)

        apreq = Kerberos(
            root=KRB_AS_REQ(
                padata=[
                    PADATA(
                        padataType=ASN1_INTEGER(128),
                        padataValue=PA_PAC_REQUEST(includePac=ASN1_BOOLEAN(-1)),
                    )
                ],
                reqBody=KRB_KDC_REQ_BODY(
                    etype=[
                        ASN1_INTEGER(EncryptionType.AES256),
                        ASN1_INTEGER(EncryptionType.AES128),
                        ASN1_INTEGER(EncryptionType.RC4),
                        ASN1_INTEGER(EncryptionType.DES_MD5),
                    ],
                    addresses=[
                        HostAddress(
                            addrType=ASN1_INTEGER(20),  # Netbios
                            address=ASN1_STRING(self.host.ljust(16, b" ")),
                        )
                    ],
                    additionalTickets=None,
                    # forwardable + renewable + canonicalize (default)
                    kdcOptions=ASN1_BIT_STRING("01000000100000010000000000010000"),
                    cname=PrincipalName(
                        nameString=[ASN1_GENERAL_STRING(self.user)],
                        nameType=ASN1_INTEGER(1),  # NT-PRINCIPAL
                    ),
                    realm=ASN1_GENERAL_STRING(self.domain),
                    sname=PrincipalName(
                        nameString=[
                            ASN1_GENERAL_STRING(b"krbtgt"),
                            ASN1_GENERAL_STRING(self.domain),
                        ],
                        nameType=ASN1_INTEGER(2),  # NT-SRV-INST
                    ),
                    till=ASN1_GENERALIZED_TIME(now_time + timedelta(hours=10)),
                    rtime=ASN1_GENERALIZED_TIME(now_time + timedelta(hours=10)),
                    nonce=ASN1_INTEGER(RandNum(0, 0x7FFFFFFF)),
                    # Fun fact: the doc says nonce=UInt32 but if
                    # you use something greater than 0x7fffffff, the server
                    # sends back garbage... (bad cast? ^^)
                ),
            )
        )
        if self.pre_auth:
            apreq.root.padata = [
                PADATA(
                    padataType=0x2,  # PA-ENC-TIMESTAMP
                    padataValue=EncryptedData(),
                ),
                apreq.root.padata[0],
            ]
            apreq.root.padata[0].padataValue.encrypt(
                self.key, PA_ENC_TS_ENC(patimestamp=ASN1_GENERALIZED_TIME(now_time))
            )
        return apreq

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.condition(BEGIN)
    def should_send_ap_req(self):
        raise self.SENT_AP_REQ()

    @ATMT.action(should_send_ap_req)
    def send_ap_req(self):
        self.send(self.ap_req())

    @ATMT.state()
    def SENT_AP_REQ(self):
        pass

    @ATMT.receive_condition(SENT_AP_REQ)
    def receive_krb_error_ap_req(self, pkt):
        if Kerberos in pkt and isinstance(pkt.root, KRB_ERROR):
            if pkt.root.errorCode == 25:  # KDC_ERR_PREAUTH_REQUIRED
                if not self.key:
                    log_runtime.warning(
                        "Got 'KDC_ERR_PREAUTH_REQUIRED', but no key was passed."
                    )
                    raise self.FINAL()
                self.pre_auth = True
                raise self.BEGIN()
            else:
                log_runtime.warning("Received KRB_ERROR")
                pkt.show()
                raise self.FINAL()

    @ATMT.receive_condition(SENT_AP_REQ)
    def receive_ap_rep(self, pkt):
        if Kerberos in pkt and isinstance(pkt.root, KRB_AS_REP):
            raise self.FINAL().action_parameters(pkt)

    @ATMT.action(receive_ap_rep)
    def decrypt_ap_rep(self, pkt):
        # Decrypt
        enc = pkt.root.encPart
        res = enc.decrypt(self.key)
        self.result = self.RES(pkt.root, res.key)

    @ATMT.state(final=1)
    def FINAL(self):
        pass


def krb_as_req(upn, ip, key=None, password=None, **kwargs):
    r"""
    Kerberos AS-Req

    :param upn: the user principal name formatted as "DOMAIN\user" or "user@DOMAIN"
    :param ip: the KDC ip
    :param key: (optional) pass the Key object
    :param password: (optional) otherwise, pass the user's password

    :return: returns a named tuple (asrep=<...>, sessionkey=<...>)

    Example::

        >>> # The KDC is on 192.168.122.17, we ask a TGT for user1
        >>> krb_as_req("user1@DOMAIN.LOCAL", "192.168.122.17", password="Password1")

    Equivalent::

        >>> from scapy.libs.rfc3961 import Key, EncryptionType
        >>> key = Key(EncryptionType.AES256, key=hex_bytes("6d0748c546f4e99205
        ...: e78f8da7681d4ec5520ae4815543720c2a647c1ae814c9"))
        >>> krb_as_req("user1@DOMAIN.LOCAL", "192.168.122.17", key=key)
    """
    m = re.match(r"^([^@\\]+)(@|\\)([^@\\]+)$", upn)
    if not m:
        raise ValueError("Invalid UPN !")
    if m.group(2) == "@":
        user = m.group(1)
        domain = m.group(3)
    else:
        user = m.group(3)
        domain = m.group(1)
    if key is None:
        if password is None:
            try:
                from prompt_toolkit import prompt

                password = prompt("Enter password: ", is_password=True)
            except ImportError:
                password = input("Enter password: ")
        if user.endswith("$"):
            # Machine account
            salt = (
                domain.upper().encode() +
                b"host" +
                user.lower().encode() +
                b"." +
                domain.lower().encode()
            )
        else:
            salt = domain.upper().encode() + user.encode()
        from scapy.libs.rfc3961 import Key, EncryptionType

        key = Key.string_to_key(EncryptionType.AES256, password.encode(), salt)
    cli = KerberosClient(
        domain=domain, ip=ip, host="WIN1", user=user, key=key, **kwargs
    )
    cli.run()
    cli.stop()
    return cli.result
