# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

r"""
Kerberos V5

Implements parts of:

- Kerberos Network Authentication Service (V5): RFC4120
- Kerberos Version 5 GSS-API: RFC1964, RFC4121
- Kerberos Pre-Authentication: RFC6113 (FAST)
- Kerberos Principal Name Canonicalization and Cross-Realm Referrals: RFC6806
- Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols: RFC3244
- User to User Kerberos Authentication: draft-ietf-cat-user2user-03
- Public Key Cryptography Based User-to-User Authentication (PKU2U): draft-zhu-pku2u-09
- Initial and Pass Through Authentication Using Kerberos V5 (IAKERB):
  draft-ietf-kitten-iakerb-03
- Kerberos Protocol Extensions: [MS-KILE]
- Kerberos Protocol Extensions: Service for User: [MS-SFU]


.. note::
    You will find more complete documentation for this layer over at
    `Kerberos <https://scapy.readthedocs.io/en/latest/layers/kerberos.html>`_

Example decryption::

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
from datetime import datetime, timedelta, timezone
from enum import IntEnum

import os
import re
import socket
import struct

from scapy.error import warning
import scapy.asn1.mib  # noqa: F401
from scapy.asn1.ber import BER_id_dec, BER_Decoding_Error
from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_Class,
    ASN1_GENERAL_STRING,
    ASN1_GENERALIZED_TIME,
    ASN1_INTEGER,
    ASN1_STRING,
    ASN1_Codecs,
)
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
    ASN1F_STRING_PacketField,
    ASN1F_enum_INTEGER,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.automaton import Automaton, ATMT
from scapy.config import conf
from scapy.compat import bytes_encode
from scapy.error import log_runtime
from scapy.fields import (
    ConditionalField,
    FieldLenField,
    FlagsField,
    IntEnumField,
    LEIntEnumField,
    LenField,
    LEShortEnumField,
    LEShortField,
    LongField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    PadField,
    ShortEnumField,
    ShortField,
    StrField,
    StrFieldUtf16,
    StrFixedLenEnumField,
    XByteField,
    XLEIntField,
    XLEShortField,
    XStrFixedLenField,
    XStrLenField,
    XStrField,
)
from scapy.packet import Packet, bind_bottom_up, bind_top_down, bind_layers
from scapy.supersocket import StreamSocket
from scapy.utils import strrot, strxor
from scapy.volatile import GeneralizedTime, RandNum, RandBin

from scapy.layers.gssapi import (
    GSSAPI_BLOB,
    GSS_C_FLAGS,
    GSS_S_BAD_MECH,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_DEFECTIVE_TOKEN,
    GSS_S_FAILURE,
    GssChannelBindings,
    SSP,
    _GSSAPI_OIDS,
    _GSSAPI_SIGNATURE_OIDS,
)
from scapy.layers.inet import TCP, UDP

# Typing imports
from typing import (
    Optional,
)


# kerberos APPLICATION


class ASN1_Class_KRB(ASN1_Class):
    name = "Kerberos"
    # APPLICATION + CONSTRUCTED = 0x40 | 0x20
    Token = 0x60 | 0  # GSSAPI
    Ticket = 0x60 | 1
    Authenticator = 0x60 | 2
    EncTicketPart = 0x60 | 3
    AS_REQ = 0x60 | 10
    AS_REP = 0x60 | 11
    TGS_REQ = 0x60 | 12
    TGS_REP = 0x60 | 13
    AP_REQ = 0x60 | 14
    AP_REP = 0x60 | 15
    PRIV = 0x60 | 21
    CRED = 0x60 | 22
    EncASRepPart = 0x60 | 25
    EncTGSRepPart = 0x60 | 26
    EncAPRepPart = 0x60 | 27
    EncKrbPrivPart = 0x60 | 28
    EncKrbCredPart = 0x60 | 29
    ERROR = 0x60 | 30


# RFC4120 sect 5.2


KerberosString = ASN1F_GENERAL_STRING
Realm = KerberosString
Int32 = ASN1F_INTEGER
UInt32 = ASN1F_INTEGER

_PRINCIPAL_NAME_TYPES = {
    0: "NT-UNKNOWN",
    1: "NT-PRINCIPAL",
    2: "NT-SRV-INST",
    3: "NT-SRV-HST",
    4: "NT-SRV-XHST",
    5: "NT-UID",
    6: "NT-X500-PRINCIPAL",
    7: "NT-SMTP-NAME",
    10: "NT-ENTERPRISE",
}


class PrincipalName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "nameType",
            0,
            _PRINCIPAL_NAME_TYPES,
            explicit_tag=0xA0,
        ),
        ASN1F_SEQUENCE_OF("nameString", [], KerberosString, explicit_tag=0xA1),
    )

    @staticmethod
    def fromUPN(upn: str):
        user, _ = _parse_upn(upn)
        return PrincipalName(
            nameString=[ASN1_GENERAL_STRING(user)],
            nameType=ASN1_INTEGER(1),  # NT-PRINCIPAL
        )

    @staticmethod
    def fromSPN(spn: bytes):
        spn, _ = _parse_spn(spn)
        if spn.startswith("krbtgt"):
            return PrincipalName(
                nameString=[ASN1_GENERAL_STRING(x) for x in spn.split("/")],
                nameType=ASN1_INTEGER(2),  # NT-SRV-INST
            )
        else:
            return PrincipalName(
                nameString=[ASN1_GENERAL_STRING(x) for x in spn.split("/")],
                nameType=ASN1_INTEGER(3),  # NT-SRV-HST
            )


KerberosTime = ASN1F_GENERALIZED_TIME
Microseconds = ASN1F_INTEGER


# https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1

_KRB_E_TYPES = {
    1: "DES-CBC-CRC",
    2: "DES-CBC-MD4",
    3: "DES-CBC-MD5",
    5: "DES3-CBC-MD5",
    7: "DES3-CBC-SHA1",
    9: "DSAWITHSHA1-CMSOID",
    10: "MD5WITHRSAENCRYPTION-CMSOID",
    11: "SHA1WITHRSAENCRYPTION-CMSOID",
    12: "RC2CBC-ENVOID",
    13: "RSAENCRYPTION-ENVOID",
    14: "RSAES-OAEP-ENV-OID",
    15: "DES-EDE3-CBC-ENV-OID",
    16: "DES3-CBC-SHA1-KD",
    17: "AES128-CTS-HMAC-SHA1-96",
    18: "AES256-CTS-HMAC-SHA1-96",
    19: "AES128-CTS-HMAC-SHA256-128",
    20: "AES256-CTS-HMAC-SHA384-192",
    23: "RC4-HMAC",
    24: "RC4-HMAC-EXP",
    25: "CAMELLIA128-CTS-CMAC",
    26: "CAMELLIA256-CTS-CMAC",
}

# https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-2

_KRB_S_TYPES = {
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
    17: "CMAC-CAMELLIA128",
    18: "CMAC-CAMELLIA256",
    19: "HMAC-SHA256-128-AES128",
    20: "HMAC-SHA384-192-AES256",
    # RFC 4121
    0x8003: "KRB-AUTHENTICATOR",
    # [MS-KILE]
    0xFFFFFF76: "MD5",
}


class EncryptedData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("etype", 0x17, _KRB_E_TYPES, explicit_tag=0xA0),
        ASN1F_optional(UInt32("kvno", None, explicit_tag=0xA1)),
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
            elif isinstance(self.underlayer, KRB_AP_REQ) and isinstance(
                self.underlayer.underlayer, PADATA
            ):
                # TGS-REQ PA-TGS-REQ Authenticator
                return 7, KRB_Authenticator
            elif isinstance(self.underlayer, KRB_TGS_REP):
                # TGS-REP encrypted part
                return 8, EncTGSRepPart
            elif isinstance(self.underlayer, KRB_AP_REQ):
                # AP-REQ Authenticator
                return 11, KRB_Authenticator
            elif isinstance(self.underlayer, KRB_AP_REP):
                # AP-REP encrypted part
                return 12, EncAPRepPart
            elif isinstance(self.underlayer, KRB_PRIV):
                # KRB-PRIV encrypted part
                return 13, EncKrbPrivPart
            elif isinstance(self.underlayer, KRB_CRED):
                # KRB-CRED encrypted part
                return 14, EncKrbCredPart
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
            try:
                return cls(d)
            except BER_Decoding_Error:
                if cls == EncASRepPart:
                    # https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.2
                    # "Compatibility note: Some implementations unconditionally send an
                    # encrypted EncTGSRepPart (application tag number 26) in this field
                    # regardless of whether the reply is a AS-REP or a TGS-REP.  In the
                    # interest of compatibility, implementors MAY relax the check on the
                    # tag number of the decrypted ENC-PART."
                    try:
                        res = EncTGSRepPart(d)
                        # https://github.com/krb5/krb5/blob/48ccd81656381522d1f9ccb8705c13f0266a46ab/src/lib/krb5/asn.1/asn1_k_encode.c#L1128
                        # This is a bug because as the RFC clearly says above, we're
                        # perfectly in our right to be strict on this. (MAY)
                        log_runtime.warning(
                            "Implementation bug detected. This looks like MIT Kerberos."
                        )
                        return res
                    except BER_Decoding_Error:
                        pass
                raise
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
        self.etype = key.etype
        self.cipher = ASN1_STRING(
            key.encrypt(key_usage_number, text, confounder=confounder)
        )


class EncryptionKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("keytype", 0, _KRB_E_TYPES, explicit_tag=0xA0),
        ASN1F_STRING("keyvalue", "", explicit_tag=0xA1),
    )

    def toKey(self):
        from scapy.libs.rfc3961 import Key

        return Key(
            etype=self.keytype.val,
            key=self.keyvalue.val,
        )

    @classmethod
    def fromKey(self, key):
        return EncryptionKey(
            keytype=key.etype,
            keyvalue=key.key,
        )


class _Checksum_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_Checksum_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.cksumtype.val == 0x8003:
            # Special case per RFC 4121
            return KRB_AuthenticatorChecksum(val[0].val, _underlayer=pkt), val[1]
        return val


class Checksum(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "cksumtype",
            0,
            _KRB_S_TYPES,
            explicit_tag=0xA0,
        ),
        _Checksum_Field("checksum", "", explicit_tag=0xA1),
    )

    def get_usage(self):
        """
        Get current key usage number
        """
        # RFC 4120 sect 7.5.1
        if self.underlayer:
            if isinstance(self.underlayer, KRB_Authenticator):
                # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum
                # (n°10 should never happen as we use RFC4121)
                return 6
            elif isinstance(self.underlayer, PA_FOR_USER):
                # [MS-SFU] sect 2.2.1
                return 17
            elif isinstance(self.underlayer, PA_S4U_X509_USER):
                # [MS-SFU] sect 2.2.1
                return 17
            elif isinstance(self.underlayer, AD_KDCIssued):
                # AD-KDC-ISSUED checksum
                return 19
            elif isinstance(self.underlayer, KrbFastArmoredReq):
                # KEY_USAGE_FAST_REQ_CHKSUM
                return 50
        raise ValueError(
            "Could not guess key usage number. Please specify key_usage_number"
        )

    def verify(self, key, text, key_usage_number=None):
        """
        Decrypt and return the data contained in cipher.

        :param key: the key to use to check the checksum
        :param text: the bytes to verify
        :param key_usage_number: (optional) specify the key usage number.
                                 Guessed otherwise
        """
        if key_usage_number is None:
            key_usage_number = self.get_usage()
        key.verify_checksum(key_usage_number, text, self.checksum.val)

    def make(self, key, text, key_usage_number=None, cksumtype=None):
        """
        Encrypt text and set it into cipher.

        :param key: the key to use to make the checksum
        :param text: the bytes to make a checksum of
        :param key_usage_number: (optional) specify the key usage number.
                                 Guessed otherwise
        """
        if key_usage_number is None:
            key_usage_number = self.get_usage()
        self.cksumtype = cksumtype or key.cksumtype
        self.checksum = ASN1_STRING(
            key.make_checksum(
                keyusage=key_usage_number,
                text=text,
                cksumtype=self.cksumtype,
            )
        )


KerberosFlags = ASN1F_FLAGS

_ADDR_TYPES = {
    # RFC4120 sect 7.5.3
    0x02: "IPv4",
    0x03: "Directional",
    0x05: "ChaosNet",
    0x06: "XNS",
    0x07: "ISO",
    0x0C: "DECNET Phase IV",
    0x10: "AppleTalk DDP",
    0x14: "NetBios",
    0x18: "IPv6",
}


class HostAddress(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "addrType",
            0,
            _ADDR_TYPES,
            explicit_tag=0xA0,
        ),
        ASN1F_STRING("address", "", explicit_tag=0xA1),
    )


HostAddresses = lambda name, **kwargs: ASN1F_SEQUENCE_OF(
    name, [], HostAddress, **kwargs
)


_AUTHORIZATIONDATA_VALUES = {
    # Filled below
}


class _AuthorizationData_value_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_AuthorizationData_value_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.adType.val in _AUTHORIZATIONDATA_VALUES:
            return (
                _AUTHORIZATIONDATA_VALUES[pkt.adType.val](val[0].val, _underlayer=pkt),
                val[1],
            )
        return val


_AD_TYPES = {
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
    # [MS-KILE] additions
    141: "KERB-AUTH-DATA-TOKEN-RESTRICTIONS",
    142: "KERB-LOCAL",
    143: "AD-AUTH-DATA-AP-OPTIONS",
    144: "KERB-AUTH-DATA-CLIENT-TARGET",
}


class AuthorizationDataItem(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "adType",
            0,
            _AD_TYPES,
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
        ASN1F_PACKET("adChecksum", Checksum(), Checksum, explicit_tag=0xA0),
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


# https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xml
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
    129: "PA-FOR-USER",
    130: "PA-FOR-X509-USER",
    131: "PA-FOR-CHECK_DUPS",
    132: "PA-AS-CHECKSUM",
    133: "PA-FX-COOKIE",
    134: "PA-AUTHENTICATION-SET",
    135: "PA-AUTH-SET-SELECTED",
    136: "PA-FX-FAST",
    137: "PA-FX-ERROR",
    138: "PA-ENCRYPTED-CHALLENGE",
    141: "PA-OTP-CHALLENGE",
    142: "PA-OTP-REQUEST",
    143: "PA-OTP-CONFIRM",
    144: "PA-OTP-PIN-CHANGE",
    145: "PA-EPAK-AS-REQ",
    146: "PA-EPAK-AS-REP",
    147: "PA-PKINIT-KX",
    148: "PA-PKU2U-NAME",
    149: "PA-REQ-ENC-PA-REP",
    150: "PA-AS-FRESHNESS",
    151: "PA-SPAKE",
    161: "KERB-KEY-LIST-REQ",
    162: "KERB-KEY-LIST-REP",
    165: "PA-SUPPORTED-ENCTYPES",
    166: "PA-EXTENDED-ERROR",
    167: "PA-PAC-OPTIONS",
}

_PADATA_CLASSES = {
    # Filled elsewhere in this file
}


# RFC4120


class _PADATA_value_Field(ASN1F_STRING_PacketField):
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
                    pkt.underlayer.underlayer is not None
                    and isinstance(pkt.underlayer.underlayer, KRB_ERROR)
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


# [MS-KILE] sect 2.2.5


class LSAP_TOKEN_INFO_INTEGRITY(Packet):
    fields_desc = [
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "UAC-Restricted",
            },
        ),
        LEIntEnumField(
            "TokenIL",
            0x00002000,
            {
                0x00000000: "Untrusted",
                0x00001000: "Low",
                0x00002000: "Medium",
                0x00003000: "High",
                0x00004000: "System",
                0x00005000: "Protected process",
            },
        ),
        XStrFixedLenField("MachineID", b"", length=32),
    ]


# [MS-KILE] sect 2.2.6


class _KerbAdRestrictionEntry_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_KerbAdRestrictionEntry_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.restrictionType.val == 0x0000:  # LSAP_TOKEN_INFO_INTEGRITY
            return LSAP_TOKEN_INFO_INTEGRITY(val[0].val, _underlayer=pkt), val[1]
        return val


class KERB_AD_RESTRICTION_ENTRY(ASN1_Packet):
    name = "KERB-AD-RESTRICTION-ENTRY"
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_enum_INTEGER(
                "restrictionType",
                0,
                {0: "LSAP_TOKEN_INFO_INTEGRITY"},
                explicit_tag=0xA0,
            ),
            _KerbAdRestrictionEntry_Field("restriction", b"", explicit_tag=0xA1),
        )
    )


_AUTHORIZATIONDATA_VALUES[141] = KERB_AD_RESTRICTION_ENTRY


# [MS-KILE] sect 3.2.5.8


class KERB_AUTH_DATA_AP_OPTIONS(Packet):
    name = "KERB-AUTH-DATA-AP-OPTIONS"
    fields_desc = [
        LEIntEnumField(
            "apOptions",
            0x4000,
            {
                0x4000: "KERB_AP_OPTIONS_CBT",
                0x8000: "KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME",
            },
        ),
    ]


_AUTHORIZATIONDATA_VALUES[143] = KERB_AUTH_DATA_AP_OPTIONS


# This has no doc..? [MS-KILE] only mentions its name.


class KERB_AUTH_DATA_CLIENT_TARGET(Packet):
    name = "KERB-AD-TARGET-PRINCIPAL"
    fields_desc = [
        StrFieldUtf16("spn", ""),
    ]


_AUTHORIZATIONDATA_VALUES[144] = KERB_AUTH_DATA_CLIENT_TARGET


# RFC6806 sect 6


class KERB_AD_LOGIN_ALIAS(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(ASN1F_SEQUENCE_OF("loginAliases", [], PrincipalName))


_AUTHORIZATIONDATA_VALUES[80] = KERB_AD_LOGIN_ALIAS


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
            ]
            + ["bit_%d" % i for i in range(11)]
            + [
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
            "",
            [
                "Claims",
                "Branch-Aware",
                "Forward-to-Full-DC",
                "Resource-based-constrained-delegation",  # [MS-SFU] 2.2.5
            ],
            explicit_tag=0xA0,
        )
    )


_PADATA_CLASSES[167] = PA_PAC_OPTIONS

# [MS-KILE] sect 2.2.11


class KERB_KEY_LIST_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "keytypes",
        [],
        ASN1F_enum_INTEGER("", 0, _KRB_E_TYPES),
    )


_PADATA_CLASSES[161] = KERB_KEY_LIST_REQ

# [MS-KILE] sect 2.2.12


class KERB_KEY_LIST_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "keys",
        [],
        ASN1F_PACKET("", None, EncryptionKey),
    )


_PADATA_CLASSES[162] = KERB_KEY_LIST_REP

# [MS-KILE] sect 2.2.13


class KERB_SUPERSEDED_BY_USER(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("name", None, PrincipalName, explicit_tag=0xA0),
        Realm("realm", None, explicit_tag=0xA1),
    )


# [MS-KILE] sect 2.2.14


class KERB_DMSA_KEY_PACKAGE(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE_OF(
            "currentKeys",
            [],
            ASN1F_PACKET("", None, EncryptionKey),
            explicit_tag=0xA0,
        ),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF(
                "previousKeys",
                [],
                ASN1F_PACKET("", None, EncryptionKey),
                explicit_tag=0xA0,
            ),
        ),
        KerberosTime("expirationInterval", GeneralizedTime(), explicit_tag=0xA2),
        KerberosTime("fetchInterval", GeneralizedTime(), explicit_tag=0xA4),
    )


# RFC6113 sect 5.4.1


class _KrbFastArmor_value_Field(ASN1F_STRING_PacketField):
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
            ASN1F_PACKET("reqChecksum", Checksum(), Checksum, explicit_tag=0xA1),
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
        KerberosTime("timestamp", GeneralizedTime(), explicit_tag=0xA0),
        Microseconds("usec", 0, explicit_tag=0xA1),
        Realm("crealm", "", explicit_tag=0xA2),
        ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA3),
        ASN1F_PACKET("ticketChecksum", Checksum(), Checksum, explicit_tag=0xA4),
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

# [MS-SFU]


# sect 2.2.1
class PA_FOR_USER(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("userName", PrincipalName(), PrincipalName, explicit_tag=0xA0),
        Realm("userRealm", "", explicit_tag=0xA1),
        ASN1F_PACKET("cksum", Checksum(), Checksum, explicit_tag=0xA2),
        KerberosString("authPackage", "Kerberos", explicit_tag=0xA3),
    )


_PADATA_CLASSES[129] = PA_FOR_USER


# sect 2.2.2


class S4UUserID(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        UInt32("nonce", 0, explicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA1),
        ),
        Realm("crealm", "", explicit_tag=0xA2),
        ASN1F_optional(
            ASN1F_STRING("subjectCertificate", None, explicit_tag=0xA3),
        ),
        ASN1F_optional(
            ASN1F_FLAGS(
                "options",
                "",
                [
                    "reserved",
                    "KDC_CHECK_LOGON_HOUR_RESTRICTIONS",
                    "KDC_KEY_USAGE_27",
                ],
                explicit_tag=0xA4,
            )
        ),
    )


class PA_S4U_X509_USER(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("userId", S4UUserID(), S4UUserID, explicit_tag=0xA0),
        ASN1F_PACKET("checksum", Checksum(), Checksum, explicit_tag=0xA1),
    )


_PADATA_CLASSES[130] = PA_S4U_X509_USER


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
    15: "AP-REP",
    16: "KRB-TGT-REQ",  # U2U
    17: "KRB-TGT-REP",  # U2U
    20: "KRB-SAFE",
    21: "KRB-PRIV",
    22: "KRB-CRED",
    25: "EncASRepPart",
    26: "EncTGSRepPart",
    27: "EncAPRepPart",
    28: "EncKrbPrivPart",
    29: "EnvKrbCredPart",
    30: "KRB-ERROR",
}

# sect 5.3


class KRB_Ticket(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("tktVno", 5, explicit_tag=0xA0),
            Realm("realm", "", explicit_tag=0xA1),
            ASN1F_PACKET("sname", PrincipalName(), PrincipalName, explicit_tag=0xA2),
            ASN1F_PACKET("encPart", EncryptedData(), EncryptedData, explicit_tag=0xA3),
        ),
        implicit_tag=ASN1_Class_KRB.Ticket,
    )

    def getSPN(self):
        return "%s@%s" % (
            "/".join(x.val.decode() for x in self.sname.nameString),
            self.realm.val.decode(),
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
    "unused",
    "canonicalize",  # RFC6806
    "anonymous",  # RFC6112 + RFC8129
]


class EncTicketPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            KerberosFlags(
                "flags",
                "",
                _TICKET_FLAGS,
                explicit_tag=0xA0,
            ),
            ASN1F_PACKET("key", EncryptionKey(), EncryptionKey, explicit_tag=0xA1),
            Realm("crealm", "", explicit_tag=0xA2),
            ASN1F_PACKET("cname", PrincipalName(), PrincipalName, explicit_tag=0xA3),
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
        implicit_tag=ASN1_Class_KRB.EncTicketPart,
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
                "cname-in-addl-tkt",  # [MS-SFU] sect 2.2.3
                "canonicalize",  # RFC6806
                "request-anonymous",  # RFC6112 + RFC8129
            ]
            + ["unused%d" % i for i in range(17, 26)]
            + [
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
            ]
            + ["res%d" % i for i in range(2, 16)]
            + ["kdc-follow-referrals"],
            explicit_tag=0xA0,
        ),
        ASN1F_SEQUENCE_OF("padata", [PADATA()], PADATA, explicit_tag=0xA1),
        ASN1F_PACKET("reqBody", None, KRB_KDC_REQ_BODY, explicit_tag=0xA2),
    )


class KRB_AS_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KRB_KDC_REQ,
        implicit_tag=ASN1_Class_KRB.AS_REQ,
    )


class KRB_TGS_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KRB_KDC_REQ,
        implicit_tag=ASN1_Class_KRB.TGS_REQ,
    )
    msgType = ASN1_INTEGER(12)


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
    ASN1_root = ASN1F_SEQUENCE(
        KRB_KDC_REP,
        implicit_tag=ASN1_Class_KRB.AS_REP,
    )


class KRB_TGS_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        KRB_KDC_REP,
        implicit_tag=ASN1_Class_KRB.TGS_REP,
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
        "",
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
    ASN1F_optional(
        ASN1F_SEQUENCE_OF("encryptedPaData", [], PADATA, explicit_tag=0xAC),
    ),
)


class EncASRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        EncKDCRepPart,
        implicit_tag=ASN1_Class_KRB.EncASRepPart,
    )


class EncTGSRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        EncKDCRepPart,
        implicit_tag=ASN1_Class_KRB.EncTGSRepPart,
    )


# sect 5.5.1


class KRB_AP_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
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
        implicit_tag=ASN1_Class_KRB.AP_REQ,
    )


_PADATA_CLASSES[1] = KRB_AP_REQ


class KRB_Authenticator(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("authenticatorPvno", 5, explicit_tag=0xA0),
            Realm("crealm", "", explicit_tag=0xA1),
            ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA2),
            ASN1F_optional(
                ASN1F_PACKET("cksum", None, Checksum, explicit_tag=0xA3),
            ),
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
        implicit_tag=ASN1_Class_KRB.Authenticator,
    )


# sect 5.5.2


class KRB_AP_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 15, KRB_MSG_TYPES, explicit_tag=0xA1),
            ASN1F_PACKET("encPart", None, EncryptedData, explicit_tag=0xA2),
        ),
        implicit_tag=ASN1_Class_KRB.AP_REP,
    )


class EncAPRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            KerberosTime("ctime", GeneralizedTime(), explicit_tag=0xA0),
            Microseconds("cusec", 0, explicit_tag=0xA1),
            ASN1F_optional(
                ASN1F_PACKET("subkey", None, EncryptionKey, explicit_tag=0xA2),
            ),
            ASN1F_optional(
                UInt32("seqNumber", 0, explicit_tag=0xA3),
            ),
        ),
        implicit_tag=ASN1_Class_KRB.EncAPRepPart,
    )


# sect 5.7


class KRB_PRIV(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 21, KRB_MSG_TYPES, explicit_tag=0xA1),
            ASN1F_PACKET("encPart", None, EncryptedData, explicit_tag=0xA3),
        ),
        implicit_tag=ASN1_Class_KRB.PRIV,
    )


class EncKrbPrivPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_STRING("userData", ASN1_STRING(""), explicit_tag=0xA0),
            ASN1F_optional(
                KerberosTime("timestamp", None, explicit_tag=0xA1),
            ),
            ASN1F_optional(
                Microseconds("usec", None, explicit_tag=0xA2),
            ),
            ASN1F_optional(
                UInt32("seqNumber", None, explicit_tag=0xA3),
            ),
            ASN1F_PACKET("sAddress", None, HostAddress, explicit_tag=0xA4),
            ASN1F_optional(
                ASN1F_PACKET("cAddress", None, HostAddress, explicit_tag=0xA5),
            ),
        ),
        implicit_tag=ASN1_Class_KRB.EncKrbPrivPart,
    )


# sect 5.8


class KRB_CRED(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 22, KRB_MSG_TYPES, explicit_tag=0xA1),
            ASN1F_SEQUENCE_OF("tickets", [KRB_Ticket()], KRB_Ticket, explicit_tag=0xA2),
            ASN1F_PACKET("encPart", None, EncryptedData, explicit_tag=0xA3),
        ),
        implicit_tag=ASN1_Class_KRB.CRED,
    )


class KrbCredInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("key", EncryptionKey(), EncryptionKey, explicit_tag=0xA0),
        ASN1F_optional(
            Realm("prealm", None, explicit_tag=0xA1),
        ),
        ASN1F_optional(
            ASN1F_PACKET("pname", None, PrincipalName, explicit_tag=0xA2),
        ),
        ASN1F_optional(
            KerberosFlags(
                "flags",
                None,
                _TICKET_FLAGS,
                explicit_tag=0xA3,
            ),
        ),
        ASN1F_optional(
            KerberosTime("authtime", None, explicit_tag=0xA4),
        ),
        ASN1F_optional(KerberosTime("starttime", None, explicit_tag=0xA5)),
        ASN1F_optional(
            KerberosTime("endtime", None, explicit_tag=0xA6),
        ),
        ASN1F_optional(
            KerberosTime("renewTill", None, explicit_tag=0xA7),
        ),
        ASN1F_optional(
            Realm("srealm", None, explicit_tag=0xA8),
        ),
        ASN1F_optional(
            ASN1F_PACKET("sname", None, PrincipalName, explicit_tag=0xA9),
        ),
        ASN1F_optional(
            HostAddresses("caddr", explicit_tag=0xAA),
        ),
    )


class EncKrbCredPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_SEQUENCE_OF(
                "ticketInfo",
                [KrbCredInfo()],
                KrbCredInfo,
                explicit_tag=0xA0,
            ),
            ASN1F_optional(
                UInt32("nonce", None, explicit_tag=0xA1),
            ),
            ASN1F_optional(
                KerberosTime("timestamp", None, explicit_tag=0xA2),
            ),
            ASN1F_optional(
                Microseconds("usec", None, explicit_tag=0xA3),
            ),
            ASN1F_optional(
                ASN1F_PACKET("sAddress", None, HostAddress, explicit_tag=0xA4),
            ),
            ASN1F_optional(
                ASN1F_PACKET("cAddress", None, HostAddress, explicit_tag=0xA5),
            ),
        ),
        implicit_tag=ASN1_Class_KRB.EncKrbCredPart,
    )


# sect 5.9.1


class MethodData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("seq", [PADATA()], PADATA)


class _KRBERROR_data_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_KRBERROR_data_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.errorCode.val in [14, 24, 25]:
            # 14: KDC_ERR_ETYPE_NOSUPP
            # 24: KDC_ERR_PREAUTH_FAILED
            # 25: KDC_ERR_PREAUTH_REQUIRED
            return MethodData(val[0].val, _underlayer=pkt), val[1]
        elif pkt.errorCode.val in [6, 7, 13, 18, 29, 41, 60]:
            # 6: KDC_ERR_C_PRINCIPAL_UNKNOWN
            # 7: KDC_ERR_S_PRINCIPAL_UNKNOWN
            # 13: KDC_ERR_BADOPTION
            # 18: KDC_ERR_CLIENT_REVOKED
            # 29: KDC_ERR_SVC_UNAVAILABLE
            # 41: KRB_AP_ERR_MODIFIED
            # 60: KRB_ERR_GENERIC
            return KERB_ERROR_DATA(val[0].val, _underlayer=pkt), val[1]
        elif pkt.errorCode.val == 69:
            # KRB_AP_ERR_USER_TO_USER_REQUIRED
            return KRB_TGT_REP(val[0].val, _underlayer=pkt), val[1]
        return val


class KRB_ERROR(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
            ASN1F_enum_INTEGER("msgType", 30, KRB_MSG_TYPES, explicit_tag=0xA1),
            ASN1F_optional(
                KerberosTime("ctime", None, explicit_tag=0xA2),
            ),
            ASN1F_optional(
                Microseconds("cusec", None, explicit_tag=0xA3),
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
                    # draft-ietf-kitten-iakerb
                    85: "KRB_AP_ERR_IAKERB_KDC_NOT_FOUND",
                    86: "KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE",
                    # RFC6113
                    90: "KDC_ERR_PREAUTH_EXPIRED",
                    91: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
                    92: "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET",
                    93: "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS",
                },
                explicit_tag=0xA6,
            ),
            ASN1F_optional(Realm("crealm", None, explicit_tag=0xA7)),
            ASN1F_optional(
                ASN1F_PACKET("cname", None, PrincipalName, explicit_tag=0xA8),
            ),
            Realm("realm", "", explicit_tag=0xA9),
            ASN1F_PACKET("sname", PrincipalName(), PrincipalName, explicit_tag=0xAA),
            ASN1F_optional(KerberosString("eText", "", explicit_tag=0xAB)),
            ASN1F_optional(_KRBERROR_data_Field("eData", "", explicit_tag=0xAC)),
        ),
        implicit_tag=ASN1_Class_KRB.ERROR,
    )


# [MS-KILE] sect 2.2.1


class KERB_EXT_ERROR(Packet):
    fields_desc = [
        XLEIntField("status", 0),
        XLEIntField("reserved", 0),
        XLEIntField("flags", 0x00000001),
    ]


# [MS-KILE] sect 2.2.2


class _Error_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_Error_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.dataType.val == 3:  # KERB_ERR_TYPE_EXTENDED
            return KERB_EXT_ERROR(val[0].val, _underlayer=pkt), val[1]
        return val


class KERB_ERROR_DATA(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER(
            "dataType",
            2,
            {
                1: "KERB_AP_ERR_TYPE_NTSTATUS",  # from the wdk
                2: "KERB_AP_ERR_TYPE_SKEW_RECOVERY",
                3: "KERB_ERR_TYPE_EXTENDED",
            },
            explicit_tag=0xA1,
        ),
        ASN1F_optional(_Error_Field("dataValue", None, explicit_tag=0xA2)),
    )


# Kerberos U2U - draft-ietf-cat-user2user-03


class KRB_TGT_REQ(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
        ASN1F_enum_INTEGER("msgType", 16, KRB_MSG_TYPES, explicit_tag=0xA1),
        ASN1F_optional(
            ASN1F_PACKET("sname", None, PrincipalName, explicit_tag=0xA2),
        ),
        ASN1F_optional(
            Realm("realm", None, explicit_tag=0xA3),
        ),
    )


class KRB_TGT_REP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("pvno", 5, explicit_tag=0xA0),
        ASN1F_enum_INTEGER("msgType", 17, KRB_MSG_TYPES, explicit_tag=0xA1),
        ASN1F_PACKET("ticket", None, KRB_Ticket, explicit_tag=0xA2),
    )


# draft-ietf-kitten-iakerb-03 sect 4


class KRB_FINISHED(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("gssMic", Checksum(), Checksum, explicit_tag=0xA1),
    )


# RFC 6542 sect 3.1


class KRB_GSS_EXT(Packet):
    fields_desc = [
        IntEnumField(
            "type",
            0,
            {
                # https://www.iana.org/assignments/kerberos-v-gss-api/kerberos-v-gss-api.xhtml
                0x00000000: "GSS_EXTS_CHANNEL_BINDING",  # RFC 6542 sect 3.2
                0x00000001: "GSS_EXTS_IAKERB_FINISHED",  # not standard
                0x00000002: "GSS_EXTS_FINISHED",  # PKU2U / IAKERB
            },
        ),
        FieldLenField("length", None, length_of="data", fmt="!I"),
        MultipleTypeField(
            [
                (
                    PacketField("data", KRB_FINISHED(), KRB_FINISHED),
                    lambda pkt: pkt.type == 0x00000002,
                ),
            ],
            XStrLenField("data", b"", length_from=lambda pkt: pkt.length),
        ),
    ]


# RFC 4121 sect 4.1.1


class KRB_AuthenticatorChecksum(Packet):
    fields_desc = [
        FieldLenField("Lgth", None, length_of="Bnd", fmt="<I"),
        PacketLenField(
            "Bnd",
            GssChannelBindings(),
            GssChannelBindings,
            length_from=lambda pkt: pkt.Lgth,
        ),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x01: "GSS_C_DELEG_FLAG",
                0x02: "GSS_C_MUTUAL_FLAG",
                0x04: "GSS_C_REPLAY_FLAG",
                0x08: "GSS_C_SEQUENCE_FLAG",
                0x10: "GSS_C_CONF_FLAG",  # confidentiality
                0x20: "GSS_C_INTEG_FLAG",  # integrity
                # RFC4757
                0x1000: "GSS_C_DCE_STYLE",
                0x2000: "GSS_C_IDENTIFY_FLAG",
                0x4000: "GSS_C_EXTENDED_ERROR_FLAG",
            },
        ),
        ConditionalField(
            LEShortField("DlgOpt", 0),
            lambda pkt: pkt.Flags.GSS_C_DELEG_FLAG,
        ),
        ConditionalField(
            FieldLenField("Dlgth", None, length_of="Deleg"),
            lambda pkt: pkt.Flags.GSS_C_DELEG_FLAG,
        ),
        ConditionalField(
            PacketLenField(
                "Deleg", KRB_CRED(), KRB_CRED, length_from=lambda pkt: pkt.Dlgth
            ),
            lambda pkt: pkt.Flags.GSS_C_DELEG_FLAG,
        ),
        # Extensions: RFC 6542 sect 3.1
        PacketListField("Exts", KRB_GSS_EXT(), KRB_GSS_EXT),
    ]


# Kerberos V5 GSS-API - RFC1964 and RFC4121

_TOK_IDS = {
    # RFC 1964
    b"\x01\x00": "KRB-AP-REQ",
    b"\x02\x00": "KRB-AP-REP",
    b"\x03\x00": "KRB-ERROR",
    b"\x01\x01": "GSS_GetMIC-RFC1964",
    b"\x02\x01": "GSS_Wrap-RFC1964",
    b"\x01\x02": "GSS_Delete_sec_context-RFC1964",
    # U2U: [draft-ietf-cat-user2user-03]
    b"\x04\x00": "KRB-TGT-REQ",
    b"\x04\x01": "KRB-TGT-REP",
    # RFC 4121
    b"\x04\x04": "GSS_GetMIC",
    b"\x05\x04": "GSS_Wrap",
    # IAKERB: [draft-ietf-kitten-iakerb-03]
    b"\x05\x01": "IAKERB_PROXY",
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

# See https://www.iana.org/assignments/kerberos-v-gss-api/kerberos-v-gss-api.xhtml
_InitialContextTokens = {}  # filled below


class KRB_InnerToken(Packet):
    name = "Kerberos v5 InnerToken"
    fields_desc = [
        StrFixedLenEnumField("TOK_ID", b"\x01\x00", _TOK_IDS, length=2),
        PacketField(
            "root",
            KRB_AP_REQ(),
            lambda x, _parent: _InitialContextTokens[_parent.TOK_ID](x),
        ),
    ]

    def mysummary(self):
        return self.sprintf(
            "Kerberos %s" % _TOK_IDS.get(self.TOK_ID, repr(self.TOK_ID))
        )

    def guess_payload_class(self, payload):
        if self.TOK_ID in [b"\x01\x01", b"\x02\x01", b"\x04\x04", b"\x05\x04"]:
            return conf.padding_layer
        return Kerberos

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 13:
            # Older RFC1964 variants of the token have KRB_GSSAPI_Token wrapper
            if _pkt[2:13] == b"\x06\t*\x86H\x86\xf7\x12\x01\x02\x02":
                return KRB_GSSAPI_Token
        return cls


# RFC 4121 - sect 4.1


class KRB_GSSAPI_Token(GSSAPI_BLOB):
    name = "Kerberos GSSAPI-Token"
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("MechType", "1.2.840.113554.1.2.2"),
        ASN1F_PACKET(
            "innerToken",
            KRB_InnerToken(),
            KRB_InnerToken,
            implicit_tag=0x0,
        ),
        implicit_tag=ASN1_Class_KRB.Token,
    )


# RFC 1964 - sect 1.2.1


class KRB_GSS_MIC_RFC1964(Packet):
    name = "Kerberos v5 MIC Token (RFC1964)"
    fields_desc = [
        LEShortEnumField("SGN_ALG", 0, _SGN_ALGS),
        XLEIntField("Filler", 0xFFFFFFFF),
        XStrFixedLenField("SND_SEQ", b"", length=8),
        PadField(  # sect 1.2.2.3
            XStrFixedLenField("SGN_CKSUM", b"", length=8),
            align=8,
            padwith=b"\x04",
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_InitialContextTokens[b"\x01\x01"] = KRB_GSS_MIC_RFC1964

# RFC 1964 - sect 1.2.2


class KRB_GSS_Wrap_RFC1964(Packet):
    name = "Kerberos v5 GSS_Wrap (RFC1964)"
    fields_desc = [
        LEShortEnumField("SGN_ALG", 0, _SGN_ALGS),
        LEShortEnumField("SEAL_ALG", 0, _SEAL_ALGS),
        XLEShortField("Filler", 0xFFFF),
        XStrFixedLenField("SND_SEQ", b"", length=8),
        PadField(  # sect 1.2.2.3
            XStrFixedLenField("SGN_CKSUM", b"", length=8),
            align=8,
            padwith=b"\x04",
        ),
        # sect 1.2.2.3
        XStrFixedLenField("CONFOUNDER", b"", length=8),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_InitialContextTokens[b"\x02\x01"] = KRB_GSS_Wrap_RFC1964


# RFC 1964 - sect 1.2.2


class KRB_GSS_Delete_sec_context_RFC1964(Packet):
    name = "Kerberos v5 GSS_Delete_sec_context (RFC1964)"
    fields_desc = KRB_GSS_MIC_RFC1964.fields_desc


_InitialContextTokens[b"\x01\x02"] = KRB_GSS_Delete_sec_context_RFC1964


# RFC 4121 - sect 4.2.2
_KRB5_GSS_Flags = [
    "SentByAcceptor",
    "Sealed",
    "AcceptorSubkey",
]


# RFC 4121 - sect 4.2.6.1


class KRB_GSS_MIC(Packet):
    name = "Kerberos v5 MIC Token"
    fields_desc = [
        FlagsField("Flags", 0, 8, _KRB5_GSS_Flags),
        XStrFixedLenField("Filler", b"\xff\xff\xff\xff\xff", length=5),
        LongField("SND_SEQ", 0),  # Big endian
        XStrField("SGN_CKSUM", b"\x00" * 12),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_InitialContextTokens[b"\x04\x04"] = KRB_GSS_MIC


# RFC 4121 - sect 4.2.6.2


class KRB_GSS_Wrap(Packet):
    name = "Kerberos v5 Wrap Token"
    fields_desc = [
        FlagsField("Flags", 0, 8, _KRB5_GSS_Flags),
        XByteField("Filler", 0xFF),
        ShortField("EC", 0),  # Big endian
        ShortField("RRC", 0),  # Big endian
        LongField("SND_SEQ", 0),  # Big endian
        MultipleTypeField(
            [
                (
                    XStrField("Data", b""),
                    lambda pkt: pkt.Flags.Sealed,
                )
            ],
            XStrLenField("Data", b"", length_from=lambda pkt: pkt.EC),
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_InitialContextTokens[b"\x05\x04"] = KRB_GSS_Wrap


# Kerberos IAKERB - draft-ietf-kitten-iakerb-03


class IAKERB_HEADER(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        Realm("targetRealm", "", explicit_tag=0xA1),
        ASN1F_optional(
            ASN1F_STRING("cookie", None, explicit_tag=0xA2),
        ),
    )


_InitialContextTokens[b"\x05\x01"] = IAKERB_HEADER


# Register for GSSAPI

# Kerberos 5
_GSSAPI_OIDS["1.2.840.113554.1.2.2"] = KRB_InnerToken
_GSSAPI_SIGNATURE_OIDS["1.2.840.113554.1.2.2"] = KRB_InnerToken
# Kerberos 5 - U2U
_GSSAPI_OIDS["1.2.840.113554.1.2.2.3"] = KRB_InnerToken
# Kerberos 5 - IAKERB
_GSSAPI_OIDS["1.3.6.1.5.2.5"] = KRB_InnerToken


# Entry class

# RFC4120 sect 5.10


class Kerberos(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "root",
        None,
        # RFC4120
        KRB_GSSAPI_Token,  # [APPLICATION 0]
        KRB_Ticket,  # [APPLICATION 1]
        KRB_Authenticator,  # [APPLICATION 2]
        KRB_AS_REQ,  # [APPLICATION 10]
        KRB_AS_REP,  # [APPLICATION 11]
        KRB_TGS_REQ,  # [APPLICATION 12]
        KRB_TGS_REP,  # [APPLICATION 13]
        KRB_AP_REQ,  # [APPLICATION 14]
        KRB_AP_REP,  # [APPLICATION 15]
        # RFC4120
        KRB_ERROR,  # [APPLICATION 30]
    )

    def mysummary(self):
        return self.root.summary()


bind_bottom_up(UDP, Kerberos, sport=88)
bind_bottom_up(UDP, Kerberos, dport=88)
bind_layers(UDP, Kerberos, sport=88, dport=88)

_InitialContextTokens[b"\x01\x00"] = KRB_AP_REQ
_InitialContextTokens[b"\x02\x00"] = KRB_AP_REP
_InitialContextTokens[b"\x03\x00"] = KRB_ERROR
_InitialContextTokens[b"\x04\x00"] = KRB_TGT_REQ
_InitialContextTokens[b"\x04\x01"] = KRB_TGT_REP


# RFC4120 sect 7.2.2


class KerberosTCPHeader(Packet):
    # According to RFC 5021, first bit to 1 has a special meaning and
    # negotiates Kerberos TCP extensions... But apart from rfc6251 no one used that
    # https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-4
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


# RFC3244 sect 2


class KPASSWD_REQ(Packet):
    fields_desc = [
        ShortField("len", None),
        ShortField("pvno", 0xFF80),
        ShortField("apreqlen", None),
        PacketLenField(
            "apreq", KRB_AP_REQ(), KRB_AP_REQ, length_from=lambda pkt: pkt.apreqlen
        ),
        ConditionalField(
            PacketLenField(
                "krbpriv",
                KRB_PRIV(),
                KRB_PRIV,
                length_from=lambda pkt: pkt.len - 6 - pkt.apreqlen,
            ),
            lambda pkt: pkt.apreqlen != 0,
        ),
        ConditionalField(
            PacketLenField(
                "error", KRB_ERROR(), KRB_ERROR, length_from=lambda pkt: pkt.len - 6
            ),
            lambda pkt: pkt.apreqlen == 0,
        ),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            p = struct.pack("!H", len(p)) + p[2:]
        if self.apreqlen is None and self.krbpriv is not None:
            p = p[:4] + struct.pack("!H", len(self.apreq)) + p[6:]
        return p + pay


class ChangePasswdData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING("newpasswd", ASN1_STRING(""), explicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_PACKET("targname", None, PrincipalName, explicit_tag=0xA1)
        ),
        ASN1F_optional(Realm("targrealm", None, explicit_tag=0xA2)),
    )


class KPASSWD_REP(Packet):
    fields_desc = [
        ShortField("len", None),
        ShortField("pvno", 0x0001),
        ShortField("apreplen", None),
        PacketLenField(
            "aprep", KRB_AP_REP(), KRB_AP_REP, length_from=lambda pkt: pkt.apreplen
        ),
        ConditionalField(
            PacketLenField(
                "krbpriv",
                KRB_PRIV(),
                KRB_PRIV,
                length_from=lambda pkt: pkt.len - 6 - pkt.apreplen,
            ),
            lambda pkt: pkt.apreplen != 0,
        ),
        ConditionalField(
            PacketLenField(
                "error", KRB_ERROR(), KRB_ERROR, length_from=lambda pkt: pkt.len - 6
            ),
            lambda pkt: pkt.apreplen == 0,
        ),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            p = struct.pack("!H", len(p)) + p[2:]
        if self.apreplen is None and self.krbpriv is not None:
            p = p[:4] + struct.pack("!H", len(self.aprep)) + p[6:]
        return p + pay

    def answers(self, other):
        return isinstance(other, KPASSWD_REQ)


KPASSWD_RESULTS = {
    0: "KRB5_KPASSWD_SUCCESS",
    1: "KRB5_KPASSWD_MALFORMED",
    2: "KRB5_KPASSWD_HARDERROR",
    3: "KRB5_KPASSWD_AUTHERROR",
    4: "KRB5_KPASSWD_SOFTERROR",
    5: "KRB5_KPASSWD_ACCESSDENIED",
    6: "KRB5_KPASSWD_BAD_VERSION",
    7: "KRB5_KPASSWD_INITIAL_FLAG_NEEDED",
}


class KPasswdRepData(Packet):
    fields_desc = [
        ShortEnumField("resultCode", 0, KPASSWD_RESULTS),
        StrField("resultString", ""),
    ]


class Kpasswd(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 4:
            if _pkt[2:4] == b"\xff\x80":
                return KPASSWD_REQ
            elif _pkt[2:4] == b"\x00\x01":
                asn1_tag = BER_id_dec(_pkt[6:8])[0] & 0x1F
                if asn1_tag == 14:
                    return KPASSWD_REQ
                elif asn1_tag == 15:
                    return KPASSWD_REP
        return KPASSWD_REQ


bind_bottom_up(UDP, Kpasswd, sport=464)
bind_bottom_up(UDP, Kpasswd, dport=464)
bind_top_down(UDP, KPASSWD_REQ, sport=464, dport=464)
bind_top_down(UDP, KPASSWD_REP, sport=464, dport=464)


class KpasswdTCPHeader(Packet):
    fields_desc = [LenField("len", None, fmt="!I")]

    @classmethod
    def tcp_reassemble(cls, data, *args, **kwargs):
        if len(data) < 4:
            return None
        length = struct.unpack("!I", data[:4])[0]
        if len(data) == length + 4:
            return cls(data)


bind_layers(KpasswdTCPHeader, Kpasswd)

bind_bottom_up(TCP, KpasswdTCPHeader, sport=464)
bind_layers(TCP, KpasswdTCPHeader, dport=464)


# Util functions


class KerberosClient(Automaton):
    RES_AS_MODE = namedtuple("AS_Result", ["asrep", "sessionkey", "kdcrep"])
    RES_TGS_MODE = namedtuple("TGS_Result", ["tgsrep", "sessionkey", "kdcrep"])

    class MODE(IntEnum):
        AS_REQ = 0
        TGS_REQ = 1
        GET_SALT = 2

    def __init__(
        self,
        mode=MODE.AS_REQ,
        ip=None,
        host=None,
        upn=None,
        password=None,
        realm=None,
        spn=None,
        ticket=None,
        renew=False,
        additional_tickets=[],
        u2u=False,
        for_user=None,
        s4u2proxy=False,
        etypes=None,
        key=None,
        port=88,
        timeout=5,
        **kwargs,
    ):
        import scapy.libs.rfc3961  # Trigger error if any  # noqa: F401
        from scapy.layers.ldap import dclocator

        if not upn:
            raise ValueError("Invalid upn")
        if not spn:
            raise ValueError("Invalid spn")
        if realm is None:
            if mode in [self.MODE.AS_REQ, self.MODE.GET_SALT]:
                _, realm = _parse_upn(upn)
            elif mode == self.MODE.TGS_REQ:
                _, realm = _parse_spn(spn)
                if not realm and ticket:
                    # if no realm is specified, but there's a ticket, take the realm
                    # of the ticket.
                    realm = ticket.realm.val.decode()
            else:
                raise ValueError("Invalid realm")

        if mode in [self.MODE.AS_REQ, self.MODE.GET_SALT]:
            if not host:
                raise ValueError("Invalid host")
        elif mode == self.MODE.TGS_REQ:
            if not ticket:
                raise ValueError("Invalid ticket")

        if not ip:
            # No KDC IP provided. Find it by querying the DNS
            ip = dclocator(
                realm,
                timeout=timeout,
                # Use connect mode instead of ldap for compatibility
                # with MIT kerberos servers
                mode="connect",
                port=port,
                debug=kwargs.get("debug", 0),
            ).ip

        if mode == self.MODE.GET_SALT:
            if etypes is not None:
                raise ValueError("Cannot specify etypes in GET_SALT mode !")

            from scapy.libs.rfc3961 import EncryptionType

            etypes = [
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                EncryptionType.AES128_CTS_HMAC_SHA1_96,
            ]
        elif etypes is None:
            from scapy.libs.rfc3961 import EncryptionType

            etypes = [
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                EncryptionType.AES128_CTS_HMAC_SHA1_96,
                EncryptionType.RC4_HMAC,
                EncryptionType.DES_CBC_MD5,
            ]
        self.etypes = etypes

        self.mode = mode

        self.result = None  # Result

        self._timeout = timeout
        self._ip = ip
        self._port = port
        sock = self._connect()

        if self.mode in [self.MODE.AS_REQ, self.MODE.GET_SALT]:
            self.host = host.upper()
            self.password = password and bytes_encode(password)
        self.spn = spn
        self.upn = upn
        self.realm = realm.upper()
        self.ticket = ticket
        self.renew = renew
        self.additional_tickets = additional_tickets  # U2U + S4U2Proxy
        self.u2u = u2u  # U2U
        self.for_user = for_user  # FOR-USER
        self.s4u2proxy = s4u2proxy  # S4U2Proxy
        self.key = key
        # See RFC4120 - sect 7.2.2
        # This marks whether we should follow-up after an EOF
        self.should_followup = False
        # Negotiated parameters
        self.pre_auth = False
        self.fxcookie = None
        super(KerberosClient, self).__init__(
            sock=sock,
            **kwargs,
        )

    def _connect(self):
        sock = socket.socket()
        sock.settimeout(self._timeout)
        sock.connect((self._ip, self._port))
        sock = StreamSocket(sock, KerberosTCPHeader)
        return sock

    def send(self, pkt):
        super(KerberosClient, self).send(KerberosTCPHeader() / pkt)

    def _base_kdc_req(self, now_time):
        kdcreq = KRB_KDC_REQ_BODY(
            etype=[ASN1_INTEGER(x) for x in self.etypes],
            additionalTickets=None,
            # Windows default
            kdcOptions="forwardable+renewable+canonicalize",
            cname=None,
            realm=ASN1_GENERAL_STRING(self.realm),
            till=ASN1_GENERALIZED_TIME(now_time + timedelta(hours=10)),
            rtime=ASN1_GENERALIZED_TIME(now_time + timedelta(hours=10)),
            nonce=ASN1_INTEGER(RandNum(0, 0x7FFFFFFF)._fix()),
        )
        if self.renew:
            kdcreq.kdcOptions.set(30, 1)  # set 'renew' (bit 30)
        return kdcreq

    def as_req(self):
        now_time = datetime.now(timezone.utc).replace(microsecond=0)

        kdc_req = self._base_kdc_req(now_time=now_time)
        kdc_req.addresses = [
            HostAddress(
                addrType=ASN1_INTEGER(20),  # Netbios
                address=ASN1_STRING(self.host.ljust(16, " ")),
            )
        ]
        kdc_req.cname = PrincipalName.fromUPN(self.upn)
        kdc_req.sname = PrincipalName.fromSPN(self.spn)

        asreq = Kerberos(
            root=KRB_AS_REQ(
                padata=[
                    PADATA(
                        padataType=ASN1_INTEGER(128),  # PA-PAC-REQUEST
                        padataValue=PA_PAC_REQUEST(includePac=ASN1_BOOLEAN(-1)),
                    )
                ],
                reqBody=kdc_req,
            )
        )
        # Pre-auth support
        if self.pre_auth:
            asreq.root.padata.insert(
                0,
                PADATA(
                    padataType=0x2,  # PA-ENC-TIMESTAMP
                    padataValue=EncryptedData(),
                ),
            )
            asreq.root.padata[0].padataValue.encrypt(
                self.key, PA_ENC_TS_ENC(patimestamp=ASN1_GENERALIZED_TIME(now_time))
            )
        # Cookie support
        if self.fxcookie:
            asreq.root.padata.insert(
                0,
                PADATA(
                    padataType=133,  # PA-FX-COOKIE
                    padataValue=self.fxcookie,
                ),
            )
        return asreq

    def tgs_req(self):
        now_time = datetime.now(timezone.utc).replace(microsecond=0)

        kdc_req = self._base_kdc_req(now_time=now_time)

        _, crealm = _parse_upn(self.upn)
        authenticator = KRB_Authenticator(
            crealm=ASN1_GENERAL_STRING(crealm),
            cname=PrincipalName.fromUPN(self.upn),
            cksum=None,
            ctime=ASN1_GENERALIZED_TIME(now_time),
            cusec=ASN1_INTEGER(0),
            subkey=None,
            seqNumber=None,
            encAuthorizationData=None,
        )

        apreq = KRB_AP_REQ(ticket=self.ticket, authenticator=EncryptedData())

        # Additional tickets
        if self.additional_tickets:
            kdc_req.additionalTickets = self.additional_tickets

        if self.u2u:  # U2U
            kdc_req.kdcOptions.set(28, 1)  # set 'enc-tkt-in-skey' (bit 28)

        kdc_req.sname = PrincipalName.fromSPN(self.spn)

        tgsreq = Kerberos(
            root=KRB_TGS_REQ(
                padata=[
                    PADATA(
                        padataType=ASN1_INTEGER(1),  # PA-TGS-REQ
                        padataValue=apreq,
                    )
                ],
                reqBody=kdc_req,
            )
        )

        # [MS-SFU] FOR-USER extension
        if self.for_user is not None:
            from scapy.libs.rfc3961 import ChecksumType

            paforuser = PA_FOR_USER(
                userName=PrincipalName.fromUPN(self.for_user),
                userRealm=ASN1_GENERAL_STRING(_parse_upn(self.for_user)[1]),
                cksum=Checksum(),
            )
            S4UByteArray = struct.pack(  # [MS-SFU] sect 2.2.1
                "<I", paforuser.userName.nameType.val
            ) + (
                (
                    "".join(x.val for x in paforuser.userName.nameString)
                    + paforuser.userRealm.val
                    + paforuser.authPackage.val
                ).encode()
            )
            paforuser.cksum.make(
                self.key,
                S4UByteArray,
                cksumtype=ChecksumType.HMAC_MD5,
            )
            tgsreq.root.padata.append(
                PADATA(
                    padataType=ASN1_INTEGER(129),  # PA-FOR-USER
                    padataValue=paforuser,
                )
            )

        # [MS-SFU] S4U2proxy - sect 3.1.5.2.1
        if self.s4u2proxy:
            # "PA-PAC-OPTIONS with resource-based constrained-delegation bit set"
            tgsreq.root.padata.append(
                PADATA(
                    padataType=ASN1_INTEGER(167),  # PA-PAC-OPTIONS
                    padataValue=PA_PAC_OPTIONS(
                        options="Resource-based-constrained-delegation",
                    ),
                )
            )
            # "kdc-options field: MUST include the new cname-in-addl-tkt options flag"
            kdc_req.kdcOptions.set(14, 1)

        # Compute checksum
        if self.key.cksumtype:
            authenticator.cksum = Checksum()
            authenticator.cksum.make(
                self.key,
                bytes(kdc_req),
            )
        # Encrypt authenticator
        apreq.authenticator.encrypt(self.key, authenticator)
        return tgsreq

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.condition(BEGIN)
    def should_send_as_req(self):
        if self.mode in [self.MODE.AS_REQ, self.MODE.GET_SALT]:
            raise self.SENT_AP_REQ()

    @ATMT.condition(BEGIN)
    def should_send_tgs_req(self):
        if self.mode == self.MODE.TGS_REQ:
            raise self.SENT_TGS_REQ()

    @ATMT.action(should_send_as_req)
    def send_as_req(self):
        self.send(self.as_req())

    @ATMT.action(should_send_tgs_req)
    def send_tgs_req(self):
        self.send(self.tgs_req())

    @ATMT.state()
    def SENT_AP_REQ(self):
        pass

    @ATMT.state()
    def SENT_TGS_REQ(self):
        pass

    def _process_padatas_and_key(self, padatas):
        from scapy.libs.rfc3961 import EncryptionType, Key

        etype = None
        salt = b""
        # Process pa-data
        if padatas is not None:
            for padata in padatas:
                if padata.padataType == 0x13 and etype is None:  # PA-ETYPE-INFO2
                    elt = padata.padataValue.seq[0]
                    if elt.etype.val in self.etypes:
                        etype = elt.etype.val
                        if etype != EncryptionType.RC4_HMAC:
                            salt = elt.salt.val
                elif padata.padataType == 133:  # PA-FX-COOKIE
                    self.fxcookie = padata.padataValue

        etype = etype or self.etypes[0]
        # Compute key if not already provided
        if self.key is None:
            self.key = Key.string_to_key(
                etype,
                self.password,
                salt,
            )

    @ATMT.receive_condition(SENT_AP_REQ, prio=0)
    def receive_salt_mode(self, pkt):
        # This is only for "Salt-Mode", a mode where we get the salt then
        # exit.
        if self.mode == self.MODE.GET_SALT:
            if Kerberos not in pkt:
                raise self.FINAL()
            if not isinstance(pkt.root, KRB_ERROR):
                log_runtime.error("Pre-auth is likely disabled !")
                raise self.FINAL()
            if pkt.root.errorCode == 25:  # KDC_ERR_PREAUTH_REQUIRED
                for padata in pkt.root.eData.seq:
                    if padata.padataType == 0x13:  # PA-ETYPE-INFO2
                        elt = padata.padataValue.seq[0]
                        if elt.etype.val in self.etypes:
                            self.result = elt.salt.val
                            raise self.FINAL()
            else:
                log_runtime.error("Failed to retrieve the salt !")
                raise self.FINAL()

    @ATMT.receive_condition(SENT_AP_REQ, prio=1)
    def receive_krb_error_as_req(self, pkt):
        # We check for a PREAUTH_REQUIRED error. This means that preauth is required
        # and we need to do a second exchange.
        if Kerberos in pkt and isinstance(pkt.root, KRB_ERROR):
            if pkt.root.errorCode == 25:  # KDC_ERR_PREAUTH_REQUIRED
                if not self.key and (not self.upn or not self.password):
                    log_runtime.error(
                        "Got 'KDC_ERR_PREAUTH_REQUIRED', "
                        "but no key, nor upn+pass was passed."
                    )
                    raise self.FINAL()
                self._process_padatas_and_key(pkt.root.eData.seq)
                self.should_followup = True
                self.pre_auth = True
                raise self.BEGIN()
            else:
                log_runtime.error("Received KRB_ERROR")
                pkt.show()
                raise self.FINAL()

    @ATMT.receive_condition(SENT_AP_REQ, prio=2)
    def receive_as_rep(self, pkt):
        if Kerberos in pkt and isinstance(pkt.root, KRB_AS_REP):
            raise self.FINAL().action_parameters(pkt)

    @ATMT.eof(SENT_AP_REQ)
    def retry_after_eof_in_apreq(self):
        if self.should_followup:
            # Reconnect and Restart
            self.should_followup = False
            self.update_sock(self._connect())
            raise self.BEGIN()
        else:
            log_runtime.error("Socket was closed in an unexpected state")
            raise self.FINAL()

    @ATMT.action(receive_as_rep)
    def decrypt_as_rep(self, pkt):
        self._process_padatas_and_key(pkt.root.padata)
        if not self.pre_auth:
            log_runtime.warning("Pre-authentication was disabled for this account !")
        # Decrypt
        enc = pkt.root.encPart
        res = enc.decrypt(self.key)
        self.result = self.RES_AS_MODE(pkt.root, res.key.toKey(), res)

    @ATMT.receive_condition(SENT_TGS_REQ)
    def receive_krb_error_tgs_req(self, pkt):
        if Kerberos in pkt and isinstance(pkt.root, KRB_ERROR):
            log_runtime.warning("Received KRB_ERROR")
            pkt.show()
            raise self.FINAL()

    @ATMT.receive_condition(SENT_TGS_REQ)
    def receive_tgs_rep(self, pkt):
        if Kerberos in pkt and isinstance(pkt.root, KRB_TGS_REP):
            if not self.renew and pkt.root.ticket.sname.nameString[0].val == b"krbtgt":
                log_runtime.warning("Received a cross-realm referral ticket !")
            raise self.FINAL().action_parameters(pkt)

    @ATMT.action(receive_tgs_rep)
    def decrypt_tgs_rep(self, pkt):
        # Decrypt
        enc = pkt.root.encPart
        res = enc.decrypt(self.key)
        self.result = self.RES_TGS_MODE(pkt.root, res.key.toKey(), res)

    @ATMT.state(final=1)
    def FINAL(self):
        pass


def _parse_upn(upn):
    m = re.match(r"^([^@\\/]+)(@|\\|/)([^@\\/]+)$", upn)
    if not m:
        raise ValueError("Invalid UPN: '%s'" % upn)
    if m.group(2) == "@":
        user = m.group(1)
        domain = m.group(3)
    else:
        user = m.group(3)
        domain = m.group(1)
    return user, domain


def _parse_spn(spn):
    m = re.match(r"^((?:[^@\\/]+)/(?:[^@\\/]+))(?:@([^@\\/]+))?$", spn)
    if not m:
        raise ValueError("Invalid SPN: '%s'" % spn)
    return m.group(1), m.group(2)


def krb_as_req(
    upn, spn=None, ip=None, key=None, password=None, realm=None, host="WIN10", **kwargs
):
    r"""
    Kerberos AS-Req

    :param upn: the user principal name formatted as "DOMAIN\user", "DOMAIN/user"
                or "user@DOMAIN"
    :param spn: (optional) the full service principal name.
                Defaults to "krbtgt/<realm>"
    :param ip: the KDC ip. (optional. If not provided, Scapy will query the DNS for
               _kerberos._tcp.dc._msdcs.domain.local).
    :param key: (optional) pass the Key object.
    :param password: (optional) otherwise, pass the user's password
    :param realm: (optional) the realm to use. Otherwise use the one from UPN.
    :param host: (optional) the host performing the AS-Req. WIN10 by default.

    :return: returns a named tuple (asrep=<...>, sessionkey=<...>)

    Example::

        >>> # The KDC is on 192.168.122.17, we ask a TGT for user1
        >>> krb_as_req("user1@DOMAIN.LOCAL", "192.168.122.17", password="Password1")

    Equivalent::

        >>> from scapy.libs.rfc3961 import Key, EncryptionType
        >>> key = Key(EncryptionType.AES256_CTS_HMAC_SHA1_96, key=hex_bytes("6d0748c546
        ...: f4e99205e78f8da7681d4ec5520ae4815543720c2a647c1ae814c9"))
        >>> krb_as_req("user1@DOMAIN.LOCAL", "192.168.122.17", key=key)
    """
    if realm is None:
        _, realm = _parse_upn(upn)
    if key is None:
        if password is None:
            try:
                from prompt_toolkit import prompt

                password = prompt("Enter password: ", is_password=True)
            except ImportError:
                password = input("Enter password: ")
    cli = KerberosClient(
        mode=KerberosClient.MODE.AS_REQ,
        realm=realm,
        ip=ip,
        spn=spn or "krbtgt/" + realm,
        host=host,
        upn=upn,
        password=password,
        key=key,
        **kwargs,
    )
    cli.run()
    cli.stop()
    return cli.result


def krb_tgs_req(
    upn,
    spn,
    sessionkey,
    ticket,
    ip=None,
    renew=False,
    realm=None,
    additional_tickets=[],
    u2u=False,
    etypes=None,
    for_user=None,
    s4u2proxy=False,
    **kwargs,
):
    r"""
    Kerberos TGS-Req

    :param upn: the user principal name formatted as "DOMAIN\user", "DOMAIN/user"
                or "user@DOMAIN"
    :param spn: the full service principal name (e.g. "cifs/srv1")
    :param sessionkey: the session key retrieved from the tgt
    :param ticket: the tgt ticket
    :param ip: the KDC ip. (optional. If not provided, Scapy will query the DNS for
               _kerberos._tcp.dc._msdcs.domain.local).
    :param renew: ask for renewal
    :param realm: (optional) the realm to use. Otherwise use the one from SPN.
    :param additional_tickets: (optional) a list of additional tickets to pass.
    :param u2u: (optional) if specified, enable U2U and request the ticket to be
                signed using the session key from the first additional ticket.
    :param etypes: array of EncryptionType values.
                   By default: AES128, AES256, RC4, DES_MD5
    :param for_user: a user principal name to request the ticket for. This is the
                     S4U2Self extension.

    :return: returns a named tuple (tgsrep=<...>, sessionkey=<...>)

    Example::

        >>> # The KDC is on 192.168.122.17, we ask a TGT for user1
        >>> krb_as_req("user1@DOMAIN.LOCAL", "192.168.122.17", password="Password1")

    Equivalent::

        >>> from scapy.libs.rfc3961 import Key, EncryptionType
        >>> key = Key(EncryptionType.AES256_CTS_HMAC_SHA1_96, key=hex_bytes("6d0748c546
        ...: f4e99205e78f8da7681d4ec5520ae4815543720c2a647c1ae814c9"))
        >>> krb_as_req("user1@DOMAIN.LOCAL", "192.168.122.17", key=key)
    """
    cli = KerberosClient(
        mode=KerberosClient.MODE.TGS_REQ,
        realm=realm,
        upn=upn,
        ip=ip,
        spn=spn,
        key=sessionkey,
        ticket=ticket,
        renew=renew,
        additional_tickets=additional_tickets,
        u2u=u2u,
        etypes=etypes,
        for_user=for_user,
        s4u2proxy=s4u2proxy,
        **kwargs,
    )
    cli.run()
    cli.stop()
    return cli.result


def krb_as_and_tgs(upn, spn, ip=None, key=None, password=None, **kwargs):
    """
    Kerberos AS-Req then TGS-Req
    """
    res = krb_as_req(upn=upn, ip=ip, key=key, password=password, **kwargs)
    if not res:
        return
    return krb_tgs_req(
        upn=upn,
        spn=spn,
        sessionkey=res.sessionkey,
        ticket=res.asrep.ticket,
        ip=ip,
        **kwargs,
    )


def krb_get_salt(upn, ip=None, realm=None, host="WIN10", **kwargs):
    """
    Kerberos AS-Req only to get the salt associated with the UPN.
    """
    if realm is None:
        _, realm = _parse_upn(upn)
    cli = KerberosClient(
        mode=KerberosClient.MODE.GET_SALT,
        realm=realm,
        ip=ip,
        spn="krbtgt/" + realm,
        upn=upn,
        host=host,
        **kwargs,
    )
    cli.run()
    cli.stop()
    return cli.result


def kpasswd(
    upn,
    targetupn=None,
    ip=None,
    password=None,
    newpassword=None,
    key=None,
    ticket=None,
    realm=None,
    ssp=None,
    setpassword=None,
    timeout=3,
    port=464,
    debug=0,
    **kwargs,
):
    """
    Change a password using RFC3244's Kerberos Set / Change Password.

    :param upn: the UPN to use for authentication
    :param targetupn: (optional) the UPN to change the password of. If not specified,
                      same as upn.
    :param ip: the KDC ip. (optional. If not provided, Scapy will query the DNS for
               _kerberos._tcp.dc._msdcs.domain.local).
    :param key: (optional) pass the Key object.
    :param ticket: (optional) a ticket to use. Either a TGT or ST for kadmin/changepw.
    :param password: (optional) otherwise, pass the user's password
    :param realm: (optional) the realm to use. Otherwise use the one from UPN.
    :param setpassword: (optional) use "Set Password" mechanism.
    :param ssp: (optional) a Kerberos SSP for the service kadmin/changepw@REALM.
                If provided, you probably don't need anything else. Otherwise built.
    """
    from scapy.layers.ldap import dclocator

    if not realm:
        _, realm = _parse_upn(upn)
    spn = "kadmin/changepw@%s" % realm
    if ip is None:
        ip = dclocator(
            realm,
            timeout=timeout,
            # Use connect mode instead of ldap for compatibility
            # with MIT kerberos servers
            mode="connect",
            port=port,
            debug=debug,
        ).ip
    if ssp is None and ticket is not None:
        tktspn = ticket.getSPN().split("/")[0]
        assert tktspn in ["krbtgt", "kadmin"], "Unexpected ticket type ! %s" % tktspn
        if tktspn == "krbtgt":
            log_runtime.info(
                "Using 'Set Password' mode. This only works with admin privileges."
            )
            setpassword = True
            resp = krb_tgs_req(
                upn=upn,
                spn=spn,
                ticket=ticket,
                sessionkey=key,
                ip=ip,
                debug=debug,
            )
            if resp is None:
                return
            ticket = resp.tgsrep.ticket
            key = resp.sessionkey
    if setpassword is None:
        setpassword = bool(targetupn)
    elif setpassword and targetupn is None:
        targetupn = upn
    assert setpassword or not targetupn, "Cannot use targetupn in changepassword mode !"
    # Get a ticket for kadmin/changepw
    if ssp is None:
        if ticket is None:
            # Get a ticket for kadmin/changepw through AS-REQ
            resp = krb_as_req(
                upn=upn,
                spn=spn,
                key=key,
                ip=ip,
                password=password,
                debug=debug,
            )
            if resp is None:
                return
            ticket = resp.asrep.ticket
            key = resp.sessionkey
        ssp = KerberosSSP(
            UPN=upn,
            SPN=spn,
            ST=ticket,
            KEY=key,
            DC_IP=ip,
            debug=debug,
            **kwargs,
        )
    Context, tok, negResult = ssp.GSS_Init_sec_context(
        None,
        req_flags=0,  # No GSS_C_MUTUAL_FLAG
    )
    if negResult != GSS_S_CONTINUE_NEEDED:
        warning("SSP failed on initial GSS_Init_sec_context !")
        if tok:
            tok.show()
        return
    apreq = tok.innerToken.root
    # Connect
    sock = socket.socket()
    sock.settimeout(timeout)
    sock.connect((ip, port))
    sock = StreamSocket(sock, KpasswdTCPHeader)
    # Do KPASSWD request
    if newpassword is None:
        try:
            from prompt_toolkit import prompt

            newpassword = prompt("Enter NEW password: ", is_password=True)
        except ImportError:
            newpassword = input("Enter NEW password: ")
    krbpriv = KRB_PRIV(encPart=EncryptedData())
    krbpriv.encPart.encrypt(
        Context.KrbSessionKey,
        EncKrbPrivPart(
            sAddress=HostAddress(
                addrType=ASN1_INTEGER(2),  # IPv4
                address=ASN1_STRING(b"\xc0\xa8\x00e"),
            ),
            userData=ASN1_STRING(
                bytes(
                    ChangePasswdData(
                        newpasswd=newpassword,
                        targname=PrincipalName.fromUPN(targetupn),
                        targrealm=realm,
                    )
                )
                if setpassword
                else newpassword
            ),
            timestamp=None,
            usec=None,
            seqNumber=Context.SendSeqNum,
        ),
    )
    resp = sock.sr1(
        KpasswdTCPHeader()
        / KPASSWD_REQ(
            pvno=0xFF80 if setpassword else 1,
            apreq=apreq,
            krbpriv=krbpriv,
        ),
        timeout=timeout,
        verbose=0,
    )
    # Verify KPASSWD response
    if not resp:
        raise TimeoutError("KPASSWD_REQ timed out !")
    if KPASSWD_REP not in resp:
        resp.show()
        raise ValueError("Invalid response to KPASSWD_REQ !")
    Context, tok, negResult = ssp.GSS_Init_sec_context(Context, resp.aprep)
    if negResult != GSS_S_COMPLETE:
        warning("SSP failed on subsequent GSS_Init_sec_context !")
        if tok:
            tok.show()
        return
    # Parse answer KRB_PRIV
    krbanswer = resp.krbpriv.encPart.decrypt(Context.KrbSessionKey)
    userRep = KPasswdRepData(krbanswer.userData.val)
    if userRep.resultCode != 0:
        warning(userRep.sprintf("KPASSWD failed !"))
        userRep.show()
        return
    print(userRep.sprintf("%resultCode%"))


# SSP


class KerberosSSP(SSP):
    """
    The KerberosSSP

    Client settings:

    :param ST: the service ticket to use for access.
               If not provided, will be retrieved
    :param SPN: the SPN of the service to use
    :param UPN: The client UPN
    :param DC_IP: (optional) is ST+KEY are not provided, will need to contact
                  the KDC at this IP. If not provided, will perform dc locator.
    :param TGT: (optional) pass a TGT to use to get the ST.
    :param KEY: the session key associated with the ST if it is provided,
                OR the session key associated with the TGT
                OR the kerberos key associated with the UPN
    :param PASSWORD: (optional) if a UPN is provided and not a KEY, this is the
                     password of the UPN.
    :param U2U: (optional) use U2U when requesting the ST.

    Server settings:

    :param SPN: the SPN of the service to use
    :param KEY: the kerberos key to use to decrypt the AP-req
    :param TGT: (optional) pass a TGT to use for U2U
    :param DC_IP: (optional) if TGT is not provided, request one on the KDC at
                  this IP using using the KEY when using U2U.
    :param REQUIRE_U2U: (optional, default False) require U2U
    """

    oid = "1.2.840.113554.1.2.2"
    auth_type = 0x10

    class STATE(SSP.STATE):
        INIT = 1
        CLI_SENT_TGTREQ = 2
        CLI_SENT_APREQ = 3
        CLI_RCVD_APREP = 4
        SRV_SENT_APREP = 5

    class CONTEXT(SSP.CONTEXT):
        __slots__ = [
            "SessionKey",
            "ServerHostname",
            "U2U",
            "KrbSessionKey",  # raw Key object
            "STSessionKey",  # raw ST Key object (for DCE_STYLE)
            "SeqNum",  # for AP
            "SendSeqNum",  # for MIC
            "RecvSeqNum",  # for MIC
            "IsAcceptor",
            "SendSealKeyUsage",
            "SendSignKeyUsage",
            "RecvSealKeyUsage",
            "RecvSignKeyUsage",
        ]

        def __init__(self, IsAcceptor, req_flags=None):
            self.state = KerberosSSP.STATE.INIT
            self.SessionKey = None
            self.ServerHostname = None
            self.U2U = False
            self.SendSeqNum = 0
            self.RecvSeqNum = 0
            self.KrbSessionKey = None
            self.STSessionKey = None
            self.IsAcceptor = IsAcceptor
            # [RFC 4121] sect 2
            if IsAcceptor:
                self.SendSealKeyUsage = 22
                self.SendSignKeyUsage = 23
                self.RecvSealKeyUsage = 24
                self.RecvSignKeyUsage = 25
            else:
                self.SendSealKeyUsage = 24
                self.SendSignKeyUsage = 25
                self.RecvSealKeyUsage = 22
                self.RecvSignKeyUsage = 23
            super(KerberosSSP.CONTEXT, self).__init__(req_flags=req_flags)

        def clifailure(self):
            self.__init__(self.IsAcceptor, req_flags=self.flags)

        def __repr__(self):
            if self.U2U:
                return "KerberosSSP-U2U"
            return "KerberosSSP"

    def __init__(
        self,
        ST=None,
        UPN=None,
        PASSWORD=None,
        U2U=False,
        KEY=None,
        SPN=None,
        TGT=None,
        DC_IP=None,
        REQUIRE_U2U=False,
        SKEY_TYPE=None,
        debug=0,
        **kwargs,
    ):
        self.ST = ST
        self.UPN = UPN
        self.KEY = KEY
        self.SPN = SPN
        self.TGT = TGT
        self.PASSWORD = PASSWORD
        self.U2U = U2U
        self.DC_IP = DC_IP
        self.REQUIRE_U2U = REQUIRE_U2U
        self.debug = debug
        if SKEY_TYPE is None:
            from scapy.libs.rfc3961 import EncryptionType

            SKEY_TYPE = EncryptionType.AES128_CTS_HMAC_SHA1_96
        self.SKEY_TYPE = SKEY_TYPE
        super(KerberosSSP, self).__init__(**kwargs)

    def GSS_GetMICEx(self, Context, msgs, qop_req=0):
        """
        [MS-KILE] sect 3.4.5.6

        - AES: RFC4121 sect 4.2.6.1
        """
        if Context.KrbSessionKey.etype in [17, 18]:  # AES
            # Concatenate the ToSign
            ToSign = b"".join(x.data for x in msgs if x.sign)
            sig = KRB_InnerToken(
                TOK_ID=b"\x04\x04",
                root=KRB_GSS_MIC(
                    Flags="AcceptorSubkey"
                    + ("+SentByAcceptor" if Context.IsAcceptor else ""),
                    SND_SEQ=Context.SendSeqNum,
                ),
            )
            ToSign += bytes(sig)[:16]
            sig.root.SGN_CKSUM = Context.KrbSessionKey.make_checksum(
                keyusage=Context.SendSignKeyUsage,
                text=ToSign,
            )
        else:
            raise NotImplementedError
        Context.SendSeqNum += 1
        return sig

    def GSS_VerifyMICEx(self, Context, msgs, signature):
        """
        [MS-KILE] sect 3.4.5.7

        - AES: RFC4121 sect 4.2.6.1
        """
        Context.RecvSeqNum = signature.root.SND_SEQ
        if Context.KrbSessionKey.etype in [17, 18]:  # AES
            # Concatenate the ToSign
            ToSign = b"".join(x.data for x in msgs if x.sign)
            ToSign += bytes(signature)[:16]
            sig = Context.KrbSessionKey.make_checksum(
                keyusage=Context.RecvSignKeyUsage,
                text=ToSign,
            )
        else:
            raise NotImplementedError
        if sig != signature.root.SGN_CKSUM:
            raise ValueError("ERROR: Checksums don't match")

    def GSS_WrapEx(self, Context, msgs, qop_req=0):
        """
        [MS-KILE] sect 3.4.5.4

        - AES: RFC4121 sect 4.2.6.2 and [MS-KILE] sect 3.4.5.4.1
        - HMAC-RC4: RFC4757 sect 7.3 and [MS-KILE] sect 3.4.5.4.1
        """
        # Is confidentiality in use?
        confidentiality = (Context.flags & GSS_C_FLAGS.GSS_C_CONF_FLAG) and any(
            x.conf_req_flag for x in msgs
        )
        if Context.KrbSessionKey.etype in [17, 18]:  # AES
            # Build token
            tok = KRB_InnerToken(
                TOK_ID=b"\x05\x04",
                root=KRB_GSS_Wrap(
                    Flags="AcceptorSubkey"
                    + ("+SentByAcceptor" if Context.IsAcceptor else "")
                    + ("+Sealed" if confidentiality else ""),
                    SND_SEQ=Context.SendSeqNum,
                    RRC=0,
                ),
            )
            Context.SendSeqNum += 1
            # Real separation starts now: RFC4121 sect 4.2.4
            if confidentiality:
                # Confidentiality is requested (see RFC4121 sect 4.3)
                # {"header" | encrypt(plaintext-data | filler | "header")}
                # 0. Roll confounder
                Confounder = os.urandom(Context.KrbSessionKey.ep.blocksize)
                # 1. Concatenate the data to be encrypted
                Data = b"".join(x.data for x in msgs if x.conf_req_flag)
                DataLen = len(Data)
                # 2. Add filler
                tok.root.EC = ((-DataLen) % Context.KrbSessionKey.ep.blocksize) or 16
                Filler = b"\x00" * tok.root.EC
                Data += Filler
                # 3. Add first 16 octets of the Wrap token "header"
                PlainHeader = bytes(tok)[:16]
                Data += PlainHeader
                # 4. Build 'ToSign', exclusively used for checksum
                ToSign = Confounder
                ToSign += b"".join(x.data for x in msgs if x.sign)
                ToSign += Filler
                ToSign += PlainHeader
                # 5. Finalize token for signing
                # "The RRC field is [...] 28 if encryption is requested."
                tok.root.RRC = 28
                # 6. encrypt() is the encryption operation (which provides for
                # integrity protection)
                Data = Context.KrbSessionKey.encrypt(
                    keyusage=Context.SendSealKeyUsage,
                    plaintext=Data,
                    confounder=Confounder,
                    signtext=ToSign,
                )
                # 7. Rotate
                Data = strrot(Data, tok.root.RRC + tok.root.EC)
                # 8. Split (token and encrypted messages)
                toklen = len(Data) - DataLen
                tok.root.Data = Data[:toklen]
                offset = toklen
                for msg in msgs:
                    msglen = len(msg.data)
                    if msg.conf_req_flag:
                        msg.data = Data[offset : offset + msglen]
                        offset += msglen
                return msgs, tok
            else:
                # No confidentiality is requested
                # {"header" | plaintext-data | get_mic(plaintext-data | "header")}
                # 0. Concatenate the data
                Data = b"".join(x.data for x in msgs if x.sign)
                DataLen = len(Data)
                # 1. Add first 16 octets of the Wrap token "header"
                ToSign = Data
                ToSign += bytes(tok)[:16]
                # 2. get_mic() is the checksum operation for the required
                # checksum mechanism
                Mic = Context.KrbSessionKey.make_checksum(
                    keyusage=Context.SendSealKeyUsage,
                    text=ToSign,
                )
                # In Wrap tokens without confidentiality, the EC field SHALL be used
                # to encode the number of octets in the trailing checksum
                tok.root.EC = 12  # len(tok.root.Data) == 12 for AES
                # "The RRC field ([RFC4121] section 4.2.5) is 12 if no encryption
                # is requested"
                tok.root.RRC = 12
                # 3. Concat and pack
                for msg in msgs:
                    if msg.sign:
                        msg.data = b""
                Data = Data + Mic
                # 4. Rotate
                tok.root.Data = strrot(Data, tok.root.RRC)
                return msgs, tok
        elif Context.KrbSessionKey.etype in [23, 24]:  # RC4
            from scapy.libs.rfc3961 import (
                Cipher,
                Hmac_MD5,
                _rfc1964pad,
                decrepit_algorithms,
            )

            # Build token
            seq = struct.pack(">I", Context.SendSeqNum)
            tok = KRB_InnerToken(
                TOK_ID=b"\x02\x01",
                root=KRB_GSS_Wrap_RFC1964(
                    SGN_ALG="HMAC",
                    SEAL_ALG="RC4" if confidentiality else "none",
                    SND_SEQ=seq
                    + (
                        # See errata
                        b"\xff\xff\xff\xff"
                        if Context.IsAcceptor
                        else b"\x00\x00\x00\x00"
                    ),
                ),
            )
            Context.SendSeqNum += 1
            # 0. Concatenate data
            ToSign = _rfc1964pad(b"".join(x.data for x in msgs if x.sign))
            ToEncrypt = b"".join(x.data for x in msgs if x.conf_req_flag)
            Kss = Context.KrbSessionKey.key
            # 1. Roll confounder
            Confounder = os.urandom(8)
            # 2. Compute the 'Kseq' key
            Klocal = strxor(Kss, len(Kss) * b"\xf0")
            if Context.KrbSessionKey.etype == 24:  # EXP
                Kcrypt = Hmac_MD5(Klocal).digest(b"fortybits\x00" + b"\x00\x00\x00\x00")
                Kcrypt = Kcrypt[:7] + b"\xab" * 9
            else:
                Kcrypt = Hmac_MD5(Klocal).digest(b"\x00\x00\x00\x00")
            Kcrypt = Hmac_MD5(Kcrypt).digest(seq)
            # 3. Build SGN_CKSUM
            tok.root.SGN_CKSUM = Context.KrbSessionKey.make_checksum(
                keyusage=13,  # See errata
                text=bytes(tok)[:8] + Confounder + ToSign,
            )[:8]
            # 4. Populate token + encrypt
            if confidentiality:
                # 'encrypt' is requested
                rc4 = Cipher(decrepit_algorithms.ARC4(Kcrypt), mode=None).encryptor()
                tok.root.CONFOUNDER = rc4.update(Confounder)
                Data = rc4.update(ToEncrypt)
                # Split encrypted data
                offset = 0
                for msg in msgs:
                    msglen = len(msg.data)
                    if msg.conf_req_flag:
                        msg.data = Data[offset : offset + msglen]
                        offset += msglen
            else:
                # 'encrypt' is not requested
                tok.root.CONFOUNDER = Confounder
            # 5. Compute the 'Kseq' key
            if Context.KrbSessionKey.etype == 24:  # EXP
                Kseq = Hmac_MD5(Kss).digest(b"fortybits\x00" + b"\x00\x00\x00\x00")
                Kseq = Kseq[:7] + b"\xab" * 9
            else:
                Kseq = Hmac_MD5(Kss).digest(b"\x00\x00\x00\x00")
            Kseq = Hmac_MD5(Kseq).digest(tok.root.SGN_CKSUM)
            # 6. Encrypt 'SND_SEQ'
            rc4 = Cipher(decrepit_algorithms.ARC4(Kseq), mode=None).encryptor()
            tok.root.SND_SEQ = rc4.update(tok.root.SND_SEQ)
            # 7. Include 'InitialContextToken pseudo ASN.1 header'
            tok = KRB_GSSAPI_Token(
                MechType="1.2.840.113554.1.2.2",  # Kerberos 5
                innerToken=tok,
            )
            return msgs, tok
        else:
            raise NotImplementedError

    def GSS_UnwrapEx(self, Context, msgs, signature):
        """
        [MS-KILE] sect 3.4.5.5

        - AES: RFC4121 sect 4.2.6.2
        - HMAC-RC4: RFC4757 sect 7.3
        """
        if Context.KrbSessionKey.etype in [17, 18]:  # AES
            confidentiality = signature.root.Flags.Sealed
            # Real separation starts now: RFC4121 sect 4.2.4
            if confidentiality:
                # 0. Concatenate the data
                Data = signature.root.Data
                Data += b"".join(x.data for x in msgs if x.conf_req_flag)
                # 1. Un-Rotate
                Data = strrot(Data, signature.root.RRC + signature.root.EC, right=False)

                # 2. Function to build 'ToSign', exclusively used for checksum
                def MakeToSign(Confounder, DecText):
                    offset = 0
                    # 2.a Confounder
                    ToSign = Confounder
                    # 2.b Messages
                    for msg in msgs:
                        msglen = len(msg.data)
                        if msg.conf_req_flag:
                            ToSign += DecText[offset : offset + msglen]
                            offset += msglen
                        elif msg.sign:
                            ToSign += msg.data
                    # 2.c Filler & Padding
                    ToSign += DecText[offset:]
                    return ToSign

                # 3. Decrypt
                Data = Context.KrbSessionKey.decrypt(
                    keyusage=Context.RecvSealKeyUsage,
                    ciphertext=Data,
                    presignfunc=MakeToSign,
                )
                # 4. Split
                Data, f16header = (
                    Data[:-16],
                    Data[-16:],
                )
                # 5. Check header
                hdr = signature.copy()
                hdr.root.RRC = 0
                if f16header != bytes(hdr)[:16]:
                    raise ValueError("ERROR: Headers don't match")
                # 6. Split (and ignore filler)
                offset = 0
                for msg in msgs:
                    msglen = len(msg.data)
                    if msg.conf_req_flag:
                        msg.data = Data[offset : offset + msglen]
                        offset += msglen
                # Case without msgs
                if len(msgs) == 1 and not msgs[0].data:
                    msgs[0].data = Data
                return msgs
            else:
                # No confidentiality is requested
                # 0. Concatenate the data
                Data = signature.root.Data
                Data += b"".join(x.data for x in msgs if x.sign)
                # 1. Un-Rotate
                Data = strrot(Data, signature.root.RRC, right=False)
                # 2. Split
                Data, Mic = Data[: -signature.root.EC], Data[-signature.root.EC :]
                # "Both the EC field and the RRC field in
                # the token header SHALL be filled with zeroes for the purpose of
                # calculating the checksum."
                ToSign = Data
                hdr = signature.copy()
                hdr.root.RRC = 0
                hdr.root.EC = 0
                # Concatenate the data
                ToSign += bytes(hdr)[:16]
                # 3. Calculate the signature
                sig = Context.KrbSessionKey.make_checksum(
                    keyusage=Context.RecvSealKeyUsage,
                    text=ToSign,
                )
                # 4. Compare
                if sig != Mic:
                    raise ValueError("ERROR: Checksums don't match")
                # Case without msgs
                if len(msgs) == 1 and not msgs[0].data:
                    msgs[0].data = Data
                return msgs
        elif Context.KrbSessionKey.etype in [23, 24]:  # RC4
            from scapy.libs.rfc3961 import (
                Cipher,
                Hmac_MD5,
                _rfc1964pad,
                decrepit_algorithms,
            )

            # Drop wrapping
            tok = signature.innerToken

            # Detect confidentiality
            confidentiality = tok.root.SEAL_ALG != 0xFFFF

            # 0. Concatenate data
            ToDecrypt = b"".join(x.data for x in msgs if x.conf_req_flag)
            Kss = Context.KrbSessionKey.key
            # 1. Compute the 'Kseq' key
            if Context.KrbSessionKey.etype == 24:  # EXP
                Kseq = Hmac_MD5(Kss).digest(b"fortybits\x00" + b"\x00\x00\x00\x00")
                Kseq = Kseq[:7] + b"\xab" * 9
            else:
                Kseq = Hmac_MD5(Kss).digest(b"\x00\x00\x00\x00")
            Kseq = Hmac_MD5(Kseq).digest(tok.root.SGN_CKSUM)
            # 2. Decrypt 'SND_SEQ'
            rc4 = Cipher(decrepit_algorithms.ARC4(Kseq), mode=None).encryptor()
            seq = rc4.update(tok.root.SND_SEQ)[:4]
            # 3. Compute the 'Kcrypt' key
            Klocal = strxor(Kss, len(Kss) * b"\xf0")
            if Context.KrbSessionKey.etype == 24:  # EXP
                Kcrypt = Hmac_MD5(Klocal).digest(b"fortybits\x00" + b"\x00\x00\x00\x00")
                Kcrypt = Kcrypt[:7] + b"\xab" * 9
            else:
                Kcrypt = Hmac_MD5(Klocal).digest(b"\x00\x00\x00\x00")
            Kcrypt = Hmac_MD5(Kcrypt).digest(seq)
            # 4. Decrypt
            if confidentiality:
                # 'encrypt' was requested
                rc4 = Cipher(decrepit_algorithms.ARC4(Kcrypt), mode=None).encryptor()
                Confounder = rc4.update(tok.root.CONFOUNDER)
                Data = rc4.update(ToDecrypt)
                # Split encrypted data
                offset = 0
                for msg in msgs:
                    msglen = len(msg.data)
                    if msg.conf_req_flag:
                        msg.data = Data[offset : offset + msglen]
                        offset += msglen
            else:
                # 'encrypt' was not requested
                Confounder = tok.root.CONFOUNDER
            # 5. Verify SGN_CKSUM
            ToSign = _rfc1964pad(b"".join(x.data for x in msgs if x.sign))
            Context.KrbSessionKey.verify_checksum(
                keyusage=13,  # See errata
                text=bytes(tok)[:8] + Confounder + ToSign,
                cksum=tok.root.SGN_CKSUM,
            )
            return msgs
        else:
            raise NotImplementedError

    def GSS_Init_sec_context(
        self, Context: CONTEXT, val=None, req_flags: Optional[GSS_C_FLAGS] = None
    ):
        if Context is None:
            # New context
            Context = self.CONTEXT(IsAcceptor=False, req_flags=req_flags)

        from scapy.libs.rfc3961 import Key

        if Context.state == self.STATE.INIT and self.U2U:
            # U2U - Get TGT
            Context.state = self.STATE.CLI_SENT_TGTREQ
            return (
                Context,
                KRB_GSSAPI_Token(
                    MechType="1.2.840.113554.1.2.2.3",  # U2U
                    innerToken=KRB_InnerToken(
                        TOK_ID=b"\x04\x00",
                        root=KRB_TGT_REQ(),
                    ),
                ),
                GSS_S_CONTINUE_NEEDED,
            )

        if Context.state in [self.STATE.INIT, self.STATE.CLI_SENT_TGTREQ]:
            if not self.UPN:
                raise ValueError("Missing UPN attribute")
            # Do we have a ST?
            if self.ST is None:
                # Client sends an AP-req
                if not self.SPN:
                    raise ValueError("Missing SPN attribute")
                additional_tickets = []
                if self.U2U:
                    try:
                        # GSSAPI / Kerberos
                        tgt_rep = val.root.innerToken.root
                    except AttributeError:
                        try:
                            # Kerberos
                            tgt_rep = val.innerToken.root
                        except AttributeError:
                            return Context, None, GSS_S_DEFECTIVE_TOKEN
                    if not isinstance(tgt_rep, KRB_TGT_REP):
                        tgt_rep.show()
                        raise ValueError("KerberosSSP: Unexpected token !")
                    additional_tickets = [tgt_rep.ticket]
                if self.TGT is not None:
                    if not self.KEY:
                        raise ValueError("Cannot use TGT without the KEY")
                    # Use TGT
                    res = krb_tgs_req(
                        upn=self.UPN,
                        spn=self.SPN,
                        ip=self.DC_IP,
                        sessionkey=self.KEY,
                        ticket=self.TGT,
                        additional_tickets=additional_tickets,
                        u2u=self.U2U,
                        debug=self.debug,
                    )
                else:
                    # Ask for TGT then ST
                    res = krb_as_and_tgs(
                        upn=self.UPN,
                        spn=self.SPN,
                        ip=self.DC_IP,
                        key=self.KEY,
                        password=self.PASSWORD,
                        additional_tickets=additional_tickets,
                        u2u=self.U2U,
                        debug=self.debug,
                    )
                if not res:
                    # Failed to retrieve the ticket
                    return Context, None, GSS_S_FAILURE
                self.ST, self.KEY = res.tgsrep.ticket, res.sessionkey
            elif not self.KEY:
                raise ValueError("Must provide KEY with ST")
            Context.STSessionKey = self.KEY
            # Save ServerHostname
            if len(self.ST.sname.nameString) == 2:
                Context.ServerHostname = self.ST.sname.nameString[1].val.decode()
            # Build the KRB-AP
            apOptions = ASN1_BIT_STRING("000")
            if Context.flags & GSS_C_FLAGS.GSS_C_MUTUAL_FLAG:
                apOptions.set(2, "1")  # mutual-required
            if self.U2U:
                apOptions.set(1, "1")  # use-session-key
                Context.U2U = True
            ap_req = KRB_AP_REQ(
                apOptions=apOptions,
                ticket=self.ST,
                authenticator=EncryptedData(),
            )
            # Build the authenticator
            now_time = datetime.now(timezone.utc).replace(microsecond=0)
            Context.KrbSessionKey = Key.random_to_key(
                self.SKEY_TYPE,
                os.urandom(16),
            )
            Context.SendSeqNum = RandNum(0, 0x7FFFFFFF)._fix()
            _, crealm = _parse_upn(self.UPN)
            ap_req.authenticator.encrypt(
                Context.STSessionKey,
                KRB_Authenticator(
                    crealm=crealm,
                    cname=PrincipalName.fromUPN(self.UPN),
                    # RFC 4121 checksum
                    cksum=Checksum(
                        cksumtype="KRB-AUTHENTICATOR",
                        checksum=KRB_AuthenticatorChecksum(Flags=int(Context.flags)),
                    ),
                    ctime=ASN1_GENERALIZED_TIME(now_time),
                    cusec=ASN1_INTEGER(0),
                    subkey=EncryptionKey.fromKey(Context.KrbSessionKey),
                    seqNumber=Context.SendSeqNum,
                    encAuthorizationData=AuthorizationData(
                        seq=[
                            AuthorizationDataItem(
                                adType="AD-IF-RELEVANT",
                                adData=AuthorizationData(
                                    seq=[
                                        AuthorizationDataItem(
                                            adType="KERB-AUTH-DATA-TOKEN-RESTRICTIONS",
                                            adData=KERB_AD_RESTRICTION_ENTRY(
                                                restriction=LSAP_TOKEN_INFO_INTEGRITY(
                                                    MachineID=bytes(RandBin(32))
                                                )
                                            ),
                                        ),
                                        AuthorizationDataItem(
                                            adType="KERB-LOCAL",
                                            adData=b"\x00" * 16,
                                        ),
                                    ]
                                ),
                            )
                        ]
                    ),
                ),
            )
            Context.state = self.STATE.CLI_SENT_APREQ
            if Context.flags & GSS_C_FLAGS.GSS_C_DCE_STYLE:
                # Raw kerberos DCE-STYLE
                return Context, ap_req, GSS_S_CONTINUE_NEEDED
            else:
                # Kerberos wrapper
                return (
                    Context,
                    KRB_GSSAPI_Token(
                        innerToken=KRB_InnerToken(
                            root=ap_req,
                        )
                    ),
                    GSS_S_CONTINUE_NEEDED,
                )

        elif Context.state == self.STATE.CLI_SENT_APREQ:
            if isinstance(val, KRB_AP_REP):
                # Raw AP_REP was passed
                ap_rep = val
            else:
                try:
                    # GSSAPI / Kerberos
                    ap_rep = val.root.innerToken.root
                except AttributeError:
                    try:
                        # Kerberos
                        ap_rep = val.innerToken.root
                    except AttributeError:
                        try:
                            # Raw kerberos DCE-STYLE
                            ap_rep = val.root
                        except AttributeError:
                            return Context, None, GSS_S_DEFECTIVE_TOKEN
            if not isinstance(ap_rep, KRB_AP_REP):
                return Context, None, GSS_S_DEFECTIVE_TOKEN
            # Retrieve SessionKey
            repPart = ap_rep.encPart.decrypt(Context.STSessionKey)
            if repPart.subkey is not None:
                Context.SessionKey = repPart.subkey.keyvalue.val
                Context.KrbSessionKey = repPart.subkey.toKey()
            # OK !
            Context.state = self.STATE.CLI_RCVD_APREP
            if Context.flags & GSS_C_FLAGS.GSS_C_DCE_STYLE:
                # [MS-KILE] sect 3.4.5.1
                # The client MUST generate an additional AP exchange reply message
                # exactly as the server would as the final message to send to the
                # server.
                now_time = datetime.now(timezone.utc).replace(microsecond=0)
                cli_ap_rep = KRB_AP_REP(encPart=EncryptedData())
                cli_ap_rep.encPart.encrypt(
                    Context.STSessionKey,
                    EncAPRepPart(
                        ctime=ASN1_GENERALIZED_TIME(now_time),
                        seqNumber=repPart.seqNumber,
                        subkey=None,
                    ),
                )
                return Context, cli_ap_rep, GSS_S_COMPLETE
            return Context, None, GSS_S_COMPLETE
        elif (
            Context.state == self.STATE.CLI_RCVD_APREP
            and Context.flags & GSS_C_FLAGS.GSS_C_DCE_STYLE
        ):
            # DCE_STYLE with SPNEGOSSP
            return Context, None, GSS_S_COMPLETE
        else:
            raise ValueError("KerberosSSP: Unknown state")

    def _setup_u2u(self):
        if not self.TGT:
            # Get a TGT for ourselves
            try:
                upn = "@".join(self.SPN.split("/")[1].split(".", 1))
            except KeyError:
                raise ValueError("Couldn't transform the SPN into a valid UPN")
            res = krb_as_req(upn, self.DC_IP, key=self.KEY)
            self.TGT, self.KEY = res.asrep.ticket, res.sessionkey

    def GSS_Accept_sec_context(self, Context: CONTEXT, val=None):
        if Context is None:
            # New context
            Context = self.CONTEXT(IsAcceptor=True, req_flags=0)

        from scapy.libs.rfc3961 import Key

        if Context.state == self.STATE.INIT:
            if not self.SPN:
                raise ValueError("Missing SPN attribute")
            # Server receives AP-req, sends AP-rep
            if isinstance(val, KRB_AP_REQ):
                # Raw AP_REQ was passed
                ap_req = val
            else:
                try:
                    # GSSAPI/Kerberos
                    ap_req = val.root.innerToken.root
                except AttributeError:
                    try:
                        # Raw Kerberos
                        ap_req = val.root
                    except AttributeError:
                        return Context, None, GSS_S_DEFECTIVE_TOKEN
            if isinstance(ap_req, KRB_TGT_REQ):
                # Special U2U case
                self._setup_u2u()
                Context.U2U = True
                return (
                    None,
                    KRB_GSSAPI_Token(
                        MechType="1.2.840.113554.1.2.2.3",  # U2U
                        innerToken=KRB_InnerToken(
                            TOK_ID=b"\x04\x01",
                            root=KRB_TGT_REP(
                                ticket=self.TGT,
                            ),
                        ),
                    ),
                    GSS_S_CONTINUE_NEEDED,
                )
            elif not isinstance(ap_req, KRB_AP_REQ):
                ap_req.show()
                raise ValueError("Unexpected type in KerberosSSP")
            if not self.KEY:
                raise ValueError("Missing KEY attribute")
            # Validate SPN
            tkt_spn = "/".join(
                x.val.decode() for x in ap_req.ticket.sname.nameString[:2]
            ).lower()
            if tkt_spn not in [self.SPN.lower(), self.SPN.lower().split(".", 1)[0]]:
                warning("KerberosSSP: bad SPN: %s != %s" % (tkt_spn, self.SPN))
                return Context, None, GSS_S_BAD_MECH
            # Enforce U2U if required
            if self.REQUIRE_U2U and ap_req.apOptions.val[1] != "1":  # use-session-key
                # Required but not provided. Return an error
                self._setup_u2u()
                Context.U2U = True
                now_time = datetime.now(timezone.utc).replace(microsecond=0)
                err = KRB_GSSAPI_Token(
                    innerToken=KRB_InnerToken(
                        TOK_ID=b"\x03\x00",
                        root=KRB_ERROR(
                            errorCode="KRB_AP_ERR_USER_TO_USER_REQUIRED",
                            stime=ASN1_GENERALIZED_TIME(now_time),
                            realm=ap_req.ticket.realm,
                            sname=ap_req.ticket.sname,
                            eData=KRB_TGT_REP(
                                ticket=self.TGT,
                            ),
                        ),
                    )
                )
                return Context, err, GSS_S_CONTINUE_NEEDED
            # Decrypt the ticket
            try:
                tkt = ap_req.ticket.encPart.decrypt(self.KEY)
            except ValueError as ex:
                warning("KerberosSSP: %s (bad KEY?)" % ex)
                now_time = datetime.now(timezone.utc).replace(microsecond=0)
                err = KRB_GSSAPI_Token(
                    innerToken=KRB_InnerToken(
                        TOK_ID=b"\x03\x00",
                        root=KRB_ERROR(
                            errorCode="KRB_AP_ERR_MODIFIED",
                            stime=ASN1_GENERALIZED_TIME(now_time),
                            realm=ap_req.ticket.realm,
                            sname=ap_req.ticket.sname,
                            eData=None,
                        ),
                    )
                )
                return Context, err, GSS_S_DEFECTIVE_TOKEN
            # Get AP-REP session key
            Context.STSessionKey = tkt.key.toKey()
            authenticator = ap_req.authenticator.decrypt(Context.STSessionKey)
            # Compute an application session key ([MS-KILE] sect 3.1.1.2)
            subkey = None
            if ap_req.apOptions.val[2] == "1":  # mutual-required
                appkey = Key.random_to_key(
                    self.SKEY_TYPE,
                    os.urandom(16),
                )
                Context.KrbSessionKey = appkey
                Context.SessionKey = appkey.key
                subkey = EncryptionKey.fromKey(appkey)
            else:
                Context.KrbSessionKey = self.KEY
                Context.SessionKey = self.KEY.key
            # Eventually process the "checksum"
            if authenticator.cksum:
                if authenticator.cksum.cksumtype == 0x8003:
                    # KRB-Authenticator
                    Context.flags = authenticator.cksum.checksum.Flags
            # Build response (RFC4120 sect 3.2.4)
            ap_rep = KRB_AP_REP(encPart=EncryptedData())
            ap_rep.encPart.encrypt(
                Context.STSessionKey,
                EncAPRepPart(
                    ctime=authenticator.ctime,
                    cusec=authenticator.cusec,
                    seqNumber=None,
                    subkey=subkey,
                ),
            )
            Context.state = self.STATE.SRV_SENT_APREP
            if Context.flags & GSS_C_FLAGS.GSS_C_DCE_STYLE:
                # [MS-KILE] sect 3.4.5.1
                return Context, ap_rep, GSS_S_CONTINUE_NEEDED
            return Context, ap_rep, GSS_S_COMPLETE  # success
        elif (
            Context.state == self.STATE.SRV_SENT_APREP
            and Context.flags & GSS_C_FLAGS.GSS_C_DCE_STYLE
        ):
            # [MS-KILE] sect 3.4.5.1
            # The server MUST receive the additional AP exchange reply message and
            # verify that the message is constructed correctly.
            if not val:
                return Context, None, GSS_S_DEFECTIVE_TOKEN
            # Server receives AP-req, sends AP-rep
            if isinstance(val, KRB_AP_REP):
                # Raw AP_REP was passed
                ap_rep = val
            else:
                try:
                    # GSSAPI/Kerberos
                    ap_rep = val.root.innerToken.root
                except AttributeError:
                    try:
                        # Raw Kerberos
                        ap_rep = val.root
                    except AttributeError:
                        return Context, None, GSS_S_DEFECTIVE_TOKEN
            # Decrypt the AP-REP
            try:
                ap_rep.encPart.decrypt(Context.STSessionKey)
            except ValueError as ex:
                warning("KerberosSSP: %s (bad KEY?)" % ex)
                return Context, None, GSS_S_DEFECTIVE_TOKEN
            return Context, None, GSS_S_COMPLETE  # success
        else:
            raise ValueError("KerberosSSP: Unknown state %s" % repr(Context.state))

    def GSS_Passive(self, Context: CONTEXT, val=None):
        if Context is None:
            Context = self.CONTEXT(True)
            Context.passive = True

        if Context.state == self.STATE.INIT:
            Context, _, status = self.GSS_Accept_sec_context(Context, val)
            Context.state = self.STATE.CLI_SENT_APREQ
            return Context, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.CLI_SENT_APREQ:
            Context, _, status = self.GSS_Init_sec_context(Context, val)
            return Context, status

    def GSS_Passive_set_Direction(self, Context: CONTEXT, IsAcceptor=False):
        if Context.IsAcceptor is not IsAcceptor:
            return
        # Swap everything
        Context.SendSealKeyUsage, Context.RecvSealKeyUsage = (
            Context.RecvSealKeyUsage,
            Context.SendSealKeyUsage,
        )
        Context.SendSignKeyUsage, Context.RecvSignKeyUsage = (
            Context.RecvSignKeyUsage,
            Context.SendSignKeyUsage,
        )
        Context.IsAcceptor = not Context.IsAcceptor

    def MaximumSignatureLength(self, Context: CONTEXT):
        if Context.flags & GSS_C_FLAGS.GSS_C_CONF_FLAG:
            # TODO: support DES
            if Context.KrbSessionKey.etype in [17, 18]:  # AES
                return 76
            elif Context.KrbSessionKey.etype in [23, 24]:  # RC4_HMAC
                return 45
            else:
                raise NotImplementedError
        else:
            return 28

    def canMechListMIC(self, Context: CONTEXT):
        return bool(Context.KrbSessionKey)
