# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Generic Security Services (GSS) API

Implements parts of
- GSSAPI: RFC2743
- GSSAPI SPNEGO: RFC4178 > RFC2478
- GSSAPI SPNEGO NEGOEX: [MS-NEGOEX]
"""

import struct
from uuid import UUID

from scapy.asn1.asn1 import ASN1_SEQUENCE, ASN1_Class_UNIVERSAL, ASN1_Codecs
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.asn1.mib import conf  # loads conf.mib
from scapy.asn1fields import (
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_FLAGS,
    ASN1F_OID,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional
)
from scapy.asn1packet import ASN1_Packet
from scapy.fields import (
    FieldListField,
    LEIntEnumField,
    LEIntField,
    LELongEnumField,
    LELongField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    StrFixedLenField,
    UUIDEnumField,
    UUIDField,
    StrField,
    XStrFixedLenField,
    XStrLenField
)
from scapy.packet import Packet, bind_layers

# Providers
from scapy.layers.kerberos import (
    Kerberos,
    KRB5_GSS,
)
from scapy.layers.ntlm import (
    NEGOEX_EXCHANGE_NTLM,
    NTLM_Header,
    _NTLMPayloadField,
)

from scapy.compat import (
    Dict,
    Tuple,
)


# https://datatracker.ietf.org/doc/html/rfc1508#page-48


class ASN1_Class_GSSAPI(ASN1_Class_UNIVERSAL):
    name = "GSSAPI"
    APPLICATION = 0x60


class ASN1_GSSAPI_APPLICATION(ASN1_SEQUENCE):
    tag = ASN1_Class_GSSAPI.APPLICATION


class BERcodec_GSSAPI_APPLICATION(BERcodec_SEQUENCE):
    tag = ASN1_Class_GSSAPI.APPLICATION


class ASN1F_SNMP_GSSAPI_APPLICATION(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_GSSAPI.APPLICATION

# SPNEGO negTokenInit
# https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.1


class SPNEGO_MechType(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_OID("oid", None)


class SPNEGO_MechTypes(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("mechTypes", None, SPNEGO_MechType)


class SPNEGO_MechListMIC(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(ASN1F_STRING("value", ""))


_mechDissector = {
    "1.3.6.1.4.1.311.2.2.10": NTLM_Header,   # NTLM
    "1.2.840.48018.1.2.2": Kerberos,  # MS KRB5 - Microsoft Kerberos 5
    "1.2.840.113554.1.2.2": Kerberos,  # Kerberos 5
}


class _SPNEGO_Token_Field(ASN1F_STRING):
    def i2m(self, pkt, x):
        if x is None:
            x = b""
        return super(_SPNEGO_Token_Field, self).i2m(pkt, bytes(x))

    def m2i(self, pkt, s):
        dat, r = super(_SPNEGO_Token_Field, self).m2i(pkt, s)
        if isinstance(pkt.underlayer, SPNEGO_negTokenInit):
            types = pkt.underlayer.mechTypes
        elif isinstance(pkt.underlayer, SPNEGO_negTokenResp):
            types = [pkt.underlayer.supportedMech]
        if types and types[0] and types[0].oid.val in _mechDissector:
            return _mechDissector[types[0].oid.val](dat.val), r
        return dat, r


class SPNEGO_Token(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = _SPNEGO_Token_Field("value", None)


_ContextFlags = ["delegFlag",
                 "mutualFlag",
                 "replayFlag",
                 "sequenceFlag",
                 "superseded",
                 "anonFlag",
                 "confFlag",
                 "integFlag"]


class SPNEGO_negTokenInit(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_optional(
                ASN1F_SEQUENCE_OF("mechTypes", None, SPNEGO_MechType,
                                  explicit_tag=0xa0)
            ),
            ASN1F_optional(
                ASN1F_FLAGS("reqFlags", None, _ContextFlags,
                            implicit_tag=0x81)),
            ASN1F_optional(
                ASN1F_PACKET("mechToken", None, SPNEGO_Token,
                             explicit_tag=0xa2)
            ),
            ASN1F_optional(
                ASN1F_PACKET("mechListMIC", None,
                             SPNEGO_MechListMIC,
                             implicit_tag=0xa3)
            )
        )
    )


# SPNEGO negTokenTarg
# https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.2

class SPNEGO_negTokenResp(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_optional(
                ASN1F_ENUMERATED("negResult", 0,
                                 {0: "accept-completed",
                                  1: "accept-incomplete",
                                  2: "reject",
                                  3: "request-mic"},
                                 explicit_tag=0xa0),
            ),
            ASN1F_optional(
                ASN1F_PACKET("supportedMech", SPNEGO_MechType(),
                             SPNEGO_MechType,
                             explicit_tag=0xa1),
            ),
            ASN1F_optional(
                ASN1F_PACKET("responseToken", None,
                             SPNEGO_Token,
                             explicit_tag=0xa2)
            ),
            ASN1F_optional(
                ASN1F_PACKET("mechListMIC", None,
                             SPNEGO_MechListMIC,
                             implicit_tag=0xa3)
            )
        )
    )


class SPNEGO_negToken(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("token", SPNEGO_negTokenInit(),
                             ASN1F_PACKET("negTokenInit",
                                          SPNEGO_negTokenInit(),
                                          SPNEGO_negTokenInit,
                                          implicit_tag=0xa0),
                             ASN1F_PACKET("negTokenResp",
                                          SPNEGO_negTokenResp(),
                                          SPNEGO_negTokenResp,
                                          implicit_tag=0xa1)
                             )

# NEGOEX
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/0ad7a003-ab56-4839-a204-b555ca6759a2


_NEGOEX_AUTH_SCHEMES = {
    # Reversed. Is there any doc related to this?
    # The NEGOEX doc is very ellusive
    UUID("5c33530d-eaf9-0d4d-b2ec-4ae3786ec308"): "UUID('[NTLM-UUID]')",
}


class NEGOEX_MESSAGE_HEADER(Packet):
    fields_desc = [
        StrFixedLenField("Signature", "NEGOEXTS", length=8),
        LEIntEnumField("MessageType", 0, {0x0: "INITIATOR_NEGO",
                                          0x01: "ACCEPTOR_NEGO",
                                          0x02: "INITIATOR_META_DATA",
                                          0x03: "ACCEPTOR_META_DATA",
                                          0x04: "CHALENGE",
                                          0x05: "AP_REQUEST",
                                          0x06: "VERIFY",
                                          0x07: "ALERT"}),
        LEIntField("SequenceNum", 0),
        LEIntField("cbHeaderLength", None),
        LEIntField("cbMessageLength", None),
        UUIDField("ConversationId", None),
    ]

    def post_build(self, pkt, pay):
        if self.cbHeaderLength is None:
            pkt = pkt[16:] + struct.pack("<I", len(pkt)) + pkt[20:]
        if self.cbMessageLength is None:
            pkt = pkt[20:] + struct.pack("<I", len(pkt) + len(pay)) + pkt[24:]
        return pkt + pay


def _NEGOEX_post_build(self, p, pay_offset, fields):
    # type: (Packet, bytes, int, Dict[str, Tuple[str, int]]) -> bytes
    """Util function to build the offset and populate the lengths"""
    for field_name, value in self.fields["Payload"]:
        length = self.get_field(
            "Payload").fields_map[field_name].i2len(self, value)
        count = self.get_field(
            "Payload").fields_map[field_name].i2count(self, value)
        offset = fields[field_name]
        # Offset
        if self.getfieldval(field_name + "BufferOffset") is None:
            p = p[:offset] + \
                struct.pack("<I", pay_offset) + p[offset + 4:]
        # Count
        if self.getfieldval(field_name + "Count") is None:
            p = p[:offset + 4] + \
                struct.pack("<H", count) + p[offset + 6:]
        pay_offset += length
    return p


class NEGOEX_BYTE_VECTOR(Packet):
    fields_desc = [
        LEIntField("ByteArrayBufferOffset", 0),
        LEIntField("ByteArrayLength", 0)
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class NEGOEX_EXTENSION_VECTOR(Packet):
    fields_desc = [
        LELongField("ExtensionArrayOffset", 0),
        LEShortField("ExtensionCount", 0)
    ]


class NEGOEX_NEGO_MESSAGE(Packet):
    OFFSET = 92
    show_indent = 0
    fields_desc = [
        NEGOEX_MESSAGE_HEADER,
        XStrFixedLenField("Random", b"", length=32),
        LELongField("ProtocolVersion", 0),
        LEIntField("AuthSchemeBufferOffset", None),
        LEShortField("AuthSchemeCount", None),
        LEIntField("ExtensionBufferOffset", None),
        LEShortField("ExtensionCount", None),
        # Payload
        _NTLMPayloadField(
            'Payload', OFFSET, [
                FieldListField("AuthScheme", [],
                               UUIDEnumField("", None, _NEGOEX_AUTH_SCHEMES),
                               count_from=lambda pkt: pkt.AuthSchemeCount),
                PacketListField("Extension", [], NEGOEX_EXTENSION_VECTOR,
                                count_from=lambda pkt: pkt.ExtensionCount),

            ],
            length_from=lambda pkt: pkt.cbMessageLength - 92),
        # TODO: dissect extensions
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _NEGOEX_post_build(self, pkt, self.OFFSET, {
            "AuthScheme": 96,
            "Extension": 102,
        }) + pay

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 12:
            MessageType = struct.unpack("<I", _pkt[8:12])[0]
            if MessageType in [0, 1]:
                return NEGOEX_NEGO_MESSAGE
            elif MessageType in [2, 3]:
                return NEGOEX_EXCHANGE_MESSAGE
        return cls


# RFC3961
_checksum_types = {
    1: "CRC32",
    2: "RSA-MD4",
    3: "RSA-MD4-DES",
    4: "DES-MAC",
    5: "DES-MAC-K",
    6: "RSA-MDA-DES-K",
    7: "RSA-MD5",
    8: "RSA-MD5-DES",
    9: "RSA-MD5-DES3",
    10: "SHA1",
    12: "HMAC-SHA1-DES3-KD",
    13: "HMAC-SHA1-DES3",
    14: "SHA1",
    15: "HMAC-SHA1-96-AES128",
    16: "HMAC-SHA1-96-AES256"
}


def _checksum_size(pkt):
    if pkt.ChecksumType == 1:
        return 4
    elif pkt.ChecksumType in [2, 4, 6, 7]:
        return 16
    elif pkt.ChecksumType in [3, 8, 9]:
        return 24
    elif pkt.ChecksumType == 5:
        return 8
    elif pkt.ChecksumType in [10, 12, 13, 14, 15, 16]:
        return 20
    return 0


class NEGOEX_CHECKSUM(Packet):
    fields_desc = [
        LELongField("cbHeaderLength", 20),
        LELongEnumField("ChecksumScheme", 1, {1: "CHECKSUM_SCHEME_RFC3961"}),
        LELongEnumField("ChecksumType", None, _checksum_types),
        XStrLenField("ChecksumValue", b"", length_from=_checksum_size)
    ]


class NEGOEX_EXCHANGE_MESSAGE(Packet):
    OFFSET = 64
    show_indent = 0
    fields_desc = [
        NEGOEX_MESSAGE_HEADER,
        UUIDEnumField("AuthScheme", None, _NEGOEX_AUTH_SCHEMES),
        LEIntField("ExchangeBufferOffset", 0),
        LEIntField("ExchangeLen", 0),
        _NTLMPayloadField(
            'Payload', OFFSET, [
                # The NEGOEX doc mentions the following blob as as an
                # "opaque handshake for the client authentication scheme".
                # NEGOEX_EXCHANGE_NTLM is a reversed interpretation, and is
                # probably not accurate.
                MultipleTypeField(
                    [
                        (PacketField("Exchange", None, NEGOEX_EXCHANGE_NTLM),
                         lambda pkt: pkt.AuthScheme == \
                            UUID("5c33530d-eaf9-0d4d-b2ec-4ae3786ec308")),
                    ],
                    StrField("Exchange", b"")
                )
            ],
            length_from=lambda pkt: pkt.cbMessageLength - pkt.cbHeaderLength),
    ]


class NEGOEX_VERIFY_MESSAGE(Packet):
    show_indent = 0
    fields_desc = [
        NEGOEX_MESSAGE_HEADER,
        UUIDEnumField("AuthScheme", None, _NEGOEX_AUTH_SCHEMES),
        PacketField("Checksum", NEGOEX_CHECKSUM(),
                    NEGOEX_CHECKSUM)
    ]


bind_layers(NEGOEX_NEGO_MESSAGE, NEGOEX_NEGO_MESSAGE)


_mechDissector["1.3.6.1.4.1.311.2.2.30"] = NEGOEX_NEGO_MESSAGE

# GSS API Blob
# https://datatracker.ietf.org/doc/html/rfc2743


_GSSAPI_OIDS = {
    "1.3.6.1.5.5.2": SPNEGO_negToken,  # SPNEGO: RFC 2478
    "1.2.840.113554.1.2.2": KRB5_GSS,  # RFC 1964
}

# sect 3.1


class GSSAPI_BLOB(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_GSSAPI_APPLICATION(
        ASN1F_OID("MechType", "1.3.6.1.5.5.2"),
        ASN1F_PACKET("innerContextToken", SPNEGO_negToken(), SPNEGO_negToken,
                     next_cls_cb=lambda pkt: _GSSAPI_OIDS.get(
            pkt.MechType.val, conf.raw_layer))
    )

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            if ord(_pkt[:1]) & 0xa0 >= 0xa0:
                # XXX: sometimes the token is raw, we should look from
                # the session what to use here. For now: hardcode SPNEGO
                # (THIS IS A VERY STRONG ASSUMPTION)
                return SPNEGO_negToken
            if _pkt[:7] == b"NTLMSSP":
                # XXX: if no mechTypes are provided during SPNEGO exchange,
                # Windows falls back to a plain NTLM_Header.
                return NTLM_Header.dispatch_hook(_pkt=_pkt, *args, **kargs)
        return cls
