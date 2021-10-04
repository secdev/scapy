# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter
# This program is published under a GPLv2 license

"""
Generic Security Services (GSS) API

Implements parts of
- GSSAPI: RFC2743
- GSSAPI SPNEGO: RFC4178 > RFC2478
"""

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
from scapy.layers.ntlm import NTLM_Header


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
    ASN1_root = ASN1F_STRING("value", "")


_mechDissector = {
    "1.3.6.1.4.1.311.2.2.10": NTLM_Header,   # NTLM
}


class _SPNEGO_Token_Field(ASN1F_STRING):
    def i2m(self, pkt, x):
        return super().i2m(pkt, bytes(x))

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
                ASN1F_PACKET("mechToken", SPNEGO_Token(), SPNEGO_Token,
                             explicit_tag=0xa2)
            ),
            ASN1F_optional(
                ASN1F_PACKET("mechListMIC", SPNEGO_MechListMIC(),
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
                ASN1F_PACKET("responseToken", SPNEGO_Token(),
                             SPNEGO_Token,
                             explicit_tag=0xa2)
            ),
            ASN1F_optional(
                ASN1F_PACKET("mechListMIC", SPNEGO_MechListMIC(),
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


# GSS API Blob
# https://datatracker.ietf.org/doc/html/rfc2743


_GSSAPI_OIDS = {
    "1.3.6.1.5.5.2": SPNEGO_negToken,  # SPNEGO: RFC rfc2478
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
        return cls
