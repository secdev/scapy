# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
SPNEGO

Implements parts of:

- GSSAPI SPNEGO: RFC4178 > RFC2478
- GSSAPI SPNEGO NEGOEX: [MS-NEGOEX]

.. note::
    You will find more complete documentation for this layer over at
    `GSSAPI <https://scapy.readthedocs.io/en/latest/layers/gssapi.html#spnego>`_
"""

import struct
from uuid import UUID

from scapy.asn1.asn1 import (
    ASN1_OID,
    ASN1_STRING,
    ASN1_Codecs,
)
from scapy.asn1.mib import conf  # loads conf.mib
from scapy.asn1fields import (
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_FLAGS,
    ASN1F_GENERAL_STRING,
    ASN1F_OID,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional,
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
    StrField,
    StrFixedLenField,
    UUIDEnumField,
    UUIDField,
    XStrFixedLenField,
    XStrLenField,
)
from scapy.packet import Packet, bind_layers

from scapy.layers.gssapi import (
    GSSAPI_BLOB,
    GSSAPI_BLOB_SIGNATURE,
    GSS_C_FLAGS,
    GSS_S_BAD_MECH,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    SSP,
    _GSSAPI_OIDS,
    _GSSAPI_SIGNATURE_OIDS,
)

# SSP Providers
from scapy.layers.kerberos import (
    Kerberos,
)
from scapy.layers.ntlm import (
    NEGOEX_EXCHANGE_NTLM,
    NTLM_Header,
    _NTLMPayloadField,
    _NTLMPayloadPacket,
)

# Typing imports
from typing import (
    Dict,
    Optional,
    Tuple,
)

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
    "1.3.6.1.4.1.311.2.2.10": NTLM_Header,  # NTLM
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


_ContextFlags = [
    "delegFlag",
    "mutualFlag",
    "replayFlag",
    "sequenceFlag",
    "superseded",
    "anonFlag",
    "confFlag",
    "integFlag",
]


class SPNEGO_negHints(ASN1_Packet):
    # [MS-SPNG] 2.2.1
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_GENERAL_STRING(
                "hintName", "not_defined_in_RFC4178@please_ignore", explicit_tag=0xA0
            ),
        ),
        ASN1F_optional(
            ASN1F_GENERAL_STRING("hintAddress", None, explicit_tag=0xA1),
        ),
    )


class SPNEGO_negTokenInit(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("mechTypes", None, SPNEGO_MechType, explicit_tag=0xA0)
        ),
        ASN1F_optional(ASN1F_FLAGS("reqFlags", None, _ContextFlags, implicit_tag=0x81)),
        ASN1F_optional(
            ASN1F_PACKET("mechToken", None, SPNEGO_Token, explicit_tag=0xA2)
        ),
        # [MS-SPNG] flavor !
        ASN1F_optional(
            ASN1F_PACKET("negHints", None, SPNEGO_negHints, explicit_tag=0xA3)
        ),
        ASN1F_optional(
            ASN1F_PACKET("mechListMIC", None, SPNEGO_MechListMIC, explicit_tag=0xA4)
        ),
        # Compat with RFC 4178's SPNEGO_negTokenInit
        ASN1F_optional(
            ASN1F_PACKET("_mechListMIC", None, SPNEGO_MechListMIC, explicit_tag=0xA3)
        ),
    )


# SPNEGO negTokenTarg
# https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.2


class SPNEGO_negTokenResp(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_ENUMERATED(
                "negResult",
                0,
                {
                    0: "accept-completed",
                    1: "accept-incomplete",
                    2: "reject",
                    3: "request-mic",
                },
                explicit_tag=0xA0,
            ),
        ),
        ASN1F_optional(
            ASN1F_PACKET(
                "supportedMech", SPNEGO_MechType(), SPNEGO_MechType, explicit_tag=0xA1
            ),
        ),
        ASN1F_optional(
            ASN1F_PACKET("responseToken", None, SPNEGO_Token, explicit_tag=0xA2)
        ),
        ASN1F_optional(
            ASN1F_PACKET("mechListMIC", None, SPNEGO_MechListMIC, explicit_tag=0xA3)
        ),
    )


class SPNEGO_negToken(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "token",
        SPNEGO_negTokenInit(),
        ASN1F_PACKET(
            "negTokenInit",
            SPNEGO_negTokenInit(),
            SPNEGO_negTokenInit,
            explicit_tag=0xA0,
        ),
        ASN1F_PACKET(
            "negTokenResp",
            SPNEGO_negTokenResp(),
            SPNEGO_negTokenResp,
            explicit_tag=0xA1,
        ),
    )


# Register for the GSS API Blob

_GSSAPI_OIDS["1.3.6.1.5.5.2"] = SPNEGO_negToken
_GSSAPI_SIGNATURE_OIDS["1.3.6.1.5.5.2"] = SPNEGO_negToken


def mechListMIC(oids):
    """
    Implementation of RFC 4178 - Appendix D. mechListMIC Computation
    """
    return bytes(SPNEGO_MechTypes(mechTypes=oids))


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
        LEIntEnumField(
            "MessageType",
            0,
            {
                0x0: "INITIATOR_NEGO",
                0x01: "ACCEPTOR_NEGO",
                0x02: "INITIATOR_META_DATA",
                0x03: "ACCEPTOR_META_DATA",
                0x04: "CHALLENGE",
                0x05: "AP_REQUEST",
                0x06: "VERIFY",
                0x07: "ALERT",
            },
        ),
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
        length = self.get_field("Payload").fields_map[field_name].i2len(self, value)
        count = self.get_field("Payload").fields_map[field_name].i2count(self, value)
        offset = fields[field_name]
        # Offset
        if self.getfieldval(field_name + "BufferOffset") is None:
            p = p[:offset] + struct.pack("<I", pay_offset) + p[offset + 4 :]
        # Count
        if self.getfieldval(field_name + "Count") is None:
            p = p[: offset + 4] + struct.pack("<H", count) + p[offset + 6 :]
        pay_offset += length
    return p


class NEGOEX_BYTE_VECTOR(Packet):
    fields_desc = [
        LEIntField("ByteArrayBufferOffset", 0),
        LEIntField("ByteArrayLength", 0),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class NEGOEX_EXTENSION_VECTOR(Packet):
    fields_desc = [
        LELongField("ExtensionArrayOffset", 0),
        LEShortField("ExtensionCount", 0),
    ]


class NEGOEX_NEGO_MESSAGE(_NTLMPayloadPacket):
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
            "Payload",
            OFFSET,
            [
                FieldListField(
                    "AuthScheme",
                    [],
                    UUIDEnumField("", None, _NEGOEX_AUTH_SCHEMES),
                    count_from=lambda pkt: pkt.AuthSchemeCount,
                ),
                PacketListField(
                    "Extension",
                    [],
                    NEGOEX_EXTENSION_VECTOR,
                    count_from=lambda pkt: pkt.ExtensionCount,
                ),
            ],
            length_from=lambda pkt: pkt.cbMessageLength - 92,
        ),
        # TODO: dissect extensions
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NEGOEX_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "AuthScheme": 96,
                    "Extension": 102,
                },
            )
            + pay
        )

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
    16: "HMAC-SHA1-96-AES256",
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
        XStrLenField("ChecksumValue", b"", length_from=_checksum_size),
    ]


class NEGOEX_EXCHANGE_MESSAGE(_NTLMPayloadPacket):
    OFFSET = 64
    show_indent = 0
    fields_desc = [
        NEGOEX_MESSAGE_HEADER,
        UUIDEnumField("AuthScheme", None, _NEGOEX_AUTH_SCHEMES),
        LEIntField("ExchangeBufferOffset", 0),
        LEIntField("ExchangeLen", 0),
        _NTLMPayloadField(
            "Payload",
            OFFSET,
            [
                # The NEGOEX doc mentions the following blob as as an
                # "opaque handshake for the client authentication scheme".
                # NEGOEX_EXCHANGE_NTLM is a reversed interpretation, and is
                # probably not accurate.
                MultipleTypeField(
                    [
                        (
                            PacketField("Exchange", None, NEGOEX_EXCHANGE_NTLM),
                            lambda pkt: pkt.AuthScheme
                            == UUID("5c33530d-eaf9-0d4d-b2ec-4ae3786ec308"),
                        ),
                    ],
                    StrField("Exchange", b""),
                )
            ],
            length_from=lambda pkt: pkt.cbMessageLength - pkt.cbHeaderLength,
        ),
    ]


class NEGOEX_VERIFY_MESSAGE(Packet):
    show_indent = 0
    fields_desc = [
        NEGOEX_MESSAGE_HEADER,
        UUIDEnumField("AuthScheme", None, _NEGOEX_AUTH_SCHEMES),
        PacketField("Checksum", NEGOEX_CHECKSUM(), NEGOEX_CHECKSUM),
    ]


bind_layers(NEGOEX_NEGO_MESSAGE, NEGOEX_NEGO_MESSAGE)


_mechDissector["1.3.6.1.4.1.311.2.2.30"] = NEGOEX_NEGO_MESSAGE

# -- SSP


class SPNEGOSSP(SSP):
    """
    The SPNEGO SSP

    :param ssps: a dict with keys being the SSP class, and the value being a
                 dictionary of the keyword arguments to pass it on init.

    Example::

        from scapy.layers.ntlm import NTLMSSP
        from scapy.layers.kerberos import KerberosSSP
        from scapy.layers.spnego import SPNEGOSSP
        from scapy.layers.smbserver import smbserver
        from scapy.libs.rfc3961 import Encryption, Key

        ssp = SPNEGOSSP([
            NTLMSSP(
                IDENTITIES={
                    "User1": MD4le("Password1"),
                    "Administrator": MD4le("Password123!"),
                }
            ),
            KerberosSSP(
                SPN="cifs/server2.domain.local",
                KEY=Key(
                    Encryption.AES256,
                    key=hex_bytes("5e9255c907b2f7e969ddad816eabbec8f1f7a387c7194ecc98b827bdc9421c2b")
                )
            )
        ])
        smbserver(ssp=ssp)
    """

    __slots__ = [
        "supported_ssps",
        "force_supported_mechtypes",
    ]
    auth_type = 0x09

    class STATE(SSP.STATE):
        FIRST = 1
        CHANGESSP = 2
        NORMAL = 3

    class CONTEXT(SSP.CONTEXT):
        __slots__ = [
            "supported_mechtypes",
            "requested_mechtypes",
            "req_flags",
            "negotiated_mechtype",
            "first_choice",
            "sub_context",
            "ssp",
        ]

        def __init__(
            self, supported_ssps, req_flags=None, force_supported_mechtypes=None
        ):
            self.state = SPNEGOSSP.STATE.FIRST
            self.requested_mechtypes = None
            self.req_flags = req_flags
            self.first_choice = True
            self.negotiated_mechtype = None
            self.sub_context = None
            self.ssp = None
            if force_supported_mechtypes is None:
                self.supported_mechtypes = [
                    SPNEGO_MechType(oid=ASN1_OID(oid)) for oid in supported_ssps
                ]
                self.supported_mechtypes.sort(
                    key=lambda x: SPNEGOSSP._PREF_ORDER.index(x.oid.val)
                )
            else:
                self.supported_mechtypes = force_supported_mechtypes
            super(SPNEGOSSP.CONTEXT, self).__init__()

        # Passthrough attributes and functions

        def clifailure(self):
            self.sub_context.clifailure()

        def __getattr__(self, attr):
            try:
                return object.__getattribute__(self, attr)
            except AttributeError:
                return getattr(self.sub_context, attr)

        def __setattr__(self, attr, val):
            try:
                return object.__setattr__(self, attr, val)
            except AttributeError:
                return setattr(self.sub_context, attr, val)

        # Passthrough the flags property

        @property
        def flags(self):
            if self.sub_context:
                return self.sub_context.flags
            return GSS_C_FLAGS(0)

        @flags.setter
        def flags(self, x):
            if not self.sub_context:
                return
            self.sub_context.flags = x

        def __repr__(self):
            return "SPNEGOSSP[%s]" % repr(self.sub_context)

    _MECH_ALIASES = {
        # Kerberos has 2 ssps
        "1.2.840.48018.1.2.2": "1.2.840.113554.1.2.2",
        "1.2.840.113554.1.2.2": "1.2.840.48018.1.2.2",
    }

    # This is the order Windows chooses. We mimic it for plausibility
    _PREF_ORDER = [
        "1.2.840.48018.1.2.2",  # MS KRB5
        "1.2.840.113554.1.2.2",  # Kerberos 5
        "1.3.6.1.4.1.311.2.2.30",  # NEGOEX
        "1.3.6.1.4.1.311.2.2.10",  # NTLM
    ]

    def __init__(self, ssps, **kwargs):
        self.supported_ssps = {x.oid: x for x in ssps}
        # Apply MechTypes aliases
        for ssp in ssps:
            if ssp.oid in self._MECH_ALIASES:
                self.supported_ssps[self._MECH_ALIASES[ssp.oid]] = self.supported_ssps[
                    ssp.oid
                ]
        self.force_supported_mechtypes = kwargs.pop("force_supported_mechtypes", None)
        super(SPNEGOSSP, self).__init__(**kwargs)

    def _extract_gssapi(self, Context, x):
        status, otherMIC, rawToken = None, None, False
        # Extract values from GSSAPI
        if isinstance(x, GSSAPI_BLOB):
            x = x.innerToken
        if isinstance(x, SPNEGO_negToken):
            x = x.token
        if hasattr(x, "mechTypes"):
            Context.requested_mechtypes = x.mechTypes
            Context.negotiated_mechtype = None
        if hasattr(x, "supportedMech") and x.supportedMech is not None:
            Context.negotiated_mechtype = x.supportedMech
        if hasattr(x, "mechListMIC") and x.mechListMIC:
            otherMIC = GSSAPI_BLOB_SIGNATURE(x.mechListMIC.value.val)
        if hasattr(x, "_mechListMIC") and x._mechListMIC:
            otherMIC = GSSAPI_BLOB_SIGNATURE(x._mechListMIC.value.val)
        if hasattr(x, "negResult"):
            status = x.negResult
        try:
            x = x.mechToken
        except AttributeError:
            try:
                x = x.responseToken
            except AttributeError:
                # No GSSAPI wrapper (windows fallback). Remember this for answer
                rawToken = True
        if isinstance(x, SPNEGO_Token):
            x = x.value
        if Context.requested_mechtypes:
            try:
                cls = _mechDissector[
                    (
                        Context.negotiated_mechtype or Context.requested_mechtypes[0]
                    ).oid.val  # noqa: E501
                ]
            except KeyError:
                cls = conf.raw_layer
            if isinstance(x, ASN1_STRING):
                x = cls(x.val)
            elif isinstance(x, conf.raw_layer):
                x = cls(x.load)
        return x, status, otherMIC, rawToken

    def NegTokenInit2(self):
        """
        Server-Initiation of GSSAPI/SPNEGO.
        See [MS-SPNG] sect 3.2.5.2
        """
        Context = self.CONTEXT(
            self.supported_ssps,
            force_supported_mechtypes=self.force_supported_mechtypes,
        )
        return (
            Context,
            GSSAPI_BLOB(
                innerToken=SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(mechTypes=Context.supported_mechtypes)
                )
            ),
        )

        # NOTE: NegoEX has an effect on how the SecurityContext is
        # initialized, as detailed in [MS-AUTHSOD] sect 3.3.2
        # But the format that the Exchange token uses appears not to
        # be documented :/

        # resp.SecurityBlob.innerToken.token.mechTypes.insert(
        #     0,
        #     # NEGOEX
        #     SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.30"),
        # )
        # resp.SecurityBlob.innerToken.token.mechToken = SPNEGO_Token(
        #     value=negoex_token
        # )  # noqa: E501

    def GSS_WrapEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_WrapEx(Context.sub_context, *args, **kwargs)

    def GSS_UnwrapEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_UnwrapEx(Context.sub_context, *args, **kwargs)

    def GSS_GetMICEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_GetMICEx(Context.sub_context, *args, **kwargs)

    def GSS_VerifyMICEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_VerifyMICEx(Context.sub_context, *args, **kwargs)

    def LegsAmount(self, Context: CONTEXT):
        return 4

    def _common_spnego_handler(self, Context, IsClient, val=None, req_flags=None):
        if Context is None:
            # New Context
            Context = SPNEGOSSP.CONTEXT(
                self.supported_ssps,
                req_flags=req_flags,
                force_supported_mechtypes=self.force_supported_mechtypes,
            )
            if IsClient:
                Context.requested_mechtypes = Context.supported_mechtypes

        # Extract values from GSSAPI token
        status, MIC, otherMIC, rawToken = 0, None, None, False
        if val:
            val, status, otherMIC, rawToken = self._extract_gssapi(Context, val)

        # If we don't have a SSP already negotiated, check for requested and available
        # SSPs and find a common one.
        if Context.ssp is None:
            if Context.negotiated_mechtype is None:
                if Context.requested_mechtypes:
                    # Find a common SSP
                    try:
                        Context.negotiated_mechtype = next(
                            x
                            for x in Context.requested_mechtypes
                            if x in Context.supported_mechtypes
                        )
                    except StopIteration:
                        # no common mechanisms
                        raise ValueError("No common SSP mechanisms !")
                    # Check whether the selected SSP was the one preferred by the client
                    if (
                        Context.negotiated_mechtype != Context.requested_mechtypes[0]
                        and val
                    ):
                        Context.first_choice = False
                # No SSPs were requested. Use the first available SSP we know.
                elif Context.supported_mechtypes:
                    Context.negotiated_mechtype = Context.supported_mechtypes[0]
                else:
                    raise ValueError("Can't figure out what SSP to use")
            # Set Context.ssp to the object matching the chosen SSP type.
            Context.ssp = self.supported_ssps[Context.negotiated_mechtype.oid.val]

        if not Context.first_choice:
            # The currently provided token is not for this SSP !
            # Typically a client opportunistically starts with Kerberos, including
            # its APREQ, and we want to use NTLM. We add one round trip
            Context.state = SPNEGOSSP.STATE.FIRST
            Context.first_choice = True  # reset to not come here again.
            tok, status = None, GSS_S_CONTINUE_NEEDED
        else:
            # The currently provided token is for this SSP !
            # Pass it to the sub ssp, with its own context
            if IsClient:
                (
                    Context.sub_context,
                    tok,
                    status,
                ) = Context.ssp.GSS_Init_sec_context(
                    Context.sub_context,
                    val=val,
                    req_flags=Context.req_flags,
                )
            else:
                Context.sub_context, tok, status = Context.ssp.GSS_Accept_sec_context(
                    Context.sub_context, val=val
                )
            # Check whether client or server says the specified mechanism is not valid
            if status == GSS_S_BAD_MECH:
                # Mechanism is not usable. Typically the Kerberos SPN is wrong
                to_remove = [Context.negotiated_mechtype.oid.val]
                # If there's an alias (for the multiple kerberos oids, also include it)
                if Context.negotiated_mechtype.oid.val in SPNEGOSSP._MECH_ALIASES:
                    to_remove.append(
                        SPNEGOSSP._MECH_ALIASES[Context.negotiated_mechtype.oid.val]
                    )
                # Drop those unusable mechanisms from the supported list
                for x in list(Context.supported_mechtypes):
                    if x.oid.val in to_remove:
                        Context.supported_mechtypes.remove(x)
                # Re-calculate negotiated mechtype
                try:
                    Context.negotiated_mechtype = next(
                        x
                        for x in Context.requested_mechtypes
                        if x in Context.supported_mechtypes
                    )
                except StopIteration:
                    # no common mechanisms
                    raise ValueError("No common SSP mechanisms after GSS_S_BAD_MECH !")
                # Start again.
                Context.state = SPNEGOSSP.STATE.CHANGESSP
                Context.ssp = None  # Reset the SSP
                Context.sub_context = None  # Reset the SSP context
                if IsClient:
                    # Call ourselves again for the client to generate a token
                    return self._common_spnego_handler(Context, True, None)
                else:
                    # Return nothing but the supported SSP list
                    tok, status = None, GSS_S_CONTINUE_NEEDED

        if rawToken:
            # No GSSAPI wrapper (fallback)
            return Context, tok, status

        # Client success
        if IsClient and tok is None and status == GSS_S_COMPLETE:
            return Context, None, status

        # Map GSSAPI codes to SPNEGO
        if status == GSS_S_COMPLETE:
            negResult = 0  # accept_completed
        elif status == GSS_S_CONTINUE_NEEDED:
            negResult = 1  # accept_incomplete
        else:
            negResult = 2  # reject

        # GSSAPI-MIC
        if Context.ssp and Context.ssp.canMechListMIC(Context.sub_context):
            # The documentation on mechListMIC wasn't clear, so note that:
            # - The mechListMIC that the client sends is computed over the
            #   list of mechanisms that it requests.
            # - the mechListMIC that the server sends is computed over the
            #   list of mechanisms that the client requested.
            # Yes, this does indeed mean that NegTokenInit2 added by [MS-SPNG]
            # is NOT protected. That's not necessarily an issue, since it was
            # optional in most cases, but it's something to keep in mind.
            if otherMIC is not None:
                # Check the received MIC if any
                if IsClient:  # from server
                    Context.ssp.verifyMechListMIC(
                        Context,
                        otherMIC,
                        mechListMIC(Context.supported_mechtypes),
                    )
                else:  # from client
                    Context.ssp.verifyMechListMIC(
                        Context,
                        otherMIC,
                        mechListMIC(Context.requested_mechtypes),
                    )
            # Then build our own MIC
            if IsClient:  # client
                if negResult == 0:
                    # Include MIC for the last packet. We could add a check
                    # here to only send the MIC when required (when preferred ssp
                    # isn't chosen)
                    MIC = Context.ssp.getMechListMIC(
                        Context,
                        mechListMIC(Context.supported_mechtypes),
                    )
            else:  # server
                MIC = Context.ssp.getMechListMIC(
                    Context,
                    mechListMIC(Context.requested_mechtypes),
                )

        if IsClient:
            if Context.state == SPNEGOSSP.STATE.FIRST:
                # First client token
                spnego_tok = SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(mechTypes=Context.supported_mechtypes)
                )
                if tok:
                    spnego_tok.token.mechToken = SPNEGO_Token(value=tok)
            else:
                # Subsequent client tokens
                spnego_tok = SPNEGO_negToken(  # GSSAPI_BLOB is stripped
                    token=SPNEGO_negTokenResp(
                        supportedMech=None,
                        negResult=None,
                    )
                )
                if tok:
                    spnego_tok.token.responseToken = SPNEGO_Token(value=tok)
                if Context.state == SPNEGOSSP.STATE.CHANGESSP:
                    # On renegotiation, include the negResult and chosen mechanism
                    spnego_tok.token.negResult = negResult
                    spnego_tok.token.supportedMech = Context.negotiated_mechtype
        else:
            spnego_tok = SPNEGO_negToken(  # GSSAPI_BLOB is stripped
                token=SPNEGO_negTokenResp(
                    supportedMech=None,
                    negResult=negResult,
                )
            )
            if Context.state in [SPNEGOSSP.STATE.FIRST, SPNEGOSSP.STATE.CHANGESSP]:
                # Include the supportedMech list if this is the first thing we do
                # or a renegotiation.
                spnego_tok.token.supportedMech = Context.negotiated_mechtype
            if tok:
                spnego_tok.token.responseToken = SPNEGO_Token(value=tok)
        # Apply MIC if available
        if MIC:
            spnego_tok.token.mechListMIC = SPNEGO_MechListMIC(
                value=ASN1_STRING(MIC),
            )
        if (
            IsClient and Context.state == SPNEGOSSP.STATE.FIRST
        ):  # Client: after the first packet, specifying 'SPNEGO' is implicit.
            # Always implicit for the server.
            spnego_tok = GSSAPI_BLOB(innerToken=spnego_tok)
        # Not the first token anymore
        Context.state = SPNEGOSSP.STATE.NORMAL
        return Context, spnego_tok, status

    def GSS_Init_sec_context(
        self, Context: CONTEXT, val=None, req_flags: Optional[GSS_C_FLAGS] = None
    ):
        return self._common_spnego_handler(Context, True, val=val, req_flags=req_flags)

    def GSS_Accept_sec_context(self, Context: CONTEXT, val=None):
        return self._common_spnego_handler(Context, False, val=val, req_flags=0)

    def GSS_Passive(self, Context: CONTEXT, val=None):
        if Context is None:
            # New Context
            Context = SPNEGOSSP.CONTEXT(self.supported_ssps)
            Context.passive = True

        # Extraction
        val, status, _, rawToken = self._extract_gssapi(Context, val)

        if val is None and status == GSS_S_COMPLETE:
            return Context, None

        # Just get the negotiated SSP
        if Context.negotiated_mechtype:
            mechtype = Context.negotiated_mechtype
        elif Context.requested_mechtypes:
            mechtype = Context.requested_mechtypes[0]
        elif rawToken and Context.supported_mechtypes:
            mechtype = Context.supported_mechtypes[0]
        else:
            return None, GSS_S_BAD_MECH
        try:
            ssp = self.supported_ssps[mechtype.oid.val]
        except KeyError:
            return None, GSS_S_BAD_MECH

        if Context.ssp is not None:
            # Detect resets
            if Context.ssp != ssp:
                Context.ssp = ssp
                Context.sub_context = None
        else:
            Context.ssp = ssp

        # Passthrough
        Context.sub_context, status = Context.ssp.GSS_Passive(Context.sub_context, val)

        return Context, status

    def GSS_Passive_set_Direction(self, Context: CONTEXT, IsAcceptor=False):
        Context.ssp.GSS_Passive_set_Direction(
            Context.sub_context, IsAcceptor=IsAcceptor
        )

    def MaximumSignatureLength(self, Context: CONTEXT):
        return Context.ssp.MaximumSignatureLength(Context.sub_context)
