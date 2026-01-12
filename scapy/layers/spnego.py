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

import os
import struct
from uuid import UUID

from scapy.asn1.asn1 import (
    ASN1_Codecs,
    ASN1_OID,
    ASN1_GENERAL_STRING,
)
from scapy.asn1.mib import conf  # loads conf.mib
from scapy.asn1fields import (
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_FLAGS,
    ASN1F_GENERAL_STRING,
    ASN1F_OID,
    ASN1F_optional,
    ASN1F_PACKET,
    ASN1F_SEQUENCE_OF,
    ASN1F_SEQUENCE,
    ASN1F_STRING_ENCAPS,
    ASN1F_STRING,
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
from scapy.error import log_runtime
from scapy.packet import Packet, bind_layers
from scapy.utils import (
    valid_ip,
    valid_ip6,
)

from scapy.layers.gssapi import (
    _GSSAPI_OIDS,
    _GSSAPI_SIGNATURE_OIDS,
    GSS_C_FLAGS,
    GSS_C_NO_CHANNEL_BINDINGS,
    GSS_S_BAD_MECH,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_FAILURE,
    GSS_S_FLAGS,
    GSSAPI_BLOB_SIGNATURE,
    GSSAPI_BLOB,
    GssChannelBindings,
    SSP,
)

# SSP Providers
from scapy.layers.kerberos import (
    Kerberos,
    KerberosSSP,
    _parse_spn,
    _parse_upn,
)
from scapy.layers.ntlm import (
    NTLMSSP,
    MD4le,
    NEGOEX_EXCHANGE_NTLM,
    NTLM_Header,
    _NTLMPayloadField,
    _NTLMPayloadPacket,
)

# Typing imports
from typing import (
    Dict,
    List,
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
    ASN1_root = ASN1F_STRING_ENCAPS("value", "", GSSAPI_BLOB_SIGNATURE)


_mechDissector = {
    "1.3.6.1.4.1.311.2.2.10": NTLM_Header,  # NTLM
    "1.2.840.48018.1.2.2": Kerberos,  # MS KRB5 - Microsoft Kerberos 5
    "1.2.840.113554.1.2.2": Kerberos,  # Kerberos 5
    "1.2.840.113554.1.2.2.3": Kerberos,  # Kerberos 5 - User to User
}


class _SPNEGO_Token_Field(ASN1F_STRING):
    def i2m(self, pkt, x):
        if x is None:
            x = b""
        return super(_SPNEGO_Token_Field, self).i2m(pkt, bytes(x))

    def m2i(self, pkt, s):
        dat, r = super(_SPNEGO_Token_Field, self).m2i(pkt, s)
        types = None
        if isinstance(pkt.underlayer, SPNEGO_negTokenInit):
            types = pkt.underlayer.mechTypes
        elif isinstance(pkt.underlayer, SPNEGO_negTokenResp):
            types = [pkt.underlayer.supportedMech]
        if types and types[0] and types[0].oid.val in _mechDissector:
            return _mechDissector[types[0].oid.val](dat.val), r
        else:
            # Use heuristics
            return GSSAPI_BLOB(dat.val), r


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
                "negState",
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

    NOTE: The documentation on mechListMIC isn't super clear, so note that:

    - The mechListMIC that the client sends is computed over the
      list of mechanisms that it requests.
    - the mechListMIC that the server sends is computed over the
      list of mechanisms that the client requested.

    This also means that NegTokenInit2 added by [MS-SPNG] is NOT protected.
    That's not necessarily an issue, since it was optional in most cases,
    but it's something to keep in mind.
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
        "ssps",
    ]

    auth_type = 0x09

    class STATE(SSP.STATE):
        FIRST = 1
        SUBSEQUENT = 2

    class CONTEXT(SSP.CONTEXT):
        __slots__ = [
            "req_flags",
            "ssps",
            "other_mechtypes",
            "sent_mechtypes",
            "first_choice",
            "require_mic",
            "verified_mic",
            "ssp",
            "ssp_context",
            "ssp_mechtype",
            "raw",
        ]

        def __init__(
            self,
            ssps: List[SSP],
            req_flags=None,
        ):
            self.state = SPNEGOSSP.STATE.FIRST
            self.req_flags = req_flags
            # Information used during negotiation
            self.ssps = ssps
            self.other_mechtypes = None  # the mechtypes our peer requested
            self.sent_mechtypes = None  # the mechtypes we sent when acting as a client
            self.first_choice = True  # whether the SSP was the peer's first choice
            self.require_mic = False  # whether the mechListMIC is required or not
            self.verified_mic = False  # whether mechListMIC has been verified
            # Information about the currently selected SSP
            self.ssp = None
            self.ssp_context = None
            self.ssp_mechtype = None
            self.raw = False  # fallback to raw SSP
            super(SPNEGOSSP.CONTEXT, self).__init__()

        # This is the order Windows chooses
        _PREF_ORDER = [
            "1.2.840.113554.1.2.2.3",  # Kerberos 5 - User to User
            "1.2.840.48018.1.2.2",  # MS KRB5
            "1.2.840.113554.1.2.2",  # Kerberos 5
            "1.3.6.1.4.1.311.2.2.30",  # NEGOEX
            "1.3.6.1.4.1.311.2.2.10",  # NTLM
        ]

        def get_supported_mechtypes(self):
            """
            Return an ordered list of mechtypes that are still available.
            """
            # 1. Build mech list
            mechs = []
            for ssp in self.ssps:
                mechs.extend(ssp.GSS_Inquire_names_for_mech())

            # 2. Sort according to the preference order.
            mechs.sort(key=lambda x: self._PREF_ORDER.index(x))

            # 3. Return wrapped in MechType
            return [SPNEGO_MechType(oid=ASN1_OID(oid)) for oid in mechs]

        def negotiate_ssp(self) -> None:
            """
            Perform SSP negotiation.

            This updates our context and sets it with the first SSP that is
            common to both client and server. This also applies rules from
            [MS-SPNG] and RFC4178 to determine if mechListMIC is required.
            """
            if self.other_mechtypes is None:
                # We don't have any information about the peer's preferred SSPs.
                # This typically happens on client side, when NegTokenInit2 isn't used.
                self.ssp = self.ssps[0]
                ssp_oid = self.ssp.GSS_Inquire_names_for_mech()[0]
            else:
                # Get first common SSP between us and our peer
                other_oids = [x.oid.val for x in self.other_mechtypes]
                try:
                    self.ssp, ssp_oid = next(
                        (ssp, requested_oid)
                        for requested_oid in other_oids
                        for ssp in self.ssps
                        if requested_oid in ssp.GSS_Inquire_names_for_mech()
                    )
                except StopIteration:
                    raise ValueError(
                        "Could not find a common SSP with the remote peer !"
                    )

                # Check whether the selected SSP was the one preferred by the client
                self.first_choice = ssp_oid == other_oids[0]

            # Check whether mechListMIC is mandatory for this exchange
            if not self.first_choice:
                # RFC4178 rules for mechListMIC: mandatory if not the first choice.
                self.require_mic = True
            elif ssp_oid == "1.3.6.1.4.1.311.2.2.10" and self.ssp.SupportsMechListMIC():
                # [MS-SPNG] note 8: "If NTLM authentication is most preferred by
                # the client and the server, and the client includes a MIC in
                # AUTHENTICATE_MESSAGE, then the mechListMIC field becomes
                # mandatory"
                self.require_mic = True

            # Get the associated ssp dissection class and mechtype
            self.ssp_mechtype = SPNEGO_MechType(oid=ASN1_OID(ssp_oid))

            # Reset the ssp context
            self.ssp_context = None

        # Passthrough attributes and functions

        def clifailure(self):
            if self.ssp_context is not None:
                self.ssp_context.clifailure()

        def __getattr__(self, attr):
            try:
                return object.__getattribute__(self, attr)
            except AttributeError:
                return getattr(self.ssp_context, attr)

        def __setattr__(self, attr, val):
            try:
                return object.__setattr__(self, attr, val)
            except AttributeError:
                return setattr(self.ssp_context, attr, val)

        # Passthrough the flags property

        @property
        def flags(self):
            if self.ssp_context:
                return self.ssp_context.flags
            return GSS_C_FLAGS(0)

        @flags.setter
        def flags(self, x):
            if not self.ssp_context:
                return
            self.ssp_context.flags = x

        def __repr__(self):
            return "SPNEGOSSP[%s]" % repr(self.ssp_context)

    def __init__(self, ssps: List[SSP], **kwargs):
        self.ssps = ssps
        super(SPNEGOSSP, self).__init__(**kwargs)

    @classmethod
    def from_cli_arguments(
        cls,
        UPN: str,
        target: str,
        password: str = None,
        HashNt: bytes = None,
        HashAes256Sha96: bytes = None,
        HashAes128Sha96: bytes = None,
        kerberos_required: bool = False,
        ST=None,
        TGT=None,
        KEY=None,
        ccache: str = None,
        debug: int = 0,
        use_krb5ccname: bool = False,
    ):
        """
        Initialize a SPNEGOSSP from a list of many arguments.
        This is useful in a CLI, with NTLM and Kerberos supported by default.

        :param UPN: the UPN of the user to use.
        :param target: the target IP/hostname entered by the user.
        :param kerberos_required: require kerberos
        :param password: (string) if provided, used for auth
        :param HashNt: (bytes) if provided, used for auth (NTLM)
        :param HashAes256Sha96: (bytes) if provided, used for auth (Kerberos)
        :param HashAes128Sha96: (bytes) if provided, used for auth (Kerberos)
        :param ST: if provided, the service ticket to use (Kerberos)
        :param TGT: if provided, the TGT to use (Kerberos)
        :param KEY: if ST provided, the session key associated to the ticket (Kerberos).
                    This can be either for the ST or TGT. Else, the user secret key.
        :param ccache: (str) if provided, a path to a CCACHE (Kerberos)
        :param use_krb5ccname: (bool) if true, the KRB5CCNAME environment variable will
                               be used if available.
        """
        kerberos = True
        hostname = None
        # Check if target is a hostname / Check IP
        if ":" in target:
            if not valid_ip6(target):
                hostname = target
        else:
            if not valid_ip(target):
                hostname = target

        # Check UPN
        try:
            _, realm = _parse_upn(UPN)
            if realm == ".":
                # Local
                kerberos = False
        except ValueError:
            # not a UPN: NTLM only
            kerberos = False

        # If we're asked, check the environment for KRB5CCNAME
        if use_krb5ccname and ccache is None and "KRB5CCNAME" in os.environ:
            ccache = os.environ["KRB5CCNAME"]

        # Do we need to ask the password?
        if all(
            x is None
            for x in [
                ST,
                password,
                HashNt,
                HashAes256Sha96,
                HashAes128Sha96,
                ccache,
            ]
        ):
            # yes.
            from prompt_toolkit import prompt

            password = prompt("Password: ", is_password=True)

        ssps = []
        # Kerberos
        if kerberos and hostname:
            # Get ticket if we don't already have one.
            if ST is None and TGT is None and ccache is not None:
                # In this case, load the KerberosSSP from ccache
                from scapy.modules.ticketer import Ticketer

                # Import into a Ticketer object
                t = Ticketer()
                t.open_ccache(ccache)

                # Look for the ticket that we'll use. We chose:
                # - either a ST if the SPN matches our target
                # - else a TGT if we got nothing better
                tgts = []
                for i, (tkt, key, upn, spn) in enumerate(t.iter_tickets()):
                    spn, _ = _parse_spn(spn)
                    spn_host = spn.split("/")[-1]
                    # Check that it's for the correct user
                    if upn.lower() == UPN.lower():
                        # Check that it's either a TGT or a ST to the correct service
                        if spn.lower().startswith("krbtgt/"):
                            # TGT. Keep it, and see if we don't have a better ST.
                            tgts.append(t.ssp(i))
                        elif hostname.lower() == spn_host.lower():
                            # ST. We're done !
                            ssps.append(t.ssp(i))
                            break
                else:
                    # No ST found
                    if tgts:
                        # Using a TGT !
                        ssps.append(tgts[0])
                    else:
                        # Nothing found
                        t.show()
                        raise ValueError(
                            f"Could not find a ticket for {upn}, either a "
                            f"TGT or towards {hostname}"
                        )
            elif ST is None and TGT is None:
                # In this case, KEY is supposed to be the user's key.
                from scapy.libs.rfc3961 import Key, EncryptionType

                if KEY is None and HashAes256Sha96:
                    KEY = Key(
                        EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        HashAes256Sha96,
                    )
                elif KEY is None and HashAes128Sha96:
                    KEY = Key(
                        EncryptionType.AES128_CTS_HMAC_SHA1_96,
                        HashAes128Sha96,
                    )
                elif KEY is None and HashNt:
                    KEY = Key(
                        EncryptionType.RC4_HMAC,
                        HashNt,
                    )
                # Make a SSP that only has a UPN and secret.
                ssps.append(
                    KerberosSSP(
                        UPN=UPN,
                        PASSWORD=password,
                        KEY=KEY,
                        debug=debug,
                    )
                )
            else:
                # We have a ST, use it with the key.
                ssps.append(
                    KerberosSSP(
                        UPN=UPN,
                        ST=ST,
                        TGT=TGT,
                        KEY=KEY,
                        debug=debug,
                    )
                )
        elif kerberos_required:
            raise ValueError(
                "Kerberos required but domain not specified in the UPN, "
                "or target isn't a hostname !"
            )

        # NTLM
        if not kerberos_required:
            if HashNt is None and password is not None:
                HashNt = MD4le(password)
            if HashNt is not None:
                ssps.append(NTLMSSP(UPN=UPN, HASHNT=HashNt))

        if not ssps:
            raise ValueError("Unexpected case ! Please report.")

        # Build the SSP
        return cls(ssps)

    def NegTokenInit2(self):
        """
        Server-Initiation of GSSAPI/SPNEGO.
        See [MS-SPNG] sect 3.2.5.2
        """
        Context = SPNEGOSSP.CONTEXT(list(self.ssps))
        return (
            Context,
            GSSAPI_BLOB(
                innerToken=SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(
                        mechTypes=Context.get_supported_mechtypes(),
                        negHints=SPNEGO_negHints(
                            hintName=ASN1_GENERAL_STRING(
                                "not_defined_in_RFC4178@please_ignore"
                            ),
                        ),
                    )
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
        return Context.ssp.GSS_WrapEx(Context.ssp_context, *args, **kwargs)

    def GSS_UnwrapEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_UnwrapEx(Context.ssp_context, *args, **kwargs)

    def GSS_GetMICEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_GetMICEx(Context.ssp_context, *args, **kwargs)

    def GSS_VerifyMICEx(self, Context, *args, **kwargs):
        # Passthrough
        return Context.ssp.GSS_VerifyMICEx(Context.ssp_context, *args, **kwargs)

    def LegsAmount(self, Context: CONTEXT):
        return 4

    def MapStatusToNegState(self, status: int) -> int:
        """
        Map a GSSAPI return code to SPNEGO negState codes
        """
        if status == GSS_S_COMPLETE:
            return 0  # accept_completed
        elif status == GSS_S_CONTINUE_NEEDED:
            return 1  # accept_incomplete
        else:
            return 2  # reject

    def GuessOtherMechtypes(self, Context: CONTEXT, input_token):
        """
        Guesses the mechtype of the peer when the "raw" fallback is used.
        """
        if isinstance(input_token, NTLM_Header):
            Context.other_mechtypes = [
                SPNEGO_MechType(oid=ASN1_OID("1.3.6.1.4.1.311.2.2.10"))
            ]
        elif isinstance(input_token, Kerberos):
            Context.other_mechtypes = [
                SPNEGO_MechType(oid=ASN1_OID("1.2.840.48018.1.2.2"))
            ]
        else:
            Context.other_mechtypes = []

    def GSS_Init_sec_context(
        self,
        Context: CONTEXT,
        input_token=None,
        target_name: Optional[str] = None,
        req_flags: Optional[GSS_C_FLAGS] = None,
        chan_bindings: GssChannelBindings = GSS_C_NO_CHANNEL_BINDINGS,
    ):
        if Context is None:
            # New Context
            Context = SPNEGOSSP.CONTEXT(
                list(self.ssps),
                req_flags=req_flags,
            )

        input_token_inner = None
        negState = None

        # Extract values from GSSAPI token, if present
        if input_token is not None:
            if isinstance(input_token, GSSAPI_BLOB):
                input_token = input_token.innerToken
            if isinstance(input_token, SPNEGO_negToken):
                input_token = input_token.token
            if isinstance(input_token, SPNEGO_negTokenInit):
                # We are handling a NegTokenInit2 request !
                # Populate context with values from the server's request
                Context.other_mechtypes = input_token.mechTypes
            elif isinstance(input_token, SPNEGO_negTokenResp):
                # Extract token and state from the client request
                if input_token.responseToken is not None:
                    input_token_inner = input_token.responseToken.value
                if input_token.negState is not None:
                    negState = input_token.negState
            else:
                # The blob is a raw token. We aren't using SPNEGO here.
                Context.raw = True
                input_token_inner = input_token
                self.GuessOtherMechtypes(Context, input_token)

        # Perform SSP negotiation
        if Context.ssp is None:
            try:
                Context.negotiate_ssp()
            except ValueError as ex:
                # Couldn't find common SSP
                log_runtime.warning("SPNEGOSSP: %s" % ex)
                return Context, None, GSS_S_BAD_MECH

        # Call inner-SSP
        Context.ssp_context, output_token_inner, status = (
            Context.ssp.GSS_Init_sec_context(
                Context.ssp_context,
                input_token=input_token_inner,
                target_name=target_name,
                req_flags=Context.req_flags,
                chan_bindings=chan_bindings,
            )
        )

        if negState == 2 or status not in [GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED]:
            # SSP failed. Remove it from the list of SSPs we're currently running
            Context.ssps.remove(Context.ssp)
            log_runtime.warning(
                "SPNEGOSSP: %s failed. Retrying with next in queue." % repr(Context.ssp)
            )

            if Context.ssps:
                # We have other SSPs remaining. Retry using another one.
                Context.ssp = None
                return self.GSS_Init_sec_context(
                    Context,
                    None,  # No input for retry.
                    target_name=target_name,
                    req_flags=req_flags,
                    chan_bindings=chan_bindings,
                )
            else:
                # We don't have anything left
                return Context, None, status

        # Raw processing ends here.
        if Context.raw:
            return Context, output_token_inner, status

        # Verify MIC if present.
        if status == GSS_S_COMPLETE and input_token and input_token.mechListMIC:
            # NOTE: the mechListMIC that the server sends is computed over the list of
            # mechanisms that the **client requested**.
            Context.ssp.VerifyMechListMIC(
                Context.ssp_context,
                input_token.mechListMIC.value,
                mechListMIC(Context.sent_mechtypes),
            )
            Context.verified_mic = True

        if negState == 0 and status == GSS_S_COMPLETE:
            # We are done.
            return Context, None, status
        elif Context.state == SPNEGOSSP.STATE.FIRST:
            # First freeze the list of available mechtypes on the first message
            Context.sent_mechtypes = Context.get_supported_mechtypes()

            # Now build the token
            spnego_tok = GSSAPI_BLOB(
                innerToken=SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(mechTypes=Context.sent_mechtypes)
                )
            )

            # Add the output token if provided
            if output_token_inner is not None:
                spnego_tok.innerToken.token.mechToken = SPNEGO_Token(
                    value=output_token_inner,
                )
        elif Context.state == SPNEGOSSP.STATE.SUBSEQUENT:
            # Build subsequent client tokens: without the list of supported mechtypes
            # NOTE: GSSAPI_BLOB is stripped.
            spnego_tok = SPNEGO_negToken(
                token=SPNEGO_negTokenResp(
                    supportedMech=None,
                    negState=None,
                )
            )

            # Add the MIC if required and the exchange is finished.
            if status == GSS_S_COMPLETE and Context.require_mic:
                spnego_tok.token.mechListMIC = SPNEGO_MechListMIC(
                    value=Context.ssp.GetMechListMIC(
                        Context.ssp_context,
                        mechListMIC(Context.sent_mechtypes),
                    ),
                )

                # If we still haven't verified the MIC, we aren't done.
                if not Context.verified_mic:
                    status = GSS_S_CONTINUE_NEEDED

            # Add the output token if provided
            if output_token_inner:
                spnego_tok.token.responseToken = SPNEGO_Token(
                    value=output_token_inner,
                )

        # Update the state
        Context.state = SPNEGOSSP.STATE.SUBSEQUENT

        return Context, spnego_tok, status

    def GSS_Accept_sec_context(
        self,
        Context: CONTEXT,
        input_token=None,
        req_flags: Optional[GSS_S_FLAGS] = GSS_S_FLAGS.GSS_S_ALLOW_MISSING_BINDINGS,
        chan_bindings: GssChannelBindings = GSS_C_NO_CHANNEL_BINDINGS,
    ):
        if Context is None:
            # New Context
            Context = SPNEGOSSP.CONTEXT(
                list(self.ssps),
                req_flags=req_flags,
            )

        input_token_inner = None
        _mechListMIC = None

        # Extract values from GSSAPI token
        if isinstance(input_token, GSSAPI_BLOB):
            input_token = input_token.innerToken
        if isinstance(input_token, SPNEGO_negToken):
            input_token = input_token.token
        if isinstance(input_token, SPNEGO_negTokenInit):
            # Populate context with values from the client's request
            if input_token.mechTypes:
                Context.other_mechtypes = input_token.mechTypes
            if input_token.mechToken:
                input_token_inner = input_token.mechToken.value
            _mechListMIC = input_token.mechListMIC or input_token._mechListMIC
        elif isinstance(input_token, SPNEGO_negTokenResp):
            if input_token.responseToken:
                input_token_inner = input_token.responseToken.value
            _mechListMIC = input_token.mechListMIC
        else:
            # The blob is a raw token. We aren't using SPNEGO here.
            Context.raw = True
            input_token_inner = input_token
            self.GuessOtherMechtypes(Context, input_token)

        if Context.other_mechtypes is None:
            # At this point, we should have already gotten the mechtypes from a current
            # or former request.
            return Context, None, GSS_S_FAILURE

        # Perform SSP negotiation
        if Context.ssp is None:
            try:
                Context.negotiate_ssp()
            except ValueError as ex:
                # Couldn't find common SSP
                log_runtime.warning("SPNEGOSSP: %s" % ex)
                return Context, None, GSS_S_FAILURE

        output_token_inner = None
        status = GSS_S_CONTINUE_NEEDED

        # If we didn't pick the client's first choice, the token we were passed
        # isn't usable.
        if not Context.first_choice:
            # Typically a client opportunistically starts with Kerberos, including
            # its APREQ, and we want to use NTLM. Here we add one round trip
            Context.first_choice = True  # Do not enter here again.
        else:
            # Send it to the negotiated SSP
            Context.ssp_context, output_token_inner, status = (
                Context.ssp.GSS_Accept_sec_context(
                    Context.ssp_context,
                    input_token=input_token_inner,
                    req_flags=Context.req_flags,
                    chan_bindings=chan_bindings,
                )
            )

        # Verify MIC if context succeeded
        if status == GSS_S_COMPLETE and _mechListMIC:
            # NOTE: the mechListMIC that the client sends is computed over the
            # **list of mechanisms that it requests**.
            if Context.ssp.SupportsMechListMIC():
                # We need to check we support checking the MIC. The only case where
                # this is needed is NTLM in guest mode: the client will send a mic
                # but we don't check it...
                Context.ssp.VerifyMechListMIC(
                    Context.ssp_context,
                    _mechListMIC.value,
                    mechListMIC(Context.other_mechtypes),
                )
                Context.verified_mic = True
                Context.require_mic = True

        # Raw processing ends here.
        if Context.raw:
            return Context, output_token_inner, status

        # 0. Build the template response token
        spnego_tok = SPNEGO_negToken(
            token=SPNEGO_negTokenResp(
                supportedMech=None,
            )
        )
        if Context.state == SPNEGOSSP.STATE.FIRST:
            # Include the supportedMech list if this is the first message we send
            # or a renegotiation.
            spnego_tok.token.supportedMech = Context.ssp_mechtype

        # Add the output token if provided
        if output_token_inner:
            spnego_tok.token.responseToken = SPNEGO_Token(value=output_token_inner)

        # Update the state
        Context.state = SPNEGOSSP.STATE.SUBSEQUENT

        # Add the MIC if required and the exchange is finished.
        if status == GSS_S_COMPLETE and Context.require_mic:
            spnego_tok.token.mechListMIC = SPNEGO_MechListMIC(
                value=Context.ssp.GetMechListMIC(
                    Context.ssp_context,
                    mechListMIC(Context.other_mechtypes),
                ),
            )

            # If we still haven't verified the MIC, we aren't done.
            if not Context.verified_mic:
                status = GSS_S_CONTINUE_NEEDED

        # Set negState
        spnego_tok.token.negState = self.MapStatusToNegState(status)

        return Context, spnego_tok, status

    def GSS_Passive(
        self,
        Context: CONTEXT,
        input_token=None,
        req_flags=None,
    ):
        if Context is None:
            # New Context
            Context = SPNEGOSSP.CONTEXT(list(self.ssps))
            Context.passive = True

        input_token_inner = None

        # Extract values from GSSAPI token
        if isinstance(input_token, GSSAPI_BLOB):
            input_token = input_token.innerToken
        if isinstance(input_token, SPNEGO_negToken):
            input_token = input_token.token
        if isinstance(input_token, SPNEGO_negTokenInit):
            if input_token.mechTypes is not None:
                Context.other_mechtypes = input_token.mechTypes
            if input_token.mechToken:
                input_token_inner = input_token.mechToken.value
        elif isinstance(input_token, SPNEGO_negTokenResp):
            if input_token.supportedMech is not None:
                Context.other_mechtypes = [input_token.supportedMech]
            if input_token.responseToken:
                input_token_inner = input_token.responseToken.value
        else:
            # Raw.
            input_token_inner = input_token

        if Context.other_mechtypes is None:
            self.GuessOtherMechtypes(Context, input_token)

        # Uninitialized OR allowed mechtypes have changed
        if Context.ssp is None or Context.ssp_mechtype not in Context.other_mechtypes:
            try:
                Context.negotiate_ssp()
            except ValueError:
                # Couldn't find common SSP
                return Context, GSS_S_FAILURE

        # Passthrough
        Context.ssp_context, status = Context.ssp.GSS_Passive(
            Context.ssp_context,
            input_token_inner,
            req_flags=req_flags,
        )

        return Context, status

    def GSS_Passive_set_Direction(self, Context: CONTEXT, IsAcceptor=False):
        Context.ssp.GSS_Passive_set_Direction(
            Context.ssp_context, IsAcceptor=IsAcceptor
        )

    def MaximumSignatureLength(self, Context: CONTEXT):
        return Context.ssp.MaximumSignatureLength(Context.ssp_context)
