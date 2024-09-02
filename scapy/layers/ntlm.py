# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
NTLM

This is documented in [MS-NLMP]

.. note::
    You will find more complete documentation for this layer over at
    `GSSAPI <https://scapy.readthedocs.io/en/latest/layers/gssapi.html#ntlm>`_
"""

import copy
import time
import os
import struct

from enum import IntEnum

from scapy.asn1.asn1 import ASN1_Codecs
from scapy.asn1.mib import conf  # loads conf.mib
from scapy.asn1fields import (
    ASN1F_OID,
    ASN1F_PRINTABLE_STRING,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
)
from scapy.asn1packet import ASN1_Packet
from scapy.compat import bytes_base64
from scapy.error import log_runtime
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FlagsField,
    LEIntEnumField,
    LEIntField,
    LEShortEnumField,
    LEShortField,
    LEThreeBytesField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    StrField,
    StrFieldUtf16,
    StrFixedLenField,
    StrLenFieldUtf16,
    UTCTimeField,
    XStrField,
    XStrFixedLenField,
    XStrLenField,
    _StrField,
)
from scapy.packet import Packet
from scapy.sessions import StringBuffer

from scapy.layers.gssapi import (
    GSS_C_FLAGS,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_DEFECTIVE_CREDENTIAL,
    GSS_S_DEFECTIVE_TOKEN,
    SSP,
    _GSSAPI_OIDS,
    _GSSAPI_SIGNATURE_OIDS,
)

# Typing imports
from typing import (
    Any,
    Callable,
    List,
    Optional,
    Tuple,
    Union,
)

# Crypto imports

from scapy.layers.tls.crypto.hash import Hash_MD4, Hash_MD5
from scapy.layers.tls.crypto.h_mac import Hmac_MD5

##########
# Fields #
##########


class _NTLMPayloadField(_StrField[List[Tuple[str, Any]]]):
    """Special field used to dissect NTLM payloads.
    This isn't trivial because the offsets are variable."""

    __slots__ = [
        "fields",
        "fields_map",
        "offset",
        "length_from",
        "force_order",
        "offset_name",
    ]
    islist = True

    def __init__(
        self,
        name,  # type: str
        offset,  # type: Union[int, Callable[[Packet], int]]
        fields,  # type: List[Field[Any, Any]]
        length_from=None,  # type: Optional[Callable[[Packet], int]]
        force_order=None,  # type: Optional[List[str]]
        offset_name="BufferOffset",  # type: str
    ):
        # type: (...) -> None
        self.offset = offset
        self.fields = fields
        self.fields_map = {field.name: field for field in fields}
        self.length_from = length_from
        self.force_order = force_order  # whether the order of fields is fixed
        self.offset_name = offset_name
        super(_NTLMPayloadField, self).__init__(
            name,
            [
                (field.name, field.default)
                for field in fields
                if field.default is not None
            ],
        )

    def _on_payload(self, pkt, x, func):
        # type: (Optional[Packet], bytes, str) -> List[Tuple[str, Any]]
        if not pkt or not x:
            return []
        results = []
        for field_name, value in x:
            if field_name not in self.fields_map:
                continue
            if not isinstance(
                self.fields_map[field_name], PacketListField
            ) and not isinstance(value, Packet):
                value = getattr(self.fields_map[field_name], func)(pkt, value)
            results.append((field_name, value))
        return results

    def i2h(self, pkt, x):
        # type: (Optional[Packet], bytes) -> List[Tuple[str, str]]
        return self._on_payload(pkt, x, "i2h")

    def h2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> List[Tuple[str, str]]
        return self._on_payload(pkt, x, "h2i")

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return repr(self._on_payload(pkt, x, "i2repr"))

    def _o_pkt(self, pkt):
        # type: (Optional[Packet]) -> int
        if callable(self.offset):
            return self.offset(pkt)
        return self.offset

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Optional[List[Tuple[str, str]]]) -> bytes
        # Create string buffer
        buf = StringBuffer()
        buf.append(s, 1)
        # Calc relative offset
        r_off = self._o_pkt(pkt) - len(s)
        if self.force_order:
            val.sort(key=lambda x: self.force_order.index(x[0]))
        for field_name, value in val:
            if field_name not in self.fields_map:
                continue
            field = self.fields_map[field_name]
            offset = pkt.getfieldval(field_name + self.offset_name)
            if offset is None:
                # No offset specified: calc
                offset = len(buf)
            else:
                # Calc relative offset
                offset -= r_off
                pad = offset + 1 - len(buf)
                # Add padding if necessary
                if pad > 0:
                    buf.append(pad * b"\x00", len(buf))
            buf.append(field.addfield(pkt, bytes(buf), value)[len(buf) :], offset + 1)
        return bytes(buf)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, List[Tuple[str, str]]]
        if self.length_from is None:
            ret, remain = b"", s
        else:
            len_pkt = self.length_from(pkt)
            ret, remain = s[len_pkt:], s[:len_pkt]
        if not pkt or not remain:
            return s, []
        results = []
        max_offset = 0
        o_pkt = self._o_pkt(pkt)
        offsets = [
            pkt.getfieldval(x.name + self.offset_name) - o_pkt for x in self.fields
        ]
        for i, field in enumerate(self.fields):
            offset = offsets[i]
            try:
                length = pkt.getfieldval(field.name + "Len")
            except AttributeError:
                length = len(remain) - offset
                # length can't be greater than the difference with the next offset
                try:
                    length = min(length, min(x - offset for x in offsets if x > offset))
                except ValueError:
                    pass
            if offset < 0:
                continue
            max_offset = max(offset + length, max_offset)
            if remain[offset : offset + length]:
                results.append(
                    (
                        offset,
                        field.name,
                        field.getfield(pkt, remain[offset : offset + length])[1],
                    )
                )
        ret += remain[max_offset:]
        results.sort(key=lambda x: x[0])
        return ret, [x[1:] for x in results]


class _NTLMPayloadPacket(Packet):
    _NTLM_PAYLOAD_FIELD_NAME = "Payload"

    def __init__(
        self,
        _pkt=b"",  # type: Union[bytes, bytearray]
        post_transform=None,  # type: Any
        _internal=0,  # type: int
        _underlayer=None,  # type: Optional[Packet]
        _parent=None,  # type: Optional[Packet]
        **fields,  # type: Any
    ):
        # pop unknown fields. We can't process them until the packet is initialized
        unknown = {
            k: fields.pop(k)
            for k in list(fields)
            if not any(k == f.name for f in self.fields_desc)
        }
        super(_NTLMPayloadPacket, self).__init__(
            _pkt=_pkt,
            post_transform=post_transform,
            _internal=_internal,
            _underlayer=_underlayer,
            _parent=_parent,
            **fields,
        )
        # check unknown fields for implicit ones
        local_fields = next(
            [y.name for y in x.fields]
            for x in self.fields_desc
            if x.name == self._NTLM_PAYLOAD_FIELD_NAME
        )
        implicit_fields = {k: v for k, v in unknown.items() if k in local_fields}
        for k, value in implicit_fields.items():
            self.setfieldval(k, value)

    def getfieldval(self, attr):
        # Ease compatibility with _NTLMPayloadField
        try:
            return super(_NTLMPayloadPacket, self).getfieldval(attr)
        except AttributeError:
            try:
                return next(
                    x[1]
                    for x in super(_NTLMPayloadPacket, self).getfieldval(
                        self._NTLM_PAYLOAD_FIELD_NAME
                    )
                    if x[0] == attr
                )
            except StopIteration:
                raise AttributeError(attr)

    def getfield_and_val(self, attr):
        # Ease compatibility with _NTLMPayloadField
        try:
            return super(_NTLMPayloadPacket, self).getfield_and_val(attr)
        except ValueError:
            PayFields = self.get_field(self._NTLM_PAYLOAD_FIELD_NAME).fields_map
            try:
                return (
                    PayFields[attr],
                    PayFields[attr].h2i(  # cancel out the i2h.. it's dumb i know
                        self,
                        next(
                            x[1]
                            for x in super(_NTLMPayloadPacket, self).__getattr__(
                                self._NTLM_PAYLOAD_FIELD_NAME
                            )
                            if x[0] == attr
                        ),
                    ),
                )
            except (StopIteration, KeyError):
                raise ValueError(attr)

    def setfieldval(self, attr, val):
        # Ease compatibility with _NTLMPayloadField
        try:
            return super(_NTLMPayloadPacket, self).setfieldval(attr, val)
        except AttributeError:
            Payload = super(_NTLMPayloadPacket, self).__getattr__(
                self._NTLM_PAYLOAD_FIELD_NAME
            )
            if attr not in self.get_field(self._NTLM_PAYLOAD_FIELD_NAME).fields_map:
                raise AttributeError(attr)
            try:
                Payload.pop(
                    next(
                        i
                        for i, x in enumerate(
                            super(_NTLMPayloadPacket, self).__getattr__(
                                self._NTLM_PAYLOAD_FIELD_NAME
                            )
                        )
                        if x[0] == attr
                    )
                )
            except StopIteration:
                pass
            Payload.append([attr, val])
            super(_NTLMPayloadPacket, self).setfieldval(
                self._NTLM_PAYLOAD_FIELD_NAME, Payload
            )


class _NTLM_ENUM(IntEnum):
    LEN = 0x0001
    MAXLEN = 0x0002
    OFFSET = 0x0004
    COUNT = 0x0008
    PAD8 = 0x1000


_NTLM_CONFIG = [
    ("Len", _NTLM_ENUM.LEN),
    ("MaxLen", _NTLM_ENUM.MAXLEN),
    ("BufferOffset", _NTLM_ENUM.OFFSET),
]


def _NTLM_post_build(self, p, pay_offset, fields, config=_NTLM_CONFIG):
    """Util function to build the offset and populate the lengths"""
    for field_name, value in self.fields[self._NTLM_PAYLOAD_FIELD_NAME]:
        fld = self.get_field(self._NTLM_PAYLOAD_FIELD_NAME).fields_map[field_name]
        length = fld.i2len(self, value)
        count = fld.i2count(self, value)
        offset = fields[field_name]
        i = 0
        r = lambda y: {2: "H", 4: "I", 8: "Q"}[y]
        for fname, ftype in config:
            if isinstance(ftype, dict):
                ftype = ftype[field_name]
            if ftype & _NTLM_ENUM.LEN:
                fval = length
            elif ftype & _NTLM_ENUM.OFFSET:
                fval = pay_offset
            elif ftype & _NTLM_ENUM.MAXLEN:
                fval = length
            elif ftype & _NTLM_ENUM.COUNT:
                fval = count
            else:
                raise ValueError
            if ftype & _NTLM_ENUM.PAD8:
                fval += (-fval) % 8
            sz = self.get_field(field_name + fname).sz
            if self.getfieldval(field_name + fname) is None:
                p = (
                    p[: offset + i]
                    + struct.pack("<%s" % r(sz), fval)
                    + p[offset + i + sz :]
                )
            i += sz
        pay_offset += length
    return p


##############
# Structures #
##############


# Sect 2.2


class NTLM_Header(Packet):
    name = "NTLM Header"
    fields_desc = [
        StrFixedLenField("Signature", b"NTLMSSP\0", length=8),
        LEIntEnumField(
            "MessageType",
            3,
            {1: "NEGOTIATE_MESSAGE", 2: "CHALLENGE_MESSAGE", 3: "AUTHENTICATE_MESSAGE"},
        ),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 10:
            MessageType = struct.unpack("<H", _pkt[8:10])[0]
            if MessageType == 1:
                return NTLM_NEGOTIATE
            elif MessageType == 2:
                return NTLM_CHALLENGE
            elif MessageType == 3:
                return NTLM_AUTHENTICATE_V2
        return cls


# Sect 2.2.2.5
_negotiateFlags = [
    "NEGOTIATE_UNICODE",  # A
    "NEGOTIATE_OEM",  # B
    "REQUEST_TARGET",  # C
    "r10",
    "NEGOTIATE_SIGN",  # D
    "NEGOTIATE_SEAL",  # E
    "NEGOTIATE_DATAGRAM",  # F
    "NEGOTIATE_LM_KEY",  # G
    "r9",
    "NEGOTIATE_NTLM",  # H
    "r8",
    "J",
    "NEGOTIATE_OEM_DOMAIN_SUPPLIED",  # K
    "NEGOTIATE_OEM_WORKSTATION_SUPPLIED",  # L
    "r7",
    "NEGOTIATE_ALWAYS_SIGN",  # M
    "TARGET_TYPE_DOMAIN",  # N
    "TARGET_TYPE_SERVER",  # O
    "r6",
    "NEGOTIATE_EXTENDED_SESSIONSECURITY",  # P
    "NEGOTIATE_IDENTIFY",  # Q
    "r5",
    "REQUEST_NON_NT_SESSION_KEY",  # R
    "NEGOTIATE_TARGET_INFO",  # S
    "r4",
    "NEGOTIATE_VERSION",  # T
    "r3",
    "r2",
    "r1",
    "NEGOTIATE_128",  # U
    "NEGOTIATE_KEY_EXCH",  # V
    "NEGOTIATE_56",  # W
]


def _NTLMStrField(name, default):
    return MultipleTypeField(
        [
            (
                StrFieldUtf16(name, default),
                lambda pkt: pkt.NegotiateFlags.NEGOTIATE_UNICODE,
            )
        ],
        StrField(name, default),
    )


# Sect 2.2.2.10


class _NTLM_Version(Packet):
    fields_desc = [
        ByteField("ProductMajorVersion", 0),
        ByteField("ProductMinorVersion", 0),
        LEShortField("ProductBuild", 0),
        LEThreeBytesField("res_ver", 0),
        ByteEnumField("NTLMRevisionCurrent", 0x0F, {0x0F: "v15"}),
    ]


# Sect 2.2.1.1


class NTLM_NEGOTIATE(_NTLMPayloadPacket):
    name = "NTLM Negotiate"
    MessageType = 1
    OFFSET = lambda pkt: (((pkt.DomainNameBufferOffset or 40) > 32) and 40 or 32)
    fields_desc = (
        [
            NTLM_Header,
            FlagsField("NegotiateFlags", 0, -32, _negotiateFlags),
            # DomainNameFields
            LEShortField("DomainNameLen", None),
            LEShortField("DomainNameMaxLen", None),
            LEIntField("DomainNameBufferOffset", None),
            # WorkstationFields
            LEShortField("WorkstationNameLen", None),
            LEShortField("WorkstationNameMaxLen", None),
            LEIntField("WorkstationNameBufferOffset", None),
        ]
        + [
            # VERSION
            ConditionalField(
                # (not present on some old Windows versions. We use a heuristic)
                x,
                lambda pkt: (
                    (
                        40
                        if pkt.DomainNameBufferOffset is None
                        else pkt.DomainNameBufferOffset or len(pkt.original or b"")
                    )
                    > 32
                )
                or pkt.fields.get(x.name, b""),
            )
            for x in _NTLM_Version.fields_desc
        ]
        + [
            # Payload
            _NTLMPayloadField(
                "Payload",
                OFFSET,
                [
                    _NTLMStrField("DomainName", b""),
                    _NTLMStrField("WorkstationName", b""),
                ],
            ),
        ]
    )

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                self.OFFSET(),
                {
                    "DomainName": 16,
                    "WorkstationName": 24,
                },
            )
            + pay
        )


# Challenge


class Single_Host_Data(Packet):
    fields_desc = [
        LEIntField("Size", 48),
        LEIntField("Z4", 0),
        XStrFixedLenField("CustomData", b"", length=8),
        XStrFixedLenField("MachineID", b"", length=32),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class AV_PAIR(Packet):
    name = "NTLM AV Pair"
    fields_desc = [
        LEShortEnumField(
            "AvId",
            0,
            {
                0x0000: "MsvAvEOL",
                0x0001: "MsvAvNbComputerName",
                0x0002: "MsvAvNbDomainName",
                0x0003: "MsvAvDnsComputerName",
                0x0004: "MsvAvDnsDomainName",
                0x0005: "MsvAvDnsTreeName",
                0x0006: "MsvAvFlags",
                0x0007: "MsvAvTimestamp",
                0x0008: "MsvAvSingleHost",
                0x0009: "MsvAvTargetName",
                0x000A: "MsvAvChannelBindings",
            },
        ),
        FieldLenField("AvLen", None, length_of="Value", fmt="<H"),
        MultipleTypeField(
            [
                (
                    LEIntEnumField(
                        "Value",
                        1,
                        {
                            0x0001: "constrained",
                            0x0002: "MIC integrity",
                            0x0004: "SPN from untrusted source",
                        },
                    ),
                    lambda pkt: pkt.AvId == 0x0006,
                ),
                (
                    UTCTimeField(
                        "Value",
                        None,
                        epoch=[1601, 1, 1, 0, 0, 0],
                        custom_scaling=1e7,
                        fmt="<Q",
                    ),
                    lambda pkt: pkt.AvId == 0x0007,
                ),
                (
                    PacketField("Value", Single_Host_Data(), Single_Host_Data),
                    lambda pkt: pkt.AvId == 0x0008,
                ),
                (
                    XStrLenField("Value", b"", length_from=lambda pkt: pkt.AvLen),
                    lambda pkt: pkt.AvId == 0x000A,
                ),
            ],
            StrLenFieldUtf16("Value", b"", length_from=lambda pkt: pkt.AvLen),
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class NTLM_CHALLENGE(_NTLMPayloadPacket):
    name = "NTLM Challenge"
    MessageType = 2
    OFFSET = lambda pkt: (((pkt.TargetInfoBufferOffset or 56) > 48) and 56 or 48)
    fields_desc = (
        [
            NTLM_Header,
            # TargetNameFields
            LEShortField("TargetNameLen", None),
            LEShortField("TargetNameMaxLen", None),
            LEIntField("TargetNameBufferOffset", None),
            #
            FlagsField("NegotiateFlags", 0, -32, _negotiateFlags),
            XStrFixedLenField("ServerChallenge", None, length=8),
            XStrFixedLenField("Reserved", None, length=8),
            # TargetInfoFields
            LEShortField("TargetInfoLen", None),
            LEShortField("TargetInfoMaxLen", None),
            LEIntField("TargetInfoBufferOffset", None),
        ]
        + [
            # VERSION
            ConditionalField(
                # (not present on some old Windows versions. We use a heuristic)
                x,
                lambda pkt: ((pkt.TargetInfoBufferOffset or 56) > 40)
                or pkt.fields.get(x.name, b""),
            )
            for x in _NTLM_Version.fields_desc
        ]
        + [
            # Payload
            _NTLMPayloadField(
                "Payload",
                OFFSET,
                [
                    _NTLMStrField("TargetName", b""),
                    PacketListField("TargetInfo", [AV_PAIR()], AV_PAIR),
                ],
            ),
        ]
    )

    def getAv(self, AvId):
        try:
            return next(x for x in self.TargetInfo if x.AvId == AvId)
        except (StopIteration, AttributeError):
            raise IndexError

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                self.OFFSET(),
                {
                    "TargetName": 12,
                    "TargetInfo": 40,
                },
            )
            + pay
        )


# Authenticate


class LM_RESPONSE(Packet):
    fields_desc = [
        StrFixedLenField("Response", b"", length=24),
    ]


class LMv2_RESPONSE(Packet):
    fields_desc = [
        StrFixedLenField("Response", b"", length=16),
        StrFixedLenField("ChallengeFromClient", b"", length=8),
    ]


class NTLM_RESPONSE(Packet):
    fields_desc = [
        StrFixedLenField("Response", b"", length=24),
    ]


class NTLMv2_CLIENT_CHALLENGE(Packet):
    fields_desc = [
        ByteField("RespType", 1),
        ByteField("HiRespType", 1),
        LEShortField("Reserved1", 0),
        LEIntField("Reserved2", 0),
        UTCTimeField(
            "TimeStamp", None, fmt="<Q", epoch=[1601, 1, 1, 0, 0, 0], custom_scaling=1e7
        ),
        StrFixedLenField("ChallengeFromClient", b"12345678", length=8),
        LEIntField("Reserved3", 0),
        PacketListField("AvPairs", [AV_PAIR()], AV_PAIR),
    ]

    def getAv(self, AvId):
        try:
            return next(x for x in self.AvPairs if x.AvId == AvId)
        except StopIteration:
            raise IndexError


class NTLMv2_RESPONSE(NTLMv2_CLIENT_CHALLENGE):
    fields_desc = [
        XStrFixedLenField("NTProofStr", b"", length=16),
        NTLMv2_CLIENT_CHALLENGE,
    ]

    def computeNTProofStr(self, ResponseKeyNT, ServerChallenge):
        """
        Set temp to ConcatenationOf(Responserversion, HiResponserversion,
            Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
        Set NTProofStr to HMAC_MD5(ResponseKeyNT,
            ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))

        Remember ServerName = AvPairs
        """
        Responserversion = b"\x01"
        HiResponserversion = b"\x01"

        ServerName = b"".join(bytes(x) for x in self.AvPairs)
        temp = b"".join(
            [
                Responserversion,
                HiResponserversion,
                b"\x00" * 6,
                struct.pack("<Q", self.TimeStamp),
                self.ChallengeFromClient,
                b"\x00" * 4,
                ServerName,
                # Final Z(4) is the EOL AvPair
            ]
        )
        return HMAC_MD5(ResponseKeyNT, ServerChallenge + temp)


class NTLM_AUTHENTICATE(_NTLMPayloadPacket):
    name = "NTLM Authenticate"
    MessageType = 3
    NTLM_VERSION = 1
    OFFSET = lambda pkt: (
        ((pkt.DomainNameBufferOffset or 88) <= 64)
        and 64
        or (((pkt.DomainNameBufferOffset or 88) > 72) and 88 or 72)
    )
    fields_desc = (
        [
            NTLM_Header,
            # LmChallengeResponseFields
            LEShortField("LmChallengeResponseLen", None),
            LEShortField("LmChallengeResponseMaxLen", None),
            LEIntField("LmChallengeResponseBufferOffset", None),
            # NtChallengeResponseFields
            LEShortField("NtChallengeResponseLen", None),
            LEShortField("NtChallengeResponseMaxLen", None),
            LEIntField("NtChallengeResponseBufferOffset", None),
            # DomainNameFields
            LEShortField("DomainNameLen", None),
            LEShortField("DomainNameMaxLen", None),
            LEIntField("DomainNameBufferOffset", None),
            # UserNameFields
            LEShortField("UserNameLen", None),
            LEShortField("UserNameMaxLen", None),
            LEIntField("UserNameBufferOffset", None),
            # WorkstationFields
            LEShortField("WorkstationLen", None),
            LEShortField("WorkstationMaxLen", None),
            LEIntField("WorkstationBufferOffset", None),
            # EncryptedRandomSessionKeyFields
            LEShortField("EncryptedRandomSessionKeyLen", None),
            LEShortField("EncryptedRandomSessionKeyMaxLen", None),
            LEIntField("EncryptedRandomSessionKeyBufferOffset", None),
            # NegotiateFlags
            FlagsField("NegotiateFlags", 0, -32, _negotiateFlags),
            # VERSION
        ]
        + [
            ConditionalField(
                # (not present on some old Windows versions. We use a heuristic)
                x,
                lambda pkt: ((pkt.DomainNameBufferOffset or 88) > 64)
                or pkt.fields.get(x.name, b""),
            )
            for x in _NTLM_Version.fields_desc
        ]
        + [
            # MIC
            ConditionalField(
                # (not present on some old Windows versions. We use a heuristic)
                XStrFixedLenField("MIC", b"", length=16),
                lambda pkt: ((pkt.DomainNameBufferOffset or 88) > 72)
                or pkt.fields.get("MIC", b""),
            ),
            # Payload
            _NTLMPayloadField(
                "Payload",
                OFFSET,
                [
                    MultipleTypeField(
                        [
                            (
                                PacketField(
                                    "LmChallengeResponse",
                                    LMv2_RESPONSE(),
                                    LMv2_RESPONSE,
                                ),
                                lambda pkt: pkt.NTLM_VERSION == 2,
                            )
                        ],
                        PacketField("LmChallengeResponse", LM_RESPONSE(), LM_RESPONSE),
                    ),
                    MultipleTypeField(
                        [
                            (
                                PacketField(
                                    "NtChallengeResponse",
                                    NTLMv2_RESPONSE(),
                                    NTLMv2_RESPONSE,
                                ),
                                lambda pkt: pkt.NTLM_VERSION == 2,
                            )
                        ],
                        PacketField(
                            "NtChallengeResponse", NTLM_RESPONSE(), NTLM_RESPONSE
                        ),
                    ),
                    _NTLMStrField("DomainName", b""),
                    _NTLMStrField("UserName", b""),
                    _NTLMStrField("Workstation", b""),
                    XStrField("EncryptedRandomSessionKey", b""),
                ],
            ),
        ]
    )

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                self.OFFSET(),
                {
                    "LmChallengeResponse": 12,
                    "NtChallengeResponse": 20,
                    "DomainName": 28,
                    "UserName": 36,
                    "Workstation": 44,
                    "EncryptedRandomSessionKey": 52,
                },
            )
            + pay
        )

    def compute_mic(self, ExportedSessionKey, negotiate, challenge):
        self.MIC = b"\x00" * 16
        self.MIC = HMAC_MD5(
            ExportedSessionKey, bytes(negotiate) + bytes(challenge) + bytes(self)
        )


class NTLM_AUTHENTICATE_V2(NTLM_AUTHENTICATE):
    NTLM_VERSION = 2


def HTTP_ntlm_negotiate(ntlm_negotiate):
    """Create an HTTP NTLM negotiate packet from an NTLM_NEGOTIATE message"""
    assert isinstance(ntlm_negotiate, NTLM_NEGOTIATE)
    from scapy.layers.http import HTTP, HTTPRequest

    return HTTP() / HTTPRequest(
        Authorization=b"NTLM " + bytes_base64(bytes(ntlm_negotiate))
    )


# Experimental - Reversed stuff

# This is the GSSAPI NegoEX Exchange metadata blob. This is not documented
# but described as an "opaque blob": this was reversed and everything is a
# placeholder.


class NEGOEX_EXCHANGE_NTLM_ITEM(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_SEQUENCE(
                ASN1F_OID("oid", ""),
                ASN1F_PRINTABLE_STRING("token", ""),
                explicit_tag=0x31,
            ),
            explicit_tag=0x80,
        )
    )


class NEGOEX_EXCHANGE_NTLM(ASN1_Packet):
    """
    GSSAPI NegoEX Exchange metadata blob
    This was reversed and may be meaningless
    """

    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_SEQUENCE_OF("items", [], NEGOEX_EXCHANGE_NTLM_ITEM), implicit_tag=0xA0
        ),
    )


# Crypto - [MS-NLMP]


def HMAC_MD5(key, data):
    return Hmac_MD5(key=key).digest(data)


def MD4le(x):
    """
    MD4 over a string encoded as utf-16le
    """
    return Hash_MD4().digest(x.encode("utf-16le"))


def RC4Init(key):
    """Alleged RC4"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    try:
        # cryptography > 43.0
        from cryptography.hazmat.decrepit.ciphers import (
            algorithms as decrepit_algorithms,
        )
    except ImportError:
        decrepit_algorithms = algorithms

    algorithm = decrepit_algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    return encryptor


def RC4(handle, data):
    """The RC4 Encryption Algorithm"""
    return handle.update(data)


def RC4K(key, data):
    """Indicates the encryption of data item D with the key K using the
    RC4 algorithm.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    try:
        # cryptography > 43.0
        from cryptography.hazmat.decrepit.ciphers import (
            algorithms as decrepit_algorithms,
        )
    except ImportError:
        decrepit_algorithms = algorithms

    algorithm = decrepit_algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# sect 2.2.2.9 - With Extended Session Security


class NTLMSSP_MESSAGE_SIGNATURE(Packet):
    # [MS-RPCE] sect 2.2.2.9.1/2.2.2.9.2
    fields_desc = [
        LEIntField("Version", 0x00000001),
        XStrFixedLenField("Checksum", b"", length=8),
        LEIntField("SeqNum", 0x00000000),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_GSSAPI_OIDS["1.3.6.1.4.1.311.2.2.10"] = NTLM_Header
_GSSAPI_SIGNATURE_OIDS["1.3.6.1.4.1.311.2.2.10"] = NTLMSSP_MESSAGE_SIGNATURE


# sect 3.3.2


def NTOWFv2(Passwd, User, UserDom, HashNt=None):
    """
    Computes the ResponseKeyNT (per [MS-NLMP] sect 3.3.2)

    :param Passwd: the plain password
    :param User: the username
    :param UserDom: the domain name
    :param HashNt: (out of spec) if you have the HashNt, use this and set
                   Passwd to None
    """
    if HashNt is None:
        HashNt = MD4le(Passwd)
    return HMAC_MD5(HashNt, (User.upper() + UserDom).encode("utf-16le"))


def NTLMv2_ComputeSessionBaseKey(ResponseKeyNT, NTProofStr):
    return HMAC_MD5(ResponseKeyNT, NTProofStr)


# sect 3.4.4.2 - With Extended Session Security


def MAC(Handle, SigningKey, SeqNum, Message):
    chksum = HMAC_MD5(SigningKey, struct.pack("<i", SeqNum) + Message)[:8]
    if Handle:
        chksum = RC4(Handle, chksum)
    return NTLMSSP_MESSAGE_SIGNATURE(
        Version=0x00000001,
        Checksum=chksum,
        SeqNum=SeqNum,
    )


# sect 3.4.2


def SIGN(Handle, SigningKey, SeqNum, Message):
    # append? where is this used?!
    return Message + MAC(Handle, SigningKey, SeqNum, Message)


# sect 3.4.3


def SEAL(Handle, SigningKey, SeqNum, Message):
    """
    SEAL() according to [MS-NLMP]
    """
    # this is unused. Use GSS_WrapEx
    sealed_message = RC4(Handle, Message)
    signature = MAC(Handle, SigningKey, SeqNum, Message)
    return sealed_message, signature


def UNSEAL(Handle, SigningKey, SeqNum, Message):
    """
    UNSEAL() according to [MS-NLMP]
    """
    # this is unused. Use GSS_UnwrapEx
    unsealed_message = RC4(Handle, Message)
    signature = MAC(Handle, SigningKey, SeqNum, Message)
    return unsealed_message, signature


# sect 3.4.5.2


def SIGNKEY(NegFlg, ExportedSessionKey, Mode):
    if NegFlg.NEGOTIATE_EXTENDED_SESSIONSECURITY:
        if Mode == "Client":
            return Hash_MD5().digest(
                ExportedSessionKey
                + b"session key to client-to-server signing key magic constant\x00"
            )
        elif Mode == "Server":
            return Hash_MD5().digest(
                ExportedSessionKey
                + b"session key to server-to-client signing key magic constant\x00"
            )
        else:
            raise ValueError("Unknown Mode")
    else:
        return None


# sect 3.4.5.3


def SEALKEY(NegFlg, ExportedSessionKey, Mode):
    if NegFlg.NEGOTIATE_EXTENDED_SESSIONSECURITY:
        if NegFlg.NEGOTIATE_128:
            SealKey = ExportedSessionKey
        elif NegFlg.NEGOTIATE_56:
            SealKey = ExportedSessionKey[:7]
        else:
            SealKey = ExportedSessionKey[:5]
        if Mode == "Client":
            return Hash_MD5().digest(
                SealKey
                + b"session key to client-to-server sealing key magic constant\x00"
            )
        elif Mode == "Server":
            return Hash_MD5().digest(
                SealKey
                + b"session key to server-to-client sealing key magic constant\x00"
            )
        else:
            raise ValueError("Unknown Mode")
    elif NegFlg.NEGOTIATE_LM_KEY:
        if NegFlg.NEGOTIATE_56:
            return ExportedSessionKey[:6] + b"\xA0"
        else:
            return ExportedSessionKey[:4] + b"\xe5\x38\xb0"
    else:
        return ExportedSessionKey


# --- SSP


class NTLMSSP(SSP):
    """
    The NTLM SSP

    Common arguments:

        :param auth_level: One of DCE_C_AUTHN_LEVEL
        :param USE_MIC: whether to use a MIC or not (default: True)
        :param NTLM_VALUES: a dictionary used to override the following values

        In case of a client::

            - NegotiateFlags
            - ProductMajorVersion
            - ProductMinorVersion
            - ProductBuild

        In case of a server::

            - NetbiosDomainName
            - NetbiosComputerName
            - DnsComputerName
            - DnsDomainName (defaults to DOMAIN)
            - DnsTreeName (defaults to DOMAIN)
            - Flags
            - Timestamp

    Client-only arguments:

        :param UPN: the UPN to use for NTLM auth. If no domain is specified, will
                    use the one provided by the server (domain in a domain, local
                    if without domain)
        :param HASHNT: the password to use for NTLM auth
        :param PASSWORD: the password to use for NTLM auth

    Server-only arguments:

        :param DOMAIN_NB_NAME: the domain Netbios name (default: DOMAIN)
        :param DOMAIN_FQDN: the domain FQDN (default: <domain_nb_name>.local)
        :param COMPUTER_NB_NAME: the server Netbios name (default: SRV)
        :param COMPUTER_FQDN: the server FQDN
                              (default: <computer_nb_name>.<domain_fqdn>)
        :param IDENTITIES: a dict {"username": <HashNT>}
                        Setting this value enables signature computation and
                        authenticates inbound users.
    """

    oid = "1.3.6.1.4.1.311.2.2.10"
    auth_type = 0x0A

    class STATE(SSP.STATE):
        INIT = 1
        CLI_SENT_NEGO = 2
        CLI_SENT_AUTH = 3
        SRV_SENT_CHAL = 4

    class CONTEXT(SSP.CONTEXT):
        __slots__ = [
            "SessionKey",
            "ExportedSessionKey",
            "IsAcceptor",
            "SendSignKey",
            "SendSealKey",
            "RecvSignKey",
            "RecvSealKey",
            "SendSealHandle",
            "RecvSealHandle",
            "SendSeqNum",
            "RecvSeqNum",
            "neg_tok",
            "chall_tok",
            "ServerHostname",
        ]

        def __init__(self, IsAcceptor, req_flags=None):
            self.state = NTLMSSP.STATE.INIT
            self.SessionKey = None
            self.ExportedSessionKey = None
            self.SendSignKey = None
            self.SendSealKey = None
            self.SendSealHandle = None
            self.RecvSignKey = None
            self.RecvSealKey = None
            self.RecvSealHandle = None
            self.SendSeqNum = 0
            self.RecvSeqNum = 0
            self.neg_tok = None
            self.chall_tok = None
            self.ServerHostname = None
            self.IsAcceptor = IsAcceptor
            super(NTLMSSP.CONTEXT, self).__init__(req_flags=req_flags)

        def clifailure(self):
            self.__init__(self.IsAcceptor, req_flags=self.flags)

        def __repr__(self):
            return "NTLMSSP"

    def __init__(
        self,
        UPN=None,
        HASHNT=None,
        PASSWORD=None,
        USE_MIC=True,
        NTLM_VALUES={},
        DOMAIN_NB_NAME="DOMAIN",
        DOMAIN_FQDN=None,
        COMPUTER_NB_NAME="SRV",
        COMPUTER_FQDN=None,
        IDENTITIES=None,
        DO_NOT_CHECK_LOGIN=False,
        SERVER_CHALLENGE=None,
        **kwargs,
    ):
        self.UPN = UPN
        if HASHNT is None and PASSWORD is not None:
            HASHNT = MD4le(PASSWORD)
        self.HASHNT = HASHNT
        self.USE_MIC = USE_MIC
        self.NTLM_VALUES = NTLM_VALUES
        self.DOMAIN_NB_NAME = DOMAIN_NB_NAME
        self.DOMAIN_FQDN = DOMAIN_FQDN or (self.DOMAIN_NB_NAME.lower() + ".local")
        self.COMPUTER_NB_NAME = COMPUTER_NB_NAME
        self.COMPUTER_FQDN = COMPUTER_FQDN or (
            self.COMPUTER_NB_NAME.lower() + "." + self.DOMAIN_FQDN
        )
        self.IDENTITIES = IDENTITIES
        self.DO_NOT_CHECK_LOGIN = DO_NOT_CHECK_LOGIN
        self.SERVER_CHALLENGE = SERVER_CHALLENGE
        super(NTLMSSP, self).__init__(**kwargs)

    def LegsAmount(self, Context: CONTEXT):
        return 3

    def GSS_GetMICEx(self, Context, msgs, qop_req=0):
        """
        [MS-NLMP] sect 3.4.8
        """
        # Concatenate the ToSign
        ToSign = b"".join(x.data for x in msgs if x.sign)
        sig = MAC(
            Context.SendSealHandle,
            Context.SendSignKey,
            Context.SendSeqNum,
            ToSign,
        )
        Context.SendSeqNum += 1
        return sig

    def GSS_VerifyMICEx(self, Context, msgs, signature):
        """
        [MS-NLMP] sect 3.4.9
        """
        Context.RecvSeqNum = signature.SeqNum
        # Concatenate the ToSign
        ToSign = b"".join(x.data for x in msgs if x.sign)
        sig = MAC(
            Context.RecvSealHandle,
            Context.RecvSignKey,
            Context.RecvSeqNum,
            ToSign,
        )
        if sig.Checksum != signature.Checksum:
            raise ValueError("ERROR: Checksums don't match")

    def GSS_WrapEx(self, Context, msgs, qop_req=0):
        """
        [MS-NLMP] sect 3.4.6
        """
        msgs_cpy = copy.deepcopy(msgs)  # Keep copy for signature
        # Encrypt
        for msg in msgs:
            if msg.conf_req_flag:
                msg.data = RC4(Context.SendSealHandle, msg.data)
        # Sign
        sig = self.GSS_GetMICEx(Context, msgs_cpy, qop_req=qop_req)
        return (
            msgs,
            sig,
        )

    def GSS_UnwrapEx(self, Context, msgs, signature):
        """
        [MS-NLMP] sect 3.4.7
        """
        # Decrypt
        for msg in msgs:
            if msg.conf_req_flag:
                msg.data = RC4(Context.RecvSealHandle, msg.data)
        # Check signature
        self.GSS_VerifyMICEx(Context, msgs, signature)
        return msgs

    def canMechListMIC(self, Context):
        if not self.USE_MIC:
            # RFC 4178
            # "If the mechanism selected by the negotiation does not support integrity
            # protection, then no mechlistMIC token is used."
            return False
        if not Context or not Context.SessionKey:
            # Not available yet
            return False
        return True

    def getMechListMIC(self, Context, input):
        # [MS-SPNG]
        # "When NTLM is negotiated, the SPNG server MUST set OriginalHandle to
        # ServerHandle before generating the mechListMIC, then set ServerHandle to
        # OriginalHandle after generating the mechListMIC."
        OriginalHandle = Context.SendSealHandle
        Context.SendSealHandle = RC4Init(Context.SendSealKey)
        try:
            return super(NTLMSSP, self).getMechListMIC(Context, input)
        finally:
            Context.SendSealHandle = OriginalHandle

    def verifyMechListMIC(self, Context, otherMIC, input):
        # [MS-SPNG]
        # "the SPNEGO Extension server MUST set OriginalHandle to ClientHandle before
        # validating the mechListMIC and then set ClientHandle to OriginalHandle after
        # validating the mechListMIC."
        OriginalHandle = Context.RecvSealHandle
        Context.RecvSealHandle = RC4Init(Context.RecvSealKey)
        try:
            return super(NTLMSSP, self).verifyMechListMIC(Context, otherMIC, input)
        finally:
            Context.RecvSealHandle = OriginalHandle

    def GSS_Init_sec_context(
        self, Context: CONTEXT, val=None, req_flags: Optional[GSS_C_FLAGS] = None
    ):
        if Context is None:
            Context = self.CONTEXT(False, req_flags=req_flags)

        if Context.state == self.STATE.INIT:
            # Client: negotiate
            # Create a default token
            tok = NTLM_NEGOTIATE(
                NegotiateFlags="+".join(
                    [
                        "NEGOTIATE_UNICODE",
                        "REQUEST_TARGET",
                        "NEGOTIATE_NTLM",
                        "NEGOTIATE_ALWAYS_SIGN",
                        "TARGET_TYPE_DOMAIN",
                        "NEGOTIATE_EXTENDED_SESSIONSECURITY",
                        "NEGOTIATE_TARGET_INFO",
                        "NEGOTIATE_VERSION",
                        "NEGOTIATE_128",
                        "NEGOTIATE_56",
                    ]
                    + (
                        [
                            "NEGOTIATE_KEY_EXCH",
                        ]
                        if Context.flags
                        & (GSS_C_FLAGS.GSS_C_INTEG_FLAG | GSS_C_FLAGS.GSS_C_CONF_FLAG)
                        else []
                    )
                    + (
                        [
                            "NEGOTIATE_SIGN",
                        ]
                        if Context.flags & GSS_C_FLAGS.GSS_C_INTEG_FLAG
                        else []
                    )
                    + (
                        [
                            "NEGOTIATE_SEAL",
                        ]
                        if Context.flags & GSS_C_FLAGS.GSS_C_CONF_FLAG
                        else []
                    )
                ),
                ProductMajorVersion=10,
                ProductMinorVersion=0,
                ProductBuild=19041,
            )
            if self.NTLM_VALUES:
                # Update that token with the customs one
                for key in [
                    "NegotiateFlags",
                    "ProductMajorVersion",
                    "ProductMinorVersion",
                    "ProductBuild",
                ]:
                    if key in self.NTLM_VALUES:
                        setattr(tok, key, self.NTLM_VALUES[key])
            Context.neg_tok = tok
            Context.SessionKey = None  # Reset signing (if previous auth failed)
            Context.state = self.STATE.CLI_SENT_NEGO
            return Context, tok, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.CLI_SENT_NEGO:
            # Client: auth (val=challenge)
            chall_tok = val
            if self.UPN is None or self.HASHNT is None:
                raise ValueError(
                    "Must provide a 'UPN' and a 'HASHNT' or 'PASSWORD' when "
                    "running in standalone !"
                )
            if not chall_tok or NTLM_CHALLENGE not in chall_tok:
                log_runtime.debug("NTLMSSP: Unexpected token. Expected NTLM Challenge")
                return Context, None, GSS_S_DEFECTIVE_TOKEN
            # Take a default token
            tok = NTLM_AUTHENTICATE_V2(
                NegotiateFlags=chall_tok.NegotiateFlags,
                ProductMajorVersion=10,
                ProductMinorVersion=0,
                ProductBuild=19041,
            )
            tok.LmChallengeResponse = LMv2_RESPONSE()
            from scapy.layers.kerberos import _parse_upn

            try:
                tok.UserName, realm = _parse_upn(self.UPN)
            except ValueError:
                tok.UserName, realm = self.UPN, None
            if realm is None:
                try:
                    tok.DomainName = chall_tok.getAv(0x0002).Value
                except IndexError:
                    log_runtime.warning(
                        "No realm specified in UPN, nor provided by server"
                    )
                    tok.DomainName = self.DOMAIN_NB_NAME.encode()
            else:
                tok.DomainName = realm
            try:
                tok.Workstation = Context.ServerHostname = chall_tok.getAv(
                    0x0001
                ).Value  # noqa: E501
            except IndexError:
                tok.Workstation = "WIN"
            cr = tok.NtChallengeResponse = NTLMv2_RESPONSE(
                ChallengeFromClient=os.urandom(8),
            )
            try:
                # the server SHOULD set the timestamp in the CHALLENGE_MESSAGE
                cr.TimeStamp = chall_tok.getAv(0x0007).Value
            except IndexError:
                cr.TimeStamp = int((time.time() + 11644473600) * 1e7)
            cr.AvPairs = (
                chall_tok.TargetInfo[:-1]
                + (
                    [
                        AV_PAIR(AvId="MsvAvFlags", Value="MIC integrity"),
                    ]
                    if self.USE_MIC
                    else []
                )
                + [
                    AV_PAIR(
                        AvId="MsvAvSingleHost",
                        Value=Single_Host_Data(MachineID=os.urandom(32)),
                    ),
                    AV_PAIR(AvId="MsvAvChannelBindings", Value=b"\x00" * 16),
                    AV_PAIR(AvId="MsvAvTargetName", Value="host/" + tok.Workstation),
                    AV_PAIR(AvId="MsvAvEOL"),
                ]
            )
            if self.NTLM_VALUES:
                # Update that token with the customs one
                for key in [
                    "NegotiateFlags",
                    "ProductMajorVersion",
                    "ProductMinorVersion",
                    "ProductBuild",
                ]:
                    if key in self.NTLM_VALUES:
                        setattr(tok, key, self.NTLM_VALUES[key])
            # Compute the ResponseKeyNT
            ResponseKeyNT = NTOWFv2(
                None,
                tok.UserName,
                tok.DomainName,
                HashNt=self.HASHNT,
            )
            # Compute the NTProofStr
            cr.NTProofStr = cr.computeNTProofStr(
                ResponseKeyNT,
                chall_tok.ServerChallenge,
            )
            # Compute the Session Key
            SessionBaseKey = NTLMv2_ComputeSessionBaseKey(ResponseKeyNT, cr.NTProofStr)
            KeyExchangeKey = SessionBaseKey  # Only true for NTLMv2
            if chall_tok.NegotiateFlags.NEGOTIATE_KEY_EXCH:
                ExportedSessionKey = os.urandom(16)
                tok.EncryptedRandomSessionKey = RC4K(
                    KeyExchangeKey,
                    ExportedSessionKey,
                )
            else:
                ExportedSessionKey = KeyExchangeKey
            if self.USE_MIC:
                tok.compute_mic(ExportedSessionKey, Context.neg_tok, chall_tok)
            Context.ExportedSessionKey = ExportedSessionKey
            # [MS-SMB] 3.2.5.3
            Context.SessionKey = Context.ExportedSessionKey
            # Compute NTLM keys
            Context.SendSignKey = SIGNKEY(
                tok.NegotiateFlags, ExportedSessionKey, "Client"
            )
            Context.SendSealKey = SEALKEY(
                tok.NegotiateFlags, ExportedSessionKey, "Client"
            )
            Context.SendSealHandle = RC4Init(Context.SendSealKey)
            Context.RecvSignKey = SIGNKEY(
                tok.NegotiateFlags, ExportedSessionKey, "Server"
            )
            Context.RecvSealKey = SEALKEY(
                tok.NegotiateFlags, ExportedSessionKey, "Server"
            )
            Context.RecvSealHandle = RC4Init(Context.RecvSealKey)
            Context.state = self.STATE.CLI_SENT_AUTH
            return Context, tok, GSS_S_COMPLETE
        elif Context.state == self.STATE.CLI_SENT_AUTH:
            if val:
                # what is that?
                status = GSS_S_DEFECTIVE_CREDENTIAL
            else:
                status = GSS_S_COMPLETE
            return Context, None, status
        else:
            raise ValueError("NTLMSSP: unexpected state %s" % repr(Context.state))

    def GSS_Accept_sec_context(self, Context: CONTEXT, val=None):
        if Context is None:
            Context = self.CONTEXT(IsAcceptor=True, req_flags=0)

        if Context.state == self.STATE.INIT:
            # Server: challenge (val=negotiate)
            nego_tok = val
            if not nego_tok or NTLM_NEGOTIATE not in nego_tok:
                log_runtime.debug("NTLMSSP: Unexpected token. Expected NTLM Negotiate")
                return Context, None, GSS_S_DEFECTIVE_TOKEN
            # Take a default token
            currentTime = (time.time() + 11644473600) * 1e7
            tok = NTLM_CHALLENGE(
                ServerChallenge=self.SERVER_CHALLENGE or os.urandom(8),
                NegotiateFlags="+".join(
                    [
                        "NEGOTIATE_UNICODE",
                        "REQUEST_TARGET",
                        "NEGOTIATE_NTLM",
                        "NEGOTIATE_ALWAYS_SIGN",
                        "NEGOTIATE_EXTENDED_SESSIONSECURITY",
                        "NEGOTIATE_TARGET_INFO",
                        "TARGET_TYPE_DOMAIN",
                        "NEGOTIATE_VERSION",
                        "NEGOTIATE_128",
                        "NEGOTIATE_KEY_EXCH",
                        "NEGOTIATE_56",
                    ]
                    + (
                        ["NEGOTIATE_SIGN"]
                        if nego_tok.NegotiateFlags.NEGOTIATE_SIGN
                        else []
                    )
                    + (
                        ["NEGOTIATE_SEAL"]
                        if nego_tok.NegotiateFlags.NEGOTIATE_SEAL
                        else []
                    )
                ),
                ProductMajorVersion=10,
                ProductMinorVersion=0,
                Payload=[
                    ("TargetName", ""),
                    (
                        "TargetInfo",
                        [
                            # MsvAvNbComputerName
                            AV_PAIR(AvId=1, Value=self.COMPUTER_NB_NAME),
                            # MsvAvNbDomainName
                            AV_PAIR(AvId=2, Value=self.DOMAIN_NB_NAME),
                            # MsvAvDnsComputerName
                            AV_PAIR(AvId=3, Value=self.COMPUTER_FQDN),
                            # MsvAvDnsDomainName
                            AV_PAIR(AvId=4, Value=self.DOMAIN_FQDN),
                            # MsvAvDnsTreeName
                            AV_PAIR(AvId=5, Value=self.DOMAIN_FQDN),
                            # MsvAvTimestamp
                            AV_PAIR(AvId=7, Value=currentTime),
                            # MsvAvEOL
                            AV_PAIR(AvId=0),
                        ],
                    ),
                ],
            )
            if self.NTLM_VALUES:
                # Update that token with the customs one
                for key in [
                    "ServerChallenge",
                    "NegotiateFlags",
                    "ProductMajorVersion",
                    "ProductMinorVersion",
                    "TargetName",
                ]:
                    if key in self.NTLM_VALUES:
                        setattr(tok, key, self.NTLM_VALUES[key])
                avpairs = {x.AvId: x.Value for x in tok.TargetInfo}
                tok.TargetInfo = [
                    AV_PAIR(AvId=i, Value=self.NTLM_VALUES.get(x, avpairs[i]))
                    for (i, x) in [
                        (2, "NetbiosDomainName"),
                        (1, "NetbiosComputerName"),
                        (4, "DnsDomainName"),
                        (3, "DnsComputerName"),
                        (5, "DnsTreeName"),
                        (6, "Flags"),
                        (7, "Timestamp"),
                        (0, None),
                    ]
                    if ((x in self.NTLM_VALUES) or (i in avpairs))
                    and self.NTLM_VALUES.get(x, True) is not None
                ]
            Context.chall_tok = tok
            Context.state = self.STATE.SRV_SENT_CHAL
            return Context, tok, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.SRV_SENT_CHAL:
            # server: OK or challenge again (val=auth)
            auth_tok = val
            if not auth_tok or NTLM_AUTHENTICATE_V2 not in auth_tok:
                log_runtime.debug(
                    "NTLMSSP: Unexpected token. Expected NTLM Authenticate v2"
                )
                return Context, None, GSS_S_DEFECTIVE_TOKEN
            if self.DO_NOT_CHECK_LOGIN:
                # Just trust me bro
                return Context, None, GSS_S_COMPLETE
            SessionBaseKey = self._getSessionBaseKey(Context, auth_tok)
            if SessionBaseKey:
                # [MS-NLMP] sect 3.2.5.1.2
                KeyExchangeKey = SessionBaseKey  # Only true for NTLMv2
                if auth_tok.NegotiateFlags.NEGOTIATE_KEY_EXCH:
                    if not auth_tok.EncryptedRandomSessionKeyLen:
                        # No EncryptedRandomSessionKey. libcurl for instance
                        # hmm. this looks bad
                        EncryptedRandomSessionKey = b"\x00" * 16
                    else:
                        EncryptedRandomSessionKey = auth_tok.EncryptedRandomSessionKey
                    ExportedSessionKey = RC4K(
                        KeyExchangeKey, EncryptedRandomSessionKey
                    )
                else:
                    ExportedSessionKey = KeyExchangeKey
                Context.ExportedSessionKey = ExportedSessionKey
                # [MS-SMB] 3.2.5.3
                Context.SessionKey = Context.ExportedSessionKey
            # Check the NTProofStr
            if Context.SessionKey:
                # Compute NTLM keys
                Context.SendSignKey = SIGNKEY(
                    auth_tok.NegotiateFlags, ExportedSessionKey, "Server"
                )
                Context.SendSealKey = SEALKEY(
                    auth_tok.NegotiateFlags, ExportedSessionKey, "Server"
                )
                Context.SendSealHandle = RC4Init(Context.SendSealKey)
                Context.RecvSignKey = SIGNKEY(
                    auth_tok.NegotiateFlags, ExportedSessionKey, "Client"
                )
                Context.RecvSealKey = SEALKEY(
                    auth_tok.NegotiateFlags, ExportedSessionKey, "Client"
                )
                Context.RecvSealHandle = RC4Init(Context.RecvSealKey)
                if self._checkLogin(Context, auth_tok):
                    # Set negotiated flags
                    if auth_tok.NegotiateFlags.NEGOTIATE_SIGN:
                        Context.flags |= GSS_C_FLAGS.GSS_C_INTEG_FLAG
                    if auth_tok.NegotiateFlags.NEGOTIATE_SEAL:
                        Context.flags |= GSS_C_FLAGS.GSS_C_CONF_FLAG
                    return Context, None, GSS_S_COMPLETE
            # Bad NTProofStr or unknown user
            Context.SessionKey = None
            Context.state = self.STATE.INIT
            return Context, None, GSS_S_DEFECTIVE_CREDENTIAL
        else:
            raise ValueError("NTLMSSP: unexpected state %s" % repr(Context.state))

    def MaximumSignatureLength(self, Context: CONTEXT):
        """
        Returns the Maximum Signature length.

        This will be used in auth_len in DceRpc5, and is necessary for
        PFC_SUPPORT_HEADER_SIGN to work properly.
        """
        return 16  # len(NTLMSSP_MESSAGE_SIGNATURE())

    def GSS_Passive(self, Context: CONTEXT, val=None):
        if Context is None:
            Context = self.CONTEXT(True)
            Context.passive = True

        # We capture the Negotiate, Challenge, then call the server's auth handling
        # and discard the output.

        if Context.state == self.STATE.INIT:
            if not val or NTLM_NEGOTIATE not in val:
                log_runtime.warning("NTLMSSP: Expected NTLM Negotiate")
                return None, GSS_S_DEFECTIVE_TOKEN
            Context.neg_tok = val
            Context.state = self.STATE.CLI_SENT_NEGO
            return Context, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.CLI_SENT_NEGO:
            if not val or NTLM_CHALLENGE not in val:
                log_runtime.warning("NTLMSSP: Expected NTLM Challenge")
                return None, GSS_S_DEFECTIVE_TOKEN
            Context.chall_tok = val
            Context.state = self.STATE.SRV_SENT_CHAL
            return Context, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.SRV_SENT_CHAL:
            if not val or NTLM_AUTHENTICATE_V2 not in val:
                log_runtime.warning("NTLMSSP: Expected NTLM Authenticate")
                return None, GSS_S_DEFECTIVE_TOKEN
            Context, _, status = self.GSS_Accept_sec_context(Context, val)
            if status != GSS_S_COMPLETE:
                log_runtime.info("NTLMSSP: auth failed.")
            Context.state = self.STATE.INIT
            return Context, status
        else:
            raise ValueError("NTLMSSP: unexpected state %s" % repr(Context.state))

    def GSS_Passive_set_Direction(self, Context: CONTEXT, IsAcceptor=False):
        if Context.IsAcceptor is not IsAcceptor:
            return
        # Swap everything
        Context.SendSignKey, Context.RecvSignKey = (
            Context.RecvSignKey,
            Context.SendSignKey,
        )
        Context.SendSealKey, Context.RecvSealKey = (
            Context.RecvSealKey,
            Context.SendSealKey,
        )
        Context.SendSealHandle, Context.RecvSealHandle = (
            Context.RecvSealHandle,
            Context.SendSealHandle,
        )
        Context.SendSeqNum, Context.RecvSeqNum = Context.RecvSeqNum, Context.SendSeqNum
        Context.IsAcceptor = not Context.IsAcceptor

    def _getSessionBaseKey(self, Context, auth_tok):
        """
        Function that returns the SessionBaseKey from the ntlm Authenticate.
        """
        if auth_tok.UserNameLen:
            username = auth_tok.UserName
        else:
            username = None
        if auth_tok.DomainNameLen:
            domain = auth_tok.DomainName
        else:
            domain = ""
        if self.IDENTITIES and username in self.IDENTITIES:
            ResponseKeyNT = NTOWFv2(
                None, username, domain, HashNt=self.IDENTITIES[username]
            )
            return NTLMv2_ComputeSessionBaseKey(
                ResponseKeyNT, auth_tok.NtChallengeResponse.NTProofStr
            )
        return None

    def _checkLogin(self, Context, auth_tok):
        """
        Function that checks the validity of an authentication.

        Overwrite and return True to bypass.
        """
        # Create the NTLM AUTH
        if auth_tok.UserNameLen:
            username = auth_tok.UserName
        else:
            username = None
        if auth_tok.DomainNameLen:
            domain = auth_tok.DomainName
        else:
            domain = ""
        if username in self.IDENTITIES:
            ResponseKeyNT = NTOWFv2(
                None, username, domain, HashNt=self.IDENTITIES[username]
            )
            NTProofStr = auth_tok.NtChallengeResponse.computeNTProofStr(
                ResponseKeyNT,
                Context.chall_tok.ServerChallenge,
            )
            if NTProofStr == auth_tok.NtChallengeResponse.NTProofStr:
                return True
        return False
