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
    _GSSAPI_OIDS,
    _GSSAPI_SIGNATURE_OIDS,
    GSS_C_FLAGS,
    GSS_C_NO_CHANNEL_BINDINGS,
    GSS_S_BAD_BINDINGS,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_DEFECTIVE_CREDENTIAL,
    GSS_S_DEFECTIVE_TOKEN,
    GSS_S_FLAGS,
    GssChannelBindings,
    SSP,
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


# NTLM structures are all in all very complicated. Many fields don't have a fixed
# position, but are rather referred to with an offset (from the beginning of the
# structure) and a length. In addition to that, there are variants of the structure
# with missing fields when running old versions of Windows (sometimes also seen when
# talking to products that reimplement NTLM, most notably backup applications).

# We add `_NTLMPayloadField` and `_NTLMPayloadPacket` to parse fields that use an
# offset, and `_NTLM_post_build` to be able to rebuild those offsets.
# In addition, the `NTLM_VARIANT*` allows to select what flavor of NTLM to use
# (NT, XP, or Recent). But in real world use only Recent should be used.


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


# -- Util: VARIANT class


class NTLM_VARIANT(IntEnum):
    """
    The message variant to use for NTLM.
    """

    NT_OR_2000 = 0
    XP_OR_2003 = 1
    RECENT = 2


class _NTLM_VARIANT_Packet(_NTLMPayloadPacket):
    def __init__(self, *args, **kwargs):
        self.VARIANT = kwargs.pop("VARIANT", NTLM_VARIANT.RECENT)
        super(_NTLM_VARIANT_Packet, self).__init__(*args, **kwargs)

    def clone_with(self, *args, **kwargs):
        pkt = super(_NTLM_VARIANT_Packet, self).clone_with(*args, **kwargs)
        pkt.VARIANT = self.VARIANT
        return pkt

    def copy(self):
        pkt = super(_NTLM_VARIANT_Packet, self).copy()
        pkt.VARIANT = self.VARIANT

        return pkt

    def show2(self, dump=False, indent=3, lvl="", label_lvl=""):
        return self.__class__(bytes(self), VARIANT=self.VARIANT).show(
            dump, indent, lvl, label_lvl
        )


# Sect 2.2


class NTLM_Header(Packet):
    name = "NTLM Header"
    fields_desc = [
        StrFixedLenField("Signature", b"NTLMSSP\0", length=8),
        LEIntEnumField(
            "MessageType",
            3,
            {
                1: "NEGOTIATE_MESSAGE",
                2: "CHALLENGE_MESSAGE",
                3: "AUTHENTICATE_MESSAGE",
            },
        ),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if cls is NTLM_Header and _pkt and len(_pkt) >= 10:
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


class NTLM_NEGOTIATE(_NTLM_VARIANT_Packet, NTLM_Header):
    name = "NTLM Negotiate"
    __slots__ = ["VARIANT"]
    MessageType = 1
    OFFSET = lambda pkt: (
        32
        if (
            pkt.VARIANT == NTLM_VARIANT.NT_OR_2000
            or (pkt.DomainNameBufferOffset or 40) <= 32
        )
        else 40
    )
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
                lambda pkt: pkt.VARIANT >= NTLM_VARIANT.XP_OR_2003
                and (
                    (
                        (
                            40
                            if pkt.DomainNameBufferOffset is None
                            else pkt.DomainNameBufferOffset or len(pkt.original or b"")
                        )
                        > 32
                    )
                    or pkt.fields.get(x.name, b"")
                ),
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
        LEIntField("Size", None),
        LEIntField("Z4", 0),
        # "CustomData" guessed using LSAP_TOKEN_INFO_INTEGRITY.
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
        # KB 5068222 - still waiting for [MS-KILE] update (oct. 2025)
        ConditionalField(
            XStrFixedLenField("PermanentMachineID", None, length=32),
            lambda pkt: pkt.Size is None or pkt.Size > 48,
        ),
    ]

    def post_build(self, pkt, pay):
        if self.Size is None:
            pkt = struct.pack("<I", len(pkt)) + pkt[4:]
        return pkt + pay

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


class NTLM_CHALLENGE(_NTLM_VARIANT_Packet, NTLM_Header):
    name = "NTLM Challenge"
    __slots__ = ["VARIANT"]
    MessageType = 2
    OFFSET = lambda pkt: (
        48
        if (
            pkt.VARIANT == NTLM_VARIANT.NT_OR_2000
            or (pkt.TargetInfoBufferOffset or 56) <= 48
        )
        else 56
    )
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
                lambda pkt: pkt.VARIANT >= NTLM_VARIANT.XP_OR_2003
                and (
                    ((pkt.TargetInfoBufferOffset or 56) > 40)
                    or pkt.fields.get(x.name, b"")
                ),
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


class NTLM_AUTHENTICATE(_NTLM_VARIANT_Packet, NTLM_Header):
    name = "NTLM Authenticate"
    __slots__ = ["VARIANT"]
    MessageType = 3
    NTLM_VERSION = 1
    OFFSET = lambda pkt: (
        64
        if (
            pkt.VARIANT == NTLM_VARIANT.NT_OR_2000
            or (pkt.DomainNameBufferOffset or 88) <= 64
        )
        else (
            72
            if pkt.VARIANT == NTLM_VARIANT.XP_OR_2003
            or ((pkt.DomainNameBufferOffset or 88) <= 72)
            else 88
        )
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
                lambda pkt: pkt.VARIANT >= NTLM_VARIANT.XP_OR_2003
                and (
                    ((pkt.DomainNameBufferOffset or 88) > 64)
                    or pkt.fields.get(x.name, b"")
                ),
            )
            for x in _NTLM_Version.fields_desc
        ]
        + [
            # MIC
            ConditionalField(
                # (not present on some old Windows versions. We use a heuristic)
                XStrFixedLenField("MIC", b"", length=16),
                lambda pkt: pkt.VARIANT >= NTLM_VARIANT.RECENT
                and (
                    ((pkt.DomainNameBufferOffset or 88) > 72)
                    or pkt.fields.get("MIC", b"")
                ),
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
            return ExportedSessionKey[:6] + b"\xa0"
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

        :param DOMAIN_FQDN: the domain FQDN (default: domain.local)
        :param DOMAIN_NB_NAME: the domain Netbios name (default: strip DOMAIN_FQDN)
        :param COMPUTER_NB_NAME: the server Netbios name (default: SRV)
        :param COMPUTER_FQDN: the server FQDN
                              (default: <computer_nb_name>.<domain_fqdn>)
        :param IDENTITIES: a dict {"username": <HashNT>}
                        Setting this value enables signature computation and
                        authenticates inbound users.
    """

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
            "ServerDomain",
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
            self.ServerDomain = None
            self.IsAcceptor = IsAcceptor
            super(NTLMSSP.CONTEXT, self).__init__(req_flags=req_flags)

        def clifailure(self):
            self.__init__(self.IsAcceptor, req_flags=self.flags)

        def __repr__(self):
            return "NTLMSSP"

    # [MS-NLMP] note <36>: "the maximum lifetime is 36 hours" (lol, Kerberos has 5min)
    NTLM_MaxLifetime = 36 * 3600

    def __init__(
        self,
        UPN=None,
        HASHNT=None,
        PASSWORD=None,
        USE_MIC=True,
        VARIANT: NTLM_VARIANT = NTLM_VARIANT.RECENT,
        NTLM_VALUES={},
        DOMAIN_FQDN=None,
        DOMAIN_NB_NAME=None,
        COMPUTER_NB_NAME=None,
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
        self.VARIANT = VARIANT
        if self.VARIANT != NTLM_VARIANT.RECENT:
            log_runtime.warning(
                "VARIANT != NTLM_VARIANT.RECENT. You shouldn't touch this !"
            )
            self.USE_MIC = False
        else:
            self.USE_MIC = USE_MIC
        self.NTLM_VALUES = NTLM_VALUES
        if UPN is not None:
            # Populate values used only in server mode.
            from scapy.layers.kerberos import _parse_upn

            try:
                user, realm = _parse_upn(UPN)
                if DOMAIN_FQDN is None:
                    DOMAIN_FQDN = realm
                if COMPUTER_NB_NAME is None:
                    COMPUTER_NB_NAME = user
            except ValueError:
                pass

        # Compute various netbios/fqdn names
        self.DOMAIN_FQDN = DOMAIN_FQDN or "domain.local"
        self.DOMAIN_NB_NAME = (
            DOMAIN_NB_NAME or self.DOMAIN_FQDN.split(".")[0].upper()[:15]
        )
        self.COMPUTER_NB_NAME = COMPUTER_NB_NAME or "WIN10"
        self.COMPUTER_FQDN = COMPUTER_FQDN or (
            self.COMPUTER_NB_NAME.lower() + "." + self.DOMAIN_FQDN
        )

        self.IDENTITIES = IDENTITIES
        self.DO_NOT_CHECK_LOGIN = DO_NOT_CHECK_LOGIN
        self.SERVER_CHALLENGE = SERVER_CHALLENGE
        super(NTLMSSP, self).__init__(**kwargs)

    def LegsAmount(self, Context: CONTEXT):
        return 3

    def GSS_Inquire_names_for_mech(self):
        return ["1.3.6.1.4.1.311.2.2.10"]

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

    def SupportsMechListMIC(self):
        if not self.USE_MIC:
            # RFC 4178
            # "If the mechanism selected by the negotiation does not support integrity
            # protection, then no mechlistMIC token is used."
            return False
        if self.DO_NOT_CHECK_LOGIN:
            # In this mode, we won't negotiate any credentials.
            return False
        return True

    def GetMechListMIC(self, Context, input):
        # [MS-SPNG]
        # "When NTLM is negotiated, the SPNG server MUST set OriginalHandle to
        # ServerHandle before generating the mechListMIC, then set ServerHandle to
        # OriginalHandle after generating the mechListMIC."
        OriginalHandle = Context.SendSealHandle
        Context.SendSealHandle = RC4Init(Context.SendSealKey)
        try:
            return super(NTLMSSP, self).GetMechListMIC(Context, input)
        finally:
            Context.SendSealHandle = OriginalHandle

    def VerifyMechListMIC(self, Context, otherMIC, input):
        # [MS-SPNG]
        # "the SPNEGO Extension server MUST set OriginalHandle to ClientHandle before
        # validating the mechListMIC and then set ClientHandle to OriginalHandle after
        # validating the mechListMIC."
        OriginalHandle = Context.RecvSealHandle
        Context.RecvSealHandle = RC4Init(Context.RecvSealKey)
        try:
            return super(NTLMSSP, self).VerifyMechListMIC(Context, otherMIC, input)
        finally:
            Context.RecvSealHandle = OriginalHandle

    def GSS_Init_sec_context(
        self,
        Context: CONTEXT,
        input_token=None,
        target_name: Optional[str] = None,
        req_flags: Optional[GSS_C_FLAGS] = None,
        chan_bindings: GssChannelBindings = GSS_C_NO_CHANNEL_BINDINGS,
    ):
        if Context is None:
            Context = self.CONTEXT(False, req_flags=req_flags)

        if Context.state == self.STATE.INIT:
            # Client: negotiate
            # Create a default token
            tok = NTLM_NEGOTIATE(
                VARIANT=self.VARIANT,
                NegotiateFlags="+".join(
                    [
                        "NEGOTIATE_UNICODE",
                        "REQUEST_TARGET",
                        "NEGOTIATE_NTLM",
                        "NEGOTIATE_ALWAYS_SIGN",
                        "TARGET_TYPE_DOMAIN",
                        "NEGOTIATE_EXTENDED_SESSIONSECURITY",
                        "NEGOTIATE_TARGET_INFO",
                        "NEGOTIATE_128",
                        "NEGOTIATE_56",
                    ]
                    + (
                        ["NEGOTIATE_VERSION"]
                        if self.VARIANT >= NTLM_VARIANT.XP_OR_2003
                        else []
                    )
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
            # Client: auth (token=challenge)
            chall_tok = input_token
            if self.UPN is None or self.HASHNT is None:
                raise ValueError(
                    "Must provide a 'UPN' and a 'HASHNT' or 'PASSWORD' when "
                    "running in standalone !"
                )

            from scapy.layers.kerberos import _parse_upn

            # Check token sanity
            if not chall_tok or NTLM_CHALLENGE not in chall_tok:
                log_runtime.debug("NTLMSSP: Unexpected token. Expected NTLM Challenge")
                return Context, None, GSS_S_DEFECTIVE_TOKEN

            # Some information from the CHALLENGE are stored
            try:
                Context.ServerHostname = chall_tok.getAv(0x0001).Value
            except IndexError:
                pass
            try:
                Context.ServerDomain = chall_tok.getAv(0x0002).Value
            except IndexError:
                pass
            try:
                # the server SHOULD set the timestamp in the CHALLENGE_MESSAGE
                ServerTimestamp = chall_tok.getAv(0x0007).Value
                ServerTime = (ServerTimestamp / 1e7) - 11644473600

                if abs(ServerTime - time.time()) >= NTLMSSP.NTLM_MaxLifetime:
                    log_runtime.warning(
                        "Server and Client times are off by more than 36h !"
                    )
                    # We could error here, but we don't.
            except IndexError:
                pass

            # Initialize a default token
            tok = NTLM_AUTHENTICATE_V2(
                VARIANT=self.VARIANT,
                NegotiateFlags=chall_tok.NegotiateFlags,
                ProductMajorVersion=10,
                ProductMinorVersion=0,
                ProductBuild=19041,
            )
            tok.LmChallengeResponse = LMv2_RESPONSE()

            # Populate the token
            # 1. Set username
            try:
                tok.UserName, realm = _parse_upn(self.UPN)
            except ValueError:
                tok.UserName, realm = self.UPN, Context.ServerDomain

            # 2. Set domain name
            if realm is None:
                log_runtime.warning(
                    "No realm specified in UPN, nor provided by server."
                )
                tok.DomainName = self.DOMAIN_FQDN
            else:
                tok.DomainName = realm

            # 3. Set workstation name
            tok.Workstation = self.COMPUTER_NB_NAME

            # 4. Create and calculate the ChallengeResponse
            # 4.1 Build the payload
            cr = tok.NtChallengeResponse = NTLMv2_RESPONSE(
                ChallengeFromClient=os.urandom(8),
            )
            cr.TimeStamp = int((time.time() + 11644473600) * 1e7)
            cr.AvPairs = (
                # Repeat AvPairs from the server
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
                ]
                + (
                    [
                        AV_PAIR(
                            # [MS-NLMP] sect 2.2.2.1 refers to RFC 4121 sect 4.1.1.2
                            # "The Bnd field contains the MD5 hash of channel bindings"
                            AvId="MsvAvChannelBindings",
                            Value=chan_bindings.digestMD5(),
                        ),
                    ]
                    if chan_bindings != GSS_C_NO_CHANNEL_BINDINGS
                    else []
                )
                + [
                    AV_PAIR(
                        AvId="MsvAvTargetName",
                        Value=target_name or ("host/" + Context.ServerHostname),
                    ),
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

            # 4.2 Compute the ResponseKeyNT
            ResponseKeyNT = NTOWFv2(
                None,
                tok.UserName,
                tok.DomainName,
                HashNt=self.HASHNT,
            )

            # 4.3 Compute the NTProofStr
            cr.NTProofStr = cr.computeNTProofStr(
                ResponseKeyNT,
                chall_tok.ServerChallenge,
            )

            # 4.4 Compute the Session Key
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

            # 4.5 Compute the MIC
            if self.USE_MIC:
                tok.compute_mic(ExportedSessionKey, Context.neg_tok, chall_tok)

            # 5. Perform key computations
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

            # Update the state
            Context.state = self.STATE.CLI_SENT_AUTH

            return Context, tok, GSS_S_COMPLETE
        elif Context.state == self.STATE.CLI_SENT_AUTH:
            if input_token:
                # what is that?
                status = GSS_S_DEFECTIVE_TOKEN
            else:
                status = GSS_S_COMPLETE
            return Context, None, status
        else:
            raise ValueError("NTLMSSP: unexpected state %s" % repr(Context.state))

    def GSS_Accept_sec_context(
        self,
        Context: CONTEXT,
        input_token=None,
        req_flags: Optional[GSS_S_FLAGS] = GSS_S_FLAGS.GSS_S_ALLOW_MISSING_BINDINGS,
        chan_bindings: GssChannelBindings = GSS_C_NO_CHANNEL_BINDINGS,
    ):
        if Context is None:
            Context = self.CONTEXT(IsAcceptor=True, req_flags=req_flags)

        if Context.state == self.STATE.INIT:
            # Server: challenge (input_token=negotiate)
            nego_tok = input_token
            if not nego_tok or NTLM_NEGOTIATE not in nego_tok:
                log_runtime.debug("NTLMSSP: Unexpected token. Expected NTLM Negotiate")
                return Context, None, GSS_S_DEFECTIVE_TOKEN

            # Build the challenge token
            currentTime = (time.time() + 11644473600) * 1e7
            tok = NTLM_CHALLENGE(
                VARIANT=self.VARIANT,
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
                        "NEGOTIATE_128",
                        "NEGOTIATE_KEY_EXCH",
                        "NEGOTIATE_56",
                    ]
                    + (
                        ["NEGOTIATE_VERSION"]
                        if self.VARIANT >= NTLM_VARIANT.XP_OR_2003
                        else []
                    )
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

            # Store for next step
            Context.chall_tok = tok

            # Update the state
            Context.state = self.STATE.SRV_SENT_CHAL

            return Context, tok, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.SRV_SENT_CHAL:
            # server: OK or challenge again (input_token=auth)
            auth_tok = input_token

            if not auth_tok or NTLM_AUTHENTICATE_V2 not in auth_tok:
                log_runtime.debug(
                    "NTLMSSP: Unexpected token. Expected NTLM Authenticate v2"
                )
                return Context, None, GSS_S_DEFECTIVE_TOKEN

            if self.DO_NOT_CHECK_LOGIN:
                # Just trust me bro. Typically used in "guest" mode.
                return Context, None, GSS_S_COMPLETE

            # Compute the session key
            SessionBaseKey = self._getSessionBaseKey(Context, auth_tok)
            if SessionBaseKey:
                # [MS-NLMP] sect 3.2.5.1.2
                KeyExchangeKey = SessionBaseKey  # Only true for NTLMv2
                if auth_tok.NegotiateFlags.NEGOTIATE_KEY_EXCH:
                    try:
                        EncryptedRandomSessionKey = auth_tok.EncryptedRandomSessionKey
                    except AttributeError:
                        # No EncryptedRandomSessionKey. libcurl for instance
                        # hmm. this looks bad
                        EncryptedRandomSessionKey = b"\x00" * 16
                    ExportedSessionKey = RC4K(KeyExchangeKey, EncryptedRandomSessionKey)
                else:
                    ExportedSessionKey = KeyExchangeKey
                Context.ExportedSessionKey = ExportedSessionKey
                # [MS-SMB] 3.2.5.3
                Context.SessionKey = Context.ExportedSessionKey

            # Check the timestamp
            try:
                ClientTimestamp = auth_tok.NtChallengeResponse.getAv(0x0007).Value
                ClientTime = (ClientTimestamp / 1e7) - 11644473600

                if abs(ClientTime - time.time()) >= NTLMSSP.NTLM_MaxLifetime:
                    log_runtime.warning(
                        "Server and Client times are off by more than 36h !"
                    )
                    # We could error here, but we don't.
            except IndexError:
                pass

            # Check the channel bindings
            if chan_bindings != GSS_C_NO_CHANNEL_BINDINGS:
                try:
                    Bnd = auth_tok.NtChallengeResponse.getAv(0x000A).Value
                    if Bnd != chan_bindings.digestMD5():
                        # Bad channel bindings
                        return Context, None, GSS_S_BAD_BINDINGS
                except IndexError:
                    if GSS_S_FLAGS.GSS_S_ALLOW_MISSING_BINDINGS not in req_flags:
                        # Uhoh, we required channel bindings
                        return Context, None, GSS_S_BAD_BINDINGS

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

                # Check the NTProofStr
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

    def GSS_Passive(self, Context: CONTEXT, token=None, req_flags=None):
        if Context is None:
            Context = self.CONTEXT(True)
            Context.passive = True

        # We capture the Negotiate, Challenge, then call the server's auth handling
        # and discard the output.

        if Context.state == self.STATE.INIT:
            if not token or NTLM_NEGOTIATE not in token:
                log_runtime.warning("NTLMSSP: Expected NTLM Negotiate")
                return None, GSS_S_DEFECTIVE_TOKEN
            Context.neg_tok = token
            Context.state = self.STATE.CLI_SENT_NEGO
            return Context, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.CLI_SENT_NEGO:
            if not token or NTLM_CHALLENGE not in token:
                log_runtime.warning("NTLMSSP: Expected NTLM Challenge")
                return None, GSS_S_DEFECTIVE_TOKEN
            Context.chall_tok = token
            Context.state = self.STATE.SRV_SENT_CHAL
            return Context, GSS_S_CONTINUE_NEEDED
        elif Context.state == self.STATE.SRV_SENT_CHAL:
            if not token or NTLM_AUTHENTICATE_V2 not in token:
                log_runtime.warning("NTLMSSP: Expected NTLM Authenticate")
                return None, GSS_S_DEFECTIVE_TOKEN
            Context, _, status = self.GSS_Accept_sec_context(Context, token)
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
        try:
            username = auth_tok.UserName
        except AttributeError:
            username = None
        try:
            domain = auth_tok.DomainName
        except AttributeError:
            domain = ""
        if self.IDENTITIES and username in self.IDENTITIES:
            ResponseKeyNT = NTOWFv2(
                None,
                username,
                domain,
                HashNt=self.IDENTITIES[username],
            )
            return NTLMv2_ComputeSessionBaseKey(
                ResponseKeyNT,
                auth_tok.NtChallengeResponse.NTProofStr,
            )
        elif self.IDENTITIES:
            log_runtime.debug("NTLMSSP: Bad credentials for %s" % username)
        return None

    def _checkLogin(self, Context, auth_tok):
        """
        Function that checks the validity of an authentication.

        Overwrite and return True to bypass.
        """
        # Create the NTLM AUTH
        try:
            username = auth_tok.UserName
        except AttributeError:
            username = None
        try:
            domain = auth_tok.DomainName
        except AttributeError:
            domain = ""
        if username in self.IDENTITIES:
            ResponseKeyNT = NTOWFv2(
                None,
                username,
                domain,
                HashNt=self.IDENTITIES[username],
            )
            NTProofStr = auth_tok.NtChallengeResponse.computeNTProofStr(
                ResponseKeyNT,
                Context.chall_tok.ServerChallenge,
            )
            if NTProofStr == auth_tok.NtChallengeResponse.NTProofStr:
                return True
        return False


class NTLMSSP_DOMAIN(NTLMSSP):
    """
    A variant of the NTLMSSP to be used in server mode that gets the session
    keys from the domain using a Netlogon channel.

    This has the same arguments as NTLMSSP, but supports the following in server
    mode:

    :param UPN: the UPN of the machine account to login for Netlogon.
    :param HASHNT: the HASHNT of the machine account (use Netlogon secure channel).
    :param ssp: a KerberosSSP to use (use Kerberos secure channel).
    :param PASSWORD: the PASSWORD of the machine account to use for Netlogon.
    :param DC_IP: (optional) specify the IP of the DC.

    Netlogon example::

        >>> mySSP = NTLMSSP_DOMAIN(
        ...     UPN="Server1@domain.local",
        ...     HASHNT=bytes.fromhex("8846f7eaee8fb117ad06bdd830b7586c"),
        ... )

    Kerberos example::

        >>> mySSP = NTLMSSP_DOMAIN(
        ...     UPN="Server1@domain.local",
        ...     KEY=Key(EncryptionType.AES256_CTS_HMAC_SHA1_96,
        ...         key=bytes.fromhex(
        ...             "85abb9b61dc2fa49d4cc04317bbd108f8f79df28"
        ...             "239155ed7b144c5d2ebcf016"
        ...         )
        ...     ),
        ... )
    """

    def __init__(self, UPN=None, *args, timeout=3, ssp=None, **kwargs):
        from scapy.layers.kerberos import KerberosSSP

        # Either PASSWORD or HASHNT or ssp
        if (
            "HASHNT" not in kwargs
            and "PASSWORD" not in kwargs
            and "KEY" not in kwargs
            and ssp is None
        ):
            raise ValueError(
                "Must specify either 'HASHNT', 'PASSWORD' or "
                "provide a ssp=KerberosSSP()"
            )
        elif ssp is not None and not isinstance(ssp, KerberosSSP):
            raise ValueError("'ssp' can only be None or a KerberosSSP !")

        self.KEY = kwargs.pop("KEY", None)
        self.PASSWORD = kwargs.get("PASSWORD", None)

        # UPN is mandatory
        if UPN is None and ssp is not None and ssp.UPN:
            UPN = ssp.UPN
        elif UPN is None:
            raise ValueError("Must specify a 'UPN' !")
        kwargs["UPN"] = UPN

        # Call parent
        super(NTLMSSP_DOMAIN, self).__init__(
            *args,
            **kwargs,
        )

        # Treat specific parameters
        self.DC_FQDN = kwargs.pop("DC_FQDN", None)
        if self.DC_FQDN is None:
            # Get DC_FQDN from dclocator
            from scapy.layers.ldap import dclocator

            dc = dclocator(
                self.DOMAIN_FQDN,
                timeout=timeout,
                debug=kwargs.get("debug", 0),
            )
            self.DC_FQDN = dc.samlogon.DnsHostName.decode().rstrip(".")

        # If logging in via Kerberos
        self.ssp = ssp

    def _getSessionBaseKey(self, Context, ntlm):
        """
        Return the Session Key by asking the DC.
        """
        # No user / no domain: skip.
        if not ntlm.UserNameLen or not ntlm.DomainNameLen:
            return super(NTLMSSP_DOMAIN, self)._getSessionBaseKey(Context, ntlm)

        # Import RPC stuff
        from scapy.layers.dcerpc import NDRUnion
        from scapy.layers.msrpce.msnrpc import (
            NETLOGON_SECURE_CHANNEL_METHOD,
            NetlogonClient,
        )
        from scapy.layers.msrpce.raw.ms_nrpc import (
            NETLOGON_LOGON_IDENTITY_INFO,
            NetrLogonSamLogonWithFlags_Request,
            PNETLOGON_AUTHENTICATOR,
            PNETLOGON_NETWORK_INFO,
            STRING,
            UNICODE_STRING,
        )

        # Create NetlogonClient with PRIVACY
        client = NetlogonClient()
        client.connect(self.DC_FQDN)

        # Establish the Netlogon secure channel (this will bind)
        try:
            if self.ssp is None and self.KEY is None:
                # Login via classic NetlogonSSP
                client.establish_secure_channel(
                    mode=NETLOGON_SECURE_CHANNEL_METHOD.NetrServerAuthenticate3,
                    UPN=f"{self.COMPUTER_NB_NAME}@{self.DOMAIN_NB_NAME}",
                    DC_FQDN=self.DC_FQDN,
                    HASHNT=self.HASHNT,
                )
            else:
                # Login via KerberosSSP (Windows 2025)
                client.establish_secure_channel(
                    mode=NETLOGON_SECURE_CHANNEL_METHOD.NetrServerAuthenticateKerberos,
                    UPN=self.UPN,
                    DC_FQDN=self.DC_FQDN,
                    PASSWORD=self.PASSWORD,
                    KEY=self.KEY,
                    ssp=self.ssp,
                )
        except ValueError:
            log_runtime.warning(
                "Couldn't establish the Netlogon secure channel. "
                "Check the credentials for '%s' !" % self.COMPUTER_NB_NAME
            )
            return super(NTLMSSP_DOMAIN, self)._getSessionBaseKey(Context, ntlm)

        # Request validation of the NTLM request
        req = NetrLogonSamLogonWithFlags_Request(
            LogonServer="",
            ComputerName=self.COMPUTER_NB_NAME,
            Authenticator=client.create_authenticator(),
            ReturnAuthenticator=PNETLOGON_AUTHENTICATOR(),
            LogonLevel=6,  # NetlogonNetworkTransitiveInformation
            LogonInformation=NDRUnion(
                tag=6,
                value=PNETLOGON_NETWORK_INFO(
                    Identity=NETLOGON_LOGON_IDENTITY_INFO(
                        LogonDomainName=UNICODE_STRING(
                            Buffer=ntlm.DomainName,
                        ),
                        ParameterControl=0x00002AE0,
                        UserName=UNICODE_STRING(
                            Buffer=ntlm.UserName,
                        ),
                        Workstation=UNICODE_STRING(
                            Buffer=ntlm.Workstation,
                        ),
                    ),
                    LmChallenge=Context.chall_tok.ServerChallenge,
                    NtChallengeResponse=STRING(
                        Buffer=bytes(ntlm.NtChallengeResponse),
                    ),
                    LmChallengeResponse=STRING(
                        Buffer=bytes(ntlm.LmChallengeResponse),
                    ),
                ),
            ),
            ValidationLevel=6,
            ExtraFlags=0,
            ndr64=client.ndr64,
        )

        # Get response
        resp = client.sr1_req(req)
        if resp and resp.status == 0:
            # Success

            # Validate DC authenticator
            client.validate_authenticator(resp.ReturnAuthenticator.value)

            # Get and return the SessionKey
            UserSessionKey = resp.ValidationInformation.value.value.UserSessionKey
            return bytes(UserSessionKey)
        else:
            # Failed
            return super(NTLMSSP_DOMAIN, self)._getSessionBaseKey(Context, ntlm)

    def _checkLogin(self, Context, auth_tok):
        # Always OK if we got the session key
        return True
