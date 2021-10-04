# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>
# This program is published under a GPLv2 license

"""
NTLM

https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf
"""

import struct
from scapy.compat import bytes_base64
from scapy.config import conf
from scapy.fields import (
    Field,
    ByteEnumField,
    ByteField,
    FieldLenField,
    FlagsField,
    LEIntField,
    _StrField,
    LEShortEnumField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    LEShortField,
    StrField,
    StrFieldUtf16,
    StrFixedLenField,
    LEIntEnumField,
    LEThreeBytesField,
    StrLenFieldUtf16,
    UTCTimeField,
    XStrField,
    XStrFixedLenField,
    XStrLenField,
)
from scapy.packet import Packet
from scapy.sessions import StringBuffer

from scapy.compat import (
    Any,
    Dict,
    List,
    Tuple,
    Optional,
)

##########
# Fields #
##########


class _NTLMPayloadField(_StrField[List[Tuple[str, Any]]]):
    """Special field used to dissect NTLM payloads.
    This isn't trivial because the offsets are variable."""
    __slots__ = ["fields", "fields_map", "offset"]
    islist = True

    def __init__(self, name, offset, fields):
        # type: (str, int, List[Field[Any, Any]]) -> None
        self.offset = offset
        self.fields = fields
        self.fields_map = {field.name: field for field in fields}
        super(_NTLMPayloadField, self).__init__(
            name,
            [(field.name, field.default) for field in fields]
        )

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> List[Tuple[str, str]]
        if not pkt or not x:
            return []
        results = []
        for field in self.fields:
            length = pkt.getfieldval(field.name + "Len")
            offset = pkt.getfieldval(field.name + "BufferOffset") - self.offset
            if offset < 0:
                continue
            results.append((offset, field.name, field.getfield(
                pkt, x[offset:offset + length])[1]))
        results.sort(key=lambda x: x[0])
        return [x[1:] for x in results]

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[List[Tuple[str, str]]]) -> bytes
        buf = StringBuffer()
        for field_name, value in x:
            if field_name not in self.fields_map:
                continue
            field = self.fields_map[field_name]
            offset = pkt.getfieldval(
                field_name + "BufferOffset") or len(buf)
            buf.append(field.addfield(pkt, b"", value), offset + 1)
        return bytes(buf)

    def i2h(self, pkt, x):
        # type: (Optional[Packet], bytes) -> List[Tuple[str, str]]
        if not pkt or not x:
            return []
        results = []
        for field_name, value in x:
            if field_name not in self.fields_map:
                continue
            results.append(
                (field_name, self.fields_map[field_name].i2h(pkt, value)))
        return results


def _NTML_post_build(self, p, pay_offset, fields):
    # type: (Packet, bytes, int, Dict[str, Tuple[str, int]]) -> bytes
    """Util function to build the offset and populate the lengths"""
    for field_name, value in self.Payload:
        length = self.get_field(
            "Payload").fields_map[field_name].i2len(self, value)
        offset = fields[field_name]
        # Length
        if self.getfieldval(field_name + "Len") is None:
            p = p[:offset] + \
                struct.pack("!H", length) + p[offset + 2:]
        # MaxLength
        if self.getfieldval(field_name + "MaxLen") is None:
            p = p[:offset + 2] + \
                struct.pack("!H", length) + p[offset + 4:]
        # Offset
        if self.getfieldval(field_name + "BufferOffset") is None:
            p = p[:offset + 4] + \
                struct.pack("!I", pay_offset) + p[offset + 8:]
        pay_offset += length
    return p


##############
# Structures #
##############


# Sect 2.2


class NTLM_Header(Packet):
    name = "NTLM Header"
    fields_desc = [
        StrFixedLenField('Signature', b'NTLMSSP\0', length=8),
        LEIntEnumField('MessageType', 3, {1: 'NEGOTIATE_MESSAGE',
                                          2: 'CHALLENGE_MESSAGE',
                                          3: 'AUTHENTICATE_MESSAGE'}),
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
    "A",  # NTLMSSP_NEGOTIATE_UNICODE
    "B",  # NTLM_NEGOTIATE_OEM
    "C",  # NTLMSSP_REQUEST_TARGET
    "r10",
    "D",  # NTLMSSP_NEGOTIATE_SIGN
    "E",  # NTLMSSP_NEGOTIATE_SEAL
    "F",  # NTLMSSP_NEGOTIATE_DATAGRAM
    "G",  # NTLMSSP_NEGOTIATE_LM_KEY
    "r9",
    "H",  # NTLMSSP_NEGOTIATE_NTLM
    "r8",
    "J",
    "K",  # NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
    "L",  # NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
    "r7",
    "M",  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    "N",  # NTLMSSP_TARGET_TYPE_DOMAIN
    "O",  # NTLMSSP_TARGET_TYPE_SERVER
    "r6",
    "P",  # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    "Q",  # NTLMSSP_NEGOTIATE_IDENTIFY
    "r5",
    "R",  # NTLMSSP_REQUEST_NON_NT_SESSION_KEY
    "S",  # NTLMSSP_NEGOTIATE_TARGET_INFO
    "r4",
    "T",  # NTLMSSP_NEGOTIATE_VERSION
    "r3",
    "r2",
    "r1",
    "U",  # NTLMSSP_NEGOTIATE_128
    "V",  # NTLMSSP_NEGOTIATE_KEY_EXCH
    "W",  # NTLMSSP_NEGOTIATE_56
]


def _NTLMStrField(name, default):
    return MultipleTypeField(
        [
            (StrFieldUtf16(name, default),
             lambda pkt: pkt.NegotiateFlags.A)
        ],
        StrField(name, default),
    )

# Sect 2.2.2.10


class _NTLM_Version(Packet):
    fields_desc = [
        ByteField('ProductMajorVersion', 0),
        ByteField('ProductMinorVersion', 0),
        LEShortField('ProductBuild', 0),
        LEThreeBytesField('res_ver', 0),
        ByteEnumField('NTLMRevisionCurrent', 0x0F, {0x0F: "v15"}),
    ]

# Sect 2.2.1.1


class NTLM_NEGOTIATE(Packet):
    name = "NTLM Negotiate"
    messageType = 1
    OFFSET = 40
    fields_desc = [
        NTLM_Header,
        FlagsField('NegotiateFlags', 0, -32, _negotiateFlags),
        # DomainNameFields
        LEShortField('DomainNameLen', None),
        LEShortField('DomainNameMaxLen', None),
        LEIntField('DomainNameBufferOffset', None),
        # WorkstationFields
        LEShortField('WorkstationNameLen', None),
        LEShortField('WorkstationNameMaxLen', None),
        LEIntField('WorkstationNameBufferOffset', None),
        # VERSION
        _NTLM_Version,
        # Payload
        _NTLMPayloadField(
            'Payload', OFFSET, [
                _NTLMStrField('DomainName', b''),
                _NTLMStrField('WorkstationName', b'')
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _NTML_post_build(self, pkt, self.OFFSET, {
            "DomainName": 16,
            "WorkstationName": 24,
        }) + pay

# Challenge


class Single_Host_Data(Packet):
    fields_desc = [
        LEIntField("Size", 0),
        LEIntField("Z4", 0),
        XStrFixedLenField("CustomData", b"", length=8),
        XStrFixedLenField("MachineID", b"", length=32),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class AV_PAIR(Packet):
    name = "NTLM AV Pair"
    fields_desc = [
        LEShortEnumField('AvId', 0, {
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
        }),
        FieldLenField('AvLen', None, length_of="Value", fmt="<H"),
        MultipleTypeField([
            (LEIntEnumField('Value', 1, {
                0x0001: "constrained",
                0x0002: "MIC integrity",
                0x0004: "SPN from untrusted source"}),
             lambda pkt: pkt.AvId == 0x0006),
            (UTCTimeField("Value", None, epoch=[
                1601, 1, 1, 0, 0, 0], custom_scaling=1e7,
                fmt="<Q"),
                lambda pkt: pkt.AvId == 0x0007),
            (PacketField('Value', Single_Host_Data(), Single_Host_Data),
             lambda pkt: pkt.AvId == 0x0008),
            (XStrLenField('Value', b"", length_from=lambda pkt: pkt.AvLen),
             lambda pkt: pkt.AvId == 0x000A),
        ],
            StrLenFieldUtf16('Value', b"", length_from=lambda pkt: pkt.AvLen)
        )
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class NTLM_CHALLENGE(Packet):
    name = "NTLM Negotiate"
    messageType = 2
    OFFSET = 56
    fields_desc = [
        NTLM_Header,
        # TargetNameFields
        LEShortField('TargetNameLen', None),
        LEShortField('TargetNameMaxLen', None),
        LEIntField('TargetNameBufferOffset', None),
        #
        FlagsField('NegotiateFlags', 0, -32, _negotiateFlags),
        XStrFixedLenField('ServerChallenge', None, length=8),
        XStrFixedLenField('Reserved', None, length=8),
        # TargetInfoFields
        LEShortField('TargetInfoLen', None),
        LEShortField('TargetInfoMaxLen', None),
        LEIntField('TargetInfoBufferOffset', None),
        # VERSION
        _NTLM_Version,
        # Payload
        _NTLMPayloadField(
            'Payload', OFFSET, [
                _NTLMStrField('TargetName', b''),
                PacketListField('TargetInfo', [AV_PAIR()], AV_PAIR)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _NTML_post_build(self, pkt, self.OFFSET, {
            "TargetName": 12,
            "TargetInfo": 40,
        }) + pay


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
        ByteField("RespType", 0),
        ByteField("HiRespType", 0),
        LEShortField("Reserved1", 0),
        LEIntField("Reserved2", 0),
        UTCTimeField("TimeStamp", None, fmt="<Q", epoch=[
                     1601, 1, 1, 0, 0, 0], custom_scaling=1e7),
        StrFixedLenField("ChallengeFromClient", b"", length=8),
        LEIntField("Reserved3", 0),
        PacketListField("AvPairs", [AV_PAIR()], AV_PAIR)
    ]


class NTLMv2_RESPONSE(Packet):
    fields_desc = [
        XStrFixedLenField("NTProofStr", b"", length=16),
        NTLMv2_CLIENT_CHALLENGE
    ]


class NTLM_AUTHENTICATE(Packet):
    name = "NTLM Authenticate"
    messageType = 3
    OFFSET = 88
    NTLM_VERSION = 1
    fields_desc = [
        NTLM_Header,
        # LmChallengeResponseFields
        LEShortField('LmChallengeResponseLen', None),
        LEShortField('LmChallengeResponseMaxLen', None),
        LEIntField('LmChallengeResponseBufferOffset', None),
        # NtChallengeResponseFields
        LEShortField('NtChallengeResponseLen', None),
        LEShortField('NtChallengeResponseMaxLen', None),
        LEIntField('NtChallengeResponseBufferOffset', None),
        # DomainNameFields
        LEShortField('DomainNameLen', None),
        LEShortField('DomainNameMaxLen', None),
        LEIntField('DomainNameBufferOffset', None),
        # UserNameFields
        LEShortField('UserNameLen', None),
        LEShortField('UserNameMaxLen', None),
        LEIntField('UserNameBufferOffset', None),
        # WorkstationFields
        LEShortField('WorkstationLen', None),
        LEShortField('WorkstationMaxLen', None),
        LEIntField('WorkstationBufferOffset', None),
        # EncryptedRandomSessionKeyFields
        LEShortField('EncryptedRandomSessionKeyLen', None),
        LEShortField('EncryptedRandomSessionKeyMaxLen', None),
        LEIntField('EncryptedRandomSessionKeyBufferOffset', None),
        # NegotiateFlags
        FlagsField('NegotiateFlags', 0, -32, _negotiateFlags),
        # VERSION
        _NTLM_Version,
        # MIC
        XStrFixedLenField('MIC', b"", length=16),
        # Payload
        _NTLMPayloadField(
            'Payload', OFFSET, [
                MultipleTypeField(
                    [(PacketField('LmChallengeResponse', LMv2_RESPONSE(),
                      LMv2_RESPONSE), lambda pkt: pkt.NTLM_VERSION == 2)],
                    PacketField('LmChallengeResponse',
                                LM_RESPONSE(), LM_RESPONSE)
                ),
                MultipleTypeField(
                    [(PacketField('NtChallengeResponse', NTLMv2_RESPONSE(),
                      NTLMv2_RESPONSE), lambda pkt: pkt.NTLM_VERSION == 2)],
                    PacketField('NtChallengeResponse',
                                NTLM_RESPONSE(), NTLM_RESPONSE)
                ),
                _NTLMStrField('DomainName', b''),
                _NTLMStrField('UserName', b''),
                _NTLMStrField('Workstation', b''),
                XStrField('EncryptedRandomSessionKey', b''),
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _NTML_post_build(self, pkt, self.OFFSET, {
            "LmChallengeResponse": 12,
            "NtChallengeResponse": 20,
            "DomainName": 28,
            "UserName": 36,
            "Workstation": 44,
            "EncryptedRandomSessionKey": 52
        }) + pay


class NTLM_AUTHENTICATE_V2(NTLM_AUTHENTICATE):
    NTLM_VERSION = 2


def HTTP_ntlm_negotiate(ntlm_negotiate):
    """Create an HTTP NTLM negotiate packet from an NTLM_NEGOTIATE message"""
    assert isinstance(ntlm_negotiate, NTLM_NEGOTIATE)
    from scapy.layers.http import HTTP, HTTPRequest
    return HTTP() / HTTPRequest(
        Authorization=b"NTLM " + bytes_base64(bytes(ntlm_negotiate))
    )
