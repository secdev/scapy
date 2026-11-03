# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016-2026 Brian Sipos

# scapy.contrib.description = DTN TCP Convergence Layer
# scapy.contrib.status = loads

import enum
import struct
from typing import Any, ClassVar, Dict, Optional, Tuple, Type
from scapy.config import conf
from scapy.error import log_runtime
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ConditionalField,
    ByteField,
    ByteEnumField,
    XByteField,
    ShortField,
    XShortField,
    LongField,
    FieldLenField,
    StrFixedLenField,
    LenField,
    StrLenField,
    FlagsField,
    PacketListField,
)
from scapy.contrib.sdnv import SDNV2FieldLenField

__all__ = [
    "TCPCL",
    "TCPCLContact",
    "TCPCLContactV3",
    "TCPCLContactV4",
    "TCPCLBaseMsgV4",
    "TCPCLSessInit",
    "TCPCLSessTerm",
    "TCPCLSessExt",
    "TCPCLKeepalive",
    "TCPCLMsgReject",
    "TCPCLXferFlag",
    "TCPCLXferExt",
    "TCPCLXferSegment",
    "TCPCLXferAck",
    "TCPCLXferRefuse",
]

MAGIC_HEAD = b"dtn!"
"""Header magic prefix data."""


class TCPCL(Packet):
    """
    This is a pseudo-packet class to decode real messages
    from a TCP stream based on an initial Contact Header with specific
    version number.
    """

    name = "TCPCL"
    match_subclass = True

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        """No payload, all extra data is padding"""
        return (None, s)

    def is_consistent(self):
        # type: () -> bool
        """ Determine if this packet content is consistent with decoding full data. """
        return True

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Type[Packet], Optional[Packet], *Any, **Any) -> Type[Packet]
        """
        This top dispatch is somewhat heuristic about detecting
        messages outside of a proper TCP stream.
        """
        if not _pkt:
            return cls
        pkt_cls = TCPCLContact.dispatch_hook(_pkt)
        if pkt_cls is not conf.raw_layer:
            return pkt_cls
        return TCPCLBaseMsgV4.dispatch_hook(_pkt)

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        # type: (Type[Packet], bytes, Dict[str,Any], Dict[str,Any]) -> Optional[Packet]
        if len(data) < 1:
            # impossible message
            return None

        orig = metadata.get("original")
        if orig:
            tcp = orig.getlayer(TCP)
            # higher port number is TCP initiator
            role = "i" if tcp.sport > tcp.dport else "r"
        else:
            role = "unk"

        pkt = None
        # first message for each role is contact header
        sesskey = f"tcpcl-version-{role}"
        if sesskey not in session:
            pkt = TCPCLContact(data)
            if isinstance(pkt, TCPCLContact):
                sesskey = f"tcpcl-version-{role}"
                if sesskey not in session:
                    session[sesskey] = int(pkt.version)
            elif data[0] != ord(b"d"):
                # something other than contact
                pkt = TCPCLBaseMsgV4(data)
                if isinstance(pkt, TCPCLBaseMsgV4) and pkt.is_consistent:
                    log_runtime.warning(
                        "TCPCL session without a contact header, assuming v4"
                    )
                    session["tcpcl-version-i"] = session["tcpcl-version-r"] = 4
                else:
                    log_runtime.error(
                        "TCPCL session without a contact header or message"
                    )
                    pkt = None
            else:
                pkt = None

        else:
            # seen contact already
            vers = session[sesskey]
            if vers == 4:
                pkt = TCPCLBaseMsgV4(data)
                if not pkt.is_consistent():
                    pkt = None

        return pkt


# Well-known ports from IANA
bind_layers(TCP, TCPCL, dport=4556)
bind_layers(TCP, TCPCL, sport=4556)


class TCPCLContact(TCPCL):
    """
    Initial stream content, separate from later messaging.
    This is not a full structure but an abstract base class to dispatch from
    during decoding.
    """

    fields_desc = [
        StrFixedLenField("magic", default=MAGIC_HEAD, length=4),
        ByteField("version", default=None),
    ]

    _reg_variants: ClassVar[Dict[int, Type["TCPCLContact"]]] = {}
    """Known contact versions."""

    @classmethod
    def register_variant(cls):
        """
        Registers the version-specific header.
        """
        if cls.version.default is not None:
            cls._reg_variants[cls.version.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Type[Packet], Optional[bytes], *Any, **Any) -> Type[Packet]
        """
        Returns the right sub-class for the given data.
        """
        if not _pkt:
            return cls
        if len(_pkt) >= 5:
            magic = _pkt[:4]
            if magic == MAGIC_HEAD:
                vers = _pkt[4]
                return cls._reg_variants.get(vers, cls)
        return conf.raw_layer


class TCPCLContactV3(TCPCLContact):
    """
    Version 3 contact header from RFC 7242.
    """

    name = "TCPCLv3 Contact"

    @enum.unique
    class Flag(enum.IntEnum):
        ENA_ACK = 0x01
        ENA_FRAG = 0x02
        ENA_REFUSE = 0x04
        ENA_LENGTH = 0x08

    fields_desc = [
        StrFixedLenField("magic", default=MAGIC_HEAD, length=4),
        ByteField("version", default=3),
        FlagsField(
            "flags", default=0, size=8, names=Flag
        ),
        ShortField("keepalive", default=0),
        SDNV2FieldLenField("nodeid_length", default=None, length_of="nodeid_data"),
        StrLenField(
            "nodeid_data", default=b"", length_from=lambda pkt: pkt.nodeid_length
        ),
    ]


class TCPCLContactV4(TCPCLContact):
    """
    Version 4 contact header from RFC 9174.
    """

    name = "TCPCLv4 Contact"

    fields_desc = [
        StrFixedLenField("magic", default=MAGIC_HEAD, length=4),
        ByteField("version", default=4),
        FlagsField("flags", default=0, size=8, names=["CAN_TLS"]),
    ]


class TCPCLBaseMsgV4(TCPCL):
    """
    Base class for all TCPCLv4 message types.
    This is helpful for testing but most users will want to use the top
    TCPCL class when decoding streams.
    """
    name = "TCPCLv4 Message"

    fields_desc = [
        XByteField("msg_type", default=None),
    ]

    _reg_variants: ClassVar[Dict[int, Type["TCPCLBaseMsgV4"]]] = {}
    """ Known message types """

    @classmethod
    def register_variant(cls):
        """
        Registers the version-specific header.
        """
        if cls.msg_type.default is not None:
            cls._reg_variants[cls.msg_type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Type[Packet], Optional[bytes], *Any, **Any) -> Type[Packet]
        """
        Returns the right sub-class for the given data.
        """
        if not _pkt:
            return cls
        msg_type = _pkt[0] if _pkt else None
        # fall-through to raw for unknown types
        return cls._reg_variants.get(msg_type, conf.raw_layer)


TCPCL_MRU_SIZE_MAX = 2**64 - 1
"""Largest 64-bit size value."""


class _TCPCLTlvHead(Packet):
    """
    Generic TLV header with data as payload.
    """

    fields_desc = [
        FlagsField("flags", default=0, size=8, names=["CRITICAL"]),
        XShortField("type", default=None),
        LenField("length", default=None, fmt="H"),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        """Length field is for payload, all extra data is padding"""
        extlen = int(self.getfieldval("length"))
        return (s[:extlen], s[extlen:])


class TCPCLSessExt(_TCPCLTlvHead):
    """
    Session extension header to bind layers to.
    """

    name = "TCPCL SESS_EXT"


class TCPCLSessInit(TCPCLBaseMsgV4):
    name = "TCPCL SESS_INIT"

    fields_desc = [
        XByteField("msg_type", default=0x07),
        ShortField("keepalive", default=0),
        LongField("segment_mru", default=TCPCL_MRU_SIZE_MAX),
        LongField("transfer_mru", default=TCPCL_MRU_SIZE_MAX),
        FieldLenField("nodeid_length", default=None, fmt="H", length_of="nodeid_data"),
        StrLenField(
            "nodeid_data", default="", length_from=lambda pkt: pkt.nodeid_length
        ),
        FieldLenField("ext_size", default=None, fmt="I", length_of="ext_items"),
        PacketListField(
            "ext_items",
            default=[],
            pkt_cls=TCPCLSessExt,
            length_from=lambda pkt: pkt.ext_size,
        ),
    ]

    def is_consistent(self) -> bool:
        field_len = self.getfieldval("nodeid_length")
        real_len = len(self.getfieldval("nodeid_data"))
        if field_len is not None and field_len != real_len:
            return False
        field_len = self.getfieldval("ext_size")
        real_len = sum(len(fld) for fld in self.getfieldval("ext_items"))
        return not (field_len is not None and field_len != real_len)


class TCPCLSessTerm(TCPCLBaseMsgV4):
    name = "TCPCL SESS_TERM"

    @enum.unique
    class Reason(enum.IntEnum):
        """Reason code points."""

        UNKNOWN = 0
        IDLE_TIMEOUT = 1
        VERSION_MISMATCH = 2
        BUSY = 3
        CONTACT_FAILURE = 4
        RESOURCE_EXHAUSTION = 5

    fields_desc = [
        XByteField("msg_type", default=0x05),
        FlagsField("flags", default=0, size=8, names=["REPLY"]),
        ByteEnumField(
            "reason",
            default=Reason.UNKNOWN,
            enum={item.value: item.name for item in Reason},
        ),
    ]


class TCPCLXferExt(_TCPCLTlvHead):
    """
    Transfer extension header to bind layers to.
    """

    name = "TCPCL XFER_EXT"


@enum.unique
class TCPCLXferFlag(enum.IntEnum):
    """
    Transfer flags.
    """

    END = 0x01
    """This segment is the end of the transfer."""
    START = 0x02
    """This segment is the start of the transfer."""


class TCPCLXferSegment(TCPCLBaseMsgV4):
    """
    A XFER_SEGMENT message with transfer data as field (not payload).
    """

    name = "TCPCL XFER_SEGMENT"

    fields_desc = [
        XByteField("msg_type", default=0x01),
        FlagsField(
            "flags",
            default=0,
            size=8,
            names={item.value: item.name for item in TCPCLXferFlag},
        ),
        LongField("transfer_id", default=None),
        ConditionalField(
            cond=lambda pkt: pkt.flags.START,
            fld=FieldLenField("ext_size", default=None, fmt="I", length_of="ext_items"),
        ),
        ConditionalField(
            cond=lambda pkt: pkt.flags.START,
            fld=PacketListField(
                "ext_items",
                default=[],
                pkt_cls=TCPCLXferExt,
                length_from=lambda pkt: pkt.ext_size,
            ),
        ),
        FieldLenField("length", default=None, fmt="Q", length_of="data"),
        StrLenField("data", default=b"", length_from=lambda pkt: pkt.length),
    ]

    def is_consistent(self) -> bool:
        field_len = self.getfieldval("length")
        if field_len is not None and field_len != len(self.getfieldval("data")):
            return False
        if self.flags.START:
            field_len = self.getfieldval("ext_size")
            real_len = sum(len(fld) for fld in self.getfieldval("ext_items"))
            if field_len is not None and field_len != real_len:
                return False
        return True


class TCPCLXferAck(TCPCLBaseMsgV4):
    name = "TCPCL XFER_ACK"

    fields_desc = [
        XByteField("msg_type", default=0x02),
        FlagsField(
            "flags",
            default=0,
            size=8,
            names={item.value: item.name for item in TCPCLXferFlag},
        ),
        LongField("transfer_id", default=None),
        LongField("ack_length", default=None),
    ]


class TCPCLXferRefuse(TCPCLBaseMsgV4):
    name = "TCPCL XFER_REFUSE"

    @enum.unique
    class Reason(enum.IntEnum):
        """Reason code points."""

        UNKNOWN = 0x00
        COMPLETED = 0x01
        NO_RESOURCES = 0x02
        RETRANSMIT = 0x03
        NOT_ACCEPTABLE = 0x04
        EXT_FAILURE = 0x05

    fields_desc = [
        XByteField("msg_type", default=0x03),
        ByteEnumField("reason", default=Reason.UNKNOWN, enum=Reason),
        LongField("transfer_id", default=None),
    ]


class TCPCLKeepalive(TCPCLBaseMsgV4):
    name = "TCPCL KEEPALIVE"

    fields_desc = [
        XByteField("msg_type", default=0x04),
    ]


class TCPCLMsgReject(TCPCLBaseMsgV4):
    name = "TCPCL MSG_REJECT"

    @enum.unique
    class Reason(enum.IntEnum):
        """Reason code points."""

        UNKNOWN = 0x01
        UNSUPPORTED = 0x02
        UNEXPECTED = 0x03

    fields_desc = [
        XByteField("msg_type", default=0x06),
        ByteEnumField(
            "reason",
            default=Reason.UNKNOWN,
            enum={item.value: item.name for item in Reason},
        ),
        XByteField("rejected_type", default=None),
    ]
