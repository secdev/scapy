# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016-2026 Brian Sipos

# scapy.contrib.description = DTN TCP Convergence Layer
# scapy.contrib.status = loads

import enum
import struct
from typing import ClassVar
from scapy import volatile, packet
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
    This is a pseudo-packet class to dispatch to the real messages
    from a TCP stream.
    """

    name = "TCPCL"
    match_subclass = True

    def extract_padding(self, s):
        """No payload, all extra data is padding"""
        return (None, s)

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        tcp = None
        if "original" in metadata:
            tcp = metadata.get("original")[TCP]

        pkt = None
        if "tcpcl-version-i" not in session or "tcpcl-version-r" not in session:
            pkt = TCPCLContact(data)
            if isinstance(pkt, TCPCLContact):
                log_runtime.info("TCPCL version %s", pkt.version)
                if "tcpcl-version-i" not in session:
                    # initiator version
                    if tcp:
                        session["tcpcl-port-i"] = tcp.sport
                        session["tcpcl-port-r"] = tcp.dport
                    session["tcpcl-version-i"] = int(pkt.version)
                elif "tcpcl-version-r" not in session:
                    # responder version
                    if tcp.sport != session["tcpcl-port-r"]:
                        raise RuntimeError("bad responder SESS_INIT")
                    session["tcpcl-version-r"] = int(pkt.version)
            else:
                # something other than contact
                pkt = _TCPCLBaseMsgV4(data)
                if isinstance(pkt, _TCPCLBaseMsgV4):
                    log_runtime.warning(
                        "TCPCL session without a contact header, assuming v4"
                    )
                    session["tcpcl-version-i"] = session["tcpcl-version-r"] = 4
                else:
                    log_runtime.error(
                        "TCPCL session without a contact header or message"
                    )
        else:
            vers = session["tcpcl-version-r"]
            if vers == 4:
                pkt = _TCPCLBaseMsgV4(data)

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

    _reg_variants: ClassVar[dict[int, "TCPCLContact"]] = {}
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
        """
        Returns the right sub-class for the given data.
        """
        if _pkt and len(_pkt) >= 5:
            magic = _pkt[:4]
            if magic == MAGIC_HEAD:
                vers = struct.unpack("!B", _pkt[4:5])[0]
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
            "flags", default=0, size=8, names={item.value: item.name for item in Flag}
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

    @enum.unique
    class Flag(enum.IntEnum):
        CAN_TLS = 0x01

    fields_desc = [
        StrFixedLenField("magic", default=MAGIC_HEAD, length=4),
        ByteField("version", default=4),
        FlagsField(
            "flags", default=0, size=8, names={item.value: item.name for item in Flag}
        ),
    ]


class _TCPCLBaseMsgV4(TCPCL):
    """
    Base class for all TCPCL message types.
    """

    fields_desc = [
        XByteField("msg_type", default=None),
    ]

    _reg_variants: ClassVar[dict[int, "_TCPCLBaseMsgV4"]] = {}
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
        """
        Returns the right sub-class for the given data.
        """
        if _pkt and len(_pkt) >= 1:
            msg_type = struct.unpack("!B", _pkt[:1])[0]
            return cls._reg_variants.get(msg_type, cls)
        return conf.raw_layer


TCPCL_MRU_SIZE_MAX = 2**64 - 1
"""Largest 64-bit size value."""


class TCPCLExtensionListField(PacketListField):
    """Provide useful randval() that fixes scapy behavior."""

    def randval(self):
        count = volatile.RandNum(0, 4)
        reprobj = self.cls()
        items = []
        for _ in range(count):
            items.append(packet.fuzz(reprobj))
        return items


class _TCPCLTlvHead(Packet):
    """
    Generic TLV header with data as payload.
    """

    @enum.unique
    class Flag(enum.IntEnum):
        """
        Extension item flags.
        """

        CRITICAL = 0x01

    fields_desc = [
        FlagsField(
            "flags", default=0, size=8, names={item.value: item.name for item in Flag}
        ),
        XShortField("type", default=None),
        LenField("length", default=None, fmt="H"),
    ]


class TCPCLSessExt(_TCPCLTlvHead):
    """
    Session extension header to bind layers to.
    """

    name = "TCPCL SESS_EXT"


class TCPCLSessInit(_TCPCLBaseMsgV4):
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
        TCPCLExtensionListField(
            "ext_items",
            default=[],
            pkt_cls=TCPCLSessExt,
            length_from=lambda pkt: pkt.ext_size,
        ),
    ]


class TCPCLSessTerm(_TCPCLBaseMsgV4):
    name = "TCPCL SESS_TERM"

    @enum.unique
    class Flag(enum.IntEnum):
        """Message flags.
        Flags must be in LSbit-first order.
        """

        REPLY = 0x01

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
        FlagsField(
            "flags", default=0, size=8, names={item.value: item.name for item in Flag}
        ),
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


class TCPCLXferSegment(_TCPCLBaseMsgV4):
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
            cond=lambda pkt: pkt.flags & TCPCLXferFlag.START,
            fld=FieldLenField("ext_size", default=None, fmt="I", length_of="ext_items"),
        ),
        ConditionalField(
            cond=lambda pkt: pkt.flags & TCPCLXferFlag.START,
            fld=TCPCLExtensionListField(
                "ext_items",
                default=[],
                pkt_cls=TCPCLXferExt,
                length_from=lambda pkt: pkt.ext_size,
            ),
        ),
        FieldLenField("length", default=None, fmt="Q", length_of="data"),
        StrLenField("data", default=b"", length_from=lambda pkt: pkt.length),
    ]


class TCPCLXferAck(_TCPCLBaseMsgV4):
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


class TCPCLXferRefuse(_TCPCLBaseMsgV4):
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
        ByteEnumField(
            "reason",
            default=Reason.UNKNOWN,
            enum={item.value: item.name for item in Reason},
        ),
        LongField("transfer_id", default=None),
    ]


class TCPCLKeepalive(_TCPCLBaseMsgV4):
    name = "TCPCL KEEPALIVE"

    fields_desc = [
        XByteField("msg_type", default=0x04),
    ]


class TCPCLMsgReject(_TCPCLBaseMsgV4):
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
