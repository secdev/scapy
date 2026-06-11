# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Scapy contributors

# scapy.contrib.description = SAE J1939 Vehicle Network Protocol
# scapy.contrib.status = loads

"""
SAE J1939 - Vehicle network protocol for heavy-duty vehicles.

J1939 uses 29-bit extended CAN identifiers to encode a structured addressing
scheme.  The 29-bit identifier is partitioned as follows::

    Bits 28-26 : Priority        (3 bits, 0 = highest)
    Bit  25    : Reserved        (1 bit)
    Bit  24    : Data Page       (1 bit)
    Bits 23-16 : PDU Format      (8 bits, PF)
    Bits 15-8  : PDU Specific    (8 bits, PS)
                     PF < 240 → Destination Address (PDU1, peer-to-peer)
                     PF ≥ 240 → Group Extension     (PDU2, broadcast)
    Bits  7-0  : Source Address  (8 bits, SA)

PGN (Parameter Group Number):
    PDU1 (PF < 240): PGN = (DP << 16) | (PF << 8)           — PS is DA
    PDU2 (PF ≥ 240): PGN = (DP << 16) | (PF << 8) | GE      — broadcast only

References:
    - SAE J1939 standard
    - Linux kernel J1939 documentation:
      https://www.kernel.org/doc/html/latest/networking/j1939.html
"""

import socket
import struct
import logging
import time
import traceback

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
    TYPE_CHECKING,
)

from scapy.automaton import ObjectPipe, select_objects
from scapy.config import conf
from scapy.consts import LINUX
from scapy.data import SO_TIMESTAMPNS
from scapy.error import Scapy_Exception, log_runtime
from scapy.fields import (
    BitField,
    ByteField,
    FieldLenField,
    FlagsField,
    LEShortField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
    XLE3BytesField,
)
from scapy.layers.can import CAN
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.compat import raw
from scapy.utils import EDecimal

if TYPE_CHECKING:
    from scapy.contrib.cansocket import CANSocket

log_j1939 = logging.getLogger("scapy.contrib.j1939")

# ---------------------------------------------------------------------------
# J1939 constants (sourced from Python socket module where available)
# socket.CAN_J1939 and related constants were added in Python 3.9.
# Fallback values are taken from the Linux kernel header linux/can/j1939.h.
# ---------------------------------------------------------------------------

# Backfill J1939 constants on old Python runtimes (< 3.9) so the module can
# consistently read them from socket.*.
if not hasattr(socket, 'J1939_NO_NAME'):
    socket.J1939_NO_NAME = 0
if not hasattr(socket, 'J1939_NO_PGN'):
    socket.J1939_NO_PGN = 0x40000000
if not hasattr(socket, 'J1939_NO_ADDR'):
    socket.J1939_NO_ADDR = 0xFF
if not hasattr(socket, 'J1939_IDLE_ADDR'):
    socket.J1939_IDLE_ADDR = 0xFE
if not hasattr(socket, 'J1939_MAX_UNICAST_ADDR'):
    socket.J1939_MAX_UNICAST_ADDR = 0xFD
if not hasattr(socket, 'J1939_PGN_REQUEST'):
    socket.J1939_PGN_REQUEST = 0xEA00
if not hasattr(socket, 'J1939_PGN_ADDRESS_CLAIMED'):
    socket.J1939_PGN_ADDRESS_CLAIMED = 0xEE00
if not hasattr(socket, 'J1939_PGN_ADDRESS_COMMANDED'):
    socket.J1939_PGN_ADDRESS_COMMANDED = 0xFED8
if not hasattr(socket, 'J1939_PGN_MAX'):
    socket.J1939_PGN_MAX = 0x3FFFF
if not hasattr(socket, 'J1939_PGN_PDU1_MAX'):
    socket.J1939_PGN_PDU1_MAX = 0x3FF00
if not hasattr(socket, 'CAN_J1939'):
    socket.CAN_J1939 = 7

SOL_CAN_BASE = 100
if not hasattr(socket, 'SOL_CAN_J1939'):
    socket.SOL_CAN_J1939 = SOL_CAN_BASE + socket.CAN_J1939
if not hasattr(socket, 'SO_J1939_FILTER'):
    socket.SO_J1939_FILTER = 1
if not hasattr(socket, 'SO_J1939_PROMISC'):
    socket.SO_J1939_PROMISC = 2
if not hasattr(socket, 'SO_J1939_SEND_PRIO'):
    socket.SO_J1939_SEND_PRIO = 3
if not hasattr(socket, 'SO_J1939_ERRQUEUE'):
    socket.SO_J1939_ERRQUEUE = 4
if not hasattr(socket, 'SCM_J1939_DEST_ADDR'):
    socket.SCM_J1939_DEST_ADDR = 1
if not hasattr(socket, 'SCM_J1939_DEST_NAME'):
    socket.SCM_J1939_DEST_NAME = 2
if not hasattr(socket, 'SCM_J1939_PRIO'):
    socket.SCM_J1939_PRIO = 3
if not hasattr(socket, 'SCM_J1939_ERRQUEUE'):
    socket.SCM_J1939_ERRQUEUE = 4

#: Global broadcast address
J1939_BROADCAST_ADDR = socket.J1939_NO_ADDR                    # 0xFF
#: Transport Protocol – Connection Management
J1939_PGN_TP_CM = 0xEC00
#: Transport Protocol – Data Transfer
J1939_PGN_TP_DT = 0xEB00

# TP control byte values (integer constants; the classes share the prefix name)
J1939_TP_CTRL_RTS = 16     # Request To Send
J1939_TP_CTRL_CTS = 17     # Clear To Send
J1939_TP_CTRL_ACK = 19     # End of Message Acknowledge
J1939_TP_CTRL_BAM = 32     # Broadcast Announce Message
J1939_TP_CTRL_ABORT = 255  # Connection Abort

# PDU format threshold: PF < 240 → PDU1 (peer-to-peer), PF ≥ 240 → PDU2 (broadcast)
J1939_PDU1_MAX_PF = 239

# Default configuration key
conf.contribs['J1939'] = {'channel': 'can0'}

# Common source address names (informational)
J1939_ADDR_NAMES = {
    0x00: "Engine #1",
    0x01: "Engine #2",
    0x02: "Turbocharger",
    0x03: "Transmission #1",
    0x04: "Transmission #2",
    0x0B: "Brakes - System Controller",
    0x0F: "Instrument Cluster #1",
    0x11: "Trip Recorder",
    0x15: "Retarder, Exhaust, Engine #1",
    0x17: "Cruise Control",
    0x21: "Transmission, Automatic #1",
    0x27: "Clutch/Converter Unit",
    0x28: "Auxiliary Valve Control",
    0x29: "Auxiliary Valve Control #2",
    0xEF: "Null/Reserved",
    0xFE: "NULL (no address)",
    0xFF: "Global (broadcast)",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def pgn_is_pdu1(pgn):
    # type: (int) -> bool
    """Return True if *pgn* is a PDU1 (peer-to-peer) Parameter Group Number."""
    return ((pgn >> 8) & 0xFF) <= J1939_PDU1_MAX_PF


def can_id_to_j1939(can_id):
    # type: (int) -> Dict[str, int]
    """Decode a 29-bit CAN identifier to a dictionary of J1939 fields.

    :param can_id: 29-bit extended CAN identifier
    :returns: dict with keys ``priority``, ``reserved``, ``data_page``,
              ``pdu_format``, ``pdu_specific``, ``src``
    """
    return {
        'priority': (can_id >> 26) & 0x7,
        'reserved': (can_id >> 25) & 0x1,
        'data_page': (can_id >> 24) & 0x1,
        'pdu_format': (can_id >> 16) & 0xFF,
        'pdu_specific': (can_id >> 8) & 0xFF,
        'src': can_id & 0xFF,
    }


def j1939_to_can_id(priority, reserved, data_page, pdu_format, pdu_specific, src):
    # type: (int, int, int, int, int, int) -> int
    """Encode J1939 fields into a 29-bit CAN identifier.

    :returns: 29-bit CAN identifier value
    """
    return (
        (priority & 0x7) << 26 |
        (reserved & 0x1) << 25 |
        (data_page & 0x1) << 24 |
        (pdu_format & 0xFF) << 16 |
        (pdu_specific & 0xFF) << 8 |
        (src & 0xFF)
    )


def pgn_from_fields(data_page, pdu_format, pdu_specific):
    # type: (int, int, int) -> int
    """Compute the PGN from J1939 CAN identifier sub-fields.

    :param data_page: data page bit (0 or 1)
    :param pdu_format: PDU format byte (0-255)
    :param pdu_specific: PDU specific byte (0-255)
    :returns: 18-bit PGN value
    """
    if pdu_format <= J1939_PDU1_MAX_PF:
        # PDU1: PS is destination address – not included in PGN
        return (data_page << 16) | (pdu_format << 8)
    else:
        # PDU2: PS is group extension – included in PGN
        return (data_page << 16) | (pdu_format << 8) | pdu_specific


def dst_from_fields(pdu_format, pdu_specific):
    # type: (int, int) -> int
    """Return the destination address encoded in J1939 identifier fields.

    :param pdu_format: PDU format byte (0-255)
    :param pdu_specific: PDU specific byte (0-255)
    :returns: destination address (0x00-0xFF), or ``socket.J1939_NO_ADDR`` for PDU2
    """
    if pdu_format <= J1939_PDU1_MAX_PF:
        return pdu_specific
    return socket.J1939_NO_ADDR


# ---------------------------------------------------------------------------
# J1939 application-layer packet
# ---------------------------------------------------------------------------

class J1939(Packet):
    """SAE J1939 application-layer message.

    This class represents a J1939 message at the application layer.  When used
    with :class:`NativeJ1939Socket`, the Linux kernel J1939 stack handles
    transport-protocol framing (segmentation / reassembly) automatically, so
    ``data`` may be larger than 8 bytes.

    Addressing information – ``priority``, ``pgn``, ``src``, ``dst`` – is
    stored in :attr:`__slots__` rather than as wire fields (the same approach
    used by :class:`~scapy.contrib.isotp.ISOTP`).  These attributes are
    populated by :class:`NativeJ1939Socket` upon reception.

    Example::

        >>> msg = J1939(b'\\x01\\x02\\x03', pgn=0xFECA, src=0x00, dst=0xFF)
        >>> msg.pgn
        65226
        >>> msg.src
        0
    """

    name = 'J1939'
    fields_desc = [
        StrField('data', b'')
    ]
    __slots__ = Packet.__slots__ + ['priority', 'pgn', 'src', 'dst']

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        self.priority = kwargs.pop('priority', 6)    # type: int
        self.pgn = kwargs.pop('pgn', 0)              # type: int
        self.src = kwargs.pop('src', socket.J1939_NO_ADDR)  # type: int
        self.dst = kwargs.pop('dst', socket.J1939_NO_ADDR)  # type: int
        Packet.__init__(self, *args, **kwargs)

    def answers(self, other):
        # type: (Packet) -> int
        if not isinstance(other, J1939):
            return 0
        return self.data == other.data

    def mysummary(self):
        # type: () -> str
        # Addressing is in __slots__, not wire fields, so build the summary directly.
        return "J1939 PGN=0x%05X SA=0x%02X DA=0x%02X prio=%d" % (
            self.pgn, self.src, self.dst, self.priority
        )


# ---------------------------------------------------------------------------
# J1939 CAN-frame-level packet
# ---------------------------------------------------------------------------

class J1939_CAN(CAN):
    """J1939 CAN frame – the 29-bit extended CAN identifier decoded as J1939.

    Inherits from :class:`~scapy.layers.can.CAN` so that all CAN lifecycle
    methods are reused automatically:

    * ``pre_dissect`` / ``post_build`` – byte-order swap controlled by
      ``conf.contribs['CAN']['swap-bytes']`` (Wireshark vs PF_CAN format).
    * ``extract_padding`` – padding removal controlled by
      ``conf.contribs['CAN']['remove-padding']``.

    The only structural difference from :class:`~scapy.layers.can.CAN` is
    that the 29-bit ``identifier`` field is decomposed into the six J1939
    sub-fields (``priority``, ``reserved``, ``data_page``, ``pdu_format``,
    ``pdu_specific``, ``src``), while the wire layout remains **identical**.

    CAN identifier sub-fields::

        priority    (bits 28-26): message priority, 0 = highest, 7 = lowest
        reserved    (bit  25)   : reserved, should be 0
        data_page   (bit  24)   : selects one of two parameter group tables
        pdu_format  (bits 23-16): determines PDU type (< 240 → PDU1)
        pdu_specific(bits 15-8) : DA if PDU1, Group Extension if PDU2
        src         (bits  7-0) : source address

    Convenience properties :attr:`pgn` and :attr:`dst` are derived from the
    sub-fields.

    Example::

        >>> pkt = J1939_CAN(priority=6, pdu_format=0xFE, pdu_specific=0xCA,
        ...                 src=0x00, data=b'\\xff' * 8)
        >>> hex(pkt.pgn)
        '0xfeca'
        >>> hex(pkt.dst)
        '0xff'
    """

    name = 'J1939_CAN'
    fields_desc = [
        # ── first 32 bits: CAN flags(3) + J1939 identifier fields(29) ──────
        FlagsField('flags', 0b100, 3,
                   ['error', 'remote_transmission_request', 'extended']),
        BitField('priority', 6, 3),       # J1939 priority
        BitField('reserved', 0, 1),       # Reserved bit
        BitField('data_page', 0, 1),      # Data Page (DP)
        ByteField('pdu_format', 0xFE),    # PDU Format (PF)
        ByteField('pdu_specific', 0xFF),  # PDU Specific (PS): DA or GE
        ByteField('src', 0xFE),           # Source Address (SA)
        # ── standard CAN data-length + padding ────────────────────────────
        FieldLenField('length', None, length_of='data', fmt='B'),
        ThreeBytesField('reserved2', 0),
        StrLenField('data', b'', length_from=lambda p: int(p.length)),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        # Always decode as J1939_CAN; do not redirect to plain CAN or CANFD.
        return cls

    @property
    def pgn(self):
        # type: () -> int
        """PGN (Parameter Group Number) derived from ``data_page``,
        ``pdu_format``, and ``pdu_specific``."""
        return pgn_from_fields(self.data_page, self.pdu_format, self.pdu_specific)

    @property
    def dst(self):
        # type: () -> int
        """Destination address for PDU1 frames; :data:`socket.J1939_NO_ADDR` for PDU2."""  # noqa: E501
        return dst_from_fields(self.pdu_format, self.pdu_specific)

    def to_can(self):
        # type: () -> CAN
        """Convert to a standard :class:`~scapy.layers.can.CAN` packet.

        The wire bytes are identical so this is simply a class change.
        """
        return CAN(bytes(self))

    @classmethod
    def from_can(cls, pkt):
        # type: (CAN) -> J1939_CAN
        """Create a :class:`J1939_CAN` from a :class:`~scapy.layers.can.CAN` packet.

        The wire bytes are identical so this is simply a class change.
        The packet timestamp is preserved from *pkt*.
        """
        result = cls(bytes(pkt))
        result.time = pkt.time
        return result

    def mysummary(self):
        # type: () -> str
        return "J1939_CAN PGN=0x%05X SA=0x%02X" % (self.pgn, self.src)


# ---------------------------------------------------------------------------
# J1939 Transport Protocol (TP) frames
# ---------------------------------------------------------------------------
# TP allows up to 1785 bytes per multi-packet session using PGN 0xEC00
# (TP.CM – Connection Management) and PGN 0xEB00 (TP.DT – Data Transfer).

_TP_CM_CTRL_NAMES = {
    J1939_TP_CTRL_RTS: 'RTS',
    J1939_TP_CTRL_CTS: 'CTS',
    J1939_TP_CTRL_ACK: 'EOM_ACK',
    J1939_TP_CTRL_BAM: 'BAM',
    J1939_TP_CTRL_ABORT: 'ABORT',
}

_TP_ABORT_REASON = {
    1: 'Already in connection',
    2: 'System resources',
    3: 'Timeout',
    4: 'CTS while DT in progress',
    5: 'Max retransmit exceeded',
    6: 'Unexpected DT packet',
    7: 'Bad sequence number',
    8: 'Duplicate sequence number',
    250: 'Other',
    251: 'Other',
    252: 'Other',
    253: 'Other',
    254: 'Other',
    255: 'Other',
}


class J1939_TP_CM_RTS(Packet):
    """J1939 TP Connection Management – Request To Send (RTS).

    Sent before a peer-to-peer multi-packet message to announce the total
    size and packet count.  Uses PGN 0xEC00.
    """
    name = 'J1939_TP_CM_RTS'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_RTS),         # 16
        LEShortField('total_size', 0),                # total message size (bytes)
        ByteField('num_packets', 0),                  # total number of TP.DT packets
        ByteField('max_packets', 0xFF),         # max packets per CTS (0xFF = no limit)
        XLE3BytesField('pgn', 0),               # PGN of the message being transferred
    ]


class J1939_TP_CM_CTS(Packet):
    """J1939 TP Connection Management – Clear To Send (CTS).

    Response to :class:`J1939_TP_CM_RTS`; authorises the sender to transmit
    up to *num_packets* TP.DT packets starting from *next_packet*.
    """
    name = 'J1939_TP_CM_CTS'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_CTS),         # 17
        ByteField('num_packets', 0),                  # number of packets to send now
        ByteField('next_packet', 1),                  # next expected sequence number
        ShortField('reserved', 0xFFFF),
        XLE3BytesField('pgn', 0),                    # PGN of the message
    ]


class J1939_TP_CM_ACK(Packet):
    """J1939 TP Connection Management – End of Message Acknowledge (EoMAck).

    Sent by the receiver after all TP.DT packets have been received.
    """
    name = 'J1939_TP_CM_ACK'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_ACK),         # 19
        LEShortField('total_size', 0),                # total message size
        ByteField('num_packets', 0),                  # total TP.DT packets received
        ByteField('reserved', 0xFF),
        XLE3BytesField('pgn', 0),                    # PGN of the message
    ]


class J1939_TP_CM_BAM(Packet):
    """J1939 TP Connection Management – Broadcast Announce Message (BAM).

    Announces a forthcoming multi-packet broadcast; no CTS handshake is used.
    """
    name = 'J1939_TP_CM_BAM'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_BAM),         # 32
        LEShortField('total_size', 0),                # total message size (bytes)
        ByteField('num_packets', 0),                  # total number of TP.DT packets
        ByteField('reserved', 0xFF),
        XLE3BytesField('pgn', 0),                    # PGN of the message
    ]


class J1939_TP_CM_ABORT(Packet):
    """J1939 TP Connection Management – Connection Abort."""
    name = 'J1939_TP_CM_ABORT'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_ABORT),       # 255
        ByteField('reason', 0),                       # abort reason
        ShortField('reserved', 0xFFFF),
        ByteField('reserved2', 0xFF),
        XLE3BytesField('pgn', 0),                    # PGN of the aborted message
    ]


class J1939_TP_CM(Packet):
    """J1939 TP Connection Management frame dispatcher.

    Parses a raw 8-byte TP.CM payload and returns the appropriate sub-class.

    Example::

        >>> J1939_TP_CM(bytes([32, 20, 0, 3, 0xFF, 0xCA, 0xFE, 0x00]))
        <J1939_TP_CM_BAM  ctrl=32 total_size=20 num_packets=3 ... >
    """
    name = 'J1939_TP_CM'

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        if _pkt and len(_pkt) >= 1:
            ctrl = _pkt[0]
            if ctrl == J1939_TP_CTRL_RTS:
                return J1939_TP_CM_RTS
            elif ctrl == J1939_TP_CTRL_CTS:
                return J1939_TP_CM_CTS
            elif ctrl == J1939_TP_CTRL_ACK:
                return J1939_TP_CM_ACK
            elif ctrl == J1939_TP_CTRL_BAM:
                return J1939_TP_CM_BAM
            elif ctrl == J1939_TP_CTRL_ABORT:
                return J1939_TP_CM_ABORT
        return cls

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        return s


class J1939_TP_DT(Packet):
    """J1939 TP Data Transfer frame.

    Each TP.DT packet carries up to 7 bytes of payload; the first byte is the
    sequence number (1–255).  Unused bytes are padded with ``0xFF``.
    """
    name = 'J1939_TP_DT'
    fields_desc = [
        ByteField('seq_num', 1),                      # sequence number 1-255
        StrFixedLenField('data', b'\xff' * 7, 7),     # 7 data bytes (0xFF = unused)
    ]


# ---------------------------------------------------------------------------
# NativeJ1939Socket
# ---------------------------------------------------------------------------

class NativeJ1939Socket(SuperSocket):
    """Linux kernel J1939 socket (``PF_CAN / SOCK_DGRAM / CAN_J1939``).

    The kernel J1939 stack handles transport-protocol framing automatically:
    messages larger than 8 bytes are fragmented / reassembled transparently,
    and the application deals only with complete J1939 messages.

    .. note:: Design – why not inherit from ``NativeCANSocket``?

        :class:`~scapy.contrib.cansocket_native.NativeCANSocket` uses
        ``SOCK_RAW / CAN_RAW``, while this class uses
        ``SOCK_DGRAM / CAN_J1939``.  The socket type, protocol, ``send()``
        logic (``sendto`` with 4-tuple destination vs plain ``send``),
        ``recv()`` logic (``recvmsg`` for J1939 ancillary data vs raw bytes
        + byte-order swap), and address binding API are all fundamentally
        different.  Inheriting from ``NativeCANSocket`` would override or
        bypass every method, making the hierarchy misleading rather than
        helpful.

    :param channel:   CAN interface name (default: ``can0``)
    :param src_name:  64-bit J1939 NAME of this node (0 = no name)
    :param src_addr:  Source address to bind to (:data:`socket.J1939_NO_ADDR` for
                      promiscuous reception of all addresses)
    :param pgn:       PGN to bind to (:data:`socket.J1939_NO_PGN` for all PGNs)
    :param promisc:   Enable promiscuous mode – receive all J1939 messages on
                      the interface regardless of destination address
    :param filters:   Optional list of ``j1939_filter`` dicts; each may
                      contain the keys ``name``, ``name_mask``, ``pgn``,
                      ``pgn_mask``, ``addr``, ``addr_mask``
    :param basecls:   Packet class used to wrap received payloads
                      (default: :class:`J1939`)

    Example – sniff all J1939 traffic on *vcan0*::

        >>> sock = NativeJ1939Socket("vcan0", promisc=True)
        >>> pkt = sock.recv()
        >>> print(pkt.pgn, pkt.src, pkt.data)

    Example – send a J1939 message::

        >>> sock = NativeJ1939Socket("vcan0", src_addr=0x00)
        >>> sock.send(J1939(data=b'\\x01\\x02', pgn=0xFECA, dst=0xFF))
    """

    desc = "read/write J1939 messages using Linux kernel PF_CAN/CAN_J1939 sockets"

    # struct j1939_filter: name(Q=8) name_mask(Q=8) pgn(I=4) pgn_mask(I=4) addr(B=1) addr_mask(B=1)  # noqa: E501
    # Packed size of the 6 fields = 8+8+4+4+1+1 = 26 bytes.
    # sizeof(struct j1939_filter) = 32 bytes on 64-bit Linux: the compiler adds 6 bytes of  # noqa: E501
    # trailing padding so that the struct size is a multiple of the largest member alignment  # noqa: E501
    # (__u64, 8 bytes).  The padding must be included when passing an array to setsockopt(2).  # noqa: E501
    _J1939_FILTER_FMT = "=QQIIBB"
    _J1939_FILTER_PAD = b'\x00' * 6  # 6 bytes padding to reach 32-byte alignment

    def __init__(
            self,
            channel=None,           # type: Optional[str]
            src_name=socket.J1939_NO_NAME,  # type: int
            src_addr=socket.J1939_NO_ADDR,  # type: int
            pgn=socket.J1939_NO_PGN,        # type: int
            promisc=True,            # type: bool
            filters=None,            # type: Optional[List[Dict[str, int]]]
            basecls=J1939,           # type: Type[Packet]
            **kwargs                 # type: Any
    ):
        # type: (...) -> None
        self.channel = channel or conf.contribs['J1939']['channel']
        self.src_name = src_name
        self.src_addr = src_addr
        self.pgn = pgn
        self.basecls = basecls

        self.ins = socket.socket(
            socket.PF_CAN, socket.SOCK_DGRAM, socket.CAN_J1939
        )

        if promisc:
            try:
                self.ins.setsockopt(
                    socket.SOL_CAN_J1939,
                    socket.SO_J1939_PROMISC,
                    struct.pack('i', 1),
                )
            except OSError as exc:
                raise Scapy_Exception(
                    "Could not enable J1939 promiscuous mode: %s" % exc
                )

        # Allow sending and receiving broadcast (global address 0xFF / socket.J1939_NO_ADDR).  # noqa: E501
        # The Linux kernel J1939 stack refuses sendto() calls with addr=socket.J1939_NO_ADDR  # noqa: E501
        # unless SO_BROADCAST is set, returning EACCES.
        try:
            self.ins.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BROADCAST,
                struct.pack('i', 1),
            )
        except OSError as exc:
            raise Scapy_Exception(
                "Could not enable SO_BROADCAST on J1939 socket: %s" % exc
            )

        # Enable ancillary data so we can read destination address and priority
        try:
            self.ins.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            self.auxdata_available = True
        except OSError:
            self.auxdata_available = False
            log_runtime.info("SO_TIMESTAMPNS not supported on this kernel")

        if filters is not None:
            self._set_filters(filters)

        self.ins.bind((self.channel, src_name, pgn, src_addr))
        self.outs = self.ins

    def _set_filters(self, filters):
        # type: (List[Dict[str, int]]) -> None
        """Apply a list of J1939 filters to the socket.

        Each filter dict may contain any of:
        ``name``, ``name_mask``, ``pgn``, ``pgn_mask``, ``addr``, ``addr_mask``.
        """
        packed = b''
        for f in filters:
            packed += struct.pack(
                self._J1939_FILTER_FMT,
                f.get('name', socket.J1939_NO_NAME),
                f.get('name_mask', socket.J1939_NO_NAME),
                f.get('pgn', socket.J1939_NO_PGN),
                f.get('pgn_mask', socket.J1939_NO_PGN),
                f.get('addr', socket.J1939_NO_ADDR),
                f.get('addr_mask', socket.J1939_NO_ADDR),
            ) + self._J1939_FILTER_PAD
        try:
            self.ins.setsockopt(socket.SOL_CAN_J1939, socket.SO_J1939_FILTER, packed)
        except OSError as exc:
            raise Scapy_Exception(
                "Could not set J1939 filter: %s" % exc
            )

    def recv_raw(self, x=4096):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]
        """Returns a tuple ``(cls, pkt_data, timestamp)``.

        .. note::
            The returned *pkt_data* is only the raw J1939 payload bytes.
            Addressing metadata (PGN, source/destination address, priority) is
            unavailable through this low-level interface; use :meth:`recv`
            instead to obtain a fully populated :class:`J1939` packet.
        """
        try:
            pkt_data = self.ins.recv(x)
        except BlockingIOError:
            log_j1939.warning('Captured no data, socket in non-blocking mode.')
            return None, None, None
        except socket.timeout:
            log_j1939.warning('Captured no data, socket read timed out.')
            return None, None, None
        except OSError as exc:
            log_j1939.warning('Captured no data: %s', exc)
            return None, None, None

        return self.basecls, pkt_data, None

    def recv(self, x=4096, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        """Receive one J1939 message, including addressing metadata.

        Returns a :attr:`basecls` instance (default: :class:`J1939`) with
        ``priority``, ``pgn``, ``src``, and ``dst`` populated from the kernel.
        """
        try:
            data, ancdata, _flags, addr = self.ins.recvmsg(x, 256)
        except BlockingIOError:
            log_j1939.warning('Captured no data, socket in non-blocking mode.')
            return None
        except socket.timeout:
            log_j1939.warning('Captured no data, socket read timed out.')
            return None
        except OSError as exc:
            log_j1939.warning('Captured no data: %s', exc)
            return None

        # addr = (iface_name, name, pgn, src_addr)
        _iface, _src_name, src_pgn, src_addr = addr

        dst_addr = socket.J1939_NO_ADDR
        priority = 6
        ts = None

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_CAN_J1939:
                if cmsg_type == socket.SCM_J1939_DEST_ADDR:
                    if cmsg_data:
                        dst_addr = struct.unpack('B', cmsg_data[:1])[0]
                elif cmsg_type == socket.SCM_J1939_PRIO:
                    if cmsg_data:
                        priority = struct.unpack('B', cmsg_data[:1])[0]

        if ts is None:
            ts = time.time()

        try:
            pkt = self.basecls(
                data,
                priority=priority,
                pgn=src_pgn,
                src=src_addr,
                dst=dst_addr,
            )
        except Exception:
            pkt = self.basecls(data)

        pkt.time = ts
        return pkt

    def send(self, x):
        # type: (Packet) -> int
        """Send a J1939 message.

        If *x* is a :class:`J1939` packet, the ``pgn``, ``dst``, and
        ``priority`` attributes are used.  For other packet types the raw bytes
        are sent to the socket's default destination.
        """
        if x is None:
            return 0

        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        # Extract payload bytes
        if isinstance(x, J1939):
            data = x.data if isinstance(x.data, bytes) else raw(x)
            dst_pgn = x.pgn if x.pgn != 0 else socket.J1939_NO_PGN
            dst_addr = x.dst
            priority = x.priority
        else:
            data = raw(x)
            dst_pgn = socket.J1939_NO_PGN
            dst_addr = socket.J1939_NO_ADDR
            priority = 6

        # Set per-message priority
        try:
            self.outs.setsockopt(
                socket.SOL_CAN_J1939,
                socket.SO_J1939_SEND_PRIO,
                struct.pack('i', priority),
            )
        except OSError:
            pass  # not critical

        dst = (self.channel, socket.J1939_NO_NAME, dst_pgn, dst_addr)
        try:
            return self.outs.sendto(data, dst)
        except OSError as exc:
            log_j1939.error("Failed to send J1939 packet: %s", exc)
            return 0


# ---------------------------------------------------------------------------
# J1939 Soft Socket
# ---------------------------------------------------------------------------
# Implements the SAE J1939 Transport Protocol (segmentation and reassembly)
# entirely in Python over any CANSocket, without requiring the Linux kernel
# CAN_J1939 socket module.  The design mirrors ISOTPSoftSocket from
# scapy.contrib.isotp.isotp_soft_socket.

# J1939-21 transport-protocol timing constants (seconds)
_J1939_TP_BAM_DELAY = 0.050   # minimum inter-packet gap for BAM sender (50 ms)
_J1939_TP_T1 = 0.750          # receiver timeout for first DT after BAM/RTS
_J1939_TP_T2 = 1.250          # receiver timeout between consecutive DT frames
_J1939_TP_T3 = 1.250          # sender timeout waiting for CTS after RTS/block
_J1939_TP_T4 = 1.050          # sender timeout waiting for End-of-Message ACK

# On slow serial interfaces (slcan) the OS serial buffer may hold hundreds of
# background CAN frames that the mux must drain before the TP.DT frames
# arrive.  When the inactivity timer fires, the handler checks the total
# elapsed time; if it is below _J1939_TP_T2 × _J1939_TP_DT_TIMEOUT_EXTENSION
# (i.e. 1.25 s × 10 = 12.5 s), the timer is re-armed and the session
# continues.  Only after that wall-clock ceiling is exceeded is the transfer
# declared timed-out.
_J1939_TP_DT_TIMEOUT_EXTENSION = 10

# Maximum payload / per-frame data constants
_J1939_TP_DT_DATA = 7         # usable data bytes per TP.DT packet
_J1939_TP_MAX_DATA = 1785     # maximum J1939 TP payload (255 × 7 bytes)

# Internal RX state codes
_J1939_RX_IDLE = 0
_J1939_RX_WAIT_DT = 1         # waiting for TP.DT frames

# Internal TX state codes
_J1939_TX_IDLE = 0
_J1939_TX_BAM = 1             # BAM TP.DT frames are being sent
_J1939_TX_RTS_WAIT_CTS = 2   # RTS sent; waiting for CTS
_J1939_TX_RTS_SENDING = 3    # CTS received; sending TP.DT block


class J1939TPImplementation:
    """Software implementation of the SAE J1939 Transport Protocol state machine.

    All state is stored here so that the garbage collector can reclaim a
    :class:`J1939SoftSocket` even while the background
    :class:`~scapy.contrib.isotp.isotp_soft_socket.TimeoutScheduler` thread
    holds a reference to this object.

    :param can_socket: a :class:`~scapy.contrib.cansocket.CANSocket` used for
                       raw CAN I/O
    :param src_addr:   this node's J1939 source address (0x00–0xFD)
    :param listen_only: when ``True`` the implementation never sends CTS, ACK,
                        or ABORT frames, allowing passive monitoring of TP
                        sessions without influencing the bus.  Received payloads
                        are still reassembled and delivered via :meth:`recv`.
    :param pgn_filter: when non-zero, only messages whose PGN matches this
                       value are delivered.  ``0`` (the default) accepts all
                       PGNs.  Inspired by BenGardiner's ``rx_pgn`` parameter.
    """

    def __init__(
            self,
            can_socket,           # type: "CANSocket"
            src_addr,             # type: int
            listen_only=False,    # type: bool
            pgn_filter=0,         # type: int
    ):
        # type: (...) -> None
        from scapy.contrib.isotp.isotp_soft_socket import TimeoutScheduler
        self._TimeoutScheduler = TimeoutScheduler

        self.can_socket = can_socket
        self.src_addr = src_addr
        self.listen_only = listen_only
        self.pgn_filter = pgn_filter  # 0 = accept all PGNs
        self.closed = False
        self.rx_tx_poll_rate = 0.005

        # ── receive path ──────────────────────────────────────────────────────
        self.rx_state = _J1939_RX_IDLE  # type: int
        # Active RX session fields (valid when rx_state == _J1939_RX_WAIT_DT)
        self.rx_pgn = 0                          # PGN being received
        self.rx_peer_sa = socket.J1939_NO_ADDR   # SA of the sending node
        self.rx_dst = socket.J1939_NO_ADDR       # DA (our SA or 0xFF broadcast)
        self.rx_total = 0                         # total payload size (bytes)
        self.rx_npkts = 0                         # total TP.DT packets expected
        self.rx_buf = b''                         # accumulated payload bytes
        self.rx_seq = 1                           # next expected DT seq number
        self.rx_ts = 0.0                          # type: Union[float, EDecimal]
        self.rx_is_bam = True                     # True=BAM; False=RTS/CTS
        self.rx_start_time = 0.0                  # wall-clock start of current TP rx
        self.rx_timeout_handle = None   # type: Optional[Any]

        # Delivered received messages: each item is (J1939, timestamp)
        self.rx_queue = ObjectPipe()   # type: ignore

        # ── transmit path ─────────────────────────────────────────────────────
        self.tx_state = _J1939_TX_IDLE  # type: int
        self.tx_buf = None              # type: Optional[bytes]
        self.tx_pgn = 0
        self.tx_dst = socket.J1939_NO_ADDR
        self.tx_priority = 6
        self.tx_data_page = 0
        self.tx_npkts = 0               # total TP.DT packets to send
        self.tx_seq = 1                 # next TP.DT sequence number to send
        self.tx_peer_sa = socket.J1939_NO_ADDR  # peer SA for RTS/CTS sessions
        # CTS block management
        self.tx_cts_count = 0           # DTs still to send in current CTS block
        self.tx_timeout_handle = None   # type: Optional[Any]

        # Enqueued outgoing messages: each item is a J1939 packet
        self.tx_queue = ObjectPipe()   # type: ignore

        # ── background polling ────────────────────────────────────────────────
        self.rx_handle = TimeoutScheduler.schedule(0, self.can_recv)
        self.tx_handle = TimeoutScheduler.schedule(0, self._tx_poll)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def __del__(self):
        # type: () -> None
        self.close()

    def close(self):
        # type: () -> None
        if self.closed:
            return
        # Wait for any in-progress TX to drain before shutting down.
        # This ensures that a send() followed immediately by close() (e.g.
        # inside a ``with`` statement) still delivers every queued message.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if (self.tx_state == _J1939_TX_IDLE
                    and not select_objects([self.tx_queue], 0)):
                break
            time.sleep(0.005)
        self.closed = True
        # Brief pause so any in-flight scheduler callback sees the flag.
        time.sleep(0.005)

        for handle in (self.rx_handle, self.tx_handle,
                       self.rx_timeout_handle, self.tx_timeout_handle):
            if handle is not None:
                try:
                    handle.cancel()
                except Exception:
                    pass

        try:
            self.rx_queue.close()
        except Exception:
            pass
        try:
            self.tx_queue.close()
        except Exception:
            pass

    # ── CAN receive loop ─────────────────────────────────────────────────────

    def can_recv(self):
        # type: () -> None
        if self.closed:
            return
        try:
            while self.can_socket.select([self.can_socket], 0):
                if self.closed:
                    break
                pkt = self.can_socket.recv()
                if pkt:
                    self.on_can_recv(pkt)
                else:
                    break
        except Exception:
            if not self.closed:
                log_j1939.warning(
                    "J1939TPImplementation.can_recv error: %s",
                    traceback.format_exc())

        if not self.closed and not self.can_socket.closed:
            self.rx_handle = self._TimeoutScheduler.schedule(
                self.rx_tx_poll_rate, self.can_recv)

    def on_can_recv(self, pkt):
        # type: (Packet) -> None
        """Decode *pkt* as a :class:`J1939_CAN` frame and route it."""
        try:
            j = J1939_CAN(bytes(pkt))
            j.time = getattr(pkt, 'time', None) or time.time()
        except Exception:
            return

        pf = j.pdu_format
        ps = j.pdu_specific
        sa = j.src

        # Ignore frames sent by this node (CAN loopback echo guard).
        if sa == self.src_addr:
            return

        # ── TP.CM (PF = 0xEC) ────────────────────────────────────────────────
        if pf == (J1939_PGN_TP_CM >> 8):          # 0xEC
            # PS must address us or be broadcast.
            if ps != self.src_addr and ps != socket.J1939_NO_ADDR:
                return
            self._on_tp_cm(j)
            return

        # ── TP.DT (PF = 0xEB) ────────────────────────────────────────────────
        if pf == (J1939_PGN_TP_DT >> 8):          # 0xEB
            if ps != self.src_addr and ps != socket.J1939_NO_ADDR:
                return
            self._on_tp_dt(j)
            return

        # ── Short (≤ 8-byte) data frame ──────────────────────────────────────
        # PDU1: ps is the destination address.  PDU2: always broadcast.
        if pf <= J1939_PDU1_MAX_PF:
            if ps != self.src_addr and ps != socket.J1939_NO_ADDR:
                return
        self._on_short_frame(j)

    # ── RX frame handlers ────────────────────────────────────────────────────

    def _on_short_frame(self, j):
        # type: (J1939_CAN) -> None
        data = bytes(j.data)
        if self.pgn_filter != 0 and j.pgn != self.pgn_filter:
            return
        msg = J1939(data, pgn=j.pgn, src=j.src, dst=j.dst, priority=j.priority)
        self.rx_queue.send((msg, j.time))

    def _on_tp_cm(self, j):
        # type: (J1939_CAN) -> None
        data = bytes(j.data)
        if not data:
            return
        ctrl = data[0]
        sa = j.src
        ts = j.time

        if ctrl == J1939_TP_CTRL_BAM:
            if len(data) < 8:
                return
            cm = J1939_TP_CM_BAM(data)
            if self.pgn_filter != 0 and cm.pgn != self.pgn_filter:
                return
            if self.rx_state != _J1939_RX_IDLE:
                log_j1939.debug("J1939 TP: new BAM overwrites active RX session")
                self._rx_reset()
            self._rx_start(sa=sa, pgn=cm.pgn, dst=socket.J1939_NO_ADDR,
                           total=cm.total_size, npkts=cm.num_packets,
                           is_bam=True, ts=ts)

        elif ctrl == J1939_TP_CTRL_RTS:
            if len(data) < 8:
                return
            cm = J1939_TP_CM_RTS(data)
            if self.pgn_filter != 0 and cm.pgn != self.pgn_filter:
                return
            if self.rx_state != _J1939_RX_IDLE:
                log_j1939.debug("J1939 TP: new RTS overwrites active RX session")
                self._rx_reset()
            self._rx_start(sa=sa, pgn=cm.pgn, dst=self.src_addr,
                           total=cm.total_size, npkts=cm.num_packets,
                           is_bam=False, ts=ts)
            # Respond with CTS authorising all packets starting at seq 1.
            if not self.listen_only:
                self._can_send_tp_cm(
                    dst_sa=sa,
                    data=bytes(J1939_TP_CM_CTS(
                        num_packets=cm.num_packets,
                        next_packet=1,
                        pgn=cm.pgn,
                    )),
                )

        elif ctrl == J1939_TP_CTRL_CTS:
            if (self.tx_state == _J1939_TX_RTS_WAIT_CTS
                    and sa == self.tx_peer_sa and len(data) >= 8):
                self._tx_handle_cts(J1939_TP_CM_CTS(data))

        elif ctrl == J1939_TP_CTRL_ACK:
            if (self.tx_state in (_J1939_TX_RTS_WAIT_CTS, _J1939_TX_RTS_SENDING)
                    and sa == self.tx_peer_sa):
                self._tx_reset()

        elif ctrl == J1939_TP_CTRL_ABORT:
            if sa == self.tx_peer_sa:
                reason = data[1] if len(data) > 1 else 0
                log_j1939.warning(
                    "J1939 TP: TX session aborted by peer (reason %d)", reason)
                self._tx_reset()

    def _on_tp_dt(self, j):
        # type: (J1939_CAN) -> None
        if self.rx_state != _J1939_RX_WAIT_DT:
            return
        sa = j.src
        if sa != self.rx_peer_sa:
            return
        data = bytes(j.data)
        if len(data) < 8:
            return

        dt = J1939_TP_DT(data)
        seq = dt.seq_num
        if seq != self.rx_seq:
            log_j1939.warning(
                "J1939 TP: bad DT seq %d (expected %d)", seq, self.rx_seq)
            if not self.rx_is_bam and not self.listen_only:
                self._can_send_tp_cm(
                    dst_sa=sa,
                    data=bytes(J1939_TP_CM_ABORT(reason=7, pgn=self.rx_pgn)),
                )
            self._rx_reset()
            return

        self.rx_buf += dt.data
        self.rx_seq += 1

        # Cancel / reschedule the DT timeout.
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
            except Exception:
                pass
            self.rx_timeout_handle = None

        if seq >= self.rx_npkts:
            # All packets received – finalise the message.
            payload = self.rx_buf[:self.rx_total]
            if not self.rx_is_bam and not self.listen_only:
                self._can_send_tp_cm(
                    dst_sa=sa,
                    data=bytes(J1939_TP_CM_ACK(
                        total_size=self.rx_total,
                        num_packets=self.rx_npkts,
                        pgn=self.rx_pgn,
                    )),
                )
            msg = J1939(payload,
                        pgn=self.rx_pgn, src=self.rx_peer_sa,
                        dst=self.rx_dst, priority=6)
            self.rx_queue.send((msg, self.rx_ts))
            self._rx_reset()
        else:
            self.rx_timeout_handle = self._TimeoutScheduler.schedule(
                _J1939_TP_T2, self._rx_timeout)

    # ── RX session helpers ────────────────────────────────────────────────────

    def _rx_start(self, sa, pgn, dst, total, npkts, is_bam, ts):
        # type: (int, int, int, int, int, bool, Union[float, EDecimal]) -> None
        self.rx_state = _J1939_RX_WAIT_DT
        self.rx_peer_sa = sa
        self.rx_pgn = pgn
        self.rx_dst = dst
        self.rx_total = total
        self.rx_npkts = npkts
        self.rx_buf = b''
        self.rx_seq = 1
        self.rx_ts = ts
        self.rx_is_bam = is_bam
        self.rx_start_time = time.monotonic()
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
            except Exception:
                pass
        self.rx_timeout_handle = self._TimeoutScheduler.schedule(
            _J1939_TP_T1, self._rx_timeout)

    def _rx_reset(self):
        # type: () -> None
        self.rx_state = _J1939_RX_IDLE
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
            except Exception:
                pass
            self.rx_timeout_handle = None

    def _rx_timeout(self):
        # type: () -> None
        if self.closed or self.rx_state == _J1939_RX_IDLE:
            return
        # On slow serial interfaces (slcan) the OS serial buffer may hold many
        # background CAN frames queued ahead of TP.DT frames.  Re-arm the
        # timer as long as the total elapsed time since the session started is
        # below _J1939_TP_T2 × _J1939_TP_DT_TIMEOUT_EXTENSION (12.5 s total).
        total_wait = time.monotonic() - self.rx_start_time
        if total_wait < _J1939_TP_T2 * _J1939_TP_DT_TIMEOUT_EXTENSION:
            self.rx_timeout_handle = self._TimeoutScheduler.schedule(
                _J1939_TP_T2, self._rx_timeout)
            return
        log_j1939.warning(
            "J1939 TP: RX timeout – discarding incomplete message "
            "(PGN=0x%05X SA=0x%02X)", self.rx_pgn, self.rx_peer_sa)
        self._rx_reset()

    # ── CAN send helpers ──────────────────────────────────────────────────────

    def _can_send(self, pkt):
        # type: (J1939_CAN) -> None
        try:
            self.can_socket.send(pkt)
        except Exception:
            log_j1939.warning(
                "J1939 CAN send failed: %s", traceback.format_exc())

    def _can_send_tp_cm(self, dst_sa, data):
        # type: (int, bytes) -> None
        pkt = J1939_CAN(
            priority=6, data_page=0,
            pdu_format=J1939_PGN_TP_CM >> 8,   # 0xEC
            pdu_specific=dst_sa,
            src=self.src_addr,
            data=data,
        )
        self._can_send(pkt)

    def _can_send_tp_dt(self, dst_sa, seq_num, chunk):
        # type: (int, int, bytes) -> None
        padded = chunk + b'\xff' * (_J1939_TP_DT_DATA - len(chunk))
        dt = J1939_TP_DT(seq_num=seq_num, data=padded[:_J1939_TP_DT_DATA])
        pkt = J1939_CAN(
            priority=7, data_page=0,
            pdu_format=J1939_PGN_TP_DT >> 8,   # 0xEB
            pdu_specific=dst_sa,
            src=self.src_addr,
            data=bytes(dt),
        )
        self._can_send(pkt)

    # ── TX state machine ──────────────────────────────────────────────────────

    def _tx_poll(self):
        # type: () -> None
        """Dequeue and start transmitting the next J1939 message."""
        if self.closed:
            return
        try:
            if self.tx_state == _J1939_TX_IDLE:
                if select_objects([self.tx_queue], 0):
                    msg = self.tx_queue.recv()
                    if msg is not None:
                        self._begin_send(msg)
        except Exception:
            if not self.closed:
                log_j1939.warning(
                    "J1939 _tx_poll error: %s", traceback.format_exc())
        if not self.closed:
            self.tx_handle = self._TimeoutScheduler.schedule(
                self.rx_tx_poll_rate, self._tx_poll)

    def _begin_send(self, msg):
        # type: (Packet) -> None
        """Start transmitting *msg*. Called from _tx_poll in the scheduler thread."""
        if isinstance(msg, J1939):
            data = msg.data
            if not isinstance(data, (bytes, bytearray)):
                data = bytes(msg)
            data = bytes(data)
            pgn = msg.pgn
            dst = msg.dst
            priority = msg.priority
        else:
            data = bytes(msg)
            pgn = 0
            dst = socket.J1939_NO_ADDR
            priority = 6

        data_page = (pgn >> 16) & 0x1
        pf = (pgn >> 8) & 0xFF

        if len(data) <= 8:
            # Single CAN frame – no TP needed.
            if pf <= J1939_PDU1_MAX_PF:
                ps = dst & 0xFF
            else:
                ps = pgn & 0xFF
            pkt = J1939_CAN(
                priority=priority, data_page=data_page,
                pdu_format=pf, pdu_specific=ps,
                src=self.src_addr, data=data,
            )
            self._can_send(pkt)

        elif dst == socket.J1939_NO_ADDR or dst == 0xFF:
            # Broadcast multi-packet message via BAM.
            self._tx_start_bam(data, pgn, dst, priority, data_page)

        else:
            # Unicast multi-packet message via RTS/CTS.
            self._tx_start_rts(data, pgn, dst, priority, data_page)

    # ── BAM TX ───────────────────────────────────────────────────────────────

    def _tx_start_bam(self, data, pgn, dst, priority, data_page):
        # type: (bytes, int, int, int, int) -> None
        npkts = (len(data) + _J1939_TP_DT_DATA - 1) // _J1939_TP_DT_DATA
        # Set tx_state BEFORE the CAN send so that close() does not see the
        # queue empty with state=IDLE and break out of the drain loop early
        # (race window: CAN send may block on slow adapters).
        self.tx_state = _J1939_TX_BAM
        self.tx_buf = data
        self.tx_pgn = pgn
        self.tx_dst = dst
        self.tx_priority = priority
        self.tx_data_page = data_page
        self.tx_npkts = npkts
        self.tx_seq = 1
        bam = J1939_TP_CM_BAM(total_size=len(data), num_packets=npkts, pgn=pgn)
        self._can_send_tp_cm(socket.J1939_NO_ADDR, bytes(bam))
        self.tx_timeout_handle = self._TimeoutScheduler.schedule(
            _J1939_TP_BAM_DELAY, self._tx_bam_next_dt)

    def _tx_bam_next_dt(self):
        # type: () -> None
        if self.closed or self.tx_state != _J1939_TX_BAM or self.tx_buf is None:
            self._tx_reset()
            return
        seq = self.tx_seq
        start = (seq - 1) * _J1939_TP_DT_DATA
        chunk = self.tx_buf[start:start + _J1939_TP_DT_DATA]
        self._can_send_tp_dt(socket.J1939_NO_ADDR, seq, chunk)
        self.tx_seq += 1
        if self.tx_seq > self.tx_npkts:
            self._tx_reset()
        else:
            self.tx_timeout_handle = self._TimeoutScheduler.schedule(
                _J1939_TP_BAM_DELAY, self._tx_bam_next_dt)

    # ── RTS/CTS TX ───────────────────────────────────────────────────────────

    def _tx_start_rts(self, data, pgn, dst, priority, data_page):
        # type: (bytes, int, int, int, int) -> None
        npkts = (len(data) + _J1939_TP_DT_DATA - 1) // _J1939_TP_DT_DATA
        # Set tx_state BEFORE the CAN send (same race-prevention as _tx_start_bam).
        self.tx_state = _J1939_TX_RTS_WAIT_CTS
        self.tx_buf = data
        self.tx_pgn = pgn
        self.tx_dst = dst
        self.tx_priority = priority
        self.tx_data_page = data_page
        self.tx_npkts = npkts
        self.tx_seq = 1
        self.tx_peer_sa = dst
        rts = J1939_TP_CM_RTS(
            total_size=len(data), num_packets=npkts,
            max_packets=0xFF, pgn=pgn,
        )
        self._can_send_tp_cm(dst, bytes(rts))
        self.tx_timeout_handle = self._TimeoutScheduler.schedule(
            _J1939_TP_T3, self._tx_timeout)

    def _tx_handle_cts(self, cts):
        # type: (J1939_TP_CM_CTS) -> None
        if self.tx_timeout_handle is not None:
            try:
                self.tx_timeout_handle.cancel()
            except Exception:
                pass
            self.tx_timeout_handle = None

        if cts.num_packets == 0:
            # Receiver requested a hold; wait for another CTS.
            self.tx_state = _J1939_TX_RTS_WAIT_CTS
            self.tx_timeout_handle = self._TimeoutScheduler.schedule(
                _J1939_TP_T3, self._tx_timeout)
            return

        self.tx_cts_count = cts.num_packets
        self.tx_seq = cts.next_packet
        self.tx_state = _J1939_TX_RTS_SENDING
        self._tx_rts_send_block()

    def _tx_rts_send_block(self):
        # type: () -> None
        """Send the block of TP.DT frames authorised by the most recent CTS."""
        if self.closed or self.tx_state != _J1939_TX_RTS_SENDING \
                or self.tx_buf is None:
            self._tx_reset()
            return

        sent = 0
        while sent < self.tx_cts_count:
            seq = self.tx_seq
            if seq > self.tx_npkts:
                break
            start = (seq - 1) * _J1939_TP_DT_DATA
            chunk = self.tx_buf[start:start + _J1939_TP_DT_DATA]
            self._can_send_tp_dt(self.tx_dst, seq, chunk)
            self.tx_seq += 1
            sent += 1

        # After the block, wait for the next CTS (or ACK if all data sent).
        self.tx_state = _J1939_TX_RTS_WAIT_CTS
        timeout = _J1939_TP_T4 if self.tx_seq > self.tx_npkts else _J1939_TP_T3
        self.tx_timeout_handle = self._TimeoutScheduler.schedule(
            timeout, self._tx_timeout)

    def _tx_timeout(self):
        # type: () -> None
        if self.closed or self.tx_state == _J1939_TX_IDLE:
            return
        log_j1939.warning(
            "J1939 TP: TX timeout (PGN=0x%05X DA=0x%02X)",
            self.tx_pgn, self.tx_dst)
        self._tx_reset()

    def _tx_reset(self):
        # type: () -> None
        self.tx_state = _J1939_TX_IDLE
        self.tx_buf = None
        if self.tx_timeout_handle is not None:
            try:
                self.tx_timeout_handle.cancel()
            except Exception:
                pass
            self.tx_timeout_handle = None

    # ── public interface ─────────────────────────────────────────────────────

    def send(self, msg):
        # type: (Packet) -> None
        """Enqueue *msg* for transmission.

        Also schedules an immediate TX poll so the message is picked up
        without waiting for the next 5 ms polling interval.  This allows
        ``send()`` followed immediately by ``close()`` to reliably deliver
        the frame (e.g. inside a ``with J1939SoftSocket(...) as s:`` block).
        """
        self.tx_queue.send(msg)
        # Cancel the pending poll and reschedule it to fire immediately so
        # the message is dispatched within microseconds, not up to 5 ms later.
        if self.tx_handle is not None:
            try:
                self.tx_handle.cancel()
            except Exception:
                pass
        self.tx_handle = self._TimeoutScheduler.schedule(0, self._tx_poll)

    def recv(self):
        # type: () -> Optional[Tuple[J1939, Union[float, EDecimal]]]
        """Return the next received :class:`J1939` message from the queue."""
        return self.rx_queue.recv()  # type: ignore


class J1939SoftSocket(SuperSocket):
    """Software J1939 application-layer socket over a :class:`CANSocket`.

    Implements the SAE J1939 Transport Protocol (segmentation and
    reassembly) entirely in Python, without requiring the Linux kernel
    ``CAN_J1939`` socket module.  It is API-compatible with
    :class:`NativeJ1939Socket` and works on any platform that has a CAN
    socket layer (Linux SocketCAN via
    :class:`~scapy.contrib.cansocket_native.NativeCANSocket`, or any platform
    via :class:`~scapy.contrib.cansocket_python_can.PythonCANSocket`).

    The implementation mirrors :class:`~scapy.contrib.isotp.ISOTPSoftSocket`:
    a background thread driven by
    :class:`~scapy.contrib.isotp.isotp_soft_socket.TimeoutScheduler` polls the
    CAN socket and advances the TP state machine, so
    :class:`J1939SoftSocket` can send Flow-Control (CTS / ACK / ABORT) frames
    even before :meth:`recv` is called.

    Example – broadcast receive::

        >>> cansock = NativeCANSocket("vcan0")
        >>> with J1939SoftSocket(cansock, src_addr=0x00) as s:
        ...     pkt = s.recv()

    Example – broadcast send::

        >>> cansock = NativeCANSocket("vcan0")
        >>> with J1939SoftSocket(cansock, src_addr=0x00) as s:
        ...     s.send(J1939(b'\\x01\\x02', pgn=0xFECA, dst=0xFF))

    :param can_socket: a :class:`~scapy.contrib.cansocket.CANSocket` instance
                       *or* a CAN interface name string (Linux only)
    :param src_addr:   this node's J1939 source address (0x00–0xFD);
                       defaults to :data:`socket.J1939_NO_ADDR` (0xFE = no address)
    :param basecls:    packet class for received messages
                       (default: :class:`J1939`)
    :param listen_only: when ``True``, never send CTS / ACK / ABORT frames;
                        all received TP sessions are still reassembled and
                        delivered.  Useful for passive bus monitoring.
    :param pgn:        when non-zero, only messages whose PGN matches this
                       value are delivered; ``0`` (the default) accepts every
                       PGN.  Inspired by BenGardiner's ``rx_pgn`` parameter.
    """

    desc = ("read/write J1939 messages using a software "
            "transport-protocol implementation")

    def __init__(
            self,
            can_socket=None,                        # type: Optional["CANSocket"]
            src_addr=socket.J1939_NO_ADDR,          # type: int
            basecls=J1939,                          # type: Type[Packet]
            listen_only=False,                      # type: bool
            pgn=0,                                  # type: int
    ):
        # type: (...) -> None
        if LINUX and isinstance(can_socket, str):
            from scapy.contrib.cansocket_native import NativeCANSocket
            can_socket = NativeCANSocket(can_socket)
        elif isinstance(can_socket, str):
            raise Scapy_Exception(
                "Provide a CANSocket object instead of an interface name")

        self.src_addr = src_addr
        self.basecls = basecls

        impl = J1939TPImplementation(
            can_socket, src_addr,
            listen_only=listen_only,
            pgn_filter=pgn,
        )
        # Cast so SuperSocket internals are satisfied (recv/send are overridden).
        self.ins = cast(socket.socket, impl)
        self.outs = cast(socket.socket, impl)
        self.impl = impl

        if basecls is None:
            log_j1939.warning("Provide a basecls")

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def close(self):
        # type: () -> None
        if not self.closed:
            if hasattr(self, "impl"):
                self.impl.close()
            self.closed = True

    # ── recv / send ──────────────────────────────────────────────────────────

    def recv_raw(self, x=0xffff):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]
        # Not used for J1939SoftSocket; recv() is overridden directly.
        return self.basecls, None, None

    def recv(self, x=0xffff, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        """Receive the next :class:`J1939` message.

        Blocks until a complete message is available or the socket is closed.
        Returns ``None`` if the socket is closed before a message arrives.
        """
        if self.closed:
            return None
        tup = self.impl.recv()
        if tup is None:
            return None
        msg, ts = tup
        msg.time = float(ts)
        return msg

    def send(self, x):
        # type: (Packet) -> int
        """Enqueue *x* for transmission.

        If *x* is a :class:`J1939` packet its ``pgn``, ``dst``, and
        ``priority`` attributes are used.  Payloads of 8 bytes or fewer are
        sent as a single CAN frame; larger payloads use the J1939 Transport
        Protocol automatically (BAM for broadcast, RTS/CTS for unicast).
        """
        if self.closed:
            return 0
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        self.impl.send(x)
        return len(bytes(x))

    # ── select ────────────────────────────────────────────────────────────────

    @staticmethod
    def select(sockets, remain=None):  # type: ignore[override]
        # type: (List[Union[SuperSocket, ObjectPipe[Any]]], Optional[float]) -> List[Union[SuperSocket, ObjectPipe[Any]]]  # noqa: E501
        """Support :func:`~scapy.sendrecv.sniff` on :class:`J1939SoftSocket`."""
        obj_pipes = [
            x.impl.rx_queue for x in sockets
            if isinstance(x, J1939SoftSocket) and not x.closed
        ]
        obj_pipes += [
            x for x in sockets
            if isinstance(x, ObjectPipe) and not x.closed
        ]
        ready_pipes = select_objects(obj_pipes, remain)
        result = [
            x for x in sockets
            if isinstance(x, J1939SoftSocket) and not x.closed
            and x.impl.rx_queue in ready_pipes
        ]
        result += [
            x for x in sockets
            if isinstance(x, ObjectPipe) and x in ready_pipes
        ]
        return result  # type: ignore[return-value]
