# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939 (SAE J1939-21) Soft Socket Library
# scapy.contrib.status = library

"""
J1939SoftSocket

A Python implementation of the SAE J1939-21 Transport Layer Protocol,
structured to allow future use of the Linux kernel's native j1939 socket
support (similar to ISOTPNativeSocket / ISOTPSoftSocket).

The SAE J1939 Transport Layer Protocol supports two modes:

- BAM (Broadcast Announce Message) for broadcast multi-packet messages
  (destination address 0xFF / J1939_GLOBAL_ADDRESS)
- CMDT (Connection Mode Data Transfer) for peer-to-peer multi-packet
  messages with flow control

Optionally, SAE J1939-81 Network Management (address claiming) is supported
when the socket is created with a ``name`` (64-bit ECU NAME) parameter.

Reference:

- SAE J1939-21 Data Link Layer specification
- SAE J1939-81 Network Management specification
- Linux kernel j1939 socket documentation:
  https://www.kernel.org/doc/html/latest/networking/j1939.html
- The structure and state-machine approach in this file were adapted from the
  Scapy ISOTPSoftSocket implementation:
  scapy/contrib/isotp/isotp_soft_socket.py
  Copyright (C) Nils Weiss <nils@we155.de>
  Copyright (C) Enrico Pozzobon <enricopozzobon@gmail.com>
  SPDX-License-Identifier: GPL-2.0-only
"""

import heapq
import logging
import socket
import struct
import time
import traceback
from threading import Thread, Event, RLock

# Typing imports
from typing import (
    Optional,
    Union,
    List,
    Tuple,
    Any,
    Type,
    cast,
    Callable,
    TYPE_CHECKING,
)

from scapy.automaton import ObjectPipe, select_objects
from scapy.config import conf
from scapy.consts import LINUX
from scapy.error import Scapy_Exception
from scapy.layers.can import CAN
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import EDecimal

if TYPE_CHECKING:
    from scapy.contrib.cansocket import CANSocket

log_j1939 = logging.getLogger("scapy.contrib.automotive.j1939")

# ---------------------------------------------------------------------------
# J1939 constants (SAE J1939-21)
# ---------------------------------------------------------------------------

#: Global (broadcast) address — used as DA in BAM transfers
J1939_GLOBAL_ADDRESS = 0xFF

#: Maximum data length for a single-frame (unfragmented) J1939 message
J1939_MAX_SF_DLEN = 8

#: Maximum data length for a multi-packet J1939 TP message (255 packets × 7 bytes)
J1939_TP_MAX_DLEN = 1785

#: PDU Format byte for TP Connection Management (TP.CM), PGN 0xEC00
J1939_TP_CM_PF = 0xEC

#: PDU Format byte for TP Data Transfer (TP.DT), PGN 0xEB00
J1939_TP_DT_PF = 0xEB

#: Padding byte used in the last TP.DT frame
J1939_TP_DT_PAD = 0xFF

#: Maximum sequence number in a TP.DT frame (wraps at 255)
J1939_TP_DT_MAX_SN = 255

#: TP.DT payload bytes per frame (7 bytes of data per TP.DT frame)
J1939_TP_DT_PAYLOAD = 7

# TP.CM control bytes
TP_CM_RTS = 0x10  # Request to Send
TP_CM_CTS = 0x11  # Clear to Send
TP_CM_EndOfMsgACK = 0x13  # End of Message Acknowledgment
TP_CM_BAM = 0x20  # Broadcast Announce Message
TP_Conn_Abort = 0xFF  # Connection Abort

#: Value for the "max packets per CTS" field in a TP.CM_RTS frame that
#: indicates no limit on how many TP.DT frames the receiver may request per CTS
TP_CM_MAX_PACKETS_NO_LIMIT = 0xFF

# Abort reason codes
TP_ABORT_ALREADY_CONNECTED = 1
TP_ABORT_NO_RESOURCES = 2
TP_ABORT_TIMEOUT = 3
TP_ABORT_CTS_WHILE_DT = 4

# Default priority for TP messages (priority 7 is used for TP.CM and TP.DT)
J1939_TP_PRIORITY = 7

#: Maximum number of tp_dt_timeout intervals to wait before declaring a
#: TP receive timeout.  On slow serial interfaces (slcan), TP.DT frames
#: may be queued behind a large backlog of background CAN frames; this
#: factor gives the mux enough time to drain the backlog.
TP_DT_TIMEOUT_EXTENSION_FACTOR = 10

# ---------------------------------------------------------------------------
# J1939-81 Network Management (Address Claiming)
# ---------------------------------------------------------------------------

#: PGN for Address Claimed / Cannot Claim messages (J1939-81)
PGN_ADDRESS_CLAIMED = 0xEE00  # 60928

#: PGN for Request messages (J1939-81)
PGN_REQUEST = 0xEA00  # 59904

#: PDU Format byte for Address Claimed (PGN 0xEE00)
J1939_PF_ADDRESS_CLAIMED = 0xEE

#: PDU Format byte for Request messages (PGN 0xEA00)
J1939_PF_REQUEST = 0xEA

#: Null (Cannot Claim) address — used as SA when address claiming fails
J1939_NULL_ADDRESS = 0xFE

#: Duration (seconds) of the 250 ms address claim window (J1939-81 §4.2)
J1939_ADDR_CLAIM_TIMEOUT = 0.250

# Address-claim state machine states
J1939_ADDR_STATE_UNCLAIMED = 0  # address claiming not enabled
J1939_ADDR_STATE_CLAIMING = 1  # 250 ms window in progress
J1939_ADDR_STATE_CLAIMED = 2  # address successfully claimed
J1939_ADDR_STATE_CANNOT_CLAIM = 3  # lost arbitration; SA = 0xFE

# ---------------------------------------------------------------------------
# State machine states (RX)
# ---------------------------------------------------------------------------
J1939_RX_IDLE = 0
J1939_RX_BAM_WAIT_DATA = 1  # BAM: received TP.CM_BAM, waiting for TP.DT
J1939_RX_CMDT_WAIT_DATA = 2  # CMDT: sent CTS, waiting for TP.DT

# ---------------------------------------------------------------------------
# State machine states (TX)
# ---------------------------------------------------------------------------
J1939_TX_IDLE = 0
J1939_TX_BAM_SENDING = 1  # BAM: sending TP.DT frames
J1939_TX_CMDT_WAIT_CTS = 2  # CMDT: sent RTS, waiting for CTS
J1939_TX_CMDT_SENDING = 3  # CMDT: sending TP.DT frames permitted by CTS
J1939_TX_CMDT_WAIT_ACK = 4  # CMDT: sent all DT, waiting for EndOfMsgACK


def _j1939_can_id(priority, pf, da, sa):
    # type: (int, int, int, int) -> int
    """Build a 29-bit J1939 CAN identifier.

    J1939 uses 29-bit extended CAN identifiers structured as:
      bits 28-26: Priority (3 bits)
      bit  25:    Reserved (0)
      bit  24:    Data Page (0)
      bits 23-16: PDU Format (PF, 8 bits)
      bits 15-8:  PDU Specific (PS = DA for PDU1 where PF < 0xF0)
      bits  7-0:  Source Address (SA, 8 bits)

    :param priority: message priority (0-7)
    :param pf: PDU Format byte (e.g. J1939_TP_CM_PF=0xEC)
    :param da: destination address (PS field for PDU1 format)
    :param sa: source address
    :returns: 29-bit CAN identifier (integer)
    """
    return ((priority & 0x7) << 26) | (pf << 16) | (da << 8) | (sa & 0xFF)


def _j1939_decode_can_id(can_id):
    # type: (int) -> Tuple[int, int, int, int]
    """Decode a 29-bit J1939 CAN identifier.

    :param can_id: 29-bit CAN identifier
    :returns: (priority, pf, ps, sa) tuple
    """
    priority = (can_id >> 26) & 0x7
    pf = (can_id >> 16) & 0xFF
    ps = (can_id >> 8) & 0xFF
    sa = can_id & 0xFF
    return priority, pf, ps, sa


class J1939(Packet):
    """Packet class for J1939 messages.

    This class holds a reassembled J1939 multi-packet message payload, along
    with addressing metadata (PGN, source address, destination address).

    :param args: Arguments for Packet init (e.g. raw bytes)
    :param kwargs: Keyword arguments for Packet init
    """

    name = "J1939"
    fields_desc = []  # type: ignore[var-annotated]

    __slots__ = Packet.__slots__ + ["pgn", "src_addr", "dst_addr", "data"]

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        self.pgn = kwargs.pop("pgn", 0)  # type: int
        self.src_addr = kwargs.pop("src_addr", 0)  # type: int
        self.dst_addr = kwargs.pop("dst_addr", J1939_GLOBAL_ADDRESS)  # type: int
        self.data = kwargs.pop("data", b"")  # type: bytes
        Packet.__init__(self, *args, **kwargs)

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        self.data = s
        return b""

    def do_build(self):
        # type: () -> bytes
        return self.data

    def __repr__(self):
        # type: () -> str
        return (
            "<J1939 pgn=0x{:05X} src_addr=0x{:02X} "
            "dst_addr=0x{:02X} data={}>".format(
                self.pgn, self.src_addr, self.dst_addr, self.data.hex()
            )
        )

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, J1939):
            return False
        return (
            self.pgn == other.pgn
            and self.src_addr == other.src_addr
            and self.dst_addr == other.dst_addr
            and self.data == other.data
        )


class J1939SoftSocket(SuperSocket):
    """J1939 soft socket implementing the SAE J1939-21 transport layer.

    This class is a wrapper around the J1939SocketImplementation, following
    the same design pattern as ISOTPSoftSocket.

    The J1939SoftSocket aims to be fully compatible with the Linux j1939
    socket support (CAN_J1939) while being usable on any operating system.

    For messages up to 8 bytes, frames are sent directly as CAN frames.
    For messages 9-1785 bytes, the J1939-21 Transport Protocol is used:

    - BAM  (Broadcast Announce Message) when dst_addr == J1939_GLOBAL_ADDRESS
    - CMDT (Connection Mode Data Transfer) for peer-to-peer messages

    Example (with NativeCANSocket underneath):

        >>> load_contrib('automotive.j1939')
        >>> with J1939Socket("can0", src_addr=0x11, dst_addr=0xFF, pgn=0xFECA) as s:
        ...     s.send(J1939(data=b"Hello, World!"))

    Example (with PythonCANSocket underneath):

        >>> conf.contribs['CANSocket'] = {'use-python-can': True}
        >>> load_contrib('automotive.j1939')
        >>> with J1939Socket(CANSocket(bustype='socketcan', channel="can0"),
        ...                  src_addr=0x11, dst_addr=0xFF, pgn=0xFECA) as s:
        ...     s.send(J1939(data=b"Hello, World!"))

    :param can_socket: a CANSocket instance or interface name (Linux only)
    :param src_addr: our J1939 source address (SA)
    :param dst_addr: destination J1939 address; J1939_GLOBAL_ADDRESS (0xFF)
                     causes BAM to be used for multi-packet messages
    :param pgn: the Parameter Group Number (PGN) for sent messages;
                also used to filter received messages (0 to accept all)
    :param rx_pgn: override PGN filter for received messages; if None,
                   the ``pgn`` parameter is used
    :param priority: J1939 message priority (0-7, default 6)
    :param bs: block size for CMDT (0 = send all in one block)
    :param listen_only: if True, never sends TP.CM flow-control frames
    :param basecls: base class of the packets emitted by this socket
    :param name: optional 64-bit ECU NAME (integer) for J1939-81 address
                 claiming; if provided the socket broadcasts an Address
                 Claimed message on startup and blocks ``send()`` until
                 the address is successfully claimed
    :param preferred_address: preferred SA (0-247) for address claiming;
                              if None, the value of ``src_addr`` is used
    """

    def __init__(
        self,
        can_socket=None,  # type: Optional[Union["CANSocket", str]]
        src_addr=0x00,  # type: int
        dst_addr=J1939_GLOBAL_ADDRESS,  # type: int
        pgn=0,  # type: int
        rx_pgn=None,  # type: Optional[int]
        priority=6,  # type: int
        bs=0,  # type: int
        listen_only=False,  # type: bool
        basecls=J1939,  # type: Type[Packet]
        name=None,  # type: Optional[int]
        preferred_address=None,  # type: Optional[int]
    ):
        # type: (...) -> None
        if LINUX and isinstance(can_socket, str):
            from scapy.contrib.cansocket_native import NativeCANSocket

            can_socket = NativeCANSocket(can_socket)
        elif isinstance(can_socket, str):
            raise Scapy_Exception("Provide a CANSocket object instead of a string")

        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.pgn = pgn
        self.rx_pgn = rx_pgn if rx_pgn is not None else pgn
        self.priority = priority
        self.basecls = basecls

        # Per-message metadata stashed by recv_raw() for recv() to use
        self._last_rx_pgn = 0  # type: int
        self._last_rx_sa = 0  # type: int
        self._last_rx_da = J1939_GLOBAL_ADDRESS  # type: int

        impl = J1939SocketImplementation(
            can_socket,
            src_addr=self.src_addr,
            dst_addr=self.dst_addr,
            pgn=self.pgn,
            rx_pgn=self.rx_pgn,
            priority=self.priority,
            bs=bs,
            listen_only=listen_only,
            name=name,
            preferred_address=preferred_address,
        )

        # Cast for compatibility with SuperSocket
        self.ins = cast(socket.socket, impl)
        self.outs = cast(socket.socket, impl)
        self.impl = impl

        if basecls is None:
            log_j1939.warning("Provide a basecls")

    def close(self):
        # type: () -> None
        if not self.closed:
            if hasattr(self, "impl"):
                self.impl.close()
            self.closed = True

    def recv_raw(self, x=0xFFFF):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]
        """Receive a complete J1939 message (potentially multi-packet)."""
        if not self.closed:
            tup = self.impl.recv()
            if tup is not None:
                # Stash per-message metadata for recv() to pick up
                self._last_rx_pgn = tup[2]
                self._last_rx_sa = tup[3]
                self._last_rx_da = tup[4]
                return self.basecls, tup[0], float(tup[1])
        return self.basecls, None, None

    def recv(self, x=0xFFFF, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        msg = super(J1939SoftSocket, self).recv(x, **kwargs)
        if msg is None:
            return None
        if hasattr(msg, "pgn"):
            msg.pgn = self._last_rx_pgn
        if hasattr(msg, "src_addr"):
            msg.src_addr = self._last_rx_sa
        if hasattr(msg, "dst_addr"):
            msg.dst_addr = self._last_rx_da
        return msg

    @staticmethod
    def select(sockets, remain=None):  # type: ignore[override]
        # type: (List[Union[SuperSocket, ObjectPipe[Any]]], Optional[float]) -> List[Union[SuperSocket, ObjectPipe[Any]]]  # noqa: E501
        """Called during sendrecv() to wait for sockets to be ready."""
        obj_pipes = [  # type: ignore[var-annotated]
            x.impl.rx_queue
            for x in sockets
            if isinstance(x, J1939SoftSocket) and not x.closed
        ]
        obj_pipes += [x for x in sockets if isinstance(x, ObjectPipe) and not x.closed]

        ready_pipes = select_objects(obj_pipes, remain)

        result = [  # type: ignore[var-annotated]
            x
            for x in sockets
            if isinstance(x, J1939SoftSocket)
            and not x.closed
            and x.impl.rx_queue in ready_pipes
        ]
        result += [x for x in sockets if isinstance(x, ObjectPipe) and x in ready_pipes]
        return result


class TimeoutScheduler:
    """A timeout scheduler which uses a single thread for all timeouts.

    Identical to the TimeoutScheduler from ISOTPSoftSocket; reproduced here
    so that j1939 has no dependency on the isotp contrib.

    Original implementation:
      scapy/contrib/isotp/isotp_soft_socket.py
      Copyright (C) Nils Weiss <nils@we155.de>
      Copyright (C) Enrico Pozzobon <enricopozzobon@gmail.com>
      SPDX-License-Identifier: GPL-2.0-only
    """

    GRACE = 0.1
    _mutex = RLock()
    _event = Event()
    _thread = None  # type: Optional[Thread]

    # use heapq functions on _handles!
    _handles = []  # type: List[TimeoutScheduler.Handle]

    logger = logging.getLogger("scapy.contrib.automotive.j1939.timeout_scheduler")

    @classmethod
    def schedule(cls, timeout, callback):
        # type: (float, Callable[[], None]) -> TimeoutScheduler.Handle
        """Schedule the execution of ``callback`` in ``timeout`` seconds."""
        when = cls._time() + timeout
        handle = cls.Handle(when, callback)

        with cls._mutex:
            heapq.heappush(cls._handles, handle)
            must_interrupt = cls._handles[0] == handle

            if cls._thread is None:
                t = Thread(target=cls._task, name="J1939TimeoutScheduler._task")
                t.daemon = True
                must_interrupt = False
                cls._thread = t
                cls._event.clear()
                t.start()

        if must_interrupt:
            cls._event.set()
            time.sleep(0)
        return handle

    @classmethod
    def cancel(cls, handle):
        # type: (TimeoutScheduler.Handle) -> None
        """Cancel the execution of a timeout given its handle."""
        with cls._mutex:
            if handle in cls._handles:
                handle._cb = None
                cls._handles.remove(handle)
                heapq.heapify(cls._handles)
                if len(cls._handles) == 0:
                    cls._event.set()
            else:
                raise Scapy_Exception("Handle not found")

    @classmethod
    def clear(cls):
        # type: () -> None
        """Cancel the execution of all timeouts."""
        with cls._mutex:
            cls._handles = []
        cls._event.set()

    @classmethod
    def _peek_next(cls):
        # type: () -> Optional[TimeoutScheduler.Handle]
        with cls._mutex:
            return cls._handles[0] if cls._handles else None

    @classmethod
    def _wait(cls, handle):
        # type: (Optional[TimeoutScheduler.Handle]) -> None
        now = cls._time()
        if handle is None:
            to_wait = cls.GRACE
        else:
            to_wait = handle._when - now
        if to_wait > 0:
            cls._event.wait(to_wait)
        cls._event.clear()

    @classmethod
    def _task(cls):
        # type: () -> None
        time_empty = None
        try:
            while 1:
                handle = cls._peek_next()
                if handle is None:
                    now = cls._time()
                    if time_empty is None:
                        time_empty = now
                    if cls.GRACE < now - time_empty:
                        return
                else:
                    time_empty = None
                cls._wait(handle)
                cls._poll()
        finally:
            cls._thread = None

    @classmethod
    def _poll(cls):
        # type: () -> None
        while 1:
            with cls._mutex:
                now = cls._time()
                if len(cls._handles) == 0 or cls._handles[0]._when > now:
                    return
                handle = heapq.heappop(cls._handles)
                callback = None
                if handle is not None:
                    callback = handle._cb
                    handle._cb = True
            if callable(callback):
                try:
                    callback()
                except Exception:
                    traceback.print_exc()

    @staticmethod
    def _time():
        # type: () -> float
        return time.monotonic()

    class Handle:
        """A handle for a scheduled timeout."""

        __slots__ = ["_when", "_cb"]

        def __init__(self, when, cb):
            # type: (float, Optional[Union[Callable[[], None], bool]]) -> None
            self._when = when
            self._cb = cb

        def cancel(self):
            # type: () -> bool
            """Cancel this timeout. Returns False if already executed."""
            if self._cb is None:
                raise Scapy_Exception("cancel() called on previously cancelled Handle")
            with TimeoutScheduler._mutex:
                if isinstance(self._cb, bool):
                    return False
                self._cb = None
                TimeoutScheduler.cancel(self)
                return True

        def __lt__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when < other._when

        def __le__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when <= other._when

        def __gt__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when > other._when

        def __ge__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when >= other._when


class J1939SocketImplementation:
    """Implementation of the J1939-21 transport layer state machine.

    This class is separated from J1939SoftSocket so the background thread
    cannot hold a reference to J1939SoftSocket, allowing the socket to be
    collected by the GC.

    The state machine handles:

    - Direct (single-frame) messages up to 8 bytes
    - BAM multi-packet messages (broadcast, dst_addr == J1939_GLOBAL_ADDRESS)
    - CMDT multi-packet messages (peer-to-peer, dst_addr != J1939_GLOBAL_ADDRESS)
    - J1939-81 address claiming (when ``name`` is provided)

    Reference: SAE J1939-21 and J1939-81 specifications.

    :param can_socket: underlying CANSocket for sending/receiving CAN frames
    :param src_addr: our J1939 source address (SA)
    :param dst_addr: default destination address for sending
    :param pgn: PGN used when sending data
    :param rx_pgn: PGN filter for receiving (0 = accept all PGNs)
    :param priority: CAN frame priority for sent frames (0-7)
    :param bs: CMDT block size (0 = send all in one block)
    :param listen_only: if True, do not send TP.CM flow-control responses
    :param name: optional 64-bit ECU NAME for J1939-81 address claiming
    :param preferred_address: preferred SA (0-247) for address claiming;
                              defaults to ``src_addr`` when None
    """

    def __init__(
        self,
        can_socket,  # type: "CANSocket"
        src_addr=0x00,  # type: int
        dst_addr=J1939_GLOBAL_ADDRESS,  # type: int
        pgn=0,  # type: int
        rx_pgn=0,  # type: int
        priority=6,  # type: int
        bs=0,  # type: int
        listen_only=False,  # type: bool
        name=None,  # type: Optional[int]
        preferred_address=None,  # type: Optional[int]
    ):
        # type: (...) -> None
        self.can_socket = can_socket
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.pgn = pgn
        self.rx_pgn = rx_pgn
        self.priority = priority
        self.listen_only = listen_only
        self.closed = False

        # J1939-81 address claiming
        self.name = name  # type: Optional[int]
        self.preferred_address = (
            preferred_address if preferred_address is not None else src_addr
        )

        # Receive state machine
        self.rx_state = J1939_RX_IDLE
        self.rx_pgn_active = 0  # PGN of message being received
        self.rx_src_addr = 0  # SA of sender
        self.rx_dst_addr = 0  # DA of message being received
        self.rx_total_size = 0  # total bytes expected
        self.rx_total_packets = 0  # total TP.DT packets expected
        self.rx_buf = b""  # accumulation buffer
        self.rx_sn = 1  # next expected sequence number
        self.rx_ts = 0.0  # type: Union[float, EDecimal]
        self.rx_start_time = 0.0  # time when current TP transfer started
        self.rx_bs = bs  # configured block size
        self.rx_bs_count = 0  # packets received in current block
        self.rx_next_packet = 1  # next packet number for CMDT CTS

        # Transmit state machine
        self.tx_state = J1939_TX_IDLE
        self.tx_buf = b""  # message to send
        self.tx_total_size = 0
        self.tx_total_packets = 0
        self.tx_pgn = 0  # PGN of message being sent
        self.tx_dst_addr = 0  # DA of message being sent
        self.tx_sn = 1  # current sequence number
        self.tx_idx = 0  # index into tx_buf (bytes sent so far)
        self.tx_packets_to_send = 0  # packets permitted by last CTS
        self.tx_packets_sent = 0  # packets sent in current CTS block
        self.tx_gap = 0.0  # inter-frame gap (seconds)

        # Protocol timeout values (seconds)
        self.tp_dt_timeout = 0.750  # T1: timeout waiting for next TP.DT (750 ms)
        self.tp_cm_timeout = 1.250  # T2/T3: timeout waiting for CTS or ACK (1250 ms)
        self.bam_dt_gap = 0.050  # inter-frame gap for BAM TP.DT (50 ms)

        # Timer handles (all None-initialised; cancelled in close())
        self.rx_timeout_handle = None  # type: Optional[TimeoutScheduler.Handle]
        self.tx_timeout_handle = None  # type: Optional[TimeoutScheduler.Handle]
        self.address_claim_handle = None  # type: Optional[TimeoutScheduler.Handle]

        # Miscellaneous state
        self.filter_warning_emitted = False
        self.last_rx_sa = 0  # last received SA (used by J1939SoftSocket.recv)

        # I/O queues
        # rx_queue carries (payload, timestamp, pgn, sa, da) tuples
        _RxTuple = Tuple[bytes, Union[float, EDecimal], int, int, int]
        self.rx_queue = ObjectPipe[_RxTuple]()
        self.tx_queue = ObjectPipe[Tuple[bytes, int, int]]()
        # tx_queue carries (payload, pgn, dst_addr) tuples

        # Background polling (5 ms default poll rate)
        self.rx_tx_poll_rate = 0.005
        self.rx_handle = TimeoutScheduler.schedule(self.rx_tx_poll_rate, self.can_recv)
        self.tx_handle = TimeoutScheduler.schedule(
            self.rx_tx_poll_rate, self._send_poll
        )

        # J1939-81 initial address claim broadcast
        self.address_state = J1939_ADDR_STATE_UNCLAIMED
        if self.name is not None:
            self.address_state = J1939_ADDR_STATE_CLAIMING
            self._send_address_claimed(self.preferred_address)
            self.address_claim_handle = TimeoutScheduler.schedule(
                J1939_ADDR_CLAIM_TIMEOUT, self._address_claim_timer_fired
            )

    # ------------------------------------------------------------------
    # Destructor / close
    # ------------------------------------------------------------------

    def __del__(self):
        # type: () -> None
        self.close()

    def close(self):
        # type: () -> None
        """Stop background threads and release resources."""
        self.closed = True
        for handle in (
            self.rx_timeout_handle,
            self.tx_timeout_handle,
            self.address_claim_handle,
        ):
            if handle is not None:
                try:
                    handle.cancel()
                except Scapy_Exception:
                    pass
        try:
            self.rx_handle.cancel()
        except Scapy_Exception:
            pass
        try:
            self.tx_handle.cancel()
        except Scapy_Exception:
            pass
        try:
            self.rx_queue.close()
        except (OSError, EOFError):
            pass
        try:
            self.tx_queue.close()
        except (OSError, EOFError):
            pass

    # ------------------------------------------------------------------
    # J1939-81 Network Management (Address Claiming)
    # ------------------------------------------------------------------

    def _send_address_claimed(self, sa):
        # type: (int) -> None
        """Send an Address Claimed message (PGN 0xEE00) broadcast with our NAME."""
        if self.name is None:
            return
        can_id = _j1939_can_id(
            self.priority, J1939_PF_ADDRESS_CLAIMED, J1939_GLOBAL_ADDRESS, sa
        )
        data = struct.pack("<Q", self.name)
        log_j1939.debug(
            "Sending Address Claimed from SA=0x%02X NAME=0x%016X", sa, self.name
        )
        self._can_send(can_id, data)

    def _send_cannot_claim(self):
        # type: () -> None
        """Send a Cannot Claim message (PGN 0xEE00 from SA=0xFE) with our NAME."""
        if self.name is None:
            return
        can_id = _j1939_can_id(
            self.priority,
            J1939_PF_ADDRESS_CLAIMED,
            J1939_GLOBAL_ADDRESS,
            J1939_NULL_ADDRESS,
        )
        data = struct.pack("<Q", self.name)
        log_j1939.warning("Sending Cannot Claim (SA=0xFE) NAME=0x%016X", self.name)
        self._can_send(can_id, data)

    def _address_claim_timer_fired(self):
        # type: () -> None
        """Called 250 ms after the initial claim broadcast.

        Transitions from CLAIMING to CLAIMED if no conflicting claim was
        received during the window.  If the state is no longer CLAIMING
        (e.g. arbitration was lost) this is a no-op.
        """
        if self.closed:
            return
        if self.address_state == J1939_ADDR_STATE_CLAIMING:
            self.address_state = J1939_ADDR_STATE_CLAIMED
            log_j1939.info(
                "Address 0x%02X claimed successfully", self.preferred_address
            )
        self.address_claim_handle = None

    def _on_address_claimed(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Handle an incoming Address Claimed / Cannot Claim frame (PGN 0xEE00).

        Only acts when the sender's source address matches our preferred
        address — a direct address conflict.

        Arbitration rule (J1939-81):

        - Lower 64-bit NAME has higher priority (wins).
        - If we have the lower NAME: re-broadcast our claim.
        - If we have the higher NAME: send Cannot Claim and enter
          CANNOT_CLAIM state.
        """
        if self.name is None:
            return
        if len(data) < 8:
            return
        # SA=0xFE (null address) means the sender already lost arbitration.
        if sa == J1939_NULL_ADDRESS:
            return
        if sa != self.preferred_address:
            return
        received_name = struct.unpack("<Q", data[:8])[0]
        if received_name == self.name:
            log_j1939.warning(
                "Address Claimed from SA=0x%02X with identical NAME=0x%016X; "
                "ignoring (configuration error)",
                sa,
                received_name,
            )
            return
        if self.name < received_name:
            # We win — re-broadcast our claim.
            log_j1939.debug(
                "Address conflict on SA=0x%02X: our NAME=0x%016X < "
                "theirs=0x%016X, re-broadcasting our claim",
                sa,
                self.name,
                received_name,
            )
            self._send_address_claimed(self.preferred_address)
        else:
            # We lose — enter Cannot Claim state.
            log_j1939.warning(
                "Address conflict on SA=0x%02X: our NAME=0x%016X > "
                "theirs=0x%016X, cannot claim address",
                sa,
                self.name,
                received_name,
            )
            if self.address_claim_handle is not None:
                try:
                    self.address_claim_handle.cancel()
                except Scapy_Exception:
                    pass
                self.address_claim_handle = None
            self.address_state = J1939_ADDR_STATE_CANNOT_CLAIM
            self._send_cannot_claim()

    def _on_request_pgn(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Handle an incoming Request message (PGN 0xEA00).

        If the requested PGN is PGN_ADDRESS_CLAIMED (0xEE00), respond
        with our Address Claimed broadcast (or Cannot Claim if we have
        not successfully claimed an address).
        """
        if self.name is None:
            return
        if len(data) < 3:
            return
        requested_pgn = data[0] | (data[1] << 8) | (data[2] << 16)
        if requested_pgn != PGN_ADDRESS_CLAIMED:
            return
        if self.address_state == J1939_ADDR_STATE_CLAIMED:
            log_j1939.debug(
                "Request for PGN_ADDRESS_CLAIMED from SA=0x%02X; "
                "responding with Address Claimed",
                sa,
            )
            self._send_address_claimed(self.preferred_address)
        else:
            log_j1939.debug(
                "Request for PGN_ADDRESS_CLAIMED from SA=0x%02X; "
                "responding with Cannot Claim (state=%d)",
                sa,
                self.address_state,
            )
            self._send_cannot_claim()

    # ------------------------------------------------------------------
    # CAN send helpers
    # ------------------------------------------------------------------

    def _can_send(self, can_id, data):
        # type: (int, bytes) -> None
        """Send a single CAN frame with the given 29-bit extended ID."""
        self.can_socket.send(CAN(identifier=can_id, flags="extended", data=data))

    def _tp_cm_can_id(self, da):
        # type: (int) -> int
        """Return the CAN ID for a TP.CM frame addressed to ``da``."""
        return _j1939_can_id(self.priority, J1939_TP_CM_PF, da, self.src_addr)

    def _tp_dt_can_id(self, da):
        # type: (int) -> int
        """Return the CAN ID for a TP.DT frame addressed to ``da``."""
        return _j1939_can_id(self.priority, J1939_TP_DT_PF, da, self.src_addr)

    def _pgn_can_id(self, pgn, da, sa):
        # type: (int, int, int) -> int
        """Build a J1939 CAN ID for a given PGN.

        For PDU1 format (PF < 0xF0), the DA is placed in the PS field and is
        NOT part of the PGN itself.  For PDU2 format (PF >= 0xF0) the PGN
        encodes the group extension and the DA is always 0xFF.
        """
        pf = (pgn >> 8) & 0xFF
        dp = (pgn >> 16) & 0x3
        if pf < 0xF0:
            ps = da
        else:
            ps = pgn & 0xFF
        return (
            ((self.priority & 0x7) << 26)
            | (dp << 24)
            | (pf << 16)
            | (ps << 8)
            | (sa & 0xFF)
        )

    # ------------------------------------------------------------------
    # CAN receive dispatch
    # ------------------------------------------------------------------

    def can_recv(self):
        # type: () -> None
        """Background CAN receive poll -- called periodically by the scheduler."""
        try:
            while self.can_socket.select([self.can_socket], 0):
                pkt = self.can_socket.recv()
                if pkt:
                    self.on_can_recv(pkt)
                else:
                    break
        except Exception:
            if not self.closed:
                log_j1939.warning("Error in can_recv: %s", traceback.format_exc())
        if not self.closed and not self.can_socket.closed:
            # Determine poll_time from J1939 TP state only.
            # Avoid calling select() here — on slow serial interfaces
            # (slcan), each select() triggers a mux() call that reads
            # N frames at ~2.5ms each, wasting time that could be spent
            # processing frames already in the rx_queue.
            if (
                self.rx_state in (J1939_RX_BAM_WAIT_DATA, J1939_RX_CMDT_WAIT_DATA)
                or self.tx_state == J1939_TX_CMDT_WAIT_CTS
            ):
                poll_time = 0.0
            else:
                poll_time = self.rx_tx_poll_rate
            self.rx_handle = TimeoutScheduler.schedule(poll_time, self.can_recv)
        else:
            try:
                self.rx_handle.cancel()
            except Scapy_Exception:
                pass

    def on_can_recv(self, p):
        # type: (Packet) -> None
        """Dispatch a received CAN frame to the appropriate handler."""
        if not (p.flags & 0x4):  # check extended flag bit
            # Ignore non-extended (11-bit) CAN frames
            return

        can_id = p.identifier
        _, pf, ps, sa = _j1939_decode_can_id(can_id)

        # Network management: Address Claimed / Cannot Claim (PGN 0xEE00)
        if pf == J1939_PF_ADDRESS_CLAIMED and self.name is not None:
            self._on_address_claimed(bytes(p.data), sa, ps)
            return

        # Network management: Request (PGN 0xEA00)
        if pf == J1939_PF_REQUEST and self.name is not None:
            da = ps  # PDU1: PS = DA
            if da == self.src_addr or da == J1939_GLOBAL_ADDRESS:
                self._on_request_pgn(bytes(p.data), sa, da)
            return

        if pf == J1939_TP_CM_PF:
            # TP Connection Management
            da = ps
            if da != self.src_addr and da != J1939_GLOBAL_ADDRESS:
                return
            self._on_tp_cm(bytes(p.data), sa, da, float(p.time))
        elif pf == J1939_TP_DT_PF:
            # TP Data Transfer
            da = ps
            if da != self.src_addr and da != J1939_GLOBAL_ADDRESS:
                return
            self._on_tp_dt(bytes(p.data), sa, da)
        else:
            # Check if it's a direct (unfragmented) message for our rx_pgn
            pgn = _pgn_from_can_id(can_id)
            if self.rx_pgn != 0 and pgn != self.rx_pgn:
                if not self.filter_warning_emitted and conf.verb >= 2:
                    log_j1939.warning(
                        "Ignoring CAN frame with unexpected PGN 0x%05X "
                        "(expected 0x%05X)",
                        pgn,
                        self.rx_pgn,
                    )
                    self.filter_warning_emitted = True
                return
            # Check destination
            if pf < 0xF0:
                da = ps
                if da != self.src_addr and da != J1939_GLOBAL_ADDRESS:
                    return
            else:
                da = J1939_GLOBAL_ADDRESS
            # Direct single-packet message
            data = bytes(p.data)
            if data:
                self.last_rx_sa = sa
                self.rx_queue.send((data, p.time, pgn, sa, da))

    # ------------------------------------------------------------------
    # TP receive state machine
    # ------------------------------------------------------------------

    def _on_tp_cm(self, data, sa, da, ts):
        # type: (bytes, int, int, float) -> None
        if len(data) < 8:
            return
        ctrl = data[0]
        if ctrl == TP_CM_BAM:
            self._recv_bam(data, sa, da, ts)
        elif ctrl == TP_CM_RTS:
            self._recv_rts(data, sa, da, ts)
        elif ctrl == TP_CM_CTS:
            self._recv_cts(data, sa, da)
        elif ctrl == TP_CM_EndOfMsgACK:
            self._recv_eom_ack(data, sa, da)
        elif ctrl == TP_Conn_Abort:
            self._recv_abort(data, sa, da)

    def _recv_bam(self, data, sa, da, ts):
        # type: (bytes, int, int, float) -> None
        """Handle a received TP.CM_BAM frame — start of a BAM transfer."""
        log_j1939.debug("Received TP.CM_BAM from SA=0x%02X", sa)
        if da != J1939_GLOBAL_ADDRESS:
            return

        total_size = struct.unpack_from("<H", data, 1)[0]
        num_packets = data[3]
        # bytes 5-7 hold the PGN (3 bytes, little-endian)
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)

        if self.rx_pgn != 0 and pgn != self.rx_pgn:
            return
        if total_size < 9 or total_size > J1939_TP_MAX_DLEN:
            return

        # Cancel any existing RX timeout
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
            except Scapy_Exception:
                pass

        self.rx_state = J1939_RX_BAM_WAIT_DATA
        self.rx_pgn_active = pgn
        self.rx_src_addr = sa
        self.rx_dst_addr = da
        self.rx_total_size = total_size
        self.rx_total_packets = num_packets
        self.rx_buf = b""
        self.rx_sn = 1
        self.rx_ts = ts
        self.rx_start_time = TimeoutScheduler._time()

        self.rx_timeout_handle = TimeoutScheduler.schedule(
            self.tp_dt_timeout, self._rx_timeout_handler
        )

    def _recv_rts(self, data, sa, da, ts):
        # type: (bytes, int, int, float) -> None
        """Handle a received TP.CM_RTS frame — start of a CMDT transfer."""
        log_j1939.debug("Received TP.CM_RTS from SA=0x%02X to DA=0x%02X", sa, da)
        if da != self.src_addr:
            return

        total_size = struct.unpack_from("<H", data, 1)[0]
        num_packets = data[3]
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)

        if self.rx_pgn != 0 and pgn != self.rx_pgn:
            if not self.listen_only:
                self._send_abort(sa, pgn, TP_ABORT_NO_RESOURCES)
            return
        if total_size < 9 or total_size > J1939_TP_MAX_DLEN:
            if not self.listen_only:
                self._send_abort(sa, pgn, TP_ABORT_NO_RESOURCES)
            return

        # Cancel any existing RX timeout
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
            except Scapy_Exception:
                pass

        self.rx_state = J1939_RX_CMDT_WAIT_DATA
        self.rx_pgn_active = pgn
        self.rx_src_addr = sa
        self.rx_dst_addr = da
        self.rx_total_size = total_size
        self.rx_total_packets = num_packets
        self.rx_buf = b""
        self.rx_sn = 1
        self.rx_bs_count = 0
        self.rx_next_packet = 1
        self.rx_ts = ts
        self.rx_start_time = TimeoutScheduler._time()

        if not self.listen_only:
            packets_this_block = self.rx_bs if self.rx_bs > 0 else num_packets
            self._send_cts(sa, pgn, packets_this_block, self.rx_next_packet)

        self.rx_timeout_handle = TimeoutScheduler.schedule(
            self.tp_dt_timeout, self._rx_timeout_handler
        )

    def _recv_cts(self, data, sa, da, ts=None):
        # type: (bytes, int, int, Optional[float]) -> None
        """Handle a received TP.CM_CTS frame (as the sender).

        The ``ts`` parameter is accepted for API consistency with other
        TP.CM handlers but is not used for CTS processing.
        """
        log_j1939.debug("Received TP.CM_CTS from SA=0x%02X", sa)
        if self.tx_state not in (J1939_TX_CMDT_WAIT_CTS,):
            return
        if self.tx_timeout_handle is not None:
            try:
                self.tx_timeout_handle.cancel()
                self.tx_timeout_handle = None
            except Scapy_Exception:
                pass

        packets_to_send = data[1]
        next_packet = data[2]
        # pgn from CTS: bytes 5-7
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)

        if pgn != self.tx_pgn:
            return
        if packets_to_send == 0:
            # Hold — sender must wait for another CTS
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.tp_cm_timeout, self._tx_timeout_handler
            )
            return

        self.tx_packets_to_send = packets_to_send
        self.tx_packets_sent = 0
        # Adjust tx_idx to resume at the correct packet
        self.tx_sn = next_packet
        self.tx_idx = (next_packet - 1) * J1939_TP_DT_PAYLOAD
        self.tx_state = J1939_TX_CMDT_SENDING

        # Start sending TP.DT frames
        self.tx_timeout_handle = TimeoutScheduler.schedule(
            self.tx_gap, self._tx_timer_handler
        )

    def _recv_eom_ack(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Handle a received TP.CM_EndOfMsgACK frame."""
        log_j1939.debug("Received TP.CM_EndOfMsgACK from SA=0x%02X", sa)
        if self.tx_state != J1939_TX_CMDT_WAIT_ACK:
            return
        if self.tx_timeout_handle is not None:
            try:
                self.tx_timeout_handle.cancel()
                self.tx_timeout_handle = None
            except Scapy_Exception:
                pass
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)
        if pgn == self.tx_pgn:
            log_j1939.debug("CMDT transfer complete (ACK from SA=0x%02X)", sa)
            self.tx_state = J1939_TX_IDLE

    def _recv_abort(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Handle a received TP.Conn_Abort frame."""
        log_j1939.warning(
            "TP.Conn_Abort received from SA=0x%02X, reason=0x%02X",
            sa,
            data[1] if len(data) > 1 else 0xFF,
        )
        # Reset both TX and RX state machines
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
                self.rx_timeout_handle = None
            except Scapy_Exception:
                pass
        if self.tx_timeout_handle is not None:
            try:
                self.tx_timeout_handle.cancel()
                self.tx_timeout_handle = None
            except Scapy_Exception:
                pass
        self.rx_state = J1939_RX_IDLE
        self.tx_state = J1939_TX_IDLE

    def _on_tp_dt(self, data, sa, da):
        # type: (bytes, int, int) -> None
        """Process a received TP.DT frame."""
        if self.rx_state not in (J1939_RX_BAM_WAIT_DATA, J1939_RX_CMDT_WAIT_DATA):
            return
        if sa != self.rx_src_addr:
            return
        if len(data) < 1:
            return

        sn = data[0]

        # Cancel the inactivity timeout; it will be rescheduled below
        if self.rx_timeout_handle is not None:
            try:
                self.rx_timeout_handle.cancel()
                self.rx_timeout_handle = None
            except Scapy_Exception:
                pass

        if sn != self.rx_sn:
            log_j1939.warning(
                "TP.DT sequence number mismatch (expected %d, got %d) "
                "from SA=0x%02X — aborting",
                self.rx_sn,
                sn,
                sa,
            )
            if self.rx_state == J1939_RX_CMDT_WAIT_DATA and not self.listen_only:
                self._send_abort(sa, self.rx_pgn_active, TP_ABORT_TIMEOUT)
            self.rx_state = J1939_RX_IDLE
            return

        payload = data[1:]  # up to 7 bytes
        self.rx_buf += payload
        self.rx_sn = (self.rx_sn % J1939_TP_DT_MAX_SN) + 1  # wrap 1-255

        if self.rx_state == J1939_RX_CMDT_WAIT_DATA:
            self.rx_bs_count += 1

        # Check if we have received all packets
        packets_received = sn  # sn is the sequence number of this frame

        if packets_received >= self.rx_total_packets:
            # All packets received — trim to actual message size
            msg = self.rx_buf[: self.rx_total_size]
            log_j1939.debug(
                "J1939 TP reassembly complete: %d bytes from SA=0x%02X PGN=0x%05X",
                len(msg),
                self.rx_src_addr,
                self.rx_pgn_active,
            )

            if self.rx_state == J1939_RX_CMDT_WAIT_DATA and not self.listen_only:
                self._send_eom_ack(
                    sa, self.rx_pgn_active, self.rx_total_size, self.rx_total_packets
                )

            self.last_rx_sa = self.rx_src_addr
            self.rx_state = J1939_RX_IDLE
            self.rx_queue.send((msg, self.rx_ts, self.rx_pgn_active,
                                self.rx_src_addr, self.rx_dst_addr))
            return

        # Not done yet — send CTS for the next block (CMDT only)
        if (
            self.rx_state == J1939_RX_CMDT_WAIT_DATA
            and self.rx_bs > 0
            and self.rx_bs_count >= self.rx_bs
            and not self.listen_only
        ):
            remaining = self.rx_total_packets - packets_received
            packets_next = min(self.rx_bs, remaining)
            self.rx_next_packet = packets_received + 1
            self.rx_bs_count = 0
            self._send_cts(sa, self.rx_pgn_active, packets_next, self.rx_next_packet)

        # Reschedule inactivity timeout
        self.rx_timeout_handle = TimeoutScheduler.schedule(
            self.tp_dt_timeout, self._rx_timeout_handler
        )

    def _rx_timeout_handler(self):
        # type: () -> None
        """Called when the TP.DT inactivity timer expires."""
        if self.closed:
            return

        if self.rx_state in (J1939_RX_BAM_WAIT_DATA, J1939_RX_CMDT_WAIT_DATA):
            # On slow serial interfaces (slcan), the mux reads frames
            # from an OS serial buffer that may contain hundreds of
            # background CAN frames.  TP.DT frames from the sender are
            # queued behind this backlog and can take several seconds to
            # reach the J1939 state machine.  Extend the timeout up to
            # 10 × tp_dt_timeout to give the mux enough time to drain
            # the backlog.
            total_wait = TimeoutScheduler._time() - self.rx_start_time
            if total_wait < self.tp_dt_timeout * TP_DT_TIMEOUT_EXTENSION_FACTOR:
                self.rx_timeout_handle = TimeoutScheduler.schedule(
                    self.tp_dt_timeout, self._rx_timeout_handler
                )
                return
            log_j1939.warning(
                "J1939 TP RX timeout (state=%d, received %d bytes of %d)",
                self.rx_state,
                len(self.rx_buf),
                self.rx_total_size,
            )
            if self.rx_state == J1939_RX_CMDT_WAIT_DATA and not self.listen_only:
                self._send_abort(self.rx_src_addr, self.rx_pgn_active, TP_ABORT_TIMEOUT)
            self.rx_state = J1939_RX_IDLE

    # ------------------------------------------------------------------
    # TP transmit state machine
    # ------------------------------------------------------------------

    def _send_cts(self, da, pgn, num_packets, next_packet):
        # type: (int, int, int, int) -> None
        """Send a TP.CM_CTS frame to ``da``."""
        pgn_bytes = struct.pack("<I", pgn)[:3]
        data = (
            struct.pack("BBB", TP_CM_CTS, num_packets, next_packet)
            + b"\xff\xff"
            + pgn_bytes
        )
        self._can_send(self._tp_cm_can_id(da), data)

    def _send_eom_ack(self, da, pgn, total_size, num_packets):
        # type: (int, int, int, int) -> None
        """Send a TP.CM_EndOfMsgACK frame to ``da``."""
        pgn_bytes = struct.pack("<I", pgn)[:3]
        data = (
            struct.pack("B", TP_CM_EndOfMsgACK)
            + struct.pack("<H", total_size)
            + struct.pack("B", num_packets)
            + b"\xff"
            + pgn_bytes
        )
        self._can_send(self._tp_cm_can_id(da), data)

    def _send_abort(self, da, pgn, reason):
        # type: (int, int, int) -> None
        """Send a TP.Conn_Abort frame to ``da``."""
        pgn_bytes = struct.pack("<I", pgn)[:3]
        data = struct.pack("BB", TP_Conn_Abort, reason) + b"\xff\xff\xff" + pgn_bytes
        self._can_send(self._tp_cm_can_id(da), data)

    def begin_send(self, payload, pgn, da):
        # type: (bytes, int, int) -> None
        """Begin sending a J1939 message.

        For messages up to 8 bytes, the payload is sent directly.
        For messages 9-1785 bytes, the J1939-21 TP protocol is used.

        :param payload: raw data bytes to send
        :param pgn: PGN of the message
        :param da: destination address
        """
        if self.tx_state != J1939_TX_IDLE:
            log_j1939.warning("J1939 TX busy, retry later")
            return

        length = len(payload)

        if length > J1939_TP_MAX_DLEN:
            log_j1939.warning(
                "Payload too large for J1939 TP (%d bytes, max %d)",
                length,
                J1939_TP_MAX_DLEN,
            )
            return

        if length <= J1939_MAX_SF_DLEN:
            # Direct single-frame send
            can_id = self._pgn_can_id(pgn, da, self.src_addr)
            self._can_send(can_id, payload)
            return

        # Multi-packet — compute number of TP.DT packets
        num_packets = (length + J1939_TP_DT_PAYLOAD - 1) // J1939_TP_DT_PAYLOAD
        pgn_bytes = struct.pack("<I", pgn)[:3]
        self.tx_buf = payload
        self.tx_total_size = length
        self.tx_total_packets = num_packets
        self.tx_pgn = pgn
        self.tx_dst_addr = da
        self.tx_sn = 1
        self.tx_idx = 0

        if da == J1939_GLOBAL_ADDRESS:
            # BAM
            log_j1939.debug(
                "Starting BAM transfer: %d bytes, %d packets, PGN=0x%05X",
                length,
                num_packets,
                pgn,
            )
            bam_data = (
                struct.pack("B", TP_CM_BAM)
                + struct.pack("<H", length)
                + struct.pack("B", num_packets)
                + b"\xff"
                + pgn_bytes
            )
            self._can_send(self._tp_cm_can_id(J1939_GLOBAL_ADDRESS), bam_data)
            self.tx_state = J1939_TX_BAM_SENDING
            # Schedule first TP.DT after BAM inter-frame gap
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.bam_dt_gap, self._tx_timer_handler
            )
        else:
            # CMDT — send RTS
            log_j1939.debug(
                "Starting CMDT RTS: %d bytes, %d packets, " "PGN=0x%05X, DA=0x%02X",
                length,
                num_packets,
                pgn,
                da,
            )
            rts_data = (
                struct.pack("B", TP_CM_RTS)
                + struct.pack("<H", length)
                + struct.pack("B", num_packets)
                + struct.pack("B", TP_CM_MAX_PACKETS_NO_LIMIT)
                + pgn_bytes
            )
            self._can_send(self._tp_cm_can_id(da), rts_data)
            self.tx_state = J1939_TX_CMDT_WAIT_CTS
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.tp_cm_timeout, self._tx_timeout_handler
            )

    def _send_next_dt(self):
        # type: () -> None
        """Send the next TP.DT frame."""
        if self.tx_state not in (J1939_TX_BAM_SENDING, J1939_TX_CMDT_SENDING):
            return

        payload_chunk = self.tx_buf[self.tx_idx : self.tx_idx + J1939_TP_DT_PAYLOAD]
        # Pad the last frame with 0xFF if needed
        if len(payload_chunk) < J1939_TP_DT_PAYLOAD:
            payload_chunk = payload_chunk.ljust(J1939_TP_DT_PAYLOAD, b"\xff")

        dt_data = struct.pack("B", self.tx_sn) + payload_chunk
        self._can_send(self._tp_dt_can_id(self.tx_dst_addr), dt_data)

        self.tx_sn = (self.tx_sn % J1939_TP_DT_MAX_SN) + 1
        self.tx_idx += J1939_TP_DT_PAYLOAD
        if self.tx_state == J1939_TX_CMDT_SENDING:
            self.tx_packets_sent += 1

    def _tx_timer_handler(self):
        # type: () -> None
        """Called by the scheduler to send the next TP.DT frame(s)."""
        if self.tx_state == J1939_TX_BAM_SENDING:
            self._send_next_dt()
            if self.tx_idx >= self.tx_total_size:
                # BAM complete
                log_j1939.debug("BAM transfer complete")
                self.tx_state = J1939_TX_IDLE
                return
            # Schedule the next TP.DT
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.bam_dt_gap, self._tx_timer_handler
            )

        elif self.tx_state == J1939_TX_CMDT_SENDING:
            self._send_next_dt()
            if self.tx_idx >= self.tx_total_size:
                # All TP.DT sent — wait for EndOfMsgACK
                self.tx_state = J1939_TX_CMDT_WAIT_ACK
                self.tx_timeout_handle = TimeoutScheduler.schedule(
                    self.tp_cm_timeout, self._tx_timeout_handler
                )
                return
            if self.tx_packets_sent >= self.tx_packets_to_send:
                # Block complete — wait for next CTS
                self.tx_state = J1939_TX_CMDT_WAIT_CTS
                self.tx_timeout_handle = TimeoutScheduler.schedule(
                    self.tp_cm_timeout, self._tx_timeout_handler
                )
                return
            # More frames to send in this block
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.tx_gap, self._tx_timer_handler
            )

    def _tx_timeout_handler(self):
        # type: () -> None
        """Called when a TX-side timeout (waiting for CTS or ACK) expires."""
        if self.closed:
            return

        if self.tx_state in (J1939_TX_CMDT_WAIT_CTS, J1939_TX_CMDT_WAIT_ACK):
            log_j1939.warning(
                "J1939 CMDT TX timeout (state=%d) — aborting", self.tx_state
            )
            self._send_abort(self.tx_dst_addr, self.tx_pgn, TP_ABORT_TIMEOUT)
            self.tx_state = J1939_TX_IDLE

    def _send_poll(self):
        # type: () -> None
        """Background TX poll -- dequeues pending messages and begins sending."""
        try:
            if self.tx_state == J1939_TX_IDLE:
                if select_objects([self.tx_queue], 0):
                    item = self.tx_queue.recv()
                    if item:
                        payload, pgn, da = item
                        self.begin_send(payload, pgn, da)
        except Exception:
            if not self.closed:
                log_j1939.warning("Error in _send_poll: %s", traceback.format_exc())
        if not self.closed:
            self.tx_handle = TimeoutScheduler.schedule(
                self.rx_tx_poll_rate, self._send_poll
            )
        else:
            try:
                self.tx_handle.cancel()
            except Scapy_Exception:
                pass

    # ------------------------------------------------------------------
    # Public send/recv interface
    # ------------------------------------------------------------------

    def send(self, p):
        # type: (bytes) -> None
        """Enqueue a raw payload for transmission.

        Raises Scapy_Exception if address claiming is enabled but the
        address has not yet been successfully claimed.
        """
        if self.name is not None and self.address_state != J1939_ADDR_STATE_CLAIMED:
            raise Scapy_Exception(
                "J1939 address not yet claimed (state=%d); "
                "cannot send application data" % self.address_state
            )
        self.tx_queue.send((p, self.pgn, self.dst_addr))

    def recv(self, timeout=None):
        # type: (Optional[int]) -> Optional[Tuple[bytes, Union[float, EDecimal], int, int, int]]  # noqa: E501
        """Receive a reassembled J1939 message.

        Returns ``(data, timestamp, pgn, src_addr, dst_addr)`` or None.
        """
        return self.rx_queue.recv()


def _pgn_from_can_id(can_id):
    # type: (int) -> int
    """Extract the PGN from a 29-bit J1939 CAN identifier.

    For PDU1 format (PF < 0xF0), the PS field carries the DA and is NOT
    part of the PGN, so it is zeroed out.
    For PDU2 format (PF >= 0xF0), the PS field is the Group Extension and
    IS part of the PGN.
    """
    dp = (can_id >> 24) & 0x3
    pf = (can_id >> 16) & 0xFF
    ps = (can_id >> 8) & 0xFF
    if pf < 0xF0:
        return (dp << 16) | (pf << 8)
    else:
        return (dp << 16) | (pf << 8) | ps
