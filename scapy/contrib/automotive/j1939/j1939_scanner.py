# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939 Controller Application (CA) Scanner
# scapy.contrib.status = library

"""
J1939 Controller Application (CA) Scanner.

Implements five complementary techniques for enumerating active J1939
Controller Applications (CAs / ECUs) on a CAN bus, modelled after the
Scapy ``isotp_scan`` API.

Technique 1 — Global Address Claim Request
    Broadcasts a single Request (PGN 59904) for the Address Claimed PGN
    (60928).  Every active CA that implements J1939-81 address claiming must
    respond.  Best for networks where all nodes are J1939-81 compliant.

Technique 2 — Global ECU Identification Request
    Broadcasts a single Request (PGN 59904) for the ECU Identification Info
    PGN (64965).  Responding nodes announce their ECU ID via a BAM transfer.
    Identifies nodes that publish an ECU Identification string.

Technique 3 — Unicast Ping Sweep
    Iterates through destination addresses 0x00–0xFD, sending a Request for
    Address Claimed to each.  Nodes that are active reply.  Detects nodes
    even if they do not respond to the broadcast in Technique 1.

Technique 4 — TP.CM RTS Probing
    Iterates through destination addresses 0x00–0xFD, sending a minimal
    TP.CM_RTS frame to each.  Active nodes reply with CTS, Conn_Abort,
    or a NACK on the Acknowledgment PGN (0xE800), all of which confirm
    the node is present.

Technique 5 — UDS TesterPresent Probe
    Iterates through destination addresses 0x00–0xFD, sending padded UDS
    TesterPresent requests (SID 0x3E, sub-functions 0x00 and 0x01,
    5 x 0xFF padding) over both J1939 Diagnostic Message A (Physical) and
    Diagnostic Message B (Functional), once for every source
    address in *src_addrs*.  Nodes that implement UDS reply with a positive
    response (SID 0x7E) or a negative response (SID 0x7F).

Technique 6 — XCP Connect Probe
    Iterates through destination addresses 0x00–0xFD, sending an XCP CONNECT
    command (command code 0xFF, mode 0x00, 6 x 0xFF padding) over J1939
    Diagnostic Message A (Physical), once for every source address in
    *src_addrs*.  Nodes that implement XCP reply with a positive response
    (status byte 0xFF).

Detection Matrix
----------------

The following table shows the probe each technique sends and the CAN
response it expects from an active CA in order to detect it.

+------------+-----------------------------------------+------------------------------------------+
| Technique  | Probe (sent by scanner)                 | Expected response (from ECU)             |
+============+=========================================+==========================================+
| addr_claim | Broadcast Request (PF=0xEA, DA=0xFF)    | Address Claimed (PF=0xEE, DA=0xFF)       |
|            | for PGN 60928 (0xEE00)                  | SA=ECU-SA, 8-byte J1939 NAME payload     |
+------------+-----------------------------------------+------------------------------------------+
| ecu_id     | Broadcast Request (PF=0xEA, DA=0xFF)    | TP.CM BAM (PF=0xEC, DA=0xFF,             |
|            | for PGN 64965 (0xFDC5)                  | ctrl=0x20) announcing PGN 64965          |
+------------+-----------------------------------------+------------------------------------------+
| unicast    | Unicast Request (PF=0xEA, DA=ECU-SA)    | Any CAN frame (extended) whose           |
|            | for PGN 60928, addressed to each DA     | SA equals the probed DA                  |
+------------+-----------------------------------------+------------------------------------------+
| rts_probe  | TP.CM_RTS (PF=0xEC, DA=ECU-SA)          | TP.CM_CTS (ctrl=0x11) **or**             |
|            | sent to each DA                         | TP_Conn_Abort (ctrl=0xFF) **or**         |
|            |                                         | NACK on ACK PGN (PF=0xE8) from probed DA|
+------------+-----------------------------------------+------------------------------------------+
| uds        | Physical (PF=diag_pgn, DA=ECU-SA) AND   | UDS response (positive 02 7E xx  |
|            | Functional (PF=diag_pgn+1, DA=0xFF)     | or negative 03 7F 3E xx)         |
|            | payload 02 3E {00,01} padded            | from responding DA               |
|            | once per SA in src_addrs                |                                  |
+------------+-----------------------------------------+------------------------------------------+
| xcp        | Physical (PF=diag_pgn, DA=ECU-SA)       | XCP positive response (byte 0 == 0xFF)   |
|            | payload FF 00 FF FF FF FF FF FF         | from responding DA                       |
|            | once per SA in src_addrs                |                                          |
+------------+-----------------------------------------+------------------------------------------+

Usage::

    >>> load_contrib('automotive.j1939')
    >>> from scapy.contrib.cansocket import CANSocket
    >>> from scapy.contrib.automotive.j1939.j1939_scanner import j1939_scan
    >>> sock = CANSocket("can0")
    >>> found = j1939_scan(sock, methods=["addr_claim", "unicast"])
    >>> for sa, info in found.items():
    ...     print("SA=0x{:02X}  found_by={}  pkts={}".format(
    ...           sa, info["methods"], len(info["packets"])))
"""

import json
import logging
import struct
import time
from threading import Event

# Typing imports
from typing import (
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

from scapy.layers.can import CAN
from scapy.supersocket import SuperSocket

from scapy.contrib.automotive.j1939.j1939_soft_socket import (
    J1939_GLOBAL_ADDRESS,
    J1939_TP_CM_PF,
    TP_CM_RTS,
    TP_CM_CTS,
    TP_Conn_Abort,
    PGN_ADDRESS_CLAIMED,
    J1939_PF_ADDRESS_CLAIMED,
    J1939_PF_REQUEST,
    _j1939_can_id,
    _j1939_decode_can_id,
    log_j1939,
)

# --- Scanner constants

#: PGN for ECU Identification Information (J1939-73 §5.7.5)
PGN_ECU_ID = 0xFDC5  # 64965

#: Bitmask for the CAN extended-frame flag (29-bit identifier)
_CAN_EXTENDED_FLAG = 0x4

#: Default priority for request frames sent by the scanner
_SCAN_PRIORITY = 6

#: Scan address range for unicast / RTS sweeps (0x00 – 0xFD inclusive)
_SCAN_ADDR_RANGE = range(0x00, 0xFE)  # 0xFE = null / 0xFF = broadcast

#: Candidate diagnostic source addresses (SAE J1939 reserved diagnostic range).
#: Used as the default for *src_addrs* in all scan functions.
J1939_DIAGADAPTERS_ADDRESSES = list(range(0xF1, 0xFE))  # [0xF1 .. 0xFD]

#: PGN for J1939 Diagnostic Message A (PDU1 peer-to-peer, PF=0xDA)
PGN_DIAG_A = 0xDA00

#: PF byte for Diagnostic Message A
J1939_PF_DIAG_A = 0xDA

#: PGN for J1939 Diagnostic Message B (PDU1 peer-to-peer, PF=0xDB)
PGN_DIAG_B = 0xDB00

#: PF byte for Diagnostic Message B
J1939_PF_DIAG_B = 0xDB

#: UDS TesterPresent request payloads: length=2, SID=0x3E, followed by 5
#: padding bytes (0xFF) to fill an 8-byte CAN frame.
#: Subfunction 0x00 asks for a response; 0x01 suppresses it (but some ECUs
#: respond anyway, confirming UDS support).
_UDS_TESTER_PRESENT_REQS = [
    b"\x02\x3e\x00\xff\xff\xff\xff\xff",
    b"\x02\x3e\x01\xff\xff\xff\xff\xff",
]

#: Expected UDS responses for TesterPresent (SID=0x3E).
#: Includes positive responses (SID=0x7E, subfunctions 0x00 and 0x01) and
#: negative responses (SID=0x7F, original SID=0x3E).
_UDS_TESTER_PRESENT_RESPS = [
    b"\x02\x7e\x00",
    b"\x02\x7e\x01",
    b"\x03\x7f\x3e",
]

#: PF byte for XCP Messages (Proprietary A, PDU1 peer-to-peer, PF=0xEF)
J1939_PF_XCP = 0xEF

#: Default source addresses used by the XCP scanner.
J1939_XCP_SRC_ADDRS = (
    [0x3F, 0x5A] + list(range(0x01, 0x10)) + [0xAC] + list(range(0xF1, 0xFE))
)

#: XCP CONNECT command payload: command byte 0xFF, mode 0x00 (normal connection),
#: followed by 6 padding bytes (0xFF) to fill an 8-byte CAN frame.
_XCP_CONNECT_REQ = b"\xff\x00\xff\xff\xff\xff\xff\xff"

#: XCP positive response byte (status byte 0xFF = OK in XCP protocol)
_XCP_POSITIVE_RESPONSE = 0xFF

#: PDU Format byte for the Acknowledgment PGN (0xE800 / 59392; J1939-21 §5.4.4).
#: ECUs that do not implement TP may respond to an RTS with a NACK on this PGN
#: instead of a TP.CM Abort.
_J1939_PF_ACK = 0xE8

#: Acknowledgment control-byte values (J1939-21 §5.4.4, data byte 0).
_ACK_CTRL_NACK = 0x01             # Negative Acknowledgment
_ACK_CTRL_ACCESS_DENIED = 0x02    # Access Denied
_ACK_CTRL_CANNOT_RESPOND = 0x03   # Cannot Respond

#: All valid CA scan method names
SCAN_METHODS = ("addr_claim", "ecu_id", "unicast", "rts_probe", "uds", "xcp")


def _build_request_payload(pgn):
    # type: (int) -> bytes
    """Encode *pgn* as a 3-byte little-endian payload for a J1939 Request (PF=0xEA) frame."""
    return struct.pack("<I", pgn)[:3]


# --- Pacing helpers

#: Default CAN bitrate for J1939 networks (SAE J1939-11, 250 kbit/s)
_J1939_DEFAULT_BITRATE = 250000  # bit/s

#: Default maximum fraction of bus bandwidth the scanner may consume (5 %)
_J1939_DEFAULT_BUSLOAD = 0.05


def _can_frame_bits(dlc):
    # type: (int) -> int
    """Return the bit count of a CAN extended frame with *dlc* data bytes.

    Uses the fixed-field formula for a 29-bit extended frame (no bit-stuffing
    overhead):

      SOF(1) + base-ID(11) + SRR(1) + IDE(1) + ext-ID(18) + RTR(1) +
      r1(1) + r0(1) + DLC(4) + data(dlc×8) + CRC(15) + CRC-del(1) +
      ACK(1) + ACK-del(1) + EOF(7) + IFS(3) = 67 + dlc×8 bits.

    :param dlc: number of data bytes (0–8)
    :returns: total frame bit count
    """
    return 67 + dlc * 8


def _inter_probe_delay(bitrate, busload, tx_dlc, rx_dlc, sniff_time):
    # type: (int, float, int, int, float) -> float
    """Compute the extra sleep needed after a probe-response cycle.

    Each probe cycle occupies *tx_dlc*-frame bits (outgoing probe) plus
    *rx_dlc*-frame bits (expected response).  The scanner's bandwidth budget
    is ``bitrate × busload`` bits per second.  If the probe-response exchange
    completes in less time than the budget requires, the caller should sleep for
    the returned value before transmitting the next probe.

    :param bitrate: CAN bus bitrate in bit/s (e.g. 250000 for 250 kbit/s)
    :param busload: fraction of bus capacity the scanner may consume
                    (0 < busload ≤ 1.0)
    :param tx_dlc: DLC of the outgoing probe frame (0–8)
    :param rx_dlc: DLC of the expected response frame (0–8)
    :param sniff_time: seconds already spent waiting for the response
    :returns: non-negative seconds to sleep before the next probe
    :raises ValueError: when *busload* is not in (0, 1.0]
    """
    if not 0.0 < busload <= 1.0:
        raise ValueError("busload must be in (0, 1.0]; got {!r}".format(busload))
    bits = _can_frame_bits(tx_dlc) + _can_frame_bits(rx_dlc)
    min_cycle = bits / (bitrate * busload)
    return max(0.0, min_cycle - sniff_time)


def _pre_probe_flush(sock):
    # type: (SuperSocket) -> None
    """Flush the kernel CAN receive buffer before sending a probe.

    On :class:`~scapy.contrib.cansocket_python_can.PythonCANSocket` the
    kernel CAN socket buffer is only drained by ``multiplex_rx_packets()``
    which is called from within ``select()``.  Between successive
    ``sniff()`` calls the buffer is **not** read, so background CAN
    traffic accumulates.  On resource-constrained embedded systems the
    kernel buffer may be small enough to overflow, causing *response*
    frames to be silently dropped.

    Calling ``sock.select([sock], 0)`` with a zero timeout triggers a
    non-blocking ``multiplex_rx_packets()`` pass, moving any
    kernel-buffered frames into the unbounded Python ``rx_queue``.  This
    frees space in the kernel buffer for the upcoming response.

    For :class:`~scapy.contrib.cansocket_native.NativeCANSocket` and test
    sockets this call is a harmless no-op (it checks readiness without
    consuming data).
    """
    try:
        sock.select([sock], 0)
    except Exception:
        pass


# --- Socketcan filter helpers

#: CAN Extended Frame Format flag for socketcan ``CAN_RAW_FILTER`` entries.
#: Set in the ``can_id`` field of ``struct can_filter`` so the kernel matches
#: only 29-bit extended identifiers.  Value equals ``socket.CAN_EFF_FLAG``.
_SOCKETCAN_EFF_FLAG = 0x80000000


def _j1939_sa_filter(target_sa):
    # type: (int) -> List[Dict[str, int]]
    """Return socketcan ``can_filters`` matching extended frames with SA=*target_sa*.

    In a 29-bit J1939 CAN identifier the source address (SA) occupies bits
    7–0.  The returned filter passes only extended-format frames whose low
    byte equals *target_sa*, dramatically reducing the number of frames
    delivered to the socket's kernel receive buffer on a busy bus.

    :param target_sa: source address to match (0x00–0xFF)
    :returns: list with one ``can_filters`` dict suitable for
              :class:`~scapy.contrib.cansocket_native.NativeCANSocket`
    """
    return [{
        "can_id": _SOCKETCAN_EFF_FLAG | (target_sa & 0xFF),
        "can_mask": _SOCKETCAN_EFF_FLAG | 0xFF,
    }]


def _open_sa_filtered_sock(sock, target_sa):
    # type: (SuperSocket, int) -> Tuple[SuperSocket, bool]
    """Try to open a CAN socket filtered to receive only SA=*target_sa*.

    On Linux with :class:`~scapy.contrib.cansocket_native.NativeCANSocket`,
    this creates a **new** raw PF_CAN socket on the same interface with a
    hardware-level ``CAN_RAW_FILTER`` that passes only extended frames
    whose source-address byte matches *target_sa*.  The kernel discards
    non-matching frames before they enter the socket receive buffer,
    preventing buffer overflow on resource-constrained embedded systems
    with busy J1939 buses.

    For any other socket type (``PythonCANSocket``, test sockets, etc.)
    the function returns the original *sock* unchanged as a safe
    fallback — the existing ``_pre_probe_flush`` mechanism handles
    those cases.

    :param sock: original CAN socket (used for sending)
    :param target_sa: source address expected in response frames
    :returns: ``(rx_sock, close_needed)`` — *rx_sock* is the socket to
              use for ``sniff()``, and *close_needed* is ``True`` when
              the caller must call ``rx_sock.close()`` after use.
    """
    channel = getattr(sock, "channel", None)
    if channel is None:
        return sock, False
    try:
        from scapy.contrib.cansocket_native import NativeCANSocket
        if not isinstance(sock, NativeCANSocket):
            return sock, False
        rx = NativeCANSocket(
            channel=channel,
            can_filters=_j1939_sa_filter(target_sa),
        )
        return rx, True
    except Exception:
        return sock, False


#: Type alias for the first parameter of all scan functions: either a live
#: CAN socket or a zero-argument callable that creates a new one.
SockOrFactory = Union[SuperSocket, Callable[[], SuperSocket]]


def _resolve_probe_sock(sock_or_factory, target_sa):
    # type: (SockOrFactory, int) -> Tuple[SuperSocket, SuperSocket, bool]
    """Resolve a socket-or-factory into ``(send_sock, rx_sock, close_rx)``.

    When *sock_or_factory* is **callable** (a socket factory), it is called
    to create a fresh per-probe socket.  On
    :class:`~scapy.contrib.cansocket_native.NativeCANSocket` the new socket
    is transparently upgraded to one with a ``CAN_RAW_FILTER`` that passes
    only extended frames whose source-address byte equals *target_sa*.
    Both *send_sock* and *rx_sock* point to the same new socket; the
    caller **must** close it via *close_rx=True*.

    When *sock_or_factory* is a **SuperSocket**, the original socket is
    used for sending and a separate filtered receive socket is opened if
    possible; otherwise *rx_sock* equals *send_sock*.

    :param sock_or_factory: CAN socket or zero-argument callable that
                            returns a new CAN socket
    :param target_sa: source address expected in response frames
    :returns: ``(send_sock, rx_sock, close_rx)`` — the caller must call
              ``rx_sock.close()`` after the probe iff *close_rx* is True.
              *send_sock* is **never** closed by the caller.
    """
    if callable(sock_or_factory):
        probe = sock_or_factory()
        channel = getattr(probe, "channel", None)
        if channel is not None:
            try:
                from scapy.contrib.cansocket_native import NativeCANSocket
                if isinstance(probe, NativeCANSocket):
                    probe.close()
                    filtered = NativeCANSocket(
                        channel=channel,
                        can_filters=_j1939_sa_filter(target_sa),
                    )
                    return filtered, filtered, True
            except Exception:
                pass
        return probe, probe, True
    rx_sock, close_rx = _open_sa_filtered_sock(sock_or_factory, target_sa)
    return sock_or_factory, rx_sock, close_rx


def _resolve_broadcast_sock(sock_or_factory):
    # type: (SockOrFactory) -> Tuple[SuperSocket, bool]
    """Resolve a socket-or-factory for broadcast (non-filtered) use.

    When *sock_or_factory* is callable, it is called once to create a
    socket.  When it is a SuperSocket, it is returned as-is.

    :returns: ``(sock, close_needed)``
    """
    if callable(sock_or_factory):
        return sock_or_factory(), True
    return sock_or_factory, False


# --- Passive scan — background noise detection


def j1939_scan_passive(
    sock,  # type: SockOrFactory
    listen_time=2.0,  # type: float
    stop_event=None,  # type: Optional[Event]
):
    # type: (...) -> Set[int]
    """Passively listen to the bus and return the set of observed source addresses.

    Listens for *listen_time* seconds without sending any probe frames and
    records every source address (SA) seen in an extended CAN frame.  The
    returned set can be passed as the ``noise_ids`` argument to the active
    scan functions so that already-known CAs are not re-probed or re-reported.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param listen_time: seconds to collect background traffic
    :param stop_event: optional :class:`threading.Event` to abort early
    :returns: set of observed source addresses (integers)
    """
    active_sock, close_sock = _resolve_broadcast_sock(sock)
    try:
        seen = set()  # type: Set[int]

        def _rx(pkt):
            # type: (CAN) -> None
            if stop_event is not None and stop_event.is_set():
                return
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, _, _, sa = _j1939_decode_can_id(pkt.identifier)
            seen.add(sa)

        active_sock.sniff(prn=_rx, timeout=listen_time, store=False)
        log_j1939.debug(
            "passive: observed %d SA(s): %s", len(seen), [hex(s) for s in sorted(seen)]
        )
        return seen
    finally:
        if close_sock:
            active_sock.close()


# --- Technique 1 – Global Address Claim Request


def j1939_scan_addr_claim(
    sock,  # type: SockOrFactory
    src_addrs=None,  # type: Optional[List[int]]
    listen_time=1.0,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
):
    # type: (...) -> Dict[int, List[CAN]]
    """Enumerate CAs via a global Request for Address Claimed (PGN 60928).

    For each address in *src_addrs*, sends a broadcast Request frame and
    listens for Address Claimed replies.  Every J1939-81-compliant CA must
    respond.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param src_addrs: list of source addresses to use in requests; defaults
                      to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xFD])
    :param listen_time: seconds to collect responses after sending each probe
    :param noise_ids: set of source addresses already seen on the bus
                      (from :func:`j1939_scan_passive`).  SAs in this set
                      are suppressed from the results unless *force* is True.
    :param force: if True, report all responding SAs even if they appear in
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000).
    :param busload: maximum scanner bus-load fraction (default 0.05).
    :returns: dict mapping responder source address (int) to a list of
              matching CAN replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    payload = _build_request_payload(PGN_ADDRESS_CLAIMED)
    found = {}  # type: Dict[int, List[CAN]]

    active_sock, close_sock = _resolve_broadcast_sock(sock)
    try:
        for _sa in src_addrs:
            if stop_event is not None and stop_event.is_set():
                break
            can_id = _j1939_can_id(
                _SCAN_PRIORITY, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, _sa
            )
            _pre_probe_flush(active_sock)
            active_sock.send(CAN(identifier=can_id, flags="extended", data=payload))
            log_j1939.debug(
                "addr_claim: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)", _sa, can_id
            )

            def _rx(pkt):
                # type: (CAN) -> None
                if not (pkt.flags & _CAN_EXTENDED_FLAG):
                    return
                if stop_event is not None and stop_event.is_set():
                    return
                _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
                if pf == J1939_PF_ADDRESS_CLAIMED and ps == J1939_GLOBAL_ADDRESS:
                    if not force and noise_ids is not None and sa in noise_ids:
                        log_j1939.debug("addr_claim: suppressing noise SA=0x%02X", sa)
                        return
                    log_j1939.debug("addr_claim: response from SA=0x%02X", sa)
                    if sa not in found:
                        found[sa] = []
                    # Record which scanner SA elicited this broadcast
                    setattr(pkt, "src_addrs", [_sa])
                    found[sa].append(pkt)

            active_sock.sniff(prn=_rx, timeout=listen_time, store=False)

            # Pace: 1 broadcast Request (DLC 3) + 1 typical response (DLC 8)
            _extra = _inter_probe_delay(bitrate, busload, 3, 8, listen_time)
            if _extra > 0.0:
                time.sleep(_extra)

        return found
    finally:
        if close_sock:
            active_sock.close()


# --- Technique 2 – Global ECU ID Request


def j1939_scan_ecu_id(
    sock,  # type: SockOrFactory
    src_addrs=None,  # type: Optional[List[int]]
    listen_time=1.0,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
):
    # type: (...) -> Dict[int, List[CAN]]
    """Enumerate CAs via a global Request for ECU Identification (PGN 64965).

    For each address in *src_addrs*, sends a broadcast Request frame and
    listens for BAM announce headers whose PGN field matches 64965.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param src_addrs: list of source addresses to use in requests; defaults
                      to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xFD])
    :param listen_time: seconds to collect responses after sending each probe
    :param noise_ids: set of source addresses to suppress from results
                      (see :func:`j1939_scan_passive`)
    :param force: if True, report all responding SAs even if in *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000).
    :param busload: maximum scanner bus-load fraction (default 0.05).
    :returns: dict mapping responder source address (int) to a list of
              matching CAN replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    payload = _build_request_payload(PGN_ECU_ID)
    found = {}  # type: Dict[int, List[CAN]]

    active_sock, close_sock = _resolve_broadcast_sock(sock)
    try:
        for _sa in src_addrs:
            if stop_event is not None and stop_event.is_set():
                break
            can_id = _j1939_can_id(
                _SCAN_PRIORITY, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, _sa
            )
            _pre_probe_flush(active_sock)
            active_sock.send(CAN(identifier=can_id, flags="extended", data=payload))
            log_j1939.debug(
                "ecu_id: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)", _sa, can_id
            )

            def _rx(pkt):
                # type: (CAN) -> None
                if not (pkt.flags & _CAN_EXTENDED_FLAG):
                    return
                if stop_event is not None and stop_event.is_set():
                    return
                _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
                # We expect a BAM header (TP.CM, DA=0xFF) announcing PGN 64965
                if pf != J1939_TP_CM_PF:
                    return
                if ps != J1939_GLOBAL_ADDRESS:
                    return
                data = bytes(pkt.data)
                if len(data) < 8:
                    return
                # BAM control byte = 0x20, PGN at bytes 5-7 (LE)
                if data[0] == 0x20 and data[5:8] == payload:
                    if not force and noise_ids is not None and sa in noise_ids:
                        log_j1939.debug("ecu_id: suppressing noise SA=0x%02X", sa)
                        return
                    log_j1939.debug("ecu_id: BAM from SA=0x%02X", sa)
                    if sa not in found:
                        found[sa] = []
                    # Record which scanner SA elicited this broadcast
                    setattr(pkt, "src_addrs", [_sa])
                    found[sa].append(pkt)

            active_sock.sniff(prn=_rx, timeout=listen_time, store=False)

            # Pace: 1 broadcast Request (DLC 3) + 1 typical BAM header (DLC 8)
            _extra = _inter_probe_delay(bitrate, busload, 3, 8, listen_time)
            if _extra > 0.0:
                time.sleep(_extra)

        return found
    finally:
        if close_sock:
            active_sock.close()


# --- Technique 3 – Unicast Ping Sweep


def j1939_scan_unicast(
    sock,  # type: SockOrFactory
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
):
    # type: (...) -> Dict[int, List[CAN]]
    """Enumerate CAs by sending unicast Address Claim Requests to each DA.

    For each destination address *da* in *scan_range*, sends a Request for
    Address Claimed (PGN 60928) addressed to *da* once for each address in
    *src_addrs*.  Any CAN frame whose source address equals *da* is counted
    as a positive response.

    When *noise_ids* is provided (and *force* is False), destination addresses
    that appear in *noise_ids* are skipped entirely — no probe is sent and no
    response is recorded for those addresses.  This prevents re-reporting CAs
    already known from background bus traffic.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus, counting both
    the outgoing probe frames and the expected response frame.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param scan_range: iterable of destination addresses to probe
    :param src_addrs: list of source addresses to use in requests; defaults
                      to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xF9])
    :param sniff_time: seconds to wait for a response after each probe
    :param noise_ids: set of source addresses already known from background
                      traffic (see :func:`j1939_scan_passive`).  DAs whose
                      value appears in this set are not probed.
    :param force: if True, probe all DAs in *scan_range* regardless of
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :returns: dict mapping responder source address (int) to a list of
              matching CAN replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    found = {}  # type: Dict[int, List[CAN]]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if not force and noise_ids is not None and da in noise_ids:
            log_j1939.debug("unicast: skipping noise DA=0x%02X", da)
            continue
        payload = _build_request_payload(PGN_ADDRESS_CLAIMED)

        # Capture the loop variable explicitly to avoid closure capture issues
        _da = da
        send_sock, rx_sock, close_rx = _resolve_probe_sock(sock, _da)

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
            # Filter for Address Claimed (0xEE) and matching target SA.
            # Many nodes broadcast the reply (PS=0xFF) instead of unicast.
            if sa == _da and pf == J1939_PF_ADDRESS_CLAIMED and (
                (ps in src_addrs or ps == J1939_GLOBAL_ADDRESS) and sa != ps
            ):
                log_j1939.debug(
                    "unicast: response from SA=0x%02X to scanner SA=0x%02X", sa, ps
                )
                if _da not in found:
                    found[_da] = []
                found[_da].append(pkt)

        def _send_probes(_da=_da):
            # type: (int) -> None
            _pre_probe_flush(rx_sock)
            for _sa in src_addrs:
                can_id = _j1939_can_id(_SCAN_PRIORITY, J1939_PF_REQUEST, _da, _sa)
                send_sock.send(CAN(identifier=can_id, flags="extended", data=payload))
            log_j1939.debug("unicast: probing DA=0x%02X", _da)

        try:
            rx_sock.sniff(prn=_rx, timeout=sniff_time, store=False,
                          started_callback=_send_probes,
                          stop_filter=lambda _, _da=_da: _da in found)
        finally:
            if close_rx:
                rx_sock.close()

        # Pace the probe rate: len(src_addrs) request frames (DLC 3) + response (DLC 8)
        _tx_bits = len(src_addrs) * _can_frame_bits(3)
        _extra = max(
            0.0, (_tx_bits + _can_frame_bits(8)) / (bitrate * busload) - sniff_time
        )
        if _extra > 0.0:
            time.sleep(_extra)

    return found


# --- Technique 4 – TP.CM RTS Probing


def j1939_scan_rts_probe(
    sock,  # type: SockOrFactory
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
):
    # type: (...) -> Dict[int, List[CAN]]
    """Enumerate CAs by sending minimal TP.CM_RTS frames to each DA.

    For each destination address *da* in *scan_range*, sends a TP.CM_RTS
    (Connection Management – Request to Send) frame once per address in
    *src_addrs*.  An active node replies with either TP.CM_CTS (clear to
    send), ``TP_Conn_Abort`` (connection abort), or a NACK on the
    Acknowledgment PGN (0xE800).  All three responses confirm the node is
    present.  Nodes that do not implement the Transport Protocol layer
    typically respond with a NACK rather than a TP.CM Abort.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param scan_range: iterable of destination addresses to probe
    :param src_addrs: list of source addresses to use in probes; defaults
                      to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xF9])
    :param sniff_time: seconds to wait for a response after each probe
    :param noise_ids: set of source addresses already known from background
                      traffic (see :func:`j1939_scan_passive`).  DAs whose
                      value appears in this set are not probed.
    :param force: if True, probe all DAs in *scan_range* regardless of
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :returns: dict mapping responder source address (int) to a list of
              matching CAN replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    found = {}  # type: Dict[int, List[CAN]]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if not force and noise_ids is not None and da in noise_ids:
            log_j1939.debug("rts_probe: skipping noise DA=0x%02X", da)
            continue
        # TP.CM_RTS payload (8 bytes):
        #   byte 0: 0x10 = RTS control
        #   bytes 1-2 LE: total message size = 9
        #   byte 3: total packets = 2
        #   byte 4: max packets per CTS = 0xFF (no limit)
        #   bytes 5-7: PGN being transferred (probe PGN = 0x0000FF)
        rts_payload = struct.pack(
            "<BHBBBBB",
            TP_CM_RTS,  # 0x10
            9,  # total message size (LE 2-byte)
            2,  # total number of TP.DT packets
            0xFF,  # max packets per CTS
            0xFF,  # PGN byte 1 (probe value)
            0x00,  # PGN byte 2
            0x00,
        )  # PGN byte 3

        _da = da
        send_sock, rx_sock, close_rx = _resolve_probe_sock(sock, _da)

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
            if sa != _da:
                return
            if ps not in src_addrs or sa == ps:
                return
            d = bytes(pkt.data)
            if not d:
                return
            # TP.CM response from the probed node (CTS or Abort)
            if pf == J1939_TP_CM_PF and d[0] in (TP_CM_CTS, TP_Conn_Abort):
                log_j1939.debug(
                    "rts_probe: TP.CM response (ctrl=0x%02X) from SA=0x%02X"
                    " to scanner SA=0x%02X",
                    d[0], sa, ps,
                )
                if _da not in found:
                    found[_da] = []
                found[_da].append(pkt)
            # Acknowledgment (NACK / Access Denied / Cannot Respond).
            # Nodes that do not implement TP may respond with a NACK on the
            # Acknowledgment PGN (0xE800) instead of a TP.CM Abort.
            elif pf == _J1939_PF_ACK and d[0] in (
                _ACK_CTRL_NACK, _ACK_CTRL_ACCESS_DENIED,
                _ACK_CTRL_CANNOT_RESPOND,
            ):
                log_j1939.debug(
                    "rts_probe: ACK response (ctrl=0x%02X) from SA=0x%02X"
                    " to scanner SA=0x%02X",
                    d[0], sa, ps,
                )
                if _da not in found:
                    found[_da] = []
                found[_da].append(pkt)

        def _send_probes(_da=_da):
            # type: (int) -> None
            _pre_probe_flush(rx_sock)
            for _sa in src_addrs:
                # CAN-ID: priority=7, PF=0xEC (TP.CM), DA=da, SA=_sa
                can_id = _j1939_can_id(7, J1939_TP_CM_PF, _da, _sa)
                send_sock.send(CAN(identifier=can_id, flags="extended", data=rts_payload))
            log_j1939.debug("rts_probe: probing DA=0x%02X", _da)

        try:
            rx_sock.sniff(prn=_rx, timeout=sniff_time, store=False,
                          started_callback=_send_probes,
                          stop_filter=lambda _, _da=_da: _da in found)
        finally:
            if close_rx:
                rx_sock.close()

        # Pace: len(src_addrs) RTS probes (DLC 8) + one expected response (DLC 8)
        _tx_bits = len(src_addrs) * _can_frame_bits(8)
        _extra = max(
            0.0, (_tx_bits + _can_frame_bits(8)) / (bitrate * busload) - sniff_time
        )
        if _extra > 0.0:
            time.sleep(_extra)

    return found


# --- Technique 5 – UDS TesterPresent Probe


def j1939_scan_uds(
    sock,  # type: SockOrFactory
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
    skip_functional=False,  # type: bool
    broadcast_listen_time=1.0,  # type: float
    diag_pgn=J1939_PF_DIAG_A,  # type: int
):
    # type: (...) -> Dict[int, List[CAN]]
    """Enumerate CAs by sending a UDS TesterPresent request to each DA.

    First, if *skip_functional* is False, sends broadcast UDS TesterPresent
    requests over Diagnostic Message B (PF=diag_pgn | 0x01, DA=0xFF).
    Attempts both subfunctions 0x00 and 0x01. Any responding source addresses
    are recorded.

    Then, for each destination address *da* in *scan_range* and each source
    address in *src_addrs*, sends padded UDS TesterPresent requests over
    Diagnostic Message A (PF=diag_pgn). Attempts both subfunctions 0x00
    and 0x01. A node that implements UDS replies with a positive response
    frame whose first three payload bytes are ``02 7E 00`` or ``02 7E 01``.
    Only well-formed positive responses are recorded.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param scan_range: iterable of destination addresses to probe
    :param src_addrs: list of source addresses to use in requests; defaults
                      to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xF9])
    :param sniff_time: seconds to wait for a response after each probe
    :param noise_ids: set of source addresses already known from background
                      traffic (see :func:`j1939_scan_passive`).  DAs whose
                      value appears in this set are not probed.
    :param force: if True, probe all DAs in *scan_range* regardless of
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :param skip_functional: if True, skip the broadcast functional scan
    :param broadcast_listen_time: seconds to wait for responses after the
                                  broadcast functional probe
    :param diag_pgn: PF byte for UDS diagnostic messages (default 0xDA).
                     Functional addressing uses ``diag_pgn | 0x01``.
    :returns: dict mapping responder source address (int) to a list of
              matching CAN replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    found = {}  # type: Dict[int, List[CAN]]

    if not skip_functional:
        func_sock, close_func = _resolve_broadcast_sock(sock)
        try:
            def _rx_functional(pkt):
                # type: (CAN) -> None
                if not (pkt.flags & _CAN_EXTENDED_FLAG):
                    return
                if stop_event is not None and stop_event.is_set():
                    return
                _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
                if not force and noise_ids is not None and sa in noise_ids:
                    return
                if pf == diag_pgn | 0x01 and ps in src_addrs:
                    data = bytes(pkt.data)
                    if data[:3] in _UDS_TESTER_PRESENT_RESPS:
                        log_j1939.debug(
                            "uds: functional response from SA=0x%02X to scanner SA=0x%02X",
                            sa,
                            ps,
                        )
                        if sa not in found:
                            found[sa] = []
                        found[sa].append(pkt)

            def _send_functional():
                # type: () -> None
                _pre_probe_flush(func_sock)
                for _sa in src_addrs:
                    # diag_pgn | 0x01 is functional addressing PF (e.g. 0xDB)
                    can_id_f = _j1939_can_id(
                        _SCAN_PRIORITY, diag_pgn | 0x01, J1939_GLOBAL_ADDRESS, _sa
                    )
                    for req in _UDS_TESTER_PRESENT_REQS:
                        func_sock.send(CAN(identifier=can_id_f, flags="extended", data=req))
                log_j1939.debug(
                    "uds: broadcast functional probe sent (PF=0x%02X)", diag_pgn | 0x01
                )

            func_sock.sniff(prn=_rx_functional, timeout=broadcast_listen_time, store=False,
                            started_callback=_send_functional)
        finally:
            if close_func:
                func_sock.close()

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if not force and noise_ids is not None and da in noise_ids:
            log_j1939.debug("uds: skipping noise DA=0x%02X", da)
            continue

        # Capture the loop variable explicitly to avoid closure capture issues
        _da = da
        send_sock, rx_sock, close_rx = _resolve_probe_sock(sock, _da)

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
            if sa == _da and pf == diag_pgn and ps in src_addrs and sa != ps:
                data = bytes(pkt.data)
                if data[:3] in _UDS_TESTER_PRESENT_RESPS:
                    log_j1939.debug(
                        "uds: response from SA=0x%02X to scanner SA=0x%02X", sa, ps
                    )
                    if _da not in found:
                        found[_da] = []
                    found[_da].append(pkt)

        def _send_probes(_da=_da):
            # type: (int) -> None
            _pre_probe_flush(rx_sock)
            for _sa in src_addrs:
                # diag_pgn is physical addressing PF (e.g. 0xDA)
                can_id_a = _j1939_can_id(_SCAN_PRIORITY, diag_pgn, _da, _sa)
                for req in _UDS_TESTER_PRESENT_REQS:
                    send_sock.send(CAN(identifier=can_id_a, flags="extended", data=req))
            log_j1939.debug("uds: physical probe DA=0x%02X on PF=0x%02X", _da, diag_pgn)

        try:
            rx_sock.sniff(prn=_rx, timeout=sniff_time, store=False,
                          started_callback=_send_probes,
                          stop_filter=lambda _, _da=_da: _da in found)
        finally:
            if close_rx:
                rx_sock.close()

        # Pace: len(_UDS_TESTER_PRESENT_REQS) probes per src_addr (Physical),
        # DLC=8, + 1 response
        _tx_bits = len(src_addrs) * len(_UDS_TESTER_PRESENT_REQS) * _can_frame_bits(8)
        _extra = max(
            0.0, (_tx_bits + _can_frame_bits(8)) / (bitrate * busload) - sniff_time
        )
        if _extra > 0.0:
            time.sleep(_extra)

    return found


# --- Technique 6 – XCP Connect Probe


def j1939_scan_xcp(
    sock,  # type: SockOrFactory
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
    diag_pgn=J1939_PF_XCP,  # type: int
):
    # type: (...) -> Dict[int, List[CAN]]
    """Enumerate CAs by sending an XCP CONNECT command to each DA.

    For each destination address *da* in *scan_range* and each source address
    in *src_addrs*, sends a padded XCP CONNECT request (command byte 0xFF,
    mode 0x00, 6 x 0xFF padding) over Diagnostic Message A (PF=diag_pgn).
    A node that implements XCP replies with a positive response frame whose
    first byte is ``0xFF``.  Only well-formed positive responses are recorded.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param scan_range: iterable of destination addresses to probe
    :param src_addrs: list of source addresses to use in requests; defaults
                      to :data:`J1939_XCP_SRC_ADDRS` ([0x3F, 0x5A])
    :param sniff_time: seconds to wait for a response after each probe
    :param noise_ids: set of source addresses already known from background
                      traffic (see :func:`j1939_scan_passive`).  DAs whose
                      value appears in this set are not probed.
    :param force: if True, probe all DAs in *scan_range* regardless of
                  *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :param diag_pgn: PF byte for XCP diagnostic messages (default 0xEF,
                     Proprietary A peer-to-peer addressing)
    :returns: dict mapping responder source address (int) to a list of
              matching CAN replies
    """
    if src_addrs is None:
        src_addrs = J1939_XCP_SRC_ADDRS
    found = {}  # type: Dict[int, List[CAN]]

    for da in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if not force and noise_ids is not None and da in noise_ids:
            log_j1939.debug("xcp: skipping noise DA=0x%02X", da)
            continue

        # Capture the loop variable explicitly to avoid closure capture issues
        _da = da
        send_sock, rx_sock, close_rx = _resolve_probe_sock(sock, _da)

        def _rx(pkt, _da=_da):
            # type: (CAN, int) -> None
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
            if sa == _da and pf == diag_pgn and ps in src_addrs and sa != ps:
                data = bytes(pkt.data)
                if data and data[0] == _XCP_POSITIVE_RESPONSE:
                    log_j1939.debug(
                        "xcp: response from SA=0x%02X to scanner SA=0x%02X", sa, ps
                    )
                    if _da not in found:
                        found[_da] = []
                    found[_da].append(pkt)

        def _send_probes(_da=_da):
            # type: (int) -> None
            _pre_probe_flush(rx_sock)
            for _sa in src_addrs:
                can_id = _j1939_can_id(_SCAN_PRIORITY, diag_pgn, _da, _sa)
                send_sock.send(CAN(identifier=can_id, flags="extended",
                                   data=_XCP_CONNECT_REQ))
            log_j1939.debug("xcp: probing DA=0x%02X on PF=0x%02X", _da, diag_pgn)

        try:
            rx_sock.sniff(prn=_rx, timeout=sniff_time, store=False,
                          started_callback=_send_probes,
                          stop_filter=lambda _, _da=_da: _da in found)
        finally:
            if close_rx:
                rx_sock.close()

        # Pace: 1 probe per src_addr (Physical), DLC=8, + 1 response
        _tx_bits = len(src_addrs) * _can_frame_bits(8)
        _extra = max(
            0.0, (_tx_bits + _can_frame_bits(8)) / (bitrate * busload) - sniff_time
        )
        if _extra > 0.0:
            time.sleep(_extra)

    return found


# --- Top-level combined scanner


def j1939_scan(
    sock,  # type: SockOrFactory
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    methods=None,  # type: Optional[List[str]]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    broadcast_listen_time=1.0,  # type: float
    noise_listen_time=1.0,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    verbose=False,  # type: bool
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
    skip_functional=False,  # type: bool
    diag_pgn=None,  # type: Optional[int]
    output_format=None,  # type: Optional[str]
):
    # type: (...) -> Union[Dict[int, Dict[str, object]], str]
    """Scan for J1939 Controller Applications using one or more techniques.

    Runs each requested scan method and merges the results.  The returned
    dictionary maps each discovered source address to a dict with keys:

    - ``"methods"`` (List[str]): list of all techniques that found this CA,
      in the order they detected it.  A CA discovered by more than one
      technique will appear in all of their names.
    - ``"packets"`` (List[List[CAN]]): list of lists of CAN response frames,
      one inner list per entry in ``"methods"``, in the same order.
    - ``"src_addrs"`` (List[List[int]]): list of scanner source addresses,
      one entry per technique in ``"methods"``.  For techniques that use
      physical addressing (``"uds"`` and ``"xcp"``), this records which
      scanner source address produced the response — i.e. which SA must be
      used for further access.  An empty list is stored for techniques where
      no scanner SA could be definitively identified (e.g. broadcast methods
      without explicit stamping).

    By default, before running any active probe the function performs a
    passive bus listen (via :func:`j1939_scan_passive`) for *noise_listen_time*
    seconds to detect pre-existing source addresses.  Those addresses are then
    excluded from active probing and from the results.  Pass *force=True* to
    disable this filtering, or supply an explicit *noise_ids* set to bypass the
    passive pre-scan.

    :param sock: raw CAN socket **or** zero-argument callable returning one.
                 Passing a callable enables per-probe socket creation with
                 socketcan hardware filters, preventing kernel buffer overflow
                 on busy buses.
    :param scan_range: DA range for unicast / RTS sweeps (default 0x00–0xFD)
    :param methods: list of method names to run; valid values are
                    ``"addr_claim"``, ``"ecu_id"``, ``"unicast"``,
                    ``"rts_probe"``, ``"uds"``, ``"xcp"``.  Default is all six.
    :param src_addrs: list of source addresses to use in outgoing probes;
                      defaults to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xF9])
    :param sniff_time: per-address listen time for unicast / RTS methods
    :param broadcast_listen_time: listen time for broadcast methods
    :param noise_listen_time: seconds for the passive pre-scan (default 1.0).
                              Only used when *noise_ids* is None and *force*
                              is False.
    :param noise_ids: explicit set of source addresses to exclude from
                      probing and results.  When provided the passive pre-scan
                      is skipped.
    :param force: if True, disable noise filtering entirely (no passive pre-scan,
                  all addresses are probed and reported)
    :param stop_event: :class:`threading.Event` to abort the scan early
    :param verbose: if True, set the ``log_j1939`` logger to
                    :data:`logging.DEBUG` and log discovered CAs to the
                    console.  Matches the verbose pattern used by
                    :func:`~scapy.contrib.isotp.isotp_scanner.isotp_scan` and
                    :class:`~scapy.contrib.automotive.xcp.scanner.XCPOnCANScanner`.
    :param bitrate: CAN bus bitrate in bit/s passed to unicast / RTS / UDS / XCP
                    methods.  When not specified the scanner tries to read the
                    ``bitrate`` attribute of *sock* automatically, and falls
                    back to ``_J1939_DEFAULT_BITRATE`` (250 kbps) if the
                    attribute is not available.
    :param busload: maximum scanner bus-load fraction passed to unicast / RTS /
                    UDS / XCP methods (default 0.05 = 5 %)
    :param skip_functional: passed to :func:`j1939_scan_uds`
    :param diag_pgn: passed to :func:`j1939_scan_uds` and :func:`j1939_scan_xcp`
    :param output_format: controls the return type.  ``None`` (default) returns
                          the raw results dict.  ``"text"`` returns a
                          human-readable string.  ``"json"`` returns a JSON
                          string.
    :returns: dict mapping SA (int) to
              ``{"methods": List[str], "packets": List[List[CAN]],
              "src_addrs": List[List[int]]}``;
              or a ``str`` when *output_format* is ``"text"`` or ``"json"``

    Example::

        >>> found = j1939_scan(sock)
        >>> for sa, info in sorted(found.items()):
        ...     for method, src_addrs in zip(info["methods"], info["src_addrs"]):
        ...         s_sas = ", ".join("0x{:02X}".format(s) for s in src_addrs)
        ...         print("SA=0x{:02X} via {} (scanner SA={})".format(
        ...               sa, method, s_sas if s_sas else "broadcast"))
    """
    if verbose:
        log_j1939.setLevel(logging.DEBUG)
    if methods is None:
        methods = list(SCAN_METHODS)

    for m in methods:
        if m not in SCAN_METHODS:
            raise ValueError(
                "Unknown scan method {!r}; valid methods: {}".format(m, SCAN_METHODS)
            )

    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES

    # If the caller left bitrate at the sentinel default, try to pull the real
    # value from the socket (e.g. CANSocket stores it as sock.bitrate).
    # When sock is a callable, probe a temporary socket for the attribute.
    if bitrate == _J1939_DEFAULT_BITRATE:
        _probe = sock() if callable(sock) else sock
        sock_bitrate = getattr(_probe, "bitrate", None)
        if sock_bitrate is not None:
            try:
                bitrate = int(sock_bitrate)
            except (TypeError, ValueError):
                pass
        if callable(sock) and _probe is not sock:
            try:
                _probe.close()
            except Exception:
                pass

    # Step 0: passive pre-scan to detect background noise unless disabled.
    if not force and noise_ids is None:
        if stop_event is not None and stop_event.is_set():
            return {}
        noise_ids = j1939_scan_passive(
            sock, listen_time=noise_listen_time, stop_event=stop_event
        )
        if verbose and noise_ids:
            log_j1939.info(
                "j1939_scan: %d noise SA(s) detected, will skip: %s",
                len(noise_ids),
                [hex(s) for s in sorted(noise_ids)],
            )

    results = {}  # type: Dict[int, Dict[str, object]]
    scan_range_list = list(scan_range)

    def _merge(found, method_name, with_src_addr=False):
        # type: (Dict[int, List[CAN]], str, bool) -> None
        for sa, pkts in found.items():
            # For methods that use physical addressing (uds, xcp, etc.), the
            # scanner's source address is embedded as the DA field (ps) of
            # the response CAN frame.  Extract all unique successful scanner
            # source addresses from the response packets so callers can tell
            # which scanner SAs are authorized or required for further access.
            src_addr = []  # type: List[int]
            if with_src_addr and pkts:
                for p in pkts:
                    # Check for explicit stamp from iterative scan methods
                    s_sa_list = getattr(p, "src_addrs", None)
                    if s_sa_list is not None:
                        for s_sa in s_sa_list:
                            if s_sa not in src_addr:
                                src_addr.append(s_sa)
                        continue

                    _, _, ps, _ = _j1939_decode_can_id(p.identifier)
                    if ps != J1939_GLOBAL_ADDRESS and ps not in src_addr:
                        src_addr.append(ps)
            if sa not in results:
                if verbose:
                    log_j1939.info(
                        "j1939_scan: found SA=0x%02X via %s", sa, method_name
                    )
                results[sa] = {
                    "methods": [method_name],
                    "packets": [pkts],
                    "src_addrs": [src_addr],
                }
            else:
                if verbose:
                    log_j1939.info(
                        "j1939_scan: SA=0x%02X also detected via %s", sa, method_name
                    )
                cast(List[str], results[sa]["methods"]).append(method_name)
                cast(List[List[CAN]], results[sa]["packets"]).append(pkts)
                cast(List, results[sa]["src_addrs"]).append(src_addr)

    if "addr_claim" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(
            j1939_scan_addr_claim(
                sock,
                src_addrs=src_addrs,
                listen_time=broadcast_listen_time,
                noise_ids=noise_ids,
                force=force,
                stop_event=stop_event,
                bitrate=bitrate,
                busload=busload,
            ),
            "addr_claim",
            with_src_addr=True,
        )

    if "ecu_id" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(
            j1939_scan_ecu_id(
                sock,
                src_addrs=src_addrs,
                listen_time=broadcast_listen_time,
                noise_ids=noise_ids,
                force=force,
                stop_event=stop_event,
                bitrate=bitrate,
                busload=busload,
            ),
            "ecu_id",
            with_src_addr=True,
        )

    if "unicast" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(
            j1939_scan_unicast(
                sock,
                scan_range=scan_range_list,
                src_addrs=src_addrs,
                sniff_time=sniff_time,
                noise_ids=noise_ids,
                force=force,
                stop_event=stop_event,
                bitrate=bitrate,
                busload=busload,
            ),
            "unicast",
            with_src_addr=True,
        )

    if "rts_probe" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        _merge(
            j1939_scan_rts_probe(
                sock,
                scan_range=scan_range_list,
                src_addrs=src_addrs,
                sniff_time=sniff_time,
                noise_ids=noise_ids,
                force=force,
                stop_event=stop_event,
                bitrate=bitrate,
                busload=busload,
            ),
            "rts_probe",
            with_src_addr=True,
        )

    if "uds" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        uds_kwargs = {
            "sock": sock,
            "scan_range": scan_range_list,
            "src_addrs": src_addrs,
            "sniff_time": sniff_time,
            "noise_ids": noise_ids,
            "force": force,
            "stop_event": stop_event,
            "bitrate": bitrate,
            "busload": busload,
            "skip_functional": skip_functional,
            "broadcast_listen_time": broadcast_listen_time,
        }
        if diag_pgn is not None:
            uds_kwargs["diag_pgn"] = diag_pgn
        _merge(j1939_scan_uds(**uds_kwargs), "uds", with_src_addr=True)

    if "xcp" in methods:
        if stop_event is not None and stop_event.is_set():
            return results
        xcp_kwargs = {
            "sock": sock,
            "scan_range": scan_range_list,
            "src_addrs": src_addrs,
            "sniff_time": sniff_time,
            "noise_ids": noise_ids,
            "force": force,
            "stop_event": stop_event,
            "bitrate": bitrate,
            "busload": busload,
        }
        if diag_pgn is not None:
            xcp_kwargs["diag_pgn"] = diag_pgn
        _merge(j1939_scan_xcp(**xcp_kwargs), "xcp", with_src_addr=True)

    if output_format == "text":
        return _generate_text_output(results)
    if output_format == "json":
        return _generate_json_output(results)
    return results


def _generate_text_output(results):
    # type: (Dict[int, Dict[str, object]]) -> str
    """Format *results* as a human-readable string.

    :param results: dict returned by :func:`j1939_scan`
    :returns: multiline text summary
    """
    if not results:
        return "No J1939 Controller Applications found."
    lines = [
        "Found {} J1939 Controller Application(s):".format(len(results))
    ]
    for sa in sorted(results):
        info = results[sa]
        methods = cast(List[str], info["methods"])
        src_addrs = cast(List, info["src_addrs"])
        lines.append(
            "\nSA: 0x{:02X}".format(sa)
        )
        for method, s_addrs in zip(methods, src_addrs):
            s_sas = ", ".join("0x{:02X}".format(s) for s in s_addrs)
            lines.append(
                "  Method: {}{}".format(
                    method,
                    " (scanner SA: {})".format(s_sas) if s_sas else "",
                )
            )
    return "\n".join(lines)


def _generate_json_output(results):
    # type: (Dict[int, Dict[str, object]]) -> str
    """Format *results* as a JSON string.

    Packet objects are not JSON-serialisable and are omitted; the output
    contains SA, methods, and src_addrs only.

    :param results: dict returned by :func:`j1939_scan`
    :returns: JSON string
    """
    out = []  # type: List[Dict[str, object]]
    for sa in sorted(results):
        info = results[sa]
        entry = {
            "sa": sa,
            "methods": list(cast(List[str], info["methods"])),
            "src_addrs": [list(s) for s in cast(List, info["src_addrs"])],
        }  # type: Dict[str, object]
        out.append(entry)
    return json.dumps(out)


__all__ = [
    "SockOrFactory",
    "j1939_scan",
    "j1939_scan_passive",
    "j1939_scan_addr_claim",
    "j1939_scan_ecu_id",
    "j1939_scan_unicast",
    "j1939_scan_rts_probe",
    "j1939_scan_uds",
    "j1939_scan_xcp",
    "J1939_DIAGADAPTERS_ADDRESSES",
    "J1939_XCP_SRC_ADDRS",
    "PGN_ECU_ID",
    "PGN_DIAG_A",
    "J1939_PF_DIAG_A",
    "PGN_DIAG_B",
    "J1939_PF_DIAG_B",
    "J1939_PF_XCP",
    "SCAN_METHODS",
]
