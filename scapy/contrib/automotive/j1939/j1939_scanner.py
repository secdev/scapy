# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

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
|            |                                         | NACK on ACK PGN (PF=0xE8) from probed DA |
+------------+-----------------------------------------+------------------------------------------+
| uds        | Physical (PF=diag_pgn, DA=ECU-SA) AND   | UDS response (positive 02 7E xx          |
|            | Functional (PF=diag_pgn+1, DA=0xFF)     | or negative 03 7F 3E xx)                 |
|            | payload 02 3E {00,01} padded            | from responding DA                       |
|            | once per SA in src_addrs                |                                          |
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

import contextlib
from dataclasses import dataclass
import logging
from threading import Event  # noqa: F401
import time

# Typing imports
from typing import (  # noqa: F401
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
    cast,
)

from scapy.contrib.automotive.j1939 import J1939Socket
from scapy.contrib.j1939 import (
    J1939,
    J1939Request,
    J1939SoftSocket,
    J1939_GLOBAL_ADDRESS,
    J1939_PGN_ADDRESS_CLAIMED,
    J1939_PGN_TP_CM,
    J1939_TP_CM,
    J1939_TP_CM_ABORT,
    J1939_TP_CM_BAM,
    J1939_TP_CM_CTS,
    J1939_TP_CM_RTS,
    NativeJ1939Socket,
    can_id_to_j1939,
    j1939_log,
    j1939_to_can_id,
)
from scapy.fields import StrField
from scapy.layers.can import CAN, CAN_EFF_FLAG
from scapy.packet import Packet, bind_layers
from scapy.supersocket import SuperSocket


J1939_TP_CM_PF = (J1939_PGN_TP_CM >> 8) & 0xFF
J1939_PF_ADDRESS_CLAIMED = 0xEE
J1939_PF_REQUEST = 0xEA


def j1939_can_id(priority, pf, da, sa):
    return j1939_to_can_id(
        priority=priority, reserved=0, data_page=0,
        pdu_format=pf, pdu_specific=da, src=sa)


def j1939_decode_can_id(can_id):
    f = can_id_to_j1939(can_id)
    return (f['priority'], f['pdu_format'],
            f['pdu_specific'], f['src'])


@dataclass
class J1939ScanResult:
    """Result of an individual J1939 scan probe.

    :param packet: the received response packet (:class:`~scapy.contrib.j1939.J1939`)
    :param scanner_src: the scanner source address that elicited the response,
                        or None if unknown/unspecified
    """

    packet: J1939
    scanner_src: Optional[int] = None


# --- Scanner constants

#: PGN for ECU Identification Information (J1939-73 §5.7.5)
J1939_PGN_ECU_ID = 0xFDC5  # 64965

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
J1939_PGN_DIAG_A = 0xDA00

#: PF byte for Diagnostic Message A
J1939_PF_DIAG_A = 0xDA

#: PGN for J1939 Diagnostic Message B (PDU1 peer-to-peer, PF=0xDB)
J1939_PGN_DIAG_B = 0xDB00

#: PF byte for Diagnostic Message B
J1939_PF_DIAG_B = 0xDB


class J1939_DiagA(Packet):
    """J1939 Diagnostic A – Physical Diagnostic (PGN 0xDA00 = 55808)."""
    name = "J1939_DiagA"
    PGN = J1939_PGN_DIAG_A
    fields_desc = [
        StrField("data", b"")
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> int
        other_inner = other.payload if getattr(other, "payload", None) else other
        if isinstance(other_inner, (J1939_DiagA, J1939_DiagB)):
            return 1
        if isinstance(other, J1939) and other.pgn in (J1939_PGN_DIAG_A, J1939_PGN_DIAG_B):
            return 1
        return 0


class J1939_DiagB(Packet):
    """J1939 Diagnostic B – Functional Diagnostic (PGN 0xDB00 = 56064)."""
    name = "J1939_DiagB"
    PGN = J1939_PGN_DIAG_B
    fields_desc = [
        StrField("data", b"")
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def answers(self, other):
        # type: (Packet) -> int
        other_inner = other.payload if getattr(other, "payload", None) else other
        if isinstance(other_inner, J1939_DiagB):
            return 1
        if isinstance(other, J1939) and other.pgn == J1939_PGN_DIAG_B:
            return 1
        return 0


bind_layers(J1939, J1939_DiagA, pgn=J1939_PGN_DIAG_A)
bind_layers(J1939, J1939_DiagB, pgn=J1939_PGN_DIAG_B)


def _get_uds_tester_present_reqs():
    # type: () -> List[bytes]
    """Build UDS TesterPresent request CAN frame payloads using UDS & ISO-TP layers."""
    from scapy.contrib.automotive.uds import UDS, UDS_TP
    from scapy.contrib.isotp.isotp_packet import ISOTP_SF
    return [
        bytes(ISOTP_SF(data=bytes(UDS() / UDS_TP(subFunction=sf)))).ljust(8, b"\xff")
        for sf in (0x00, 0x01)
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


def _get_xcp_connect_req():
    # type: () -> bytes
    """Build XCP CONNECT request payload using XCP definitions, padded to 8 bytes."""
    from scapy.contrib.automotive.xcp.xcp import CTORequest
    from scapy.contrib.automotive.xcp.cto_commands_master import Connect
    return bytes(CTORequest() / Connect()).ljust(8, b"\xff")


#: XCP positive response byte (status byte 0xFF = OK in XCP protocol)
_XCP_POSITIVE_RESPONSE = 0xFF

#: PDU Format byte for the Acknowledgment PGN (0xE800 / 59392; J1939-21 §5.4.4).
#: ECUs that do not implement TP may respond to an RTS with a NACK on this PGN
#: instead of a TP.CM Abort.
J1939_PF_ACK = 0xE8

#: Acknowledgment control-byte values (J1939-21 §5.4.4, data byte 0).
_ACK_CTRL_NACK = 0x01             # Negative Acknowledgment
_ACK_CTRL_ACCESS_DENIED = 0x02    # Access Denied
_ACK_CTRL_CANNOT_RESPOND = 0x03   # Cannot Respond

#: All valid CA scan method names
SCAN_METHODS = ("addr_claim", "ecu_id", "unicast", "rts_probe", "uds", "xcp")


def _build_request_payload(pgn):
    # type: (int) -> bytes
    """Encode *pgn* as a 3-byte little-endian payload for a J1939 Request (PF=0xEA) frame."""
    return bytes(J1939Request(req_pgn=pgn))


# --- Pacing helpers

#: Default CAN bitrate for J1939 networks (SAE J1939-11, 250 kbit/s)
J1939_DEFAULT_BITRATE = 250000  # bit/s

#: Default maximum fraction of bus bandwidth the scanner may consume (5 %)
J1939_DEFAULT_BUSLOAD = 0.05


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


def j1939_inter_probe_delay(bitrate, busload, tx_dlc, rx_dlc, sniff_time):
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


def j1939_pre_probe_flush(sock):
    # type: (SuperSocket) -> None
    """Flush the kernel CAN receive buffer before sending a probe."""
    try:
        sock.select([sock], 0)
    except (AttributeError, OSError) as ex:
        j1939_log.debug("pre_probe_flush failed: %s", ex)


# --- Socketcan filter helpers

def j1939_sa_filter(target_sa):
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
        "can_id": CAN_EFF_FLAG | (target_sa & 0xFF),
        "can_mask": CAN_EFF_FLAG | 0xFF,
    }]


_j1939_sa_filter = j1939_sa_filter


def j1939_check_socket_can_filters(sock, target_sa):
    # type: (SuperSocket, int) -> None
    """Check if *sock* has CAN filters configured and warn if they do not match *target_sa*.

    Emits at most one warning per socket to prevent log flooding.
    """
    raw_sock = (
        getattr(getattr(sock, "impl", None), "can_socket", None)
        or getattr(sock, "can_socket", None)
        or sock
    )
    filters = (
        getattr(raw_sock, "can_filters", None)
        or getattr(raw_sock, "_can_filters", None)
    )
    if (
        filters is not None
        and not getattr(sock, "filter_warning_emitted", False)
        and not getattr(sock, "_filter_warned", False)
        and not getattr(raw_sock, "filter_warning_emitted", False)
        and not getattr(raw_sock, "_filter_warned", False)
    ):
        matches = False
        for f in filters:
            if isinstance(f, dict):
                can_id = f.get("can_id", 0)
                can_mask = f.get("can_mask", 0)
                test_id = CAN_EFF_FLAG | (target_sa & 0xFF)
                if (test_id & can_mask) == (can_id & can_mask):
                    matches = True
                    break
            elif isinstance(f, int):
                if (f & 0xFF) == (target_sa & 0xFF):
                    matches = True
                    break
        if not matches:
            j1939_log.warning(
                "CAN socket filters do not match target SA=0x%02X",
                target_sa,
            )
            setattr(sock, "filter_warning_emitted", True)
            setattr(sock, "_filter_warned", True)
            setattr(raw_sock, "filter_warning_emitted", True)
            setattr(raw_sock, "_filter_warned", True)


def _emit_sa_filter_warning(sock_objs, target_sa):
    # type: (Iterable[Any], int) -> None
    """Emit warning recommending a CAN filter for *target_sa* once across *sock_objs*."""
    if not any(
        getattr(obj, "filter_warning_emitted", False)
        or getattr(obj, "_filter_warned", False)
        for obj in sock_objs
    ):
        j1939_log.warning(
            "You should put a filter for SA=0x%02X on your CAN socket",
            target_sa,
        )
        for obj in sock_objs:
            setattr(obj, "filter_warning_emitted", True)
            setattr(obj, "_filter_warned", True)


@contextlib.contextmanager
def _filter_warning_recv(sock_to_wrap, target_sa, warning_targets):
    # type: (SuperSocket, Optional[int], Iterable[Any]) -> Iterator[None]
    """Temporarily wrap *sock_to_wrap.recv* to warn if received frame SA does not match *target_sa*."""
    if target_sa is None:
        yield
        return
    orig_recv = sock_to_wrap.recv

    def _filtered_recv(*args, **kwargs):
        pkt = orig_recv(*args, **kwargs)
        if pkt is not None:
            sa = getattr(pkt, "src", None)
            if sa is not None and sa != target_sa:
                _emit_sa_filter_warning(warning_targets, target_sa)
        return pkt

    sock_to_wrap.recv = _filtered_recv
    try:
        yield
    finally:
        sock_to_wrap.recv = orig_recv


def j1939_resolve_probe_sock(sock, target_sa=None, reconnect_handler=None):
    # type: (SuperSocket, Optional[int], Optional[Callable[[], SuperSocket]]) -> Tuple[SuperSocket, SuperSocket, bool]
    """Resolve a socket into ``(send_sock, rx_sock, close_rx)``.

    When *reconnect_handler* is provided, it is called to create a fresh socket
    for this probe. Both *send_sock* and *rx_sock* point to this newly opened
    socket; the caller must close it via *close_rx=True*.

    When *reconnect_handler* is None, the original *sock* is used for both
    sending and receiving, and *close_rx* is False.

    :param sock: CAN socket
    :param target_sa: optional source address expected in response frames
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket
    :returns: ``(send_sock, rx_sock, close_rx)``
    """
    if reconnect_handler is not None:
        probe = reconnect_handler()
        if target_sa is not None:
            j1939_check_socket_can_filters(probe, target_sa)
        return probe, probe, True
    if target_sa is not None:
        j1939_check_socket_can_filters(sock, target_sa)
    return sock, sock, False


def j1939_resolve_broadcast_sock(sock, reconnect_handler=None):
    # type: (SuperSocket, Optional[Callable[[], SuperSocket]]) -> Tuple[SuperSocket, bool]
    """Resolve a socket for broadcast (non-filtered) use.

    When *reconnect_handler* is provided, the factory is called once to create a socket.
    When *reconnect_handler* is None, the live *sock* is returned as-is.

    :returns: ``(sock, close_needed)``
    """
    if reconnect_handler is not None:
        return reconnect_handler(), True
    return sock, False


@contextlib.contextmanager
def j1939_get_sock(
    sock,  # type: SuperSocket
    src_addr=0xF9,  # type: int
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
    target_sa=None,  # type: Optional[int]
    include_tp_cm=False,  # type: bool
    promisc=True,  # type: bool
):
    # type: (...) -> Iterator[SuperSocket]
    """Context manager yielding a J1939Socket configured with *src_addr*.

    If *reconnect_handler* is provided, creates a fresh underlying socket and
    J1939Socket per iteration, closing both on exit.
    If *sock* is already a J1939Socket, temporarily updates its *src_addr*
    and restores it on exit without closing *sock*.
    Otherwise wraps *sock* in a J1939Socket and closes the wrapper on exit
    (preserving the underlying CAN socket).
    """
    if target_sa is not None:
        j1939_check_socket_can_filters(sock, target_sa)

    if reconnect_handler is not None:
        raw = reconnect_handler()
        if target_sa is not None:
            j1939_check_socket_can_filters(raw, target_sa)
        j_sock = (
            raw
            if isinstance(raw, (J1939SoftSocket, NativeJ1939Socket))
            else J1939Socket(
                raw,
                src_addr=src_addr,
                include_tp_cm=include_tp_cm,
                promisc=promisc,
            )
        )
        try:
            with _filter_warning_recv(j_sock, target_sa, [sock, raw, j_sock]):
                yield j_sock
        finally:
            j_sock.close()
            if j_sock is not raw:
                try:
                    raw.close()
                except (AttributeError, OSError):
                    pass

    elif isinstance(sock, (J1939SoftSocket, NativeJ1939Socket)):
        raw_sock = (
            getattr(getattr(sock, "impl", None), "can_socket", None)
            or getattr(sock, "can_socket", None)
            or sock
        )
        old_sa = getattr(sock, "src_addr", None)
        old_include_tp_cm = getattr(getattr(sock, "impl", None), "include_tp_cm", None)
        old_promisc = getattr(getattr(sock, "impl", None), "promisc", None)

        sock.src_addr = src_addr
        if hasattr(sock, "impl"):
            sock.impl.src_addr = src_addr
            if include_tp_cm:
                sock.impl.include_tp_cm = True
            if promisc:
                sock.impl.promisc = True
        try:
            with _filter_warning_recv(sock, target_sa, [sock, raw_sock]):
                yield sock
        finally:
            if old_sa is not None:
                sock.src_addr = old_sa
                if hasattr(sock, "impl"):
                    sock.impl.src_addr = old_sa
            if old_include_tp_cm is not None and hasattr(sock, "impl"):
                sock.impl.include_tp_cm = old_include_tp_cm
            if old_promisc is not None and hasattr(sock, "impl"):
                sock.impl.promisc = old_promisc

    else:
        j_sock = J1939Socket(
            sock, src_addr=src_addr, include_tp_cm=include_tp_cm, promisc=promisc
        )
        try:
            with _filter_warning_recv(j_sock, target_sa, [sock, j_sock]):
                yield j_sock
        finally:
            j_sock.close()


# --- Passive scan — background noise detection


def j1939_scan_passive(

    sock,  # type: SuperSocket
    listen_time=2.0,  # type: float
    stop_event=None,  # type: Optional[Event]
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Set[int]
    """Passively listen to the bus and return the set of observed source addresses.

    Listens for *listen_time* seconds without sending any probe frames and
    records every source address (SA) seen in an extended CAN frame.  The
    returned set can be passed as the ``noise_ids`` argument to the active
    scan functions so that already-known CAs are not re-probed or re-reported.

    :param sock: raw CAN socket
    :param listen_time: seconds to collect background traffic
    :param stop_event: optional :class:`threading.Event` to abort early
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket
    :returns: set of observed source addresses (integers)
    """
    active_sock, close_sock = j1939_resolve_broadcast_sock(sock, reconnect_handler=reconnect_handler)
    try:
        seen = set()  # type: Set[int]

        def _rx(pkt):
            # type: (CAN) -> None
            if stop_event is not None and stop_event.is_set():
                return
            if not (pkt.flags & _CAN_EXTENDED_FLAG):
                return
            _, _, _, sa = j1939_decode_can_id(pkt.identifier)
            seen.add(sa)

        active_sock.sniff(prn=_rx, timeout=listen_time, store=False)
        j1939_log.debug(
            "passive: observed %d SA(s): %s", len(seen), [hex(s) for s in sorted(seen)]
        )
        return seen
    finally:
        if close_sock:
            active_sock.close()


# --- Core Scan Execution Engines


def _j1939_scan_broadcast_loop(
    sock,  # type: SuperSocket
    src_addrs,  # type: Optional[Iterable[int]]
    build_probes,  # type: Callable[[int], Iterable[Packet]]
    match_response,  # type: Callable[[Packet], bool]
    log_name,  # type: str
    listen_time=1.0,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
    include_tp_cm=False,  # type: bool
    tx_dlc=3,  # type: int
    rx_dlc=8,  # type: int
    on_match=None,  # type: Optional[Callable[[int, int, Packet], None]]
    found=None,  # type: Optional[Dict[int, List[J1939ScanResult]]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Execute broadcast discovery loop across *src_addrs*."""
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    if found is None:
        found = {}

    with (
        j1939_get_sock(sock, include_tp_cm=include_tp_cm)
        if reconnect_handler is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        for _sa in src_addrs:
            if stop_event is not None and stop_event.is_set():
                break
            with j1939_get_sock(
                base_j_sock,
                src_addr=_sa,
                reconnect_handler=reconnect_handler,
                include_tp_cm=include_tp_cm,
            ) as j_sock:
                for req in build_probes(_sa):
                    if stop_event is not None and stop_event.is_set():
                        break
                    ans, _ = j_sock.sr(
                        req, multi=True, timeout=listen_time, verbose=False
                    )
                    for _, rcv in ans:
                        if stop_event is not None and stop_event.is_set():
                            break
                        if match_response(rcv):
                            sa = rcv.src
                            if not force and noise_ids is not None and sa in noise_ids:
                                j1939_log.debug(
                                    "%s: suppressing noise SA=0x%02X", log_name, sa
                                )
                                continue
                            if on_match is not None:
                                on_match(sa, _sa, rcv)
                            if sa not in found:
                                found[sa] = []
                            found[sa].append(
                                J1939ScanResult(packet=rcv, scanner_src=_sa)
                            )

        _extra = j1939_inter_probe_delay(bitrate, busload, tx_dlc, rx_dlc, listen_time)
        if _extra > 0.0:
            time.sleep(_extra)

    return found


def _j1939_scan_sweep_loop(
    sock,  # type: SuperSocket
    scan_range,  # type: Iterable[int]
    src_addrs,  # type: Optional[Iterable[int]]
    default_src_addrs,  # type: List[int]
    probe_step,  # type: Callable[[SuperSocket, int, int], Optional[Union[Packet, List[Packet]]]]
    log_name,  # type: str
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
    tx_dlc=3,  # type: int
    rx_dlc=8,  # type: int
    num_tx_probes=1,  # type: int
    pace_per_sa=False,  # type: bool
    found=None,  # type: Optional[Dict[int, List[J1939ScanResult]]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Execute unicast address sweep across *scan_range* and *src_addrs*."""
    if src_addrs is None:
        src_addrs = default_src_addrs
    else:
        src_addrs = list(src_addrs)
    if found is None:
        found = {}

    def _calc_extra():
        # type: () -> float
        tx_bits = num_tx_probes * _can_frame_bits(tx_dlc)
        return max(
            0.0,
            (tx_bits + _can_frame_bits(rx_dlc)) / (bitrate * busload) - sniff_time,
        )

    with (
        j1939_get_sock(sock)
        if reconnect_handler is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        for da in scan_range:
            if stop_event is not None and stop_event.is_set():
                break
            if not force and noise_ids is not None and da in noise_ids:
                j1939_log.debug("%s: skipping noise DA=0x%02X", log_name, da)
                continue

            _da = da
            with j1939_get_sock(
                base_j_sock, reconnect_handler=reconnect_handler, target_sa=_da
            ) as j_sock:
                for _sa in src_addrs:
                    if stop_event is not None and stop_event.is_set():
                        break
                    resps = probe_step(j_sock, _da, _sa)
                    if resps:
                        resp_list = resps if isinstance(resps, list) else [resps]
                        if _da not in found:
                            found[_da] = []
                        for pkt in resp_list:
                            found[_da].append(
                                J1939ScanResult(packet=pkt, scanner_src=_sa)
                            )
                    if pace_per_sa:
                        _extra = _calc_extra()
                        if _extra > 0.0:
                            time.sleep(_extra)

            if not pace_per_sa:
                _extra = _calc_extra()
                if _extra > 0.0:
                    time.sleep(_extra)

    return found


# --- Technique 1 – Global Address Claim Request


def j1939_scan_addr_claim(
    sock,  # type: SuperSocket
    src_addrs=None,  # type: Optional[List[int]]
    listen_time=1.0,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Enumerate CAs via a global Request for Address Claimed (PGN 60928).

    For each address in *src_addrs*, sends a broadcast Request frame and
    listens for Address Claimed replies.  Every J1939-81-compliant CA must
    respond.

    :param sock: raw CAN socket
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
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    def make_probes(sa):
        # type: (int) -> List[Packet]
        can_id = j1939_can_id(
            _SCAN_PRIORITY, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, sa
        )
        j1939_log.debug(
            "addr_claim: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)",
            sa,
            can_id,
        )
        return [
            J1939Request(
                req_pgn=J1939_PGN_ADDRESS_CLAIMED, dst=J1939_GLOBAL_ADDRESS, src=sa
            )
        ]

    return _j1939_scan_broadcast_loop(
        sock=sock,
        src_addrs=src_addrs,
        build_probes=make_probes,
        match_response=lambda rcv: rcv.pgn == J1939_PGN_ADDRESS_CLAIMED,
        log_name="addr_claim",
        listen_time=listen_time,
        noise_ids=noise_ids,
        force=force,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reconnect_handler=reconnect_handler,
        tx_dlc=3,
        rx_dlc=8,
    )


# --- Technique 2 – Global ECU ID Request


def j1939_scan_ecu_id(
    sock,  # type: SuperSocket
    src_addrs=None,  # type: Optional[List[int]]
    listen_time=1.0,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Enumerate CAs via a global Request for ECU Identification (PGN 64965).

    For each address in *src_addrs*, sends a broadcast Request frame and
    listens for BAM announce headers whose PGN field matches 64965.

    :param sock: raw CAN socket
    :param src_addrs: list of source addresses to use in requests; defaults
                      to :data:`J1939_DIAGADAPTERS_ADDRESSES` ([0xF1..0xFD])
    :param listen_time: seconds to collect responses after sending each probe
    :param noise_ids: set of source addresses to suppress from results
                      (see :func:`j1939_scan_passive`)
    :param force: if True, report all responding SAs even if in *noise_ids*
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000).
    :param busload: maximum scanner bus-load fraction (default 0.05).
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    def make_probes(sa):
        # type: (int) -> List[Packet]
        can_id = j1939_can_id(
            _SCAN_PRIORITY, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, sa
        )
        j1939_log.debug(
            "ecu_id: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)",
            sa,
            can_id,
        )
        return [
            J1939Request(
                req_pgn=J1939_PGN_ECU_ID, dst=J1939_GLOBAL_ADDRESS, src=sa
            )
        ]

    def match_resp(rcv):
        # type: (Packet) -> bool
        if rcv.pgn == J1939_PGN_ECU_ID:
            return True
        if rcv.pgn == J1939_PGN_TP_CM:
            d = rcv.data if rcv.data else bytes(rcv.payload)
            if len(d) >= 8:
                tp_cm = J1939_TP_CM(d)
                return (
                    isinstance(tp_cm, J1939_TP_CM_BAM)
                    and tp_cm.pgn == J1939_PGN_ECU_ID
                )
        return False

    def on_match(sa, scanner_sa, rcv):
        # type: (int, int, Packet) -> None
        j1939_log.debug("ecu_id: BAM from SA=0x%02X", sa)

    return _j1939_scan_broadcast_loop(
        sock=sock,
        src_addrs=src_addrs,
        build_probes=make_probes,
        match_response=match_resp,
        log_name="ecu_id",
        listen_time=listen_time,
        noise_ids=noise_ids,
        force=force,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reconnect_handler=reconnect_handler,
        include_tp_cm=True,
        tx_dlc=3,
        rx_dlc=8,
        on_match=on_match,
    )


# --- Technique 3 – Unicast Ping Sweep


def j1939_scan_unicast(
    sock,  # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
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

    :param sock: raw CAN socket
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
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket. When provided, a fresh socket is
                              created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    def probe(j_sock, da, sa):
        # type: (SuperSocket, int, int) -> Optional[Packet]
        req = J1939Request(req_pgn=J1939_PGN_ADDRESS_CLAIMED, dst=da, src=sa)
        j1939_log.debug("unicast: probing DA=0x%02X from SA=0x%02X", da, sa)
        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
        if rcv is not None:
            j1939_log.debug(
                "unicast: response from SA=0x%02X to scanner SA=0x%02X",
                rcv.src,
                rcv.dst,
            )
            return rcv
        return None

    return _j1939_scan_sweep_loop(
        sock=sock,
        scan_range=scan_range,
        src_addrs=src_addrs,
        default_src_addrs=J1939_DIAGADAPTERS_ADDRESSES,
        probe_step=probe,
        log_name="unicast",
        sniff_time=sniff_time,
        noise_ids=noise_ids,
        force=force,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reconnect_handler=reconnect_handler,
        tx_dlc=3,
        rx_dlc=8,
    )


# --- Technique 4 – TP.CM RTS Probing


def j1939_scan_rts_probe(
    sock,  # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Enumerate CAs by sending minimal TP.CM_RTS frames to each DA.

    For each destination address *da* in *scan_range*, sends a TP.CM_RTS
    (Connection Management – Request to Send) frame once per address in
    *src_addrs*.  An active node replies with either TP.CM_CTS (clear to
    send), ``TP_Conn_Abort`` (connection abort), or a NACK on the
    Nodes that implement the J1939 Transport Protocol respond with either a
    TP.CM_CTS or a TP.Conn_Abort frame.  Nodes that do not implement TP may
    respond with an Acknowledgment frame (PGN 0xE800 / 59392) carrying a NACK,
    Access Denied, or Cannot Respond control byte.  Silent nodes simply time
    out.

    This technique is faster and simpler than DM14/DM13 for detecting CAs that
    ignore Address Claim Requests.

    :param sock: raw CAN socket
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
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket. When provided, a fresh socket is
                              created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    def probe(j_sock, da, sa):
        # type: (SuperSocket, int, int) -> Optional[Packet]
        req = J1939(pgn=0xEC00, dst=da, src=sa) / J1939_TP_CM_RTS(
            total_size=9,
            num_packets=2,
            max_packets=0xFF,
            pgn=0x0000FF,
        )
        j1939_log.debug("rts_probe: probing DA=0x%02X from SA=0x%02X", da, sa)
        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
        if rcv is not None:
            d = rcv.data if rcv.data else bytes(rcv.payload)
            if d:
                if rcv.pgn == J1939_PGN_TP_CM and len(d) >= 8:
                    tp_cm = J1939_TP_CM(d)
                    if isinstance(tp_cm, (J1939_TP_CM_CTS, J1939_TP_CM_ABORT)):
                        j1939_log.debug(
                            "rts_probe: %s from SA=0x%02X to scanner SA=0x%02X",
                            tp_cm.name,
                            rcv.src,
                            sa,
                        )
                        return rcv
                elif rcv.pgn == J1939_PF_ACK << 8 and d[0] in (
                    _ACK_CTRL_NACK,
                    _ACK_CTRL_ACCESS_DENIED,
                    _ACK_CTRL_CANNOT_RESPOND,
                ):
                    j1939_log.debug(
                        "rts_probe: ACK (ctrl=0x%02X) from SA=0x%02X to scanner SA=0x%02X",
                        d[0],
                        rcv.src,
                        sa,
                    )
                    return rcv
        return None

    return _j1939_scan_sweep_loop(
        sock=sock,
        scan_range=scan_range,
        src_addrs=src_addrs,
        default_src_addrs=J1939_DIAGADAPTERS_ADDRESSES,
        probe_step=probe,
        log_name="rts_probe",
        sniff_time=sniff_time,
        noise_ids=noise_ids,
        force=force,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reconnect_handler=reconnect_handler,
        tx_dlc=8,
        rx_dlc=8,
    )


# --- Technique 5 – UDS TesterPresent Probe


def j1939_scan_uds(
    sock,  # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    skip_functional=False,  # type: bool
    broadcast_listen_time=1.0,  # type: float
    diag_pgn=J1939_PF_DIAG_A,  # type: int
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
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

    :param sock: raw CAN socket
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
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket. When provided, a fresh socket is
                              created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    else:
        src_addrs = list(src_addrs)
    found = {}  # type: Dict[int, List[J1939ScanResult]]
    reqs = _get_uds_tester_present_reqs()

    if not skip_functional:
        def make_bcast_probes(sa):
            # type: (int) -> List[Packet]
            j1939_log.debug(
                "uds: broadcast functional probe sent SA=0x%02X (PF=0x%02X)",
                sa,
                diag_pgn | 0x01,
            )
            return [
                J1939(
                    pgn=(diag_pgn | 0x01) << 8,
                    dst=J1939_GLOBAL_ADDRESS,
                    src=sa,
                ) / J1939_DiagB(data=req_data)
                for req_data in reqs
            ]

        def match_bcast(rcv):
            # type: (Packet) -> bool
            data = rcv.data if rcv.data else bytes(rcv.payload)
            return data[:3] in _UDS_TESTER_PRESENT_RESPS

        def on_bcast_match(sa, scanner_sa, rcv):
            # type: (int, int, Packet) -> None
            j1939_log.debug(
                "uds: functional response from SA=0x%02X to scanner SA=0x%02X",
                sa,
                scanner_sa,
            )

        _j1939_scan_broadcast_loop(
            sock=sock,
            src_addrs=src_addrs,
            build_probes=make_bcast_probes,
            match_response=match_bcast,
            log_name="uds",
            listen_time=broadcast_listen_time,
            noise_ids=noise_ids,
            force=force,
            stop_event=stop_event,
            bitrate=bitrate,
            busload=busload,
            reconnect_handler=reconnect_handler,
            on_match=on_bcast_match,
            found=found,
        )

    def probe_phys(j_sock, da, sa):
        # type: (SuperSocket, int, int) -> Optional[Packet]
        for req_data in reqs:
            if stop_event is not None and stop_event.is_set():
                break
            j1939_log.debug(
                "uds: physical probe DA=0x%02X SA=0x%02X on PF=0x%02X",
                da,
                sa,
                diag_pgn,
            )
            req = J1939(
                pgn=diag_pgn << 8, dst=da, src=sa
            ) / J1939_DiagA(data=req_data)
            rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
            if rcv is not None:
                data = rcv.data if rcv.data else bytes(rcv.payload)
                if data[:3] in _UDS_TESTER_PRESENT_RESPS:
                    j1939_log.debug(
                        "uds: response from SA=0x%02X to scanner SA=0x%02X",
                        rcv.src,
                        sa,
                    )
                    return rcv
        return None

    return _j1939_scan_sweep_loop(
        sock=sock,
        scan_range=scan_range,
        src_addrs=src_addrs,
        default_src_addrs=J1939_DIAGADAPTERS_ADDRESSES,
        probe_step=probe_phys,
        log_name="uds",
        sniff_time=sniff_time,
        noise_ids=noise_ids,
        force=force,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reconnect_handler=reconnect_handler,
        tx_dlc=8,
        rx_dlc=8,
        num_tx_probes=len(reqs),
        pace_per_sa=True,
        found=found,
    )


# --- Technique 6 – XCP Connect Probe


def j1939_scan_xcp(
    sock,  # type: SuperSocket
    scan_range=_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    diag_pgn=J1939_PF_XCP,  # type: int
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Enumerate CAs by sending an XCP CONNECT command to each DA.

    For each destination address *da* in *scan_range* and each source address
    in *src_addrs*, sends a padded XCP CONNECT request (command byte 0xFF,
    mode 0x00, 6 x 0xFF padding) over Diagnostic Message A (PF=diag_pgn).
    A node that implements XCP replies with a positive response frame whose
    first byte is ``0xFF``.  Only well-formed positive responses are recorded.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus.

    :param sock: raw CAN socket
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
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket. When provided, a fresh socket is
                              created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    connect_req = _get_xcp_connect_req()

    def probe(j_sock, da, sa):
        # type: (SuperSocket, int, int) -> Optional[Packet]
        req = J1939(pgn=diag_pgn << 8, dst=da, src=sa, data=connect_req)
        j1939_log.debug("xcp: probing DA=0x%02X from SA=0x%02X", da, sa)
        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
        if rcv is not None:
            data = rcv.data if rcv.data else bytes(rcv.payload)
            if data and data[0] == _XCP_POSITIVE_RESPONSE:
                j1939_log.debug(
                    "xcp: response from SA=0x%02X to scanner SA=0x%02X",
                    rcv.src,
                    sa,
                )
                return rcv
        return None

    return _j1939_scan_sweep_loop(
        sock=sock,
        scan_range=scan_range,
        src_addrs=src_addrs,
        default_src_addrs=J1939_XCP_SRC_ADDRS,
        probe_step=probe,
        log_name="xcp",
        sniff_time=sniff_time,
        noise_ids=noise_ids,
        force=force,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reconnect_handler=reconnect_handler,
        tx_dlc=8,
        rx_dlc=8,
    )


# --- Top-level combined scanner


def j1939_scan(

    sock,  # type: SuperSocket
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
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    skip_functional=False,  # type: bool
    diag_pgn=None,  # type: Optional[int]
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, Dict[str, object]]
    """Scan for J1939 Controller Applications using one or more techniques.

    Runs each requested scan method and merges the results.  The returned
    dictionary maps each discovered source address to a dict with keys:

    - ``"methods"`` (List[str]): list of all techniques that found this CA,
      in the order they detected it.  A CA discovered by more than one
      technique will appear in all of their names.
    - ``"packets"`` (List[List[CAN]]): list of lists of CAN response frames,
      one inner list per entry in ``"methods"``, in the same order.
    - ``"results"`` (List[List[J1939ScanResult]]): list of lists of
      :class:`J1939ScanResult` objects, one inner list per entry in
      ``"methods"``, in the same order.
    - ``"src_addrs"`` (List[List[int]]): list of scanner source addresses,
      one entry per technique in ``"methods"``.  For techniques that use
      physical addressing (``"uds"`` and ``"xcp"``), this records which
      scanner source address produced the response — i.e. which SA must be
      used for further access.  An empty list is stored for techniques where
      no scanner SA could be definitively identified.

    By default, before running any active probe the function performs a
    passive bus listen (via :func:`j1939_scan_passive`) for *noise_listen_time*
    seconds to detect pre-existing source addresses.  Those addresses are then
    excluded from active probing and from the results.  Pass *force=True* to
    disable this filtering, or supply an explicit *noise_ids* set to bypass the
    passive pre-scan.

    :param sock: raw CAN socket
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
    :param verbose: if True, set the ``j1939_log`` logger to
                    :data:`logging.DEBUG` and log discovered CAs to the
                    console.  Matches the verbose pattern used by
                    :func:`~scapy.contrib.isotp.isotp_scanner.isotp_scan` and
                    :class:`~scapy.contrib.automotive.xcp.scanner.XCPOnCANScanner`.
    :param bitrate: CAN bus bitrate in bit/s passed to unicast / RTS / UDS / XCP
                    methods.  When not specified the scanner tries to read the
                    ``bitrate`` attribute of *sock* automatically, and falls
                    back to ``J1939_DEFAULT_BITRATE`` (250 kbps) if the
                    attribute is not available.
    :param busload: maximum scanner bus-load fraction passed to unicast / RTS /
                    UDS / XCP methods (default 0.05 = 5 %)
    :param skip_functional: passed to :func:`j1939_scan_uds`
    :param diag_pgn: passed to :func:`j1939_scan_uds` and :func:`j1939_scan_xcp`
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket passed down to each scan method.
    :returns: dict mapping SA (int) to
              ``{"methods": List[str], "packets": List[List[CAN]],
              "src_addrs": List[List[int]]}``

    Example::

        >>> found = j1939_scan(sock)
        >>> for sa, info in sorted(found.items()):
        ...     for method, src_addrs in zip(info["methods"], info["src_addrs"]):
        ...         s_sas = ", ".join("0x{:02X}".format(s) for s in src_addrs)
        ...         print("SA=0x{:02X} via {} (scanner SA={})".format(
        ...               sa, method, s_sas if s_sas else "broadcast"))
    """
    if verbose:
        j1939_log.setLevel(logging.DEBUG)
    if methods is None:
        methods = list(SCAN_METHODS)

    for m in methods:
        if m not in SCAN_METHODS:
            raise ValueError(
                "Unknown scan method {!r}; valid methods: {}".format(m, SCAN_METHODS)
            )

    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    else:
        src_addrs = list(src_addrs)

    # If the caller left bitrate at the sentinel default, try to pull the real
    # value from the socket (e.g. CANSocket stores it as sock.bitrate).
    # When reconnect_handler is provided, probe a temporary socket for the attribute.
    if bitrate == J1939_DEFAULT_BITRATE:
        _probe = reconnect_handler() if reconnect_handler is not None else sock
        sock_bitrate = getattr(_probe, "bitrate", None)
        if sock_bitrate is not None:
            try:
                bitrate = int(sock_bitrate)
            except (TypeError, ValueError):
                # Fall back to default bitrate if attribute is non-numeric
                pass
        if reconnect_handler is not None and _probe is not sock:
            try:
                _probe.close()
            except Exception as ex:
                j1939_log.debug("failed to close probe socket: %s", ex)

    # Step 0: passive pre-scan to detect background noise unless disabled.
    if not force and noise_ids is None:
        if stop_event is not None and stop_event.is_set():
            return {}
        noise_ids = j1939_scan_passive(
            sock,
            listen_time=noise_listen_time,
            stop_event=stop_event,
            reconnect_handler=reconnect_handler,
        )
        if verbose and noise_ids:
            j1939_log.info(
                "j1939_scan: %d noise SA(s) detected, will skip: %s",
                len(noise_ids),
                [hex(s) for s in sorted(noise_ids)],
            )

    results = {}  # type: Dict[int, Dict[str, object]]
    scan_range_list = list(scan_range)

    def _merge(found, method_name):
        # type: (Dict[int, List[J1939ScanResult]], str) -> None
        for sa, scan_results in found.items():
            src_addr = []  # type: List[int]
            pkts = []  # type: List[J1939]
            for r in scan_results:
                pkts.append(r.packet)
                if r.scanner_src is not None and r.scanner_src not in src_addr:
                    src_addr.append(r.scanner_src)

            if sa not in results:
                if verbose:
                    j1939_log.info(
                        "j1939_scan: found SA=0x%02X via %s", sa, method_name
                    )
                results[sa] = {
                    "methods": [method_name],
                    "packets": [pkts],
                    "results": [scan_results],
                    "src_addrs": [src_addr],
                }
            else:
                if verbose:
                    j1939_log.info(
                        "j1939_scan: SA=0x%02X also detected via %s", sa, method_name
                    )
                cast(List[str], results[sa]["methods"]).append(method_name)
                cast(List[List[Any]], results[sa]["packets"]).append(pkts)
                cast(List[List[J1939ScanResult]], results[sa]["results"]).append(
                    scan_results
                )
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
                reconnect_handler=reconnect_handler,
            ),
            "addr_claim",
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
                reconnect_handler=reconnect_handler,
            ),
            "ecu_id",
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
                reconnect_handler=reconnect_handler,
            ),
            "unicast",
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
                reconnect_handler=reconnect_handler,
            ),
            "rts_probe",
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
            "reconnect_handler": reconnect_handler,
        }
        if diag_pgn is not None:
            uds_kwargs["diag_pgn"] = diag_pgn
        _merge(j1939_scan_uds(**uds_kwargs), "uds")

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
            "reconnect_handler": reconnect_handler,
        }
        if diag_pgn is not None:
            xcp_kwargs["diag_pgn"] = diag_pgn
        _merge(j1939_scan_xcp(**xcp_kwargs), "xcp")

    return results


_xcp_connect_req_cache = None  # type: Optional[bytes]
_uds_tester_present_reqs_cache = None  # type: Optional[List[bytes]]


def __getattr__(name):
    # type: (str) -> Any
    global _xcp_connect_req_cache, _uds_tester_present_reqs_cache
    if name == "_XCP_CONNECT_REQ":
        if _xcp_connect_req_cache is None:
            _xcp_connect_req_cache = _get_xcp_connect_req()
        return _xcp_connect_req_cache
    if name == "_UDS_TESTER_PRESENT_REQS":
        if _uds_tester_present_reqs_cache is None:
            _uds_tester_present_reqs_cache = _get_uds_tester_present_reqs()
        return _uds_tester_present_reqs_cache
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


__all__ = [
    "J1939_DEFAULT_BITRATE",
    "J1939_DEFAULT_BUSLOAD",
    "J1939_DIAGADAPTERS_ADDRESSES",
    "J1939_DiagA",
    "J1939_DiagB",
    "J1939_PF_ACK",
    "J1939_PF_ADDRESS_CLAIMED",
    "J1939_PF_DIAG_A",
    "J1939_PF_DIAG_B",
    "J1939_PF_REQUEST",
    "J1939_PF_XCP",
    "J1939_PGN_DIAG_A",
    "J1939_PGN_DIAG_B",
    "J1939_PGN_ECU_ID",
    "J1939_TP_CM_PF",
    "J1939_XCP_SRC_ADDRS",
    "J1939ScanResult",
    "SCAN_METHODS",
    "j1939_can_id",
    "j1939_check_socket_can_filters",
    "j1939_decode_can_id",
    "j1939_get_sock",
    "j1939_inter_probe_delay",
    "j1939_pre_probe_flush",
    "j1939_resolve_broadcast_sock",
    "j1939_resolve_probe_sock",
    "j1939_sa_filter",
    "j1939_scan",
    "j1939_scan_addr_claim",
    "j1939_scan_ecu_id",
    "j1939_scan_passive",
    "j1939_scan_rts_probe",
    "j1939_scan_uds",
    "j1939_scan_unicast",
    "j1939_scan_xcp",
]
