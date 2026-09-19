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
import json
import logging
import struct
import time
from threading import Event  # noqa: F401

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
    Union,
    cast,
)

from scapy.layers.can import CAN, CAN_EFF_FLAG
from scapy.supersocket import SuperSocket

from scapy.contrib.automotive.j1939 import J1939Socket
from scapy.contrib.j1939 import (
    J1939,
    J1939Request,
    J1939_BROADCAST_ADDR as J1939_GLOBAL_ADDRESS,
    J1939_PGN_TP_CM,
    J1939_TP_CTRL_BAM,
    J1939_TP_CTRL_RTS as TP_CM_RTS,
    J1939_TP_CTRL_CTS as TP_CM_CTS,
    J1939_TP_CTRL_ABORT as TP_Conn_Abort,
    can_id_to_j1939,
    j1939_to_can_id,
    log_j1939,
)


J1939_TP_CM_PF = (J1939_PGN_TP_CM >> 8) & 0xFF
PGN_ADDRESS_CLAIMED = 0xEE00
J1939_PF_ADDRESS_CLAIMED = 0xEE
PGN_REQUEST = 0xEA00
J1939_PF_REQUEST = 0xEA


def _j1939_can_id(priority, pf, da, sa):
    return j1939_to_can_id(
        priority=priority, reserved=0, data_page=0,
        pdu_format=pf, pdu_specific=da, src=sa)


def _j1939_decode_can_id(can_id):
    f = can_id_to_j1939(can_id)
    return (f['priority'], f['pdu_format'],
            f['pdu_specific'], f['src'])


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
    """Flush the kernel CAN receive buffer before sending a probe."""
    try:
        sock.select([sock], 0)
    except (AttributeError, OSError) as ex:
        log_j1939.debug("pre_probe_flush failed: %s", ex)


# --- Socketcan filter helpers

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
        "can_id": CAN_EFF_FLAG | (target_sa & 0xFF),
        "can_mask": CAN_EFF_FLAG | 0xFF,
    }]


def _open_sa_filtered_sock(sock, target_sa):
    # type: (SuperSocket, int) -> Tuple[SuperSocket, bool]
    """Try to open a CAN socket filtered to receive only SA=*target_sa*.

    When *sock* is a :class:`~scapy.contrib.cansocket.CANSocket`,
    this creates a **new** raw CAN socket on the same interface with a
    hardware-level or backend-level filter that passes only extended
    frames whose source-address byte matches *target_sa*.  The filter
    discards non-matching frames before they enter the socket receive buffer,
    preventing buffer overflow on resource-constrained embedded systems
    with busy J1939 buses.

    For any other socket type (test sockets, etc.) the function returns
    the original *sock* unchanged as a safe fallback — the existing
    ``_pre_probe_flush`` mechanism handles those cases.

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
        from scapy.contrib.cansocket import CANSocket
        if not isinstance(sock, CANSocket):
            return sock, False
        rx = CANSocket(
            channel=channel,
            can_filters=_j1939_sa_filter(target_sa),
        )
        return rx, True
    except Exception as ex:
        log_j1939.debug("failed to create filtered rx socket: %s", ex)
        return sock, False


#: Type alias for the socket parameter of scan functions: a live CAN socket.
SockOrFactory = SuperSocket


def _resolve_probe_sock(sock, target_sa, reconnect=None):
    # type: (SuperSocket, int, Optional[Callable[[], SuperSocket]]) -> Tuple[SuperSocket, SuperSocket, bool]
    """Resolve a socket into ``(send_sock, rx_sock, close_rx)``.

    When *reconnect* is provided, it is called to create a fresh per-probe socket
    for this iteration.  On :class:`~scapy.contrib.cansocket.CANSocket` the new
    socket is transparently upgraded to one with a filter that passes only extended
    frames whose source-address byte equals *target_sa*.  Both *send_sock*
    and *rx_sock* point to the same newly opened socket; the caller **must**
    close it via *close_rx=True*.

    When *reconnect* is None and *sock* is a live socket, the original
    socket is used for sending and a separate filtered receive socket is opened
    if possible; otherwise *rx_sock* equals *send_sock*.  The caller's
    *send_sock* is **never** closed.

    :param sock: CAN socket
    :param target_sa: source address expected in response frames
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket
    :returns: ``(send_sock, rx_sock, close_rx)`` — the caller must call
              ``rx_sock.close()`` after the probe iff *close_rx* is True.
              *send_sock* is **never** closed when *close_rx* is False.
    """
    if reconnect is not None:
        probe = reconnect()
        channel = getattr(probe, "channel", None)
        if channel is not None:
            try:
                from scapy.contrib.cansocket import CANSocket
                if isinstance(probe, CANSocket):
                    probe.close()
                    filtered = CANSocket(
                        channel=channel,
                        can_filters=_j1939_sa_filter(target_sa),
                    )
                    return filtered, filtered, True
            except Exception as ex:
                log_j1939.debug(
                    "failed to create filtered probe socket: %s", ex
                )
        return probe, probe, True
    rx_sock, close_rx = _open_sa_filtered_sock(sock, target_sa)
    return sock, rx_sock, close_rx


def _resolve_broadcast_sock(sock, reconnect=None):
    # type: (SuperSocket, Optional[Callable[[], SuperSocket]]) -> Tuple[SuperSocket, bool]
    """Resolve a socket for broadcast (non-filtered) use.

    When *reconnect* is provided, the factory is called once to create a socket.
    When *reconnect* is None, the live *sock* is returned as-is.

    :returns: ``(sock, close_needed)``
    """
    if reconnect is not None:
        return reconnect(), True
    return sock, False


@contextlib.contextmanager
def _get_j1939_sock(
    sock,  # type: SockOrFactory
    src_addr=0xF9,  # type: int
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
    target_sa=None,  # type: Optional[int]
    include_tp_cm=False,  # type: bool
    promisc=True,  # type: bool
):
    # type: (...) -> Iterator[SuperSocket]
    """Context manager yielding a J1939Socket configured with *src_addr*.

    If *reconnect* is provided, creates a fresh underlying socket and
    J1939Socket per iteration, closing both on exit.
    If *sock* is already a J1939Socket, temporarily updates its *src_addr*
    and restores it on exit without closing *sock*.
    Otherwise wraps *sock* in a J1939Socket and closes the wrapper on exit
    (preserving the underlying CAN socket).
    """
    if reconnect is not None:
        probe = reconnect()
        if target_sa is not None:
            channel = getattr(probe, "channel", None)
            if channel is not None:
                try:
                    from scapy.contrib.cansocket import CANSocket
                    if isinstance(probe, CANSocket):
                        probe.close()
                        probe = CANSocket(
                            channel=channel,
                            can_filters=_j1939_sa_filter(target_sa),
                        )
                except Exception as ex:
                    log_j1939.debug(
                        "failed to create filtered probe socket: %s", ex
                    )
        j_sock = J1939Socket(
            probe, src_addr=src_addr, include_tp_cm=include_tp_cm, promisc=promisc
        )
        try:
            yield j_sock
        finally:
            j_sock.close()
            probe.close()
    elif isinstance(sock, J1939Socket):
        old_sa = getattr(sock, "src_addr", None)
        old_include_tp_cm = getattr(getattr(sock, "impl", None), "include_tp_cm", None)
        old_promisc = getattr(getattr(sock, "impl", None), "promisc", None)
        try:
            sock.src_addr = src_addr
            if hasattr(sock, "impl"):
                sock.impl.src_addr = src_addr
                if include_tp_cm:
                    sock.impl.include_tp_cm = True
                if promisc:
                    sock.impl.promisc = True
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
            yield j_sock
        finally:
            j_sock.close()


# --- Passive scan — background noise detection


def j1939_scan_passive(

    sock,  # type: SockOrFactory
    listen_time=2.0,  # type: float
    stop_event=None,  # type: Optional[Event]
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket
    :returns: set of observed source addresses (integers)
    """
    active_sock, close_sock = _resolve_broadcast_sock(sock, reconnect=reconnect)
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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket
    :returns: dict mapping responder source address (int) to a list of
              matching J1939 replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    found = {}  # type: Dict[int, List[J1939]]

    with (
        _get_j1939_sock(sock)
        if reconnect is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        for _sa in src_addrs:
            if stop_event is not None and stop_event.is_set():
                break
            can_id = _j1939_can_id(
                _SCAN_PRIORITY, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, _sa
            )
            req = J1939Request(
                req_pgn=PGN_ADDRESS_CLAIMED, dst=J1939_GLOBAL_ADDRESS, src=_sa
            )
            with _get_j1939_sock(
                base_j_sock, src_addr=_sa, reconnect=reconnect
            ) as j_sock:
                log_j1939.debug(
                    "addr_claim: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)",
                    _sa,
                    can_id,
                )
                ans, _ = j_sock.sr(req, multi=True, timeout=listen_time, verbose=False)
                for _, rcv in ans:
                    if stop_event is not None and stop_event.is_set():
                        break
                    if rcv.pgn == PGN_ADDRESS_CLAIMED:
                        sa = rcv.src
                        if not force and noise_ids is not None and sa in noise_ids:
                            log_j1939.debug("addr_claim: suppressing noise SA=0x%02X", sa)
                            continue
                        if sa not in found:
                            found[sa] = []
                        # Record which scanner SA elicited this broadcast
                        setattr(rcv, "src_addrs", [_sa])
                        found[sa].append(rcv)

        # Pace: 1 broadcast Request (DLC 3) + 1 typical response (DLC 8)
        _extra = _inter_probe_delay(bitrate, busload, 3, 8, listen_time)
        if _extra > 0.0:
            time.sleep(_extra)

    return found


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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket
    :returns: dict mapping responder source address (int) to a list of
              matching J1939 replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    found = {}  # type: Dict[int, List[J1939]]

    with (
        _get_j1939_sock(sock, include_tp_cm=True)
        if reconnect is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        for _sa in src_addrs:
            if stop_event is not None and stop_event.is_set():
                break
            can_id = _j1939_can_id(
                _SCAN_PRIORITY, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, _sa
            )
            req = J1939Request(
                req_pgn=PGN_ECU_ID, dst=J1939_GLOBAL_ADDRESS, src=_sa
            )
            with _get_j1939_sock(
                base_j_sock, src_addr=_sa, reconnect=reconnect, include_tp_cm=True
            ) as j_sock:
                log_j1939.debug(
                    "ecu_id: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)",
                    _sa,
                    can_id,
                )
                ans, _ = j_sock.sr(req, multi=True, timeout=listen_time, verbose=False)

            for _, rcv in ans:
                if stop_event is not None and stop_event.is_set():
                    break
                matched = False
                if rcv.pgn == PGN_ECU_ID:
                    matched = True
                elif rcv.pgn == J1939_PGN_TP_CM:
                    d = rcv.data if rcv.data else bytes(rcv.payload)
                    if len(d) >= 8 and d[0] == J1939_TP_CTRL_BAM:
                        bam_pgn = d[5] | (d[6] << 8) | (d[7] << 16)
                        if bam_pgn == PGN_ECU_ID:
                            matched = True
                if matched:
                    sa = rcv.src
                    if not force and noise_ids is not None and sa in noise_ids:
                        log_j1939.debug("ecu_id: suppressing noise SA=0x%02X", sa)
                        continue
                    log_j1939.debug("ecu_id: BAM from SA=0x%02X", sa)
                    if sa not in found:
                        found[sa] = []
                    # Record which scanner SA elicited this broadcast
                    setattr(rcv, "src_addrs", [_sa])
                    found[sa].append(rcv)

        # Pace: 1 broadcast Request (DLC 3) + 1 typical BAM header (DLC 8)
        _extra = _inter_probe_delay(bitrate, busload, 3, 8, listen_time)
        if _extra > 0.0:
            time.sleep(_extra)

    return found


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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket. When provided, a fresh socket is
                      created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              matching J1939 replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    else:
        src_addrs = list(src_addrs)
    found = {}  # type: Dict[int, List[J1939]]

    with (
        _get_j1939_sock(sock)
        if reconnect is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        for da in scan_range:
            if stop_event is not None and stop_event.is_set():
                break
            if not force and noise_ids is not None and da in noise_ids:
                log_j1939.debug("unicast: skipping noise DA=0x%02X", da)
                continue

            _da = da
            with _get_j1939_sock(
                base_j_sock, reconnect=reconnect, target_sa=_da
            ) as j_sock:
                for _sa in src_addrs:
                    if stop_event is not None and stop_event.is_set():
                        break
                    req = J1939Request(req_pgn=PGN_ADDRESS_CLAIMED, dst=_da, src=_sa)
                    log_j1939.debug("unicast: probing DA=0x%02X from SA=0x%02X", _da, _sa)
                    rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
                    if (
                        rcv is not None
                        and rcv.src == _da
                        and rcv.pgn == PGN_ADDRESS_CLAIMED
                        and rcv.src != _sa
                        and (rcv.dst == _sa or rcv.dst == J1939_GLOBAL_ADDRESS)
                    ):
                        log_j1939.debug(
                            "unicast: response from SA=0x%02X to scanner SA=0x%02X",
                            rcv.src,
                            rcv.dst,
                        )
                        if _da not in found:
                            found[_da] = []
                        if rcv.dst == J1939_GLOBAL_ADDRESS:
                            setattr(rcv, "src_addrs", [_sa])
                        found[_da].append(rcv)

            # Pace the probe rate
            _tx_bits = _can_frame_bits(3)
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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[CAN]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket. When provided, a fresh socket is
                      created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              matching J1939 replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    else:
        src_addrs = list(src_addrs)
    found = {}  # type: Dict[int, List[J1939]]

    with (
        _get_j1939_sock(sock)
        if reconnect is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
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
            with _get_j1939_sock(
                base_j_sock, reconnect=reconnect, target_sa=_da
            ) as j_sock:
                for _sa in src_addrs:
                    if stop_event is not None and stop_event.is_set():
                        break
                    req = J1939(pgn=0xEC00, dst=_da, src=_sa, data=rts_payload)
                    log_j1939.debug("rts_probe: probing DA=0x%02X from SA=0x%02X", _da, _sa)
                    rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
                    if rcv is not None and rcv.src == _da and rcv.src != _sa:
                        d = rcv.data if rcv.data else bytes(rcv.payload)
                        if d:
                            if rcv.pgn == J1939_PGN_TP_CM and d[0] in (TP_CM_CTS, TP_Conn_Abort):
                                log_j1939.debug(
                                    "rts_probe: TP.CM (ctrl=0x%02X) from SA=0x%02X"
                                    " to scanner SA=0x%02X",
                                    d[0],
                                    rcv.src,
                                    _sa,
                                )
                                if _da not in found:
                                    found[_da] = []
                                found[_da].append(rcv)
                            elif rcv.pgn == _J1939_PF_ACK << 8 and d[0] in (
                                _ACK_CTRL_NACK,
                                _ACK_CTRL_ACCESS_DENIED,
                                _ACK_CTRL_CANNOT_RESPOND,
                            ):
                                log_j1939.debug(
                                    "rts_probe: ACK (ctrl=0x%02X) from SA=0x%02X"
                                    " to scanner SA=0x%02X",
                                    d[0],
                                    rcv.src,
                                    _sa,
                                )
                                if _da not in found:
                                    found[_da] = []
                                found[_da].append(rcv)

            # Pace: 1 RTS probe (DLC 8) + one expected response (DLC 8)
            _tx_bits = _can_frame_bits(8)
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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket. When provided, a fresh socket is
                      created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              matching J1939 replies
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    else:
        src_addrs = list(src_addrs)
    found = {}  # type: Dict[int, List[J1939]]
    reqs = _get_uds_tester_present_reqs()

    with (
        _get_j1939_sock(sock)
        if reconnect is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        if not skip_functional:
            for _sa in src_addrs:
                if stop_event is not None and stop_event.is_set():
                    break
                with _get_j1939_sock(base_j_sock, src_addr=_sa, reconnect=reconnect) as j_sock:
                    log_j1939.debug(
                        "uds: broadcast functional probe sent SA=0x%02X (PF=0x%02X)",
                        _sa,
                        diag_pgn | 0x01,
                    )
                    for req_data in reqs:
                        if stop_event is not None and stop_event.is_set():
                            break
                        req = J1939(
                            pgn=(diag_pgn | 0x01) << 8,
                            dst=J1939_GLOBAL_ADDRESS,
                            src=_sa,
                            data=req_data,
                        )
                        ans, _ = j_sock.sr(
                            req, multi=True, timeout=broadcast_listen_time, verbose=False
                        )
                        for _, rcv in ans:
                            if stop_event is not None and stop_event.is_set():
                                break
                            sa = rcv.src
                            if not force and noise_ids is not None and sa in noise_ids:
                                continue
                            data = rcv.data if rcv.data else bytes(rcv.payload)
                            if data[:3] in _UDS_TESTER_PRESENT_RESPS:
                                log_j1939.debug(
                                    "uds: functional response from SA=0x%02X to scanner SA=0x%02X",
                                    sa,
                                    _sa,
                                )
                                if sa not in found:
                                    found[sa] = []
                                found[sa].append(rcv)

        for da in scan_range:
            if stop_event is not None and stop_event.is_set():
                break
            if not force and noise_ids is not None and da in noise_ids:
                log_j1939.debug("uds: skipping noise DA=0x%02X", da)
                continue

            _da = da
            with _get_j1939_sock(
                base_j_sock, reconnect=reconnect, target_sa=_da
            ) as j_sock:
                for _sa in src_addrs:
                    if stop_event is not None and stop_event.is_set():
                        break
                    _sa_resps = []  # type: List[J1939]
                    for req_data in reqs:
                        if stop_event is not None and stop_event.is_set():
                            break
                        if _sa_resps:
                            break
                        log_j1939.debug(
                            "uds: physical probe DA=0x%02X SA=0x%02X on PF=0x%02X",
                            _da,
                            _sa,
                            diag_pgn,
                        )
                        req = J1939(pgn=diag_pgn << 8, dst=_da, src=_sa, data=req_data)
                        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
                        if (
                            rcv is not None
                            and rcv.src == _da
                            and rcv.dst == _sa
                            and rcv.src != _sa
                        ):
                            data = rcv.data if rcv.data else bytes(rcv.payload)
                            if data[:3] in _UDS_TESTER_PRESENT_RESPS:
                                log_j1939.debug(
                                    "uds: response from SA=0x%02X to scanner SA=0x%02X",
                                    rcv.src,
                                    _sa,
                                )
                                if _da not in found:
                                    found[_da] = []
                                found[_da].append(rcv)
                                _sa_resps.append(rcv)

                    # Pace: probes per src_addr + 1 response
                    _tx_bits = len(reqs) * _can_frame_bits(8)
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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket. When provided, a fresh socket is
                      created for each probed DA and closed after that iteration.
    :returns: dict mapping responder source address (int) to a list of
              matching J1939 replies
    """
    if src_addrs is None:
        src_addrs = J1939_XCP_SRC_ADDRS
    else:
        src_addrs = list(src_addrs)
    found = {}  # type: Dict[int, List[J1939]]
    connect_req = _get_xcp_connect_req()

    with (
        _get_j1939_sock(sock)
        if reconnect is None
        else contextlib.nullcontext(sock)
    ) as base_j_sock:
        for da in scan_range:
            if stop_event is not None and stop_event.is_set():
                break
            if not force and noise_ids is not None and da in noise_ids:
                log_j1939.debug("xcp: skipping noise DA=0x%02X", da)
                continue

            _da = da
            with _get_j1939_sock(
                base_j_sock, reconnect=reconnect, target_sa=_da
            ) as j_sock:
                for _sa in src_addrs:
                    if stop_event is not None and stop_event.is_set():
                        break
                    req = J1939(pgn=diag_pgn << 8, dst=_da, src=_sa, data=connect_req)
                    log_j1939.debug(
                        "xcp: probing DA=0x%02X from SA=0x%02X", _da, _sa
                    )
                    rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
                    if (
                        rcv is not None
                        and rcv.src == _da
                        and rcv.dst == _sa
                        and rcv.src != _sa
                    ):
                        data = rcv.data if rcv.data else bytes(rcv.payload)
                        if data and data[0] == _XCP_POSITIVE_RESPONSE:
                            log_j1939.debug(
                                "xcp: response from SA=0x%02X to scanner SA=0x%02X",
                                rcv.src,
                                _sa,
                            )
                            if _da not in found:
                                found[_da] = []
                            found[_da].append(rcv)

            _tx_bits = _can_frame_bits(8)
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
    reconnect=None,  # type: Optional[Callable[[], SuperSocket]]
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
    :param reconnect: optional zero-argument callable returning a newly
                      created CAN socket passed down to each scan method.
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
    else:
        src_addrs = list(src_addrs)

    # If the caller left bitrate at the sentinel default, try to pull the real
    # value from the socket (e.g. CANSocket stores it as sock.bitrate).
    # When reconnect is provided, probe a temporary socket for the attribute.
    if bitrate == _J1939_DEFAULT_BITRATE:
        _probe = reconnect() if reconnect is not None else sock
        sock_bitrate = getattr(_probe, "bitrate", None)
        if sock_bitrate is not None:
            try:
                bitrate = int(sock_bitrate)
            except (TypeError, ValueError):
                # Fall back to default bitrate if attribute is non-numeric
                pass
        if reconnect is not None and _probe is not sock:
            try:
                _probe.close()
            except Exception as ex:
                log_j1939.debug("failed to close probe socket: %s", ex)

    # Step 0: passive pre-scan to detect background noise unless disabled.
    if not force and noise_ids is None:
        if stop_event is not None and stop_event.is_set():
            return {}
        noise_ids = j1939_scan_passive(
            sock,
            listen_time=noise_listen_time,
            stop_event=stop_event,
            reconnect=reconnect,
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
        # type: (Dict[int, List[Any]], str, bool) -> None
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

                    if hasattr(p, "dst") and p.dst != J1939_GLOBAL_ADDRESS:
                        ps = p.dst
                    elif hasattr(p, "identifier"):
                        _, _, ps, _ = _j1939_decode_can_id(p.identifier)
                    else:
                        ps = J1939_GLOBAL_ADDRESS
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
                cast(List[List[Any]], results[sa]["packets"]).append(pkts)
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
                reconnect=reconnect,
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
                reconnect=reconnect,
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
                reconnect=reconnect,
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
                reconnect=reconnect,
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
            "reconnect": reconnect,
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
            "reconnect": reconnect,
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
