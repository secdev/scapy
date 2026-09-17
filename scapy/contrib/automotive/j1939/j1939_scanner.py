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

+------------+-----------------------------------+------------------------------------+
| Technique  | Probe (sent by scanner)           | Expected response (from ECU)       |
+============+===================================+====================================+
| addr_claim | Broadcast Request (PF=EA, DA=FF)  | Address Claimed (PF=EE, DA=FF)     |
|            | for PGN 60928 (0xEE00)            | SA=ECU-SA, 8-byte J1939 NAME       |
+------------+-----------------------------------+------------------------------------+
| ecu_id     | Broadcast Request (PF=EA, DA=FF)  | TP.CM BAM (PF=EC, DA=FF,           |
|            | for PGN 64965 (0xFDC5)            | ctrl=0x20) announcing PGN 64965    |
+------------+-----------------------------------+------------------------------------+
| unicast    | Unicast Request (PF=EA, DA=ECU)   | Any CAN frame (extended) whose     |
|            | for PGN 60928 to each DA          | SA equals probed DA                |
+------------+-----------------------------------+------------------------------------+
| rts_probe  | TP.CM_RTS (PF=EC, DA=ECU-SA)      | TP.CM_CTS (ctrl=0x11) or           |
|            | sent to each DA                   | TP_Conn_Abort (ctrl=0xFF) or       |
|            |                                   | NACK on ACK PGN (PF=E8)            |
+------------+-----------------------------------+------------------------------------+
| uds        | Physical (PF=diag, DA=ECU-SA) and | UDS response (positive 02 7E xx    |
|            | Functional (PF=diag+1, DA=FF)     | or negative 03 7F 3E xx)           |
|            | payload 02 3E {00,01} padded      | from responding DA                 |
|            | once per SA in src_addrs          |                                    |
+------------+-----------------------------------+------------------------------------+
| xcp        | Physical (PF=diag, DA=ECU-SA)     | XCP positive response (byte 0=FF)  |
|            | payload FF 00 FF FF FF FF FF FF   | from responding DA                 |
|            | once per SA in src_addrs          |                                    |
+------------+-----------------------------------+------------------------------------+

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
import copy
from dataclasses import dataclass
import logging
import time
import weakref

# Typing imports
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    TYPE_CHECKING,
    Type,
    Union,
    cast,
)

if TYPE_CHECKING:
    from threading import Event

from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.scanner.executor import AutomotiveTestCaseExecutor
from scapy.contrib.automotive.scanner.test_case import (
    AutomotiveTestCase,
    AutomotiveTestCaseABC,
)
from scapy.contrib.automotive.uds import (
    UDS,
    UDS_NR,
    UDS_TP,
    UDS_TPPR,
)
from scapy.contrib.automotive.xcp.xcp import (
    CTORequest,
    Connect,
)
from scapy.contrib.j1939 import (
    J1939,
    J1939Ack,
    J1939DiagA,
    J1939DiagB,
    J1939Request,
    J1939Socket,
    J1939SoftSocket,
    J1939_GLOBAL_ADDRESS,
    J1939_PGN_ADDRESS_CLAIMED,
    J1939_PGN_DIAG_A,
    J1939_PGN_REQUEST,
    J1939_TP_CM_ABORT,
    J1939_TP_CM_BAM,
    J1939_TP_CM_CTS,
    J1939_TP_CM_RTS,
    NativeJ1939Socket,
    log_j1939,
)
from scapy.error import Scapy_Exception
from scapy.layers.can import CAN, CAN_EFF_FLAG
from scapy.packet import Packet
from scapy.supersocket import SuperSocket


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

#: Default priority for request frames sent by the scanner
_J1939_SCAN_PRIORITY = 6

#: Scan address range for unicast / RTS sweeps (0x00 – 0xFD inclusive)
_J1939_SCAN_ADDR_RANGE = range(0x00, 0xFE)  # 0xFE = null / 0xFF = broadcast

_J1939ProbeResult = Optional[Union[Packet, List[Packet]]]
_J1939ProbeCallable = Callable[[SuperSocket, int, int], _J1939ProbeResult]

#: Candidate diagnostic source addresses (SAE J1939 reserved diagnostic range).
#: Used as the default for *src_addrs* in all scan functions.
J1939_DIAGADAPTERS_ADDRESSES = list(range(0xF1, 0xFE))  # [0xF1 .. 0xFD]


#: Pre-computed UDS TesterPresent request CAN frame payloads
#: (sub-functions 0x00 and 0x01).
J1939_UDS_TESTER_PRESENT_REQS = [
    (bytes([len(p)]) + bytes(p)).ljust(8, b"\xff")
    for p in (
        UDS() / UDS_TP(subFunction=0x00),
        UDS() / UDS_TP(subFunction=0x01),
    )
]

#: Expected UDS responses for TesterPresent (SID=0x3E).
#: Truncated to positive responses (SID=0x7E, sub-functions 0x00 and 0x01) and
#: negative response header (SID=0x7F, original SID=0x3E) so any NRC matches.
J1939_UDS_TESTER_PRESENT_RESPS = [
    bytes(UDS() / UDS_TPPR(zeroSubFunction=0x00)),
    bytes(UDS() / UDS_TPPR(zeroSubFunction=0x01)),
    bytes(UDS() / UDS_NR(requestServiceId=0x3E))[:2],
]

#: PGN for XCP Messages (Proprietary A, PDU1 peer-to-peer, PGN 0xEF00)
J1939_PGN_XCP = 0xEF00

#: Default source addresses used by the XCP scanner.
J1939_XCP_SRC_ADDRS = (
    [0x3F, 0x5A] + list(range(0x01, 0x10)) + [0xAC] + list(range(0xF1, 0xFE))
)

#: Padded XCP CONNECT request payload (8 bytes: 0xFF 0x00 followed by padding).
J1939_XCP_CONNECT_REQ = bytes(CTORequest() / Connect()).ljust(8, b"\xff")

#: XCP positive response byte (status byte 0xFF = OK in XCP protocol)
J1939_XCP_POSITIVE_RESPONSE = 0xFF

#: Acknowledgment control-byte values (J1939-21 §5.4.4, data byte 0).
J1939_ACK_CTRL_ACK = 0x00             # Positive Acknowledgment
J1939_ACK_CTRL_NACK = 0x01            # Negative Acknowledgment
J1939_ACK_CTRL_ACCESS_DENIED = 0x02   # Access Denied
J1939_ACK_CTRL_CANNOT_RESPOND = 0x03  # Cannot Respond

#: All valid CA scan method names
J1939_SCAN_METHODS = ("addr_claim", "ecu_id", "unicast", "rts_probe", "uds", "xcp")


# --- Pacing helpers

#: Default CAN bitrate for J1939 networks (SAE J1939-11, 250 kbit/s)
J1939_DEFAULT_BITRATE = 250000  # bit/s

#: Default maximum fraction of bus bandwidth the scanner may consume (5 %)
J1939_DEFAULT_BUSLOAD = 0.05


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
    bits = (67 + tx_dlc * 8) + (67 + rx_dlc * 8)
    min_cycle = bits / (bitrate * busload)
    return max(0.0, min_cycle - sniff_time)


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


_J1939_FILTER_WARNED_SOCKETS = weakref.WeakSet()  # type: weakref.WeakSet[Any]


def j1939_emit_sa_filter_warning(sock_objs, target_sa):
    # type: (Iterable[Any], int) -> None
    """Emit warning recommending a CAN filter for *target_sa* once."""
    if not any(obj in _J1939_FILTER_WARNED_SOCKETS for obj in sock_objs):
        log_j1939.warning(
            "You should put a filter for SA=0x%02X on your CAN socket",
            target_sa,
        )
        for obj in sock_objs:
            try:
                _J1939_FILTER_WARNED_SOCKETS.add(obj)
            except TypeError as ex:
                # Sockets without weakref support cannot be tracked in WeakSet
                log_j1939.debug(
                    "failed to track socket object in WeakSet: %s", ex
                )


def j1939_check_rx_filter_warning(pkt, target_sa, warning_targets):
    # type: (Any, Optional[int], Iterable[Any]) -> None
    """Inspect a received packet and emit filter warning if SA != target_sa."""
    if target_sa is None or pkt is None:
        return
    sa = getattr(pkt, "src", None)
    if sa is None and hasattr(pkt, "identifier"):
        try:
            sa = pkt.identifier & 0xFF
        except (AttributeError, TypeError, ValueError) as ex:
            log_j1939.debug(
                "j1939_check_rx_filter_warning: failed to decode CAN ID: %s", ex
            )
    if sa is not None and sa != target_sa:
        j1939_emit_sa_filter_warning(warning_targets, target_sa)


def j1939_reconnect_with_retry(
    reconnect_handler,  # type: Callable[[], SuperSocket]
    reconnect_retries=5,  # type: int
    retry_delay=1.0,  # type: float
    stop_event=None,  # type: Optional[Event]
):
    # type: (...) -> SuperSocket
    """Invoke *reconnect_handler* with retries on failure."""
    for attempt in range(max(1, reconnect_retries)):
        try:
            return reconnect_handler()
        except (AttributeError, OSError, Scapy_Exception) as ex:
            if attempt == reconnect_retries - 1:
                raise
            log_j1939.debug(
                "reconnect attempt %d/%d failed: %s, retrying in %s s",
                attempt + 1,
                reconnect_retries,
                ex,
                retry_delay,
            )
            if stop_event is not None:
                stop_event.wait(retry_delay)
            else:
                time.sleep(retry_delay)
    raise OSError("reconnect_handler failed after exhausting retries")


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

    If *sock* is closed or not working and *reconnect_handler* is provided,
    obtains a fresh socket from *reconnect_handler* and closes it on exit.
    If *sock* is already a J1939Socket, yields it without closing *sock*.
    Otherwise wraps *sock* in a J1939Socket and closes the wrapper on exit
    (preserving the underlying CAN socket).
    """
    inner_sock = getattr(sock, "_inner", sock)
    is_closed = (
        inner_sock is None
        or getattr(inner_sock, "closed", False)
        or getattr(getattr(inner_sock, "impl", None), "closed", False)
        or getattr(getattr(inner_sock, "can_socket", None), "closed", False)
    )

    close_raw = False
    if is_closed and reconnect_handler is not None:
        raw = reconnect_handler()
        close_raw = True
    else:
        raw = inner_sock

    if isinstance(raw, (J1939SoftSocket, NativeJ1939Socket)):
        try:
            yield raw
        finally:
            if close_raw:
                try:
                    raw.close()
                except (AttributeError, OSError) as ex:
                    log_j1939.debug(
                        "j1939_get_sock: failed to close socket: %s", ex
                    )
    else:
        j_sock = J1939Socket(
            raw,
            src_addr=src_addr,
            include_tp_cm=include_tp_cm,
            promisc=promisc,
        )
        try:
            yield j_sock
        finally:
            try:
                j_sock.close()
            except (AttributeError, OSError) as ex:
                log_j1939.debug(
                    "j1939_get_sock: failed to close j_sock: %s", ex
                )
            if close_raw:
                try:
                    raw.close()
                except (AttributeError, OSError) as ex:
                    log_j1939.debug(
                        "j1939_get_sock: failed to close raw socket: %s", ex
                    )


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
    if reconnect_handler is not None:
        active_sock, close_sock = reconnect_handler(), True
    else:
        active_sock, close_sock = sock, False
    try:
        seen = set()  # type: Set[int]

        def _rx(pkt):
            # type: (CAN) -> None
            if stop_event is not None and stop_event.is_set():
                return
            if not pkt.flags.extended:
                return
            seen.add(pkt.identifier & 0xFF)

        active_sock.sniff(prn=_rx, timeout=listen_time, store=False)
        log_j1939.debug(
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
                                log_j1939.debug(
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
    probe_step,  # type: _J1939ProbeCallable
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
        tx_bits = num_tx_probes * (67 + tx_dlc * 8)
        return max(
            0.0,
            (tx_bits + 67 + rx_dlc * 8) / (bitrate * busload) - sniff_time,
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
                log_j1939.debug("%s: skipping noise DA=0x%02X", log_name, da)
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
                        for pkt in resp_list:
                            j1939_check_rx_filter_warning(
                                pkt, _da, [base_j_sock, j_sock]
                            )
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
        req = J1939(
            pgn=J1939_PGN_REQUEST, dst=J1939_GLOBAL_ADDRESS, src=sa
        ) / J1939Request(
            req_pgn=J1939_PGN_ADDRESS_CLAIMED
        )
        log_j1939.debug(
            "addr_claim: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)",
            sa,
            req.to_can_id(),
        )
        return [req]

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
        req = J1939(
            pgn=J1939_PGN_REQUEST, dst=J1939_GLOBAL_ADDRESS, src=sa
        ) / J1939Request(
            req_pgn=J1939_PGN_ECU_ID
        )
        log_j1939.debug(
            "ecu_id: broadcast request sent SA=0x%02X (CAN-ID=0x%08X)",
            sa,
            req.to_can_id(),
        )
        return [req]

    def match_resp(rcv):
        # type: (Packet) -> bool
        if rcv.pgn == J1939_PGN_ECU_ID:
            return True
        bam = rcv.getlayer(J1939_TP_CM_BAM)
        return bam is not None and bam.pgn == J1939_PGN_ECU_ID

    def on_match(sa, scanner_sa, rcv):
        # type: (int, int, Packet) -> None
        log_j1939.debug("ecu_id: BAM from SA=0x%02X", sa)

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
    scan_range=_J1939_SCAN_ADDR_RANGE,  # type: Iterable[int]
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
                              created for each probed DA and closed after that
                              iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    def probe(j_sock, da, sa):
        # type: (SuperSocket, int, int) -> Optional[Packet]
        req = J1939(
            pgn=J1939_PGN_REQUEST, dst=da, src=sa
        ) / J1939Request(
            req_pgn=J1939_PGN_ADDRESS_CLAIMED
        )
        log_j1939.debug("unicast: probing DA=0x%02X from SA=0x%02X", da, sa)
        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
        if rcv is not None:
            log_j1939.debug(
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
    scan_range=_J1939_SCAN_ADDR_RANGE,  # type: Iterable[int]
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
                              created for each probed DA and closed after that
                              iteration.
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
        log_j1939.debug("rts_probe: probing DA=0x%02X from SA=0x%02X", da, sa)
        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
        if rcv is not None:
            tp_cm = rcv.getlayer(J1939_TP_CM_CTS) or rcv.getlayer(J1939_TP_CM_ABORT)
            if tp_cm is not None:
                log_j1939.debug(
                    "rts_probe: %s from SA=0x%02X to scanner SA=0x%02X",
                    tp_cm.name,
                    rcv.src,
                    sa,
                )
                return rcv

            ack = rcv.getlayer(J1939Ack)
            if ack is not None and ack.ctrl in (
                J1939_ACK_CTRL_NACK,
                J1939_ACK_CTRL_ACCESS_DENIED,
                J1939_ACK_CTRL_CANNOT_RESPOND,
            ):
                log_j1939.debug(
                    "rts_probe: ACK (ctrl=0x%02X) from SA=0x%02X to"
                    " scanner SA=0x%02X",
                    ack.ctrl,
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


def _j1939_is_uds_tester_present_resp(rcv):
    # type: (Packet) -> bool
    """Check if a received packet contains a UDS TesterPresent response."""
    uds = rcv.getlayer(UDS)
    if uds is None:
        data = getattr(rcv, "data", None) or bytes(rcv.payload)
        if not data:
            return False
        uds = UDS(data)
        if not (
            uds.haslayer(UDS_TPPR)
            or (uds.haslayer(UDS_NR) and uds[UDS_NR].requestServiceId == 0x3E)
        ) and len(data) > 1:
            uds = UDS(data[1:])
    if uds.haslayer(UDS_TPPR):
        return True
    nr = uds.getlayer(UDS_NR)
    if nr is not None and nr.requestServiceId == 0x3E:
        return True
    return False


def j1939_scan_uds(
    sock,  # type: SuperSocket
    scan_range=_J1939_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    skip_functional=False,  # type: bool
    broadcast_listen_time=1.0,  # type: float
    diag_pgn=J1939_PGN_DIAG_A,  # type: int
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Enumerate CAs by sending a UDS TesterPresent request to each DA.

    First, if *skip_functional* is False, sends broadcast UDS TesterPresent
    requests over Diagnostic Message B (DA=0xFF).
    Attempts both subfunctions 0x00 and 0x01. Any responding source addresses
    are recorded.

    Then, for each destination address *da* in *scan_range* and each source
    address in *src_addrs*, sends padded UDS TesterPresent requests over
    Diagnostic Message A. Attempts both subfunctions 0x00
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
    :param diag_pgn: PGN for UDS diagnostic messages (default :data:`J1939_PGN_DIAG_A`).
                     Functional addressing uses ``(pf | 0x01) << 8``.
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket. When provided, a fresh socket is
                              created for each probed DA and closed after that
                              iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    if src_addrs is None:
        src_addrs = J1939_DIAGADAPTERS_ADDRESSES
    else:
        src_addrs = list(src_addrs)
    found = {}  # type: Dict[int, List[J1939ScanResult]]
    reqs = J1939_UDS_TESTER_PRESENT_REQS
    pf = (diag_pgn >> 8) & 0xFF if diag_pgn > 0xFF else diag_pgn
    func_pgn = (pf | 0x01) << 8
    phys_pgn = pf << 8

    if not skip_functional:
        def make_bcast_probes(sa):
            # type: (int) -> List[Packet]
            log_j1939.debug(
                "uds: broadcast functional probe sent SA=0x%02X (PF=0x%02X)",
                sa,
                pf | 0x01,
            )
            return [
                J1939(
                    pgn=func_pgn,
                    dst=J1939_GLOBAL_ADDRESS,
                    src=sa,
                ) / J1939DiagB(data=req_data)
                for req_data in reqs
            ]

        def match_bcast(rcv):
            # type: (Packet) -> bool
            return _j1939_is_uds_tester_present_resp(rcv)

        def on_bcast_match(sa, scanner_sa, rcv):
            # type: (int, int, Packet) -> None
            log_j1939.debug(
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
            log_j1939.debug(
                "uds: physical probe DA=0x%02X SA=0x%02X on PF=0x%02X",
                da,
                sa,
                pf,
            )
            req = J1939(
                pgn=phys_pgn, dst=da, src=sa
            ) / J1939DiagA(data=req_data)
            rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
            if rcv is not None and _j1939_is_uds_tester_present_resp(rcv):
                log_j1939.debug(
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
    scan_range=_J1939_SCAN_ADDR_RANGE,  # type: Iterable[int]
    src_addrs=None,  # type: Optional[List[int]]
    sniff_time=0.1,  # type: float
    noise_ids=None,  # type: Optional[Set[int]]
    force=False,  # type: bool
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    diag_pgn=J1939_PGN_XCP,  # type: int
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
):
    # type: (...) -> Dict[int, List[J1939ScanResult]]
    """Enumerate CAs by sending an XCP CONNECT command to each DA.

    For each destination address *da* in *scan_range* and each source address
    in *src_addrs*, sends a padded XCP CONNECT request (command byte 0xFF,
    mode 0x00, 6 x 0xFF padding) over Diagnostic Message A.
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
    :param diag_pgn: PGN for XCP diagnostic messages (default :data:`J1939_PGN_XCP`,
                     Proprietary A peer-to-peer addressing)
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN socket. When provided, a fresh socket is
                              created for each probed DA and closed after that
                              iteration.
    :returns: dict mapping responder source address (int) to a list of
              :class:`J1939ScanResult` objects
    """
    connect_req = J1939_XCP_CONNECT_REQ
    pf = (diag_pgn >> 8) & 0xFF if diag_pgn > 0xFF else diag_pgn
    xcp_pgn = pf << 8

    def probe(j_sock, da, sa):
        # type: (SuperSocket, int, int) -> Optional[Packet]
        req = J1939(pgn=xcp_pgn, dst=da, src=sa, data=connect_req)
        log_j1939.debug("xcp: probing DA=0x%02X from SA=0x%02X", da, sa)
        rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
        if rcv is not None:
            data = rcv.data if rcv.data else bytes(rcv.payload)
            if data and data[0] == J1939_XCP_POSITIVE_RESPONSE:
                log_j1939.debug(
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


# --- Automotive Scanner Integration


class J1939_CA_TestCaseBase(AutomotiveTestCase):
    """Base test case for J1939 Controller Application enumeration."""

    _method_name = "base"
    _supported_kwargs = copy.copy(AutomotiveTestCase._supported_kwargs)
    _supported_kwargs.update({
        "bitrate": (int, None),
        "broadcast_listen_time": (None, None),
        "busload": (None, None),
        "diag_pgn": (None, None),
        "force": (bool, None),
        "noise_ids": (None, None),
        "reconnect_handler": (None, None),
        "scan_range": (None, None),
        "skip_functional": (bool, None),
        "sniff_time": (None, None),
        "src_addrs": (None, None),
        "stop_event": (None, None),
    })

    def __init__(self):
        # type: () -> None
        super(J1939_CA_TestCaseBase, self).__init__()
        self.results = {}  # type: Dict[int, List[J1939ScanResult]]

    @property
    def supported_responses(self):
        # type: () -> List[Any]
        return []

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        raise NotImplementedError()


class J1939_AddrClaim_TestCase(J1939_CA_TestCaseBase):
    """Address Claim (PGN 60928) broadcast discovery test case."""

    _method_name = "addr_claim"

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        self.results = j1939_scan_addr_claim(
            sock=socket,
            src_addrs=kwargs.get("src_addrs"),
            listen_time=kwargs.get("broadcast_listen_time", 1.0),
            noise_ids=kwargs.get("noise_ids"),
            force=kwargs.get("force", False),
            stop_event=kwargs.get("stop_event"),
            bitrate=kwargs.get("bitrate", J1939_DEFAULT_BITRATE),
            busload=kwargs.get("busload", J1939_DEFAULT_BUSLOAD),
            reconnect_handler=kwargs.get("reconnect_handler"),
        )
        self._state_completed[state] = True


class J1939_EcuId_TestCase(J1939_CA_TestCaseBase):
    """ECU Identification (PGN 64965) broadcast discovery test case."""

    _method_name = "ecu_id"

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        self.results = j1939_scan_ecu_id(
            sock=socket,
            src_addrs=kwargs.get("src_addrs"),
            listen_time=kwargs.get("broadcast_listen_time", 1.0),
            noise_ids=kwargs.get("noise_ids"),
            force=kwargs.get("force", False),
            stop_event=kwargs.get("stop_event"),
            bitrate=kwargs.get("bitrate", J1939_DEFAULT_BITRATE),
            busload=kwargs.get("busload", J1939_DEFAULT_BUSLOAD),
            reconnect_handler=kwargs.get("reconnect_handler"),
        )
        self._state_completed[state] = True


class J1939_Unicast_TestCase(J1939_CA_TestCaseBase):
    """Unicast Address Claim request address sweep test case."""

    _method_name = "unicast"

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        self.results = j1939_scan_unicast(
            sock=socket,
            scan_range=kwargs.get("scan_range", _J1939_SCAN_ADDR_RANGE),
            src_addrs=kwargs.get("src_addrs"),
            sniff_time=kwargs.get("sniff_time", 0.1),
            noise_ids=kwargs.get("noise_ids"),
            force=kwargs.get("force", False),
            stop_event=kwargs.get("stop_event"),
            bitrate=kwargs.get("bitrate", J1939_DEFAULT_BITRATE),
            busload=kwargs.get("busload", J1939_DEFAULT_BUSLOAD),
            reconnect_handler=kwargs.get("reconnect_handler"),
        )
        self._state_completed[state] = True


class J1939_RtsProbe_TestCase(J1939_CA_TestCaseBase):
    """TP.CM_RTS connection-abort sweep test case."""

    _method_name = "rts_probe"

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        self.results = j1939_scan_rts_probe(
            sock=socket,
            scan_range=kwargs.get("scan_range", _J1939_SCAN_ADDR_RANGE),
            src_addrs=kwargs.get("src_addrs"),
            sniff_time=kwargs.get("sniff_time", 0.1),
            noise_ids=kwargs.get("noise_ids"),
            force=kwargs.get("force", False),
            stop_event=kwargs.get("stop_event"),
            bitrate=kwargs.get("bitrate", J1939_DEFAULT_BITRATE),
            busload=kwargs.get("busload", J1939_DEFAULT_BUSLOAD),
            reconnect_handler=kwargs.get("reconnect_handler"),
        )
        self._state_completed[state] = True


class J1939_UDS_TestCase(J1939_CA_TestCaseBase):
    """UDS TesterPresent probe sweep test case."""

    _method_name = "uds"

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        uds_kwargs = {
            "sock": socket,
            "scan_range": kwargs.get("scan_range", _J1939_SCAN_ADDR_RANGE),
            "src_addrs": kwargs.get("src_addrs"),
            "sniff_time": kwargs.get("sniff_time", 0.1),
            "noise_ids": kwargs.get("noise_ids"),
            "force": kwargs.get("force", False),
            "stop_event": kwargs.get("stop_event"),
            "bitrate": kwargs.get("bitrate", J1939_DEFAULT_BITRATE),
            "busload": kwargs.get("busload", J1939_DEFAULT_BUSLOAD),
            "skip_functional": kwargs.get("skip_functional", False),
            "broadcast_listen_time": kwargs.get("broadcast_listen_time", 1.0),
            "reconnect_handler": kwargs.get("reconnect_handler"),
        }
        if kwargs.get("diag_pgn") is not None:
            uds_kwargs["diag_pgn"] = kwargs["diag_pgn"]
        self.results = j1939_scan_uds(**uds_kwargs)
        self._state_completed[state] = True


class J1939_XCP_TestCase(J1939_CA_TestCaseBase):
    """XCP CONNECT probe sweep test case."""

    _method_name = "xcp"

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        xcp_kwargs = {
            "sock": socket,
            "scan_range": kwargs.get("scan_range", _J1939_SCAN_ADDR_RANGE),
            "src_addrs": kwargs.get("src_addrs"),
            "sniff_time": kwargs.get("sniff_time", 0.1),
            "noise_ids": kwargs.get("noise_ids"),
            "force": kwargs.get("force", False),
            "stop_event": kwargs.get("stop_event"),
            "bitrate": kwargs.get("bitrate", J1939_DEFAULT_BITRATE),
            "busload": kwargs.get("busload", J1939_DEFAULT_BUSLOAD),
            "reconnect_handler": kwargs.get("reconnect_handler"),
        }
        if kwargs.get("diag_pgn") is not None:
            xcp_kwargs["diag_pgn"] = kwargs["diag_pgn"]
        self.results = j1939_scan_xcp(**xcp_kwargs)
        self._state_completed[state] = True


_J1939_TECHNIQUE_TC_MAP = {
    "addr_claim": J1939_AddrClaim_TestCase,
    "ecu_id": J1939_EcuId_TestCase,
    "unicast": J1939_Unicast_TestCase,
    "rts_probe": J1939_RtsProbe_TestCase,
    "uds": J1939_UDS_TestCase,
    "xcp": J1939_XCP_TestCase,
}


class J1939_Scanner(AutomotiveTestCaseExecutor):
    """Automotive scanner for J1939 Controller Application enumeration.

    Coordinates test case execution across selected discovery techniques and
    merges results into standard format.
    """

    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [
            J1939_AddrClaim_TestCase,
            J1939_EcuId_TestCase,
            J1939_Unicast_TestCase,
            J1939_RtsProbe_TestCase,
            J1939_UDS_TestCase,
            J1939_XCP_TestCase,
        ]

    def get_results(self, verbose=False):
        # type: (bool) -> Dict[int, Dict[str, object]]
        """Merge scan results across all executed test cases."""
        merged = {}  # type: Dict[int, Dict[str, object]]
        for tc in self.configuration.test_cases:
            if not isinstance(tc, J1939_CA_TestCaseBase):
                continue
            method_name = getattr(tc, "_method_name", "unknown")
            for sa, scan_results in tc.results.items():
                src_addr = []  # type: List[int]
                pkts = []  # type: List[J1939]
                for r in scan_results:
                    pkts.append(r.packet)
                    if r.scanner_src is not None and r.scanner_src not in src_addr:
                        src_addr.append(r.scanner_src)

                if sa not in merged:
                    if verbose:
                        log_j1939.info(
                            "j1939_scan: found SA=0x%02X via %s", sa, method_name
                        )
                    merged[sa] = {
                        "methods": [method_name],
                        "packets": [pkts],
                        "results": [scan_results],
                        "src_addrs": [src_addr],
                    }
                else:
                    if verbose:
                        log_j1939.info(
                            "j1939_scan: SA=0x%02X also detected via %s",
                            sa,
                            method_name,
                        )
                    cast(List[str], merged[sa]["methods"]).append(method_name)
                    cast(List[List[Any]], merged[sa]["packets"]).append(pkts)
                    cast(List[List[J1939ScanResult]], merged[sa]["results"]).append(
                        scan_results
                    )
                    cast(List, merged[sa]["src_addrs"]).append(src_addr)
        return merged


# --- Top-level combined scanner


def j1939_scan(
    sock,  # type: SuperSocket
    scan_range=_J1939_SCAN_ADDR_RANGE,  # type: Iterable[int]
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
    :param verbose: if True, set the ``log_j1939`` logger to
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
        log_j1939.setLevel(logging.DEBUG)
    if methods is None:
        methods = list(J1939_SCAN_METHODS)

    for m in methods:
        if m not in J1939_SCAN_METHODS:
            raise ValueError(
                "Unknown scan method {!r}; valid methods: {}".format(
                    m, J1939_SCAN_METHODS
                )
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
            except (TypeError, ValueError) as ex:
                # Fall back to default bitrate if attribute is non-numeric
                log_j1939.debug(
                    "invalid socket bitrate %r, using default: %s",
                    sock_bitrate,
                    ex,
                )
        if reconnect_handler is not None and _probe is not sock:
            try:
                _probe.close()
            except (AttributeError, OSError) as ex:
                log_j1939.debug("failed to close probe socket: %s", ex)

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
            log_j1939.info(
                "j1939_scan: %d noise SA(s) detected, will skip: %s",
                len(noise_ids),
                [hex(s) for s in sorted(noise_ids)],
            )

    if not methods:
        return {}

    if stop_event is not None and stop_event.is_set():
        return {}

    if sock is None and reconnect_handler is not None:
        sock = reconnect_handler()

    scan_range_list = list(scan_range)
    unique_methods = list(dict.fromkeys(methods))
    selected_tcs = [_J1939_TECHNIQUE_TC_MAP[m]() for m in unique_methods]
    tc_kwargs = {
        "bitrate": bitrate,
        "broadcast_listen_time": broadcast_listen_time,
        "busload": busload,
        "force": force,
        "noise_ids": noise_ids,
        "reconnect_handler": reconnect_handler,
        "scan_range": scan_range_list,
        "skip_functional": skip_functional,
        "sniff_time": sniff_time,
        "src_addrs": src_addrs,
        "stop_event": stop_event,
    }
    if diag_pgn is not None:
        tc_kwargs["diag_pgn"] = diag_pgn

    scanner_kwargs = {
        "{}_kwargs".format(tc.__class__.__name__): dict(tc_kwargs)
        for tc in selected_tcs
    }
    scanner = J1939_Scanner(
        sock,
        test_cases=selected_tcs,
        reconnect_handler=reconnect_handler,
        **scanner_kwargs,
    )
    if stop_event is not None:
        scanner.configuration.stop_event = stop_event
    scanner.scan()
    return scanner.get_results(verbose=verbose)
__all__ = [
    "J1939ScanResult",
    "J1939_ACK_CTRL_ACCESS_DENIED",
    "J1939_ACK_CTRL_ACK",
    "J1939_ACK_CTRL_CANNOT_RESPOND",
    "J1939_ACK_CTRL_NACK",
    "J1939_AddrClaim_TestCase",
    "J1939_CA_TestCaseBase",
    "J1939_DEFAULT_BITRATE",
    "J1939_DEFAULT_BUSLOAD",
    "J1939_DIAGADAPTERS_ADDRESSES",
    "J1939_EcuId_TestCase",
    "J1939_PGN_ECU_ID",
    "J1939_PGN_XCP",
    "J1939_RtsProbe_TestCase",
    "J1939_SCAN_METHODS",
    "J1939_Scanner",
    "J1939_UDS_TESTER_PRESENT_REQS",
    "J1939_UDS_TESTER_PRESENT_RESPS",
    "J1939_UDS_TestCase",
    "J1939_Unicast_TestCase",
    "J1939_XCP_CONNECT_REQ",
    "J1939_XCP_POSITIVE_RESPONSE",
    "J1939_XCP_SRC_ADDRS",
    "J1939_XCP_TestCase",
    "j1939_check_rx_filter_warning",
    "j1939_emit_sa_filter_warning",
    "j1939_get_sock",
    "j1939_inter_probe_delay",
    "j1939_reconnect_with_retry",
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
