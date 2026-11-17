# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

# scapy.contrib.description = SAE J1939 Diagnostic Message (DM) Scanner
# scapy.contrib.status = library

"""
J1939 Diagnostic Message (DM) Scanner.

Probes a single J1939 ECU (identified by its Destination Address) to discover
which SAE J1939-73 Diagnostic Messages it supports.  For each PGN in
:data:`J1939_DM_PGNS` the scanner sends a unicast Request (PGN 59904) and
classifies the response:

- **Positive response** — ECU replies with the requested PGN.
- **NACK** — ECU replies with an Acknowledgment (PGN 0xE800), control byte
  0x01 (Negative Acknowledgment).
- **Timeout** — ECU does not reply within *sniff_time* seconds.

This scanner could functionally be implemented as an ``.sr1()``-based scanner,
but it has been prepared to be runtime-optimized instead.  It uses raw CAN
socket filtering, asynchronous sniffing with a
transmission callback, and busload pacing.

Usage::

    >>> load_contrib('automotive.j1939')
    >>> from scapy.contrib.cansocket import CANSocket
    >>> from scapy.contrib.automotive.j1939.j1939_dm_scanner import (
    ...     j1939_scan_dm,
    ... )
    >>> sock = CANSocket("can0")
    >>> results = j1939_scan_dm(sock, target_da=0x00)
    >>> for name, res in sorted(results.items()):
    ...     print("{}: supported={} error={}".format(
    ...         name, res.supported, res.error))
"""

import copy
from dataclasses import dataclass
import time
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    TYPE_CHECKING,
    Type,
    Union,
)

if TYPE_CHECKING:
    from threading import Event
    from scapy.supersocket import SuperSocket

from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.j1939.j1939_scanner import (
    J1939_ACK_CTRL_NACK,
    J1939_DEFAULT_BITRATE,
    J1939_DEFAULT_BUSLOAD,
    j1939_emit_sa_filter_warning,
    j1939_inter_probe_delay,
    j1939_reconnect_with_retry,
)
from scapy.contrib.automotive.scanner.enumerator import ServiceEnumerator
from scapy.contrib.automotive.scanner.executor import AutomotiveTestCaseExecutor
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC
from scapy.contrib.j1939 import (
    J1939,
    J1939Ack,
    J1939Request,
    J1939_GLOBAL_ADDRESS,
    J1939_PGN_REQUEST,
    J1939_PGN_TP_CM,
    J1939_TP_CM_ABORT,
    J1939_TP_CM_BAM,
    J1939_TP_CM_RTS,
    log_j1939,
)
from scapy.layers.can import CAN
from scapy.packet import Packet

# --- Scanner constants

#: PGN for Vehicle Identification Number (VIN / VI) (J1939-71)
J1939_PGN_VIN = 0xFEE4  # 65260

#: Default priority for request frames sent by the DM scanner
_J1939_DM_SCAN_PRIORITY = 6

#: Ordered mapping from DM name (str) to PGN number (int).
#: Most entries are PDU2 (PF byte >= 0xF0) broadcast-capable messages;
#: some higher DMs use PDU1 (peer-to-peer) PGNs.
J1939_DM_PGNS = {
    "DM1": 0xFECA,  # Active Diagnostic Trouble Codes
    "DM2": 0xFECB,  # Previously Active Diagnostic Trouble Codes
    "DM3": 0xFECC,  # Diagnostic Data Clear/Reset for Previously Active DTCs
    "DM4": 0xFECD,  # Freeze Frame Parameters
    "DM5": 0xFECE,  # Diagnostic Readiness 1
    "DM6": 0xFECF,  # Emission-Related Pending DTCs
    "DM7": 0xE300,  # Command Noncontinuously Monitored Test
    "DM8": 0xFED0,  # Test Results for Noncontinuously Monitored Systems
    "DM9": 0xFED1,  # Oxygen Sensor Test Results
    "DM10": 0xFED2,  # Non-continuously Monitored Systems Test Identifiers Support
    "DM11": 0xFED3,  # Diagnostic Data Clear/Reset for Active DTCs
    "DM12": 0xFED4,  # Emission-Related Active DTCs
    "DM13": 0xDF00,  # Stop Start Broadcast
    "DM14": 0xD900,  # Memory Access Request
    "DM15": 0xD800,  # Memory Access Response
    "DM16": 0xD700,  # Binary Data Transfer
    "DM17": 0xD600,  # Boot Load Data
    "DM18": 0xD400,  # Data Security
    "DM19": 0xD300,  # Calibration Information
    "DM20": 0xC200,  # Monitor Performance Ratio
    "DM21": 0xC100,  # Diagnostic Readiness 2
    "DM22": 0xC300,  # Individual Clear/Reset of Active and Previously Active DTC
    "DM23": 0xFDB5,  # Emission-Related Previously Active DTCs
    "DM24": 0xFDB6,  # SPN Support
    "DM25": 0xFDB7,  # Expanded Freeze Frame
    "DM26": 0xFDB8,  # Diagnostic Readiness 3
    "DM27": 0xFD82,  # All Pending DTCs
    "DM28": 0xFD80,  # Permanent DTCs
    "DM29": 0x9E00,  # Regulated DTC Counts (Pending, Permanent, MIL-On, PMIL-On)
    "DM30": 0xA400,  # Scaled Test Results
    "DM31": 0xA300,  # DTC to Lamp Association
    "DM32": 0xA200,  # Regulated Exhaust Emission Level Exceedance
    "DM33": 0xA100,  # Emission Increasing Auxiliary Emission Control Device Active Time
    "DM34": 0xA000,  # NTE Status
    "DM35": 0x9F00,  # Immediate Fault Status
    "DM36": 0xFD64,  # Harmonized Roadworthiness - Vehicle (HRWV)
    "DM37": 0xFD63,  # Harmonized Roadworthiness - System (HRWS)
    "DM38": 0xFD62,  # Harmonized Global Regulation Description (HGRD)
    "DM39": 0xFD61,  # Harmonized Cumulative Continuous Malfunction Indicator - System
    "DM40": 0xFD60,  # Harmonized B1 Failure Counts (HB1C)
    "DM41": 0xFD5F,  # DTCs - A, Pending
    "DM42": 0xFD5E,  # DTCs - A, Confirmed and Active
    "DM43": 0xFD5D,  # DTCs - A, Previously Active
    "DM44": 0xFD5C,  # DTCs - B1, Pending
    "DM45": 0xFD5B,  # DTCs - B1, Confirmed and Active
    "DM46": 0xFD5A,  # DTCs - B1, Previously Active
    "DM47": 0xFD59,  # DTCs - B2, Pending
    "DM48": 0xFD58,  # DTCs - B2, Confirmed and Active
    "DM49": 0xFD57,  # DTCs - B2, Previously Active
    "DM50": 0xFD56,  # DTCs - C, Pending
    "DM51": 0xFD55,  # DTCs - C, Confirmed and Active
    "DM52": 0xFD54,  # DTCs - C, Previously Active
    "DM53": 0xFCD1,  # Active Service Only DTCs
    "DM54": 0xFCD2,  # Previously Active Service Only DTCs
    "DM55": 0xFCD3,  # Diagnostic Data Clear/Reset for All Service Only DTCs
    "DM56": 0xFCC7,  # Engine Emissions Certification Information
    "DM57": 0xFCC6,  # OBD Information
}


# --- Result containers


@dataclass
class J1939PgnScanResult:
    """Result record for a single PGN probe sent by :func:`j1939_scan_pgns`.

    :param pgn: PGN number that was requested
    :param supported: ``True`` if the ECU replied with the requested PGN
    :param name: human-readable name for the PGN
    :param packet: the first CAN response received (``None`` on timeout)
    :param error: ``None`` when supported; ``"NACK"`` for negative ack;
                  ``"Timeout"`` when no reply; ``"Aborted"`` if stopped early
    """

    pgn: int
    supported: bool
    name: str = "Unknown"
    packet: Optional[CAN] = None
    error: Optional[str] = None


class J1939_PGN_Enumerator(ServiceEnumerator):
    """Enumerator for J1939 Parameter Group Numbers (PGNs)."""

    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        "bitrate": (int, None),
        "busload": (None, None),
        "pgns": (None, None),
        "reconnect_handler": (None, None),
        "reconnect_retries": (int, None),
        "reset_handler": (None, None),
        "retry_delay": (None, None),
        "sniff_time": (None, None),
        "src_addr": (int, None),
        "stop_event": (None, None),
        "target_da": (int, None),
    })

    def __init__(self):
        # type: () -> None
        super(J1939_PGN_Enumerator, self).__init__()
        self.pgn_results = {}  # type: Dict[Any, J1939PgnScanResult]

    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        ack = resp.getlayer(J1939Ack) if resp is not None else None
        if ack is not None:
            return ack.ctrl
        return getattr(resp, "negativeResponseCode", 0)

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        if nrc == J1939_ACK_CTRL_NACK:
            return "NACK"
        return str(nrc)

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return "NACK"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        pgns = kwargs.get("pgns", [])
        target_da = kwargs.get("target_da", 0x00)
        src_addr = kwargs.get("src_addr", 0xF9)
        if isinstance(pgns, dict):
            items = list(pgns.items())
        else:
            items = [(pgn, pgn) for pgn in pgns]

        for _, pgn in items:
            yield J1939(
                pgn=J1939_PGN_REQUEST,
                dst=target_da,
                src=src_addr,
                priority=_J1939_DM_SCAN_PRIORITY,
            ) / J1939Request(
                req_pgn=pgn,
            )

    def execute(self, socket, state, **kwargs):
        # type: (Any, EcuState, Any) -> None
        target_da = kwargs.get("target_da", 0x00)
        pgns = kwargs.get("pgns", [])
        src_addr = kwargs.get("src_addr", 0xF9)
        sniff_time = kwargs.get("sniff_time", 1.0)
        stop_event = kwargs.get("stop_event")
        bitrate = kwargs.get("bitrate", J1939_DEFAULT_BITRATE)
        busload = kwargs.get("busload", J1939_DEFAULT_BUSLOAD)
        reset_handler = kwargs.get("reset_handler")
        reconnect_handler = kwargs.get("reconnect_handler")
        reconnect_retries = kwargs.get("reconnect_retries", 5)
        retry_delay = kwargs.get("retry_delay", 1.0)

        if isinstance(pgns, dict):
            items = list(pgns.items())
        else:
            items = [(pgn, pgn) for pgn in pgns]

        results = {}  # type: Dict[Any, J1939PgnScanResult]
        active_sock = socket
        num_items = len(items)

        send_sock = rx_sock = active_sock
        close_rx = False

        requests = list(self._get_initial_requests(**kwargs))

        try:
            for i, ((key, pgn), req_pkt) in enumerate(zip(items, requests)):
                name_str = (
                    str(key) if isinstance(key, str) else "PGN_0x{:04X}".format(pgn)
                )
                if stop_event is not None and stop_event.is_set():
                    results[key] = J1939PgnScanResult(
                        pgn, False, name=name_str, error="Aborted"
                    )
                    break

                res_list = []  # type: List[J1939PgnScanResult]

                def _rx(pkt):
                    # type: (CAN) -> None
                    if res_list:
                        return
                    if stop_event is not None and stop_event.is_set():
                        return
                    if hasattr(pkt, "flags") and not pkt.flags.extended:
                        return
                    sa = (
                        pkt.identifier & 0xFF
                        if hasattr(pkt, "identifier")
                        else getattr(pkt, "src", None)
                    )
                    if sa != target_da:
                        j1939_emit_sa_filter_warning([active_sock], target_da)
                        return
                    j_pkt = pkt if isinstance(pkt, J1939) else J1939.from_can(pkt)
                    if j_pkt.pgn == pgn:
                        log_j1939.debug(
                            "pgn_scan: positive response SA=0x%02X PGN=0x%04X",
                            sa,
                            pgn,
                        )
                        res_list.append(
                            J1939PgnScanResult(
                                pgn, True, name=name_str, packet=pkt
                            )
                        )
                        return

                    tp_cm = (
                        j_pkt.getlayer(J1939_TP_CM_BAM)
                        or j_pkt.getlayer(J1939_TP_CM_RTS)
                    )
                    if tp_cm is not None and (
                        (
                            isinstance(tp_cm, J1939_TP_CM_BAM)
                            and j_pkt.dst == J1939_GLOBAL_ADDRESS
                        )
                        or (
                            isinstance(tp_cm, J1939_TP_CM_RTS)
                            and j_pkt.dst == src_addr
                        )
                    ) and tp_cm.pgn == pgn:
                        log_j1939.debug(
                            "pgn_scan: TP positive response "
                            "SA=0x%02X PGN=0x%04X",
                            sa,
                            pgn,
                        )
                        if isinstance(tp_cm, J1939_TP_CM_RTS):
                            try:
                                abort_pkt = J1939(
                                    priority=7,
                                    pgn=J1939_PGN_TP_CM,
                                    dst=target_da,
                                    src=src_addr,
                                ) / J1939_TP_CM_ABORT(
                                    reason=0xFF, pgn=pgn
                                )
                                send_sock.send(abort_pkt.to_can())
                            except (AttributeError, OSError) as ex:
                                log_j1939.debug(
                                    "pgn_scan: failed to send TP abort to "
                                    "SA=0x%02X: %s",
                                    src_addr,
                                    ex,
                                )
                        res_list.append(
                            J1939PgnScanResult(
                                pgn, True, name=name_str, packet=pkt
                            )
                        )
                        return

                    ack = j_pkt.getlayer(J1939Ack)
                    if (
                        ack is not None
                        and ack.ctrl == J1939_ACK_CTRL_NACK
                        and ack.pgn == pgn
                    ):
                        log_j1939.debug(
                            "pgn_scan: NACK from SA=0x%02X PGN=0x%04X",
                            sa,
                            pgn,
                        )
                        res_list.append(
                            J1939PgnScanResult(
                                pgn,
                                False,
                                name=name_str,
                                packet=pkt,
                                error="NACK",
                            )
                        )

                def _send_probe():
                    # type: () -> None
                    send_sock.send(req_pkt.to_can())
                    log_j1939.debug(
                        "pgn_scan: probing DA=0x%02X PGN=0x%04X (%s)",
                        target_da,
                        pgn,
                        name_str,
                    )

                rx_sock.sniff(
                    prn=_rx,
                    timeout=sniff_time,
                    store=False,
                    started_callback=_send_probe,
                    stop_filter=lambda _: bool(res_list),
                )

                _extra = j1939_inter_probe_delay(
                    bitrate, busload, 3, 8, sniff_time
                )
                if _extra > 0.0:
                    time.sleep(_extra)

                if res_list:
                    results[key] = res_list[0]
                elif stop_event is not None and stop_event.is_set():
                    results[key] = J1939PgnScanResult(
                        pgn, False, name=name_str, error="Aborted"
                    )
                else:
                    log_j1939.debug(
                        "pgn_scan: timeout waiting for DA=0x%02X PGN=0x%04X",
                        target_da,
                        pgn,
                    )
                    results[key] = J1939PgnScanResult(
                        pgn, False, name=name_str, error="Timeout"
                    )

                if i < num_items - 1:
                    if reset_handler is not None:
                        log_j1939.debug(
                            "pgn_scan: calling reset_handler between probes"
                        )
                        reset_handler()
                    if reconnect_handler is not None:
                        log_j1939.debug("pgn_scan: calling reconnect_handler")
                        if close_rx:
                            rx_sock.close()
                        active_sock = j1939_reconnect_with_retry(
                            reconnect_handler,
                            reconnect_retries=reconnect_retries,
                            retry_delay=retry_delay,
                            stop_event=stop_event,
                        )
                        send_sock = rx_sock = active_sock
                        close_rx = True
        finally:
            if close_rx:
                rx_sock.close()

        self.pgn_results = results
        self._state_completed[state] = True


class J1939_DM_Enumerator(J1939_PGN_Enumerator):
    """Enumerator for SAE J1939-73 Diagnostic Message PGNs."""

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        kwargs_copy = dict(kwargs)
        if "pgns" not in kwargs_copy or kwargs_copy["pgns"] is None:
            kwargs_copy["pgns"] = J1939_DM_PGNS
        return super(J1939_DM_Enumerator, self)._get_initial_requests(
            **kwargs_copy
        )


class J1939_DM_Scanner(AutomotiveTestCaseExecutor):
    """Automotive scanner for J1939 Diagnostic Message enumeration."""

    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [J1939_DM_Enumerator]


# --- General PGN request scanner


def j1939_scan_pgns(
    sock,  # type: SuperSocket
    target_da,  # type: int
    pgns,  # type: Union[List[int], Dict[Any, int]]
    src_addr=0xF9,  # type: int
    sniff_time=1.0,  # type: float
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reset_handler=None,  # type: Optional[Callable[[], None]]
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
    reconnect_retries=5,  # type: int
    retry_delay=1.0,  # type: float
):
    # type: (...) -> Dict[Any, J1939PgnScanResult]
    """Probe *target_da* for a sequence of Parameter Group Numbers (PGNs).

    Iterates over the PGNs specified in *pgns* (either a dictionary mapping
    names/identifiers to PGN integers, or an iterable of PGN integers),
    sending a unicast Request (PGN 59904) for each and classifying the response.

    If *reset_handler* is provided it is called between each pair of probes to
    reset the target ECU to a known state. If *reconnect_handler* is also
    provided it is called immediately after the reset to obtain a fresh socket;
    subsequent probes will use the returned socket.

    :param sock: raw CAN socket
    :param target_da: destination address of the ECU to probe (0x00–0xFD)
    :param pgns: dict mapping names to PGN numbers or list of PGN numbers
    :param src_addr: source address used in outgoing probes (default 0xF9)
    :param sniff_time: per-PGN listen time in seconds (default 1.0)
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :param reset_handler: optional callable to reset the target ECU between probes
    :param reconnect_handler: optional callable returning a new CAN socket
    :param reconnect_retries: maximum number of reconnect attempts (default 5)
    :param retry_delay: delay in seconds between failed reconnect attempts (default 1.0)
    :returns: dict mapping each input key/PGN to its :class:`J1939PgnScanResult`
    """
    if busload <= 0.0 or busload > 1.0:
        raise ValueError("busload must be in range (0.0, 1.0], got {}".format(busload))

    if isinstance(pgns, dict):
        items = list(pgns.items())
    else:
        items = [(pgn, pgn) for pgn in pgns]

    if stop_event is not None and stop_event.is_set():
        return {
            key: J1939PgnScanResult(
                pgn,
                False,
                name=str(key) if isinstance(key, str) else "PGN_0x{:04X}".format(pgn),
                error="Aborted",
            )
            for key, pgn in items
        }

    enumerator = J1939_PGN_Enumerator()
    tc_kwargs = {
        "bitrate": bitrate,
        "busload": busload,
        "pgns": pgns,
        "reconnect_handler": reconnect_handler,
        "reconnect_retries": reconnect_retries,
        "reset_handler": reset_handler,
        "retry_delay": retry_delay,
        "sniff_time": sniff_time,
        "src_addr": src_addr,
        "stop_event": stop_event,
        "target_da": target_da,
    }
    scanner = J1939_DM_Scanner(
        sock,
        test_cases=[enumerator],
        J1939_PGN_Enumerator_kwargs=tc_kwargs,
        J1939_DM_Enumerator_kwargs=tc_kwargs,
    )
    scanner.scan()
    return enumerator.pgn_results


# --- Top-level DM scanner (special case of j1939_scan_pgns)


def j1939_scan_dm(
    sock,  # type: SuperSocket
    target_da,  # type: int
    dms=None,  # type: Optional[List[str]]
    src_addr=0xF9,  # type: int
    sniff_time=1.0,  # type: float
    stop_event=None,  # type: Optional[Event]
    bitrate=J1939_DEFAULT_BITRATE,  # type: int
    busload=J1939_DEFAULT_BUSLOAD,  # type: float
    reset_handler=None,  # type: Optional[Callable[[], None]]
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
    reconnect_retries=5,  # type: int
    retry_delay=1.0,  # type: float
):
    # type: (...) -> Dict[str, J1939PgnScanResult]
    """Probe *target_da* for all (or a selected subset of) Diagnostic Message PGNs.

    Special case of :func:`j1939_scan_pgns` for SAE J1939-73 Diagnostic Messages
    (:data:`J1939_DM_PGNS`).

    :param sock: raw CAN socket
    :param target_da: destination address of the ECU to probe (0x00–0xFD)
    :param dms: list of DM names to scan; must be keys of
                 :data:`J1939_DM_PGNS`. Default is all entries.
    :param src_addr: source address used in outgoing probes (default 0xF9)
    :param sniff_time: per-PGN listen time in seconds (default 1.0)
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :param reset_handler: optional callable to reset the target ECU between probes
    :param reconnect_handler: optional callable returning a new CAN socket
    :param reconnect_retries: maximum number of reconnect attempts (default 5)
    :param retry_delay: delay in seconds between failed reconnect attempts (default 1.0)
    :returns: dict mapping each DM name (str) to its :class:`J1939PgnScanResult`
    """
    if dms is None:
        dms = list(J1939_DM_PGNS.keys())

    for name in dms:
        if name not in J1939_DM_PGNS:
            raise ValueError(
                "Unknown DM name {!r}; valid names: {}".format(
                    name, list(J1939_DM_PGNS.keys())
                )
            )

    pgn_dict = {dm_name: J1939_DM_PGNS[dm_name] for dm_name in dms}
    return j1939_scan_pgns(
        sock=sock,
        target_da=target_da,
        pgns=pgn_dict,
        src_addr=src_addr,
        sniff_time=sniff_time,
        stop_event=stop_event,
        bitrate=bitrate,
        busload=busload,
        reset_handler=reset_handler,
        reconnect_handler=reconnect_handler,
        reconnect_retries=reconnect_retries,
        retry_delay=retry_delay,
    )


__all__ = [
    "J1939PgnScanResult",
    "J1939_DM_Enumerator",
    "J1939_DM_PGNS",
    "J1939_DM_Scanner",
    "J1939_PGN_Enumerator",
    "J1939_PGN_VIN",
    "j1939_scan_dm",
    "j1939_scan_pgns",
]
