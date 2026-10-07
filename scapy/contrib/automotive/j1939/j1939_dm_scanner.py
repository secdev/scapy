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
socket filtering, a pre-probe socket flush, asynchronous sniffing with a
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

from dataclasses import dataclass
import time
from threading import Event  # noqa: F401

# Typing imports
from typing import (  # noqa: F401
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)

from scapy.layers.can import CAN
from scapy.supersocket import SuperSocket  # noqa: F401

from scapy.contrib.automotive.j1939.j1939_scanner import (  # noqa: F401
    J1939_DEFAULT_BITRATE,
    J1939_DEFAULT_BUSLOAD,
    J1939_PF_ACK,
    J1939_PF_REQUEST,
    J1939_TP_CM_PF,
    j1939_can_id,
    j1939_check_socket_can_filters,
    j1939_decode_can_id,
    j1939_inter_probe_delay,
    j1939_pre_probe_flush,
    j1939_resolve_probe_sock,
)
from scapy.contrib.j1939 import (
    J1939Request,
    J1939_GLOBAL_ADDRESS,
    J1939_TP_CM,
    J1939_TP_CM_ABORT,
    J1939_TP_CM_BAM,
    J1939_TP_CM_RTS,
    j1939_log,
    j1939_pgn_from_fields,
)

# --- Scanner constants

#: PGN for Acknowledgment / NACK messages (J1939-21 §5.4.4)
J1939_PGN_ACK = 0xE800  # 59392

#: PGN for Vehicle Identification Number (VIN / VI) (J1939-71)
J1939_PGN_VIN = 0xFEE4  # 65260

#: NACK control byte in an Acknowledgment message data payload (byte 0)
_ACK_CTRL_NACK = 0x01

#: Bitmask for the CAN extended-frame flag (29-bit identifier)
_CAN_EXTENDED_FLAG = 0x4

#: Default priority for request frames sent by the DM scanner
_DM_SCAN_PRIORITY = 6

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

    @property
    def dm_name(self) -> str:
        """Alias for name for compatibility with DmScanResult."""
        return self.name

    def __repr__(self) -> str:
        return "<J1939PgnScanResult name={} pgn=0x{:04X} supported={} error={}>".format(
            self.name, self.pgn, self.supported, self.error
        )


@dataclass
class DmScanResult:
    """Result record for a single DM PGN probe sent by :func:`j1939_scan_dm`.

    Special case of :class:`J1939PgnScanResult` for Diagnostic Messages.

    :param dm_name: human-readable DM name (e.g. ``"DM1"``)
    :param pgn: PGN number that was requested
    :param supported: ``True`` if the ECU replied with the requested PGN
    :param packet: the first CAN response received (``None`` on timeout)
    :param error: ``None`` when supported; ``"NACK"`` for negative ack;
                  ``"Timeout"`` when no reply
    """

    dm_name: str
    pgn: int
    supported: bool
    packet: Optional[CAN] = None
    error: Optional[str] = None

    @property
    def name(self) -> str:
        return self.dm_name

    def __repr__(self) -> str:
        return "<DmScanResult dm={} pgn=0x{:04X} supported={} error={}>".format(
            self.dm_name, self.pgn, self.supported, self.error
        )


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
    if isinstance(pgns, dict):
        items = list(pgns.items())
    else:
        items = [(pgn, pgn) for pgn in pgns]

    results = {}  # type: Dict[Any, J1939PgnScanResult]
    active_sock = sock
    num_items = len(items)

    send_sock, rx_sock, close_rx = j1939_resolve_probe_sock(
        active_sock, target_da
    )

    try:
        for i, (key, pgn) in enumerate(items):
            name_str = (
                str(key) if isinstance(key, str) else "PGN_0x{:04X}".format(pgn)
            )
            if stop_event is not None and stop_event.is_set():
                results[key] = J1939PgnScanResult(
                    pgn, False, name=name_str, error="Aborted"
                )
                break

            can_id = j1939_can_id(
                _DM_SCAN_PRIORITY, J1939_PF_REQUEST, target_da, src_addr
            )
            payload = bytes(J1939Request(req_pgn=pgn))

            res_list = []  # type: List[J1939PgnScanResult]

            def _rx(pkt):
                # type: (CAN) -> None
                if res_list:
                    return
                if stop_event is not None and stop_event.is_set():
                    return
                if not (pkt.flags & _CAN_EXTENDED_FLAG):
                    return
                _, pf, ps, sa = j1939_decode_can_id(pkt.identifier)
                if sa != target_da:
                    if (
                        not getattr(active_sock, "filter_warning_emitted", False)
                        and not getattr(active_sock, "_filter_warned", False)
                    ):
                        j1939_log.warning(
                            "You should put a filter for SA=0x%02X on your CAN socket",
                            target_da,
                        )
                        setattr(active_sock, "filter_warning_emitted", True)
                        setattr(active_sock, "_filter_warned", True)
                    return
                if j1939_pgn_from_fields(0, pf, ps) == pgn:
                    j1939_log.debug(
                        "pgn_scan: positive response SA=0x%02X PGN=0x%04X", sa, pgn
                    )
                    res_list.append(
                        J1939PgnScanResult(pgn, True, name=name_str, packet=pkt)
                    )
                    return
                if pf == J1939_TP_CM_PF:
                    data = bytes(pkt.data)
                    if len(data) >= 8:
                        tp_cm = J1939_TP_CM(data)
                        if (
                            (
                                isinstance(tp_cm, J1939_TP_CM_BAM)
                                and ps == J1939_GLOBAL_ADDRESS
                            )
                            or (
                                isinstance(tp_cm, J1939_TP_CM_RTS)
                                and ps == src_addr
                            )
                        ) and tp_cm.pgn == pgn:
                            j1939_log.debug(
                                "pgn_scan: TP positive response SA=0x%02X PGN=0x%04X",
                                sa,
                                pgn,
                            )
                            if isinstance(tp_cm, J1939_TP_CM_RTS):
                                try:
                                    abort_id = j1939_can_id(
                                        7, J1939_TP_CM_PF, target_da, src_addr
                                    )
                                    abort_pkt = CAN(
                                        identifier=abort_id,
                                        flags="extended",
                                        data=bytes(
                                            J1939_TP_CM_ABORT(reason=0xFF, pgn=pgn)
                                        ),
                                    )
                                    send_sock.send(abort_pkt)
                                except (AttributeError, OSError) as ex:
                                    j1939_log.debug(
                                        "pgn_scan: failed to send TP abort to "
                                        "SA=0x%02X: %s",
                                        src_addr,
                                        ex,
                                    )
                            res_list.append(
                                J1939PgnScanResult(pgn, True, name=name_str, packet=pkt)
                            )
                            return
                if pf == J1939_PF_ACK:
                    data = bytes(pkt.data)
                    if data and data[0] == _ACK_CTRL_NACK:
                        j1939_log.debug(
                            "pgn_scan: NACK from SA=0x%02X PGN=0x%04X", sa, pgn
                        )
                        res_list.append(
                            J1939PgnScanResult(
                                pgn, False, name=name_str, packet=pkt, error="NACK"
                            )
                        )

            def _send_probe():
                # type: () -> None
                j1939_pre_probe_flush(rx_sock)
                send_sock.send(CAN(identifier=can_id, flags="extended", data=payload))
                j1939_log.debug(
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

            _extra = j1939_inter_probe_delay(bitrate, busload, 3, 8, sniff_time)
            if _extra > 0.0:
                time.sleep(_extra)

            if res_list:
                results[key] = res_list[0]
            elif stop_event is not None and stop_event.is_set():
                results[key] = J1939PgnScanResult(
                    pgn, False, name=name_str, error="Aborted"
                )
            else:
                j1939_log.debug(
                    "pgn_scan: timeout waiting for DA=0x%02X PGN=0x%04X",
                    target_da,
                    pgn,
                )
                results[key] = J1939PgnScanResult(
                    pgn, False, name=name_str, error="Timeout"
                )

            if i < num_items - 1:
                if reset_handler is not None:
                    j1939_log.debug("pgn_scan: calling reset_handler between probes")
                    reset_handler()
                if reconnect_handler is not None:
                    j1939_log.debug("pgn_scan: calling reconnect_handler")
                    for attempt in range(max(1, reconnect_retries)):
                        try:
                            if close_rx:
                                rx_sock.close()
                            active_sock = reconnect_handler()
                            send_sock, rx_sock, close_rx = j1939_resolve_probe_sock(
                                active_sock,
                                target_da,
                            )
                            break
                        except Exception:
                            if attempt == reconnect_retries - 1:
                                raise
                            j1939_log.debug(
                                "pgn_scan: reconnect attempt %d/%d failed, "
                                "retrying in 1 s",
                                attempt + 1,
                                reconnect_retries,
                            )
                            if stop_event is not None:
                                stop_event.wait(retry_delay)
                            else:
                                time.sleep(retry_delay)
    finally:
        if close_rx:
            rx_sock.close()

    return results


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
    # type: (...) -> Dict[str, DmScanResult]
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
    :returns: dict mapping each DM name (str) to its :class:`DmScanResult`
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
    raw_results = j1939_scan_pgns(
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
    return {
        str(name): DmScanResult(
            dm_name=res.name,
            pgn=res.pgn,
            supported=res.supported,
            packet=res.packet,
            error=res.error,
        )
        for name, res in raw_results.items()
    }


__all__ = [
    "DmScanResult",
    "J1939PgnScanResult",
    "J1939_DM_PGNS",
    "J1939_PF_ACK",
    "J1939_PGN_ACK",
    "J1939_PGN_VIN",
    "j1939_scan_dm",
    "j1939_scan_pgns",
]
