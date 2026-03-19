# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

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

import struct
import time
from threading import Event

# Typing imports
from typing import (
    Callable,
    Dict,
    List,
    Optional,
)

from scapy.layers.can import CAN
from scapy.supersocket import SuperSocket

from scapy.contrib.automotive.j1939.j1939_soft_socket import (
    J1939_NULL_ADDRESS,
    J1939_PF_REQUEST,
    _j1939_can_id,
    _j1939_decode_can_id,
    log_j1939,
)

from scapy.contrib.automotive.j1939.j1939_scanner import (
    _J1939_DEFAULT_BITRATE,
    _J1939_DEFAULT_BUSLOAD,
    _inter_probe_delay,
    _pre_probe_flush,
    _resolve_probe_sock,
    SockOrFactory,
)

# --- DM scanner constants

#: PDU Format byte for Acknowledgment messages (J1939-21 §5.4.4, PGN 0xE800)
J1939_PF_ACK = 0xE8  # 232

#: PGN for Acknowledgment / NACK messages (J1939-21 §5.4.4)
PGN_ACK = 0xE800  # 59392

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


# --- Result container


class DmScanResult(object):
    """Result record for a single DM PGN probe sent by :func:`j1939_scan_dm_pgn`.

    :param dm_name: human-readable DM name (e.g. ``"DM1"``)
    :param pgn: PGN number that was requested
    :param supported: ``True`` if the ECU replied with the requested PGN
    :param packet: the first CAN response received (``None`` on timeout)
    :param error: ``None`` when supported; ``"NACK"`` for negative ack;
                  ``"Timeout"`` when no reply
    """

    __slots__ = ("dm_name", "pgn", "supported", "packet", "error")

    def __init__(
        self,
        dm_name,  # type: str
        pgn,  # type: int
        supported,  # type: bool
        packet=None,  # type: Optional[CAN]
        error=None,  # type: Optional[str]
    ):
        # type: (...) -> None
        self.dm_name = dm_name
        self.pgn = pgn
        self.supported = supported
        self.packet = packet
        self.error = error

    def __repr__(self):
        # type: () -> str
        return "<DmScanResult dm={} pgn=0x{:04X} supported={} error={}>".format(
            self.dm_name, self.pgn, self.supported, self.error
        )


# --- Internal helpers


def _pgn_matches(pf, ps, pgn):
    # type: (int, int, int) -> bool
    """Return True if (*pf*, *ps*) decoded from a CAN-ID match *pgn*."""
    if pf >= 0xF0:
        # PDU2: PS is the low byte of the PGN (group extension)
        return pf * 256 + ps == pgn
    # PDU1: PS is the DA; PGN family is pf * 256 (low byte of pgn must be 0)
    return pf * 256 == (pgn & 0xFF00)


# --- Technique: unicast DM PGN probe


def j1939_scan_dm_pgn(
    sock,  # type: SockOrFactory
    target_da,  # type: int
    pgn,  # type: int
    dm_name="Unknown",  # type: str
    src_addr=0xF9,  # type: int

    sniff_time=1.0,  # type: float
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
):
    # type: (...) -> DmScanResult
    """Probe *target_da* for support of a single Diagnostic Message PGN.

    Sends a unicast Request (PGN 59904) to *target_da* asking for *pgn* and
    waits up to *sniff_time* seconds for a reply.  The ECU is considered to
    support the PGN if it replies with that PGN.  A NACK (PGN 0xE800, control
    byte 0x01) means the ECU does not support it.  Silence is a Timeout.

    The inter-probe gap is automatically paced so that the scanner contributes
    at most *busload* × *bitrate* bits per second to the bus, counting both
    the outgoing probe frame (3-byte payload) and the expected response frame
    (8-byte payload).

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param target_da: destination address of the ECU to probe (0x00–0xFD)
    :param pgn: the Diagnostic Message PGN to request
    :param dm_name: human-readable DM name included in the returned result
    :param src_addr: source address used in outgoing probes (default 0xF9)
    :param sniff_time: seconds to wait for a response after sending the probe
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :returns: :class:`DmScanResult` describing the outcome for this PGN
    """
    if stop_event is not None and stop_event.is_set():
        return DmScanResult(dm_name, pgn, False, error="Aborted")

    can_id = _j1939_can_id(_DM_SCAN_PRIORITY, J1939_PF_REQUEST, target_da, src_addr)
    payload = struct.pack("<I", pgn)[:3]

    result = []  # type: List[DmScanResult]
    send_sock, rx_sock, close_rx = _resolve_probe_sock(sock, target_da)

    def _rx(pkt):
        # type: (CAN) -> None
        if result:
            return
        if stop_event is not None and stop_event.is_set():
            return
        if not (pkt.flags & _CAN_EXTENDED_FLAG):
            return
        _, pf, ps, sa = _j1939_decode_can_id(pkt.identifier)
        if sa != target_da:
            return
        if _pgn_matches(pf, ps, pgn):
            log_j1939.debug("dm_scan: positive response SA=0x%02X PGN=0x%04X", sa, pgn)
            result.append(DmScanResult(dm_name, pgn, True, packet=pkt))
            return
        if pf == J1939_PF_ACK:
            data = bytes(pkt.data)
            if data and data[0] == _ACK_CTRL_NACK:
                log_j1939.debug("dm_scan: NACK from SA=0x%02X PGN=0x%04X", sa, pgn)
                result.append(
                    DmScanResult(dm_name, pgn, False, packet=pkt, error="NACK")
                )

    def _send_probe():
        # type: () -> None
        _pre_probe_flush(rx_sock)
        send_sock.send(CAN(identifier=can_id, flags="extended", data=payload))
        log_j1939.debug(
            "dm_scan: probing DA=0x%02X PGN=0x%04X (%s)", target_da, pgn, dm_name
        )

    try:
        rx_sock.sniff(prn=_rx, timeout=sniff_time, store=False,
                      started_callback=_send_probe,
                      stop_filter=lambda _: bool(result))
    finally:
        if close_rx:
            rx_sock.close()

    # Pace the probe rate: request=3 bytes (DLC 3), response=8 bytes (DLC 8)
    _extra = _inter_probe_delay(bitrate, busload, 3, 8, sniff_time)
    if _extra > 0.0:
        time.sleep(_extra)

    if result:
        return result[0]

    log_j1939.debug("dm_scan: timeout waiting for DA=0x%02X PGN=0x%04X", target_da, pgn)
    return DmScanResult(dm_name, pgn, False, error="Timeout")


# --- Top-level DM scanner


def j1939_scan_dm(
    sock,  # type: SockOrFactory
    target_da,  # type: int
    dms=None,  # type: Optional[List[str]]
    src_addr=0xF9,  # type: int

    sniff_time=1.0,  # type: float
    stop_event=None,  # type: Optional[Event]
    bitrate=_J1939_DEFAULT_BITRATE,  # type: int
    busload=_J1939_DEFAULT_BUSLOAD,  # type: float
    reset_handler=None,  # type: Optional[Callable[[], None]]
    reconnect_handler=None,  # type: Optional[Callable[[], SuperSocket]]
    reconnect_retries=5,  # type: int
):
    # type: (...) -> Dict[str, DmScanResult]
    """Probe *target_da* for all (or a selected subset of) Diagnostic Message PGNs.

    Iterates over the DM names in *dms* (or all entries in
    :data:`J1939_DM_PGNS` when *dms* is ``None``), calling
    :func:`j1939_scan_dm_pgn` for each one and collecting the results.

    If *reset_handler* is provided it is called between each pair of DM PGN
    probes to reset the target ECU to a known state.  If *reconnect_handler*
    is also provided it is called immediately after the reset to obtain a fresh
    socket; subsequent probes will use the returned socket.  This mirrors the
    interface of :class:`~scapy.contrib.automotive.uds_scan.UDS_Scanner` where
    ``reset_handler`` and ``reconnect_handler`` serve the same role.

    When *reconnect_handler* is provided the call is retried up to
    *reconnect_retries* times (with a 1-second pause between attempts) if it
    raises an exception.  This mirrors the retry logic in
    :class:`~scapy.contrib.automotive.scanner.executor.AutomotiveTestCaseExecutor`.

    :param sock: raw CAN socket **or** zero-argument callable returning one
    :param target_da: destination address of the ECU to probe (0x00–0xFD)
    :param dms: list of DM names to scan; must be keys of
                 :data:`J1939_DM_PGNS`.  Default is all entries.
    :param src_addr: source address used in outgoing probes (default 0xF9)
    :param sniff_time: per-PGN listen time in seconds (default 1.0)
    :param stop_event: optional :class:`threading.Event` to abort early
    :param bitrate: CAN bus bitrate in bit/s (default 250000 for J1939)
    :param busload: maximum fraction of bus capacity the scanner may consume
                    (default 0.05 = 5 %)
    :param reset_handler: optional callable (no arguments, no return value)
                          to reset the target ECU between DM probes.  Called
                          after each probe except the last.
    :param reconnect_handler: optional callable (no arguments) that returns a
                              new :class:`~scapy.supersocket.SuperSocket`.
                              Called after *reset_handler* when provided;
                              the returned socket is used for all subsequent
                              probes.
    :param reconnect_retries: maximum number of attempts when calling
                              *reconnect_handler* (default 5).  A 1-second
                              pause is inserted between retries.
    :returns: dict mapping each DM name (str) to its :class:`DmScanResult`

    Example::

        >>> results = j1939_scan_dm(sock, target_da=0x00)
        >>> for name, res in sorted(results.items()):
        ...     if res.supported:
        ...         print("[+] {} (PGN 0x{:04X})".format(name, res.pgn))

    Example with reset and reconnect::

        >>> def reset():
        ...     pass  # reset ECU via HW reset line or similar
        >>> def reconnect():
        ...     return CANSocket("can0")
        >>> results = j1939_scan_dm(
        ...     reconnect(), target_da=0x00,
        ...     reset_handler=reset,
        ...     reconnect_handler=reconnect,
        ... )
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

    results = {}  # type: Dict[str, DmScanResult]
    active_sock = sock  # may be replaced if reconnect_handler is used
    num_pgns = len(dms)

    for i, dm_name in enumerate(dms):
        if stop_event is not None and stop_event.is_set():
            break
        results[dm_name] = j1939_scan_dm_pgn(
            active_sock,
            target_da=target_da,
            pgn=J1939_DM_PGNS[dm_name],
            dm_name=dm_name,
            src_addr=src_addr,
            sniff_time=sniff_time,
            stop_event=stop_event,
            bitrate=bitrate,
            busload=busload,
        )
        # Between probes: reset target and/or reconnect if handlers provided
        if i < num_pgns - 1:
            if reset_handler is not None:
                log_j1939.debug("dm_scan: calling reset_handler between probes")
                reset_handler()
            if reconnect_handler is not None:
                log_j1939.debug("dm_scan: calling reconnect_handler")
                for attempt in range(max(1, reconnect_retries)):
                    try:
                        active_sock = reconnect_handler()
                        break
                    except Exception:
                        if attempt == reconnect_retries - 1:
                            raise
                        log_j1939.debug(
                            "dm_scan: reconnect attempt %d/%d failed, "
                            "retrying in 1 s",
                            attempt + 1,
                            reconnect_retries,
                        )
                        if stop_event is not None:
                            stop_event.wait(1)
                        else:
                            time.sleep(1)

    return results


__all__ = [
    "DmScanResult",
    "J1939_DM_PGNS",
    "J1939_PF_ACK",
    "PGN_ACK",
    "j1939_scan_dm",
    "j1939_scan_dm_pgn",
]
