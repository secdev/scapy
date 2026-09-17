# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2026 Ben Gardiner <ben.l.gardiner@gmail.com>

"""SAE J1939 Automotive Network Protocol Support.

This package provides protocol definitions, network discovery / scanner tools,
diagnostic messaging (DM), and 64-bit NAME decoder for SAE J1939 heavy-duty
commercial vehicle networks.
"""
from scapy.contrib.automotive.j1939.j1939_scanner import (
    J1939ScanResult,
    J1939_ACK_CTRL_ACCESS_DENIED,
    J1939_ACK_CTRL_ACK,
    J1939_ACK_CTRL_CANNOT_RESPOND,
    J1939_ACK_CTRL_NACK,
    J1939_DEFAULT_BITRATE,
    J1939_DEFAULT_BUSLOAD,
    J1939_DIAGADAPTERS_ADDRESSES,
    J1939_PGN_ECU_ID,
    J1939_PGN_XCP,
    J1939_SCAN_METHODS,
    J1939_UDS_TESTER_PRESENT_REQS,
    J1939_UDS_TESTER_PRESENT_RESPS,
    J1939_XCP_CONNECT_REQ,
    J1939_XCP_POSITIVE_RESPONSE,
    J1939_XCP_SRC_ADDRS,
    j1939_check_rx_filter_warning,
    j1939_emit_sa_filter_warning,
    j1939_get_sock,
    j1939_inter_probe_delay,
    j1939_reconnect_with_retry,
    j1939_sa_filter,
    j1939_scan,
    j1939_scan_addr_claim,
    j1939_scan_ecu_id,
    j1939_scan_passive,
    j1939_scan_rts_probe,
    j1939_scan_uds,
    j1939_scan_unicast,
    j1939_scan_xcp,
)

__all__ = [
    "J1939ScanResult",
    "J1939_ACK_CTRL_ACCESS_DENIED",
    "J1939_ACK_CTRL_ACK",
    "J1939_ACK_CTRL_CANNOT_RESPOND",
    "J1939_ACK_CTRL_NACK",
    "J1939_DEFAULT_BITRATE",
    "J1939_DEFAULT_BUSLOAD",
    "J1939_DIAGADAPTERS_ADDRESSES",
    "J1939_PGN_ECU_ID",
    "J1939_PGN_XCP",
    "J1939_SCAN_METHODS",
    "J1939_UDS_TESTER_PRESENT_REQS",
    "J1939_UDS_TESTER_PRESENT_RESPS",
    "J1939_XCP_CONNECT_REQ",
    "J1939_XCP_POSITIVE_RESPONSE",
    "J1939_XCP_SRC_ADDRS",
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
