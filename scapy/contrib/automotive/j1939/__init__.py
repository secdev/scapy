# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

# scapy.contrib.description = SAE J1939 (SAE J1939-21) Transport Layer Socket & Diagnostics
# scapy.contrib.status = loads

import abc
from scapy.config import conf
from scapy.consts import LINUX
from scapy.contrib.j1939 import (
    J1939,
    J1939_CAN,
    J1939_GLOBAL_ADDRESS,
    J1939_NULL_ADDRESS,
    J1939_PGN_ADDRESS_CLAIMED,
    J1939_PGN_ADDRESS_COMMANDED,
    J1939_PGN_REQUEST,
    J1939_PGN_TP_CM,
    J1939_PGN_TP_DT,
    J1939_TP_CTRL_ABORT,
    J1939_TP_CTRL_ACK,
    J1939_TP_CTRL_BAM,
    J1939_TP_CTRL_CTS,
    J1939_TP_CTRL_RTS,
    J1939NativeSocket,
    J1939Request,
    J1939SoftSocket,
    J1939TPImplementation,
    can_id_to_j1939,
    j1939_dst_from_fields,
    j1939_log,
    j1939_pgn_from_fields,
    j1939_pgn_is_pdu1,
    j1939_to_can_id,
)
from scapy.supersocket import SuperSocket

J1939_PF_ADDRESS_CLAIMED = 0xEE
J1939_PF_REQUEST = 0xEA


class _J1939SocketMeta(type(SuperSocket), abc.ABCMeta):
    pass


class J1939Socket(SuperSocket, metaclass=_J1939SocketMeta):
    """Platform-aware J1939 socket.

    Dispatches to J1939NativeSocket when running on Linux with a network
    interface string and use-can-j1939-kernel-module is enabled in config,
    otherwise dispatches to J1939SoftSocket.
    """

    def __new__(cls, can_socket=None, *args, **kwargs):
        if isinstance(can_socket, (J1939SoftSocket, J1939NativeSocket)):
            return can_socket
        sock = can_socket if can_socket is not None else kwargs.get("can_socket")
        if LINUX and isinstance(sock, str):
            j1939_conf = conf.contribs.get("J1939", {})
            if j1939_conf.get("use-can-j1939-kernel-module", False):
                if can_socket is not None:
                    return J1939NativeSocket(can_socket, *args, **kwargs)
                return J1939NativeSocket(*args, **kwargs)
        if can_socket is not None:
            return J1939SoftSocket(can_socket, *args, **kwargs)
        return J1939SoftSocket(*args, **kwargs)

    @classmethod
    def __subclasshook__(cls, C):
        if cls is J1939Socket:
            if issubclass(C, (J1939SoftSocket, J1939NativeSocket)):
                return True
        return NotImplemented


from scapy.contrib.automotive.j1939.j1939_dm import (
    J1939_DM1,
    J1939_DM13,
    J1939_DM14,
    J1939_DTC,
    J1939_PGN_DM1,
    J1939_PGN_DM13,
    J1939_PGN_DM14,
    send_dm14_request,
    sniff_dm1,
)
from scapy.contrib.automotive.j1939.j1939_dm_scanner import (
    DmScanResult,
    J1939_DM_PGNS,
    J1939_PF_ACK,
    J1939_PGN_ACK,
    j1939_scan_dm,
    j1939_scan_dm_pgn,
)
from scapy.contrib.automotive.j1939.j1939_name import (
    J1939_INDUSTRY_GROUPS,
    J1939_INDUSTRY_SPECIFIC_FUNCTIONS,
    J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS,
    J1939_MANUFACTURERS,
    J1939_NAME,
    J1939_PRE_ASSIGNED_FUNCTIONS,
    j1939_decode_name,
    j1939_request_name,
    j1939_request_names,
    simulate_arbitration,
)
from scapy.contrib.automotive.j1939.j1939_scanner import (
    J1939_DEFAULT_BITRATE,
    J1939_DEFAULT_BUSLOAD,
    J1939_DIAGADAPTERS_ADDRESSES,
    J1939_PF_DIAG_A,
    J1939_PF_DIAG_B,
    J1939_PF_XCP,
    J1939_PGN_DIAG_A,
    J1939_PGN_DIAG_B,
    J1939_PGN_ECU_ID,
    J1939_TP_CM_PF,
    J1939_XCP_SRC_ADDRS,
    J1939ScanResult,
    SCAN_METHODS,
    SockOrFactory,
    j1939_can_id,
    j1939_decode_can_id,
    j1939_get_sock,
    j1939_inter_probe_delay,
    j1939_pre_probe_flush,
    j1939_resolve_broadcast_sock,
    j1939_resolve_probe_sock,
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
    "DmScanResult",
    "J1939",
    "J1939_CAN",
    "J1939_DEFAULT_BITRATE",
    "J1939_DEFAULT_BUSLOAD",
    "J1939_DIAGADAPTERS_ADDRESSES",
    "J1939_DM1",
    "J1939_DM13",
    "J1939_DM14",
    "J1939_DM_PGNS",
    "J1939_DTC",
    "J1939_GLOBAL_ADDRESS",
    "J1939_INDUSTRY_GROUPS",
    "J1939_INDUSTRY_SPECIFIC_FUNCTIONS",
    "J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS",
    "J1939_MANUFACTURERS",
    "J1939_NAME",
    "J1939_NULL_ADDRESS",
    "J1939_PF_ACK",
    "J1939_PF_ADDRESS_CLAIMED",
    "J1939_PF_DIAG_A",
    "J1939_PF_DIAG_B",
    "J1939_PF_REQUEST",
    "J1939_PF_XCP",
    "J1939_PGN_ACK",
    "J1939_PGN_ADDRESS_CLAIMED",
    "J1939_PGN_ADDRESS_COMMANDED",
    "J1939_PGN_DIAG_A",
    "J1939_PGN_DIAG_B",
    "J1939_PGN_DM1",
    "J1939_PGN_DM13",
    "J1939_PGN_DM14",
    "J1939_PGN_ECU_ID",
    "J1939_PGN_REQUEST",
    "J1939_PGN_TP_CM",
    "J1939_PGN_TP_DT",
    "J1939_PRE_ASSIGNED_FUNCTIONS",
    "J1939_TP_CM_PF",
    "J1939_TP_CTRL_ABORT",
    "J1939_TP_CTRL_ACK",
    "J1939_TP_CTRL_BAM",
    "J1939_TP_CTRL_CTS",
    "J1939_TP_CTRL_RTS",
    "J1939_XCP_SRC_ADDRS",
    "J1939NativeSocket",
    "J1939Request",
    "J1939ScanResult",
    "J1939Socket",
    "J1939SoftSocket",
    "J1939TPImplementation",
    "SCAN_METHODS",
    "SockOrFactory",
    "can_id_to_j1939",
    "j1939_can_id",
    "j1939_decode_can_id",
    "j1939_decode_name",
    "j1939_dst_from_fields",
    "j1939_get_sock",
    "j1939_inter_probe_delay",
    "j1939_log",
    "j1939_pgn_from_fields",
    "j1939_pgn_is_pdu1",
    "j1939_pre_probe_flush",
    "j1939_request_name",
    "j1939_request_names",
    "j1939_resolve_broadcast_sock",
    "j1939_resolve_probe_sock",
    "j1939_scan",
    "j1939_scan_addr_claim",
    "j1939_scan_dm",
    "j1939_scan_dm_pgn",
    "j1939_scan_ecu_id",
    "j1939_scan_passive",
    "j1939_scan_rts_probe",
    "j1939_scan_uds",
    "j1939_scan_unicast",
    "j1939_scan_xcp",
    "j1939_to_can_id",
    "send_dm14_request",
    "simulate_arbitration",
    "sniff_dm1",
]
