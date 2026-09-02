# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

# scapy.contrib.description = SAE J1939 (SAE J1939-21) Transport Layer Socket & Diagnostics
# scapy.contrib.status = loads

from scapy.consts import LINUX
from scapy.config import conf

from scapy.contrib.j1939 import (
    J1939,
    J1939_CAN,
    J1939SoftSocket,
    NativeJ1939Socket,
    J1939TPImplementation,
    J1939_BROADCAST_ADDR,
    J1939_PGN_TP_CM,
    J1939_PGN_TP_DT,
    J1939_TP_CTRL_RTS,
    J1939_TP_CTRL_CTS,
    J1939_TP_CTRL_ACK,
    J1939_TP_CTRL_BAM,
    J1939_TP_CTRL_ABORT,
    can_id_to_j1939,
    j1939_to_can_id,
    pgn_from_fields,
    dst_from_fields,
    pgn_is_pdu1,
    log_j1939,
)

J1939_GLOBAL_ADDRESS = J1939_BROADCAST_ADDR
J1939_NULL_ADDRESS = 0xFE
PGN_ADDRESS_CLAIMED = 0xEE00
PGN_REQUEST = 0xEA00
J1939_PF_ADDRESS_CLAIMED = 0xEE
J1939_PF_REQUEST = 0xEA
TP_CM_RTS = J1939_TP_CTRL_RTS
TP_CM_CTS = J1939_TP_CTRL_CTS
TP_CM_EndOfMsgACK = J1939_TP_CTRL_ACK
TP_CM_BAM = J1939_TP_CTRL_BAM
TP_Conn_Abort = J1939_TP_CTRL_ABORT

from scapy.contrib.automotive.j1939.j1939_dm import (
    J1939_DTC,
    J1939_DM1,
    J1939_DM13,
    J1939_DM14,
    PGN_DM1,
    PGN_DM13,
    PGN_DM14,
    sniff_dm1,
    send_dm14_request,
)

from scapy.contrib.automotive.j1939.j1939_scanner import (
    _j1939_can_id,
    _j1939_decode_can_id,
    J1939_TP_CM_PF,
    j1939_scan,
    j1939_scan_passive,
    j1939_scan_addr_claim,
    j1939_scan_ecu_id,
    j1939_scan_unicast,
    j1939_scan_rts_probe,
    j1939_scan_uds,
    j1939_scan_xcp,
    J1939_DIAGADAPTERS_ADDRESSES,
    J1939_XCP_SRC_ADDRS,
    PGN_ECU_ID,
    PGN_DIAG_A,
    J1939_PF_DIAG_A,
    PGN_DIAG_B,
    J1939_PF_DIAG_B,
    J1939_PF_XCP,
    SCAN_METHODS,
)

from scapy.contrib.automotive.j1939.j1939_dm_scanner import (
    DmScanResult,
    J1939_DM_PGNS,
    J1939_PF_ACK,
    PGN_ACK,
    j1939_scan_dm,
    j1939_scan_dm_pgn,
)

J1939Socket = J1939SoftSocket

__all__ = [
    'J1939',
    'J1939_CAN',
    'J1939SoftSocket',
    'NativeJ1939Socket',
    'J1939TPImplementation',
    'J1939Socket',
    'J1939_BROADCAST_ADDR',
    'J1939_GLOBAL_ADDRESS',
    'J1939_NULL_ADDRESS',
    'log_j1939',
    'J1939_DTC',
    'J1939_DM1',
    'J1939_DM13',
    'J1939_DM14',
    'PGN_DM1',
    'PGN_DM13',
    'PGN_DM14',
    'sniff_dm1',
    'send_dm14_request',
    'j1939_scan',
    'j1939_scan_passive',
    'j1939_scan_addr_claim',
    'j1939_scan_ecu_id',
    'j1939_scan_unicast',
    'j1939_scan_rts_probe',
    'j1939_scan_uds',
    'j1939_scan_xcp',
    'J1939_DIAGADAPTERS_ADDRESSES',
    'J1939_XCP_SRC_ADDRS',
    'PGN_ECU_ID',
    'PGN_DIAG_A',
    'J1939_PF_DIAG_A',
    'PGN_DIAG_B',
    'J1939_PF_DIAG_B',
    'J1939_PF_XCP',
    'SCAN_METHODS',
    'DmScanResult',
    'J1939_DM_PGNS',
    'J1939_PF_ACK',
    'PGN_ACK',
    'j1939_scan_dm',
    'j1939_scan_dm_pgn',
]
