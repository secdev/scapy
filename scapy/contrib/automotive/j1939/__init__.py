# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

# scapy.contrib.description = SAE J1939 (SAE J1939-21) Transport Layer Socket & Diagnostics
# scapy.contrib.status = loads

import abc
from scapy.consts import LINUX
from scapy.config import conf
from scapy.supersocket import SuperSocket

from scapy.contrib.j1939 import (
    J1939,
    J1939Request,
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

j1939_log = log_j1939
j1939_pgn_from_fields = pgn_from_fields
j1939_dst_from_fields = dst_from_fields
j1939_pgn_is_pdu1 = pgn_is_pdu1

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


class _J1939SocketMeta(type(SuperSocket), abc.ABCMeta):
    pass


class J1939Socket(SuperSocket, metaclass=_J1939SocketMeta):
    """Platform-aware J1939 socket.

    Dispatches to NativeJ1939Socket when running on Linux with a network
    interface string and use-can-j1939-kernel-module is enabled in config,
    otherwise dispatches to J1939SoftSocket.
    """

    def __new__(cls, can_socket=None, *args, **kwargs):
        if isinstance(can_socket, (J1939SoftSocket, NativeJ1939Socket)):
            return can_socket
        sock = can_socket if can_socket is not None else kwargs.get("can_socket")
        if LINUX and isinstance(sock, str):
            j1939_conf = conf.contribs.get("J1939", {})
            if j1939_conf.get("use-can-j1939-kernel-module", False):
                if can_socket is not None:
                    return NativeJ1939Socket(can_socket, *args, **kwargs)
                return NativeJ1939Socket(*args, **kwargs)
        if can_socket is not None:
            return J1939SoftSocket(can_socket, *args, **kwargs)
        return J1939SoftSocket(*args, **kwargs)

    @classmethod
    def __subclasshook__(cls, C):
        if cls is J1939Socket:
            if issubclass(C, (J1939SoftSocket, NativeJ1939Socket)):
                return True
        return NotImplemented


from scapy.contrib.automotive.j1939.j1939_scanner import (
    SockOrFactory,
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

__all__ = [
    'J1939',
    'J1939Request',
    'J1939_CAN',
    'J1939SoftSocket',
    'NativeJ1939Socket',
    'J1939TPImplementation',
    'J1939Socket',
    'J1939_BROADCAST_ADDR',
    'J1939_GLOBAL_ADDRESS',
    'J1939_NULL_ADDRESS',
    'j1939_log',
    'pgn_from_fields',
    'j1939_pgn_from_fields',
    'dst_from_fields',
    'j1939_dst_from_fields',
    'pgn_is_pdu1',
    'j1939_pgn_is_pdu1',
    'SockOrFactory',
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
]
