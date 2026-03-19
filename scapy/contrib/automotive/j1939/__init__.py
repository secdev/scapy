# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ben Gardiner <ben@bengardiner.com>

# scapy.contrib.description = SAE J1939 (SAE J1939-21) Transport Layer Socket
# scapy.contrib.status = loads

"""
J1939 transport layer socket for Scapy.

Provides a socket abstraction for SAE J1939-21 multi-packet communication
over CAN, analogous to ISOTPSocket / ISOTPSoftSocket.

Currently only a pure-Python soft-socket implementation is provided.
The package is structured to allow a future native Linux j1939 socket
implementation (similar to ISOTPNativeSocket) using the kernel's CAN_J1939
socket type (available since Linux 5.4).

Usage:
    >>> load_contrib('automotive.j1939')
    >>> with J1939Socket("can0", src_addr=0x11, dst_addr=0xFF, pgn=0xFECA) as s:
    ...     s.send(J1939(data=b"Hello, J1939!"))

Configuration to enable a future native j1939 kernel socket:
    >>> conf.contribs['J1939'] = {'use-j1939-kernel-module': True}
"""

from scapy.consts import LINUX
from scapy.config import conf
from scapy.error import log_loading

from scapy.contrib.automotive.j1939.j1939_soft_socket import (
    J1939,
    J1939SoftSocket,
    J1939SocketImplementation,
    TimeoutScheduler,
    J1939_GLOBAL_ADDRESS,
    J1939_TP_MAX_DLEN,
    J1939_MAX_SF_DLEN,
    TP_CM_BAM,
    TP_CM_RTS,
    TP_CM_CTS,
    TP_CM_EndOfMsgACK,
    TP_Conn_Abort,
    TP_CM_MAX_PACKETS_NO_LIMIT,
    TP_DT_TIMEOUT_EXTENSION_FACTOR,
    PGN_ADDRESS_CLAIMED,
    PGN_REQUEST,
    J1939_PF_ADDRESS_CLAIMED,
    J1939_PF_REQUEST,
    J1939_NULL_ADDRESS,
    J1939_ADDR_CLAIM_TIMEOUT,
    J1939_ADDR_STATE_UNCLAIMED,
    J1939_ADDR_STATE_CLAIMING,
    J1939_ADDR_STATE_CLAIMED,
    J1939_ADDR_STATE_CANNOT_CLAIM,
    log_j1939,
)

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
    j1939_scan,
    j1939_scan_passive,
    j1939_scan_addr_claim,
    j1939_scan_ecu_id,
    j1939_scan_unicast,
    j1939_scan_rts_probe,
    PGN_ECU_ID,
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

__all__ = [
    "J1939",
    "J1939SoftSocket",
    "J1939SocketImplementation",
    "J1939Socket",
    "TimeoutScheduler",
    "J1939_GLOBAL_ADDRESS",
    "J1939_TP_MAX_DLEN",
    "J1939_MAX_SF_DLEN",
    "TP_CM_BAM",
    "TP_CM_RTS",
    "TP_CM_CTS",
    "TP_CM_EndOfMsgACK",
    "TP_Conn_Abort",
    "TP_CM_MAX_PACKETS_NO_LIMIT",
    "TP_DT_TIMEOUT_EXTENSION_FACTOR",
    "PGN_ADDRESS_CLAIMED",
    "PGN_REQUEST",
    "J1939_PF_ADDRESS_CLAIMED",
    "J1939_PF_REQUEST",
    "J1939_NULL_ADDRESS",
    "J1939_ADDR_CLAIM_TIMEOUT",
    "J1939_ADDR_STATE_UNCLAIMED",
    "J1939_ADDR_STATE_CLAIMING",
    "J1939_ADDR_STATE_CLAIMED",
    "J1939_ADDR_STATE_CANNOT_CLAIM",
    "USE_J1939_KERNEL_MODULE",
    "log_j1939",
    # Diagnostic Messages (J1939-73)
    "J1939_DTC",
    "J1939_DM1",
    "J1939_DM13",
    "J1939_DM14",
    "PGN_DM1",
    "PGN_DM13",
    "PGN_DM14",
    "sniff_dm1",
    "send_dm14_request",
    # CA Scanner (J1939-73)
    "j1939_scan",
    "j1939_scan_passive",
    "j1939_scan_addr_claim",
    "j1939_scan_ecu_id",
    "j1939_scan_unicast",
    "j1939_scan_rts_probe",
    "PGN_ECU_ID",
    "SCAN_METHODS",
    # DM Scanner (J1939-73)
    "DmScanResult",
    "J1939_DM_PGNS",
    "J1939_PF_ACK",
    "PGN_ACK",
    "j1939_scan_dm",
    "j1939_scan_dm_pgn",
]

USE_J1939_KERNEL_MODULE = False

if LINUX:
    try:
        if conf.contribs["J1939"]["use-j1939-kernel-module"]:
            USE_J1939_KERNEL_MODULE = True
    except KeyError:
        log_loading.info(
            "Specify 'conf.contribs['J1939'] = "
            "{'use-j1939-kernel-module': True}' "
            "to enable usage of the Linux j1939 kernel module (Linux >= 5.4)."
        )

    # Future: import J1939NativeSocket here when implemented
    # if USE_J1939_KERNEL_MODULE:
    #     from scapy.contrib.automotive.j1939.j1939_native_socket import \
    #         J1939NativeSocket
    #     __all__.append("J1939NativeSocket")

if USE_J1939_KERNEL_MODULE:
    # Placeholder — native socket not yet implemented; fall through to soft
    J1939Socket = J1939SoftSocket  # type: ignore[assignment]
else:
    J1939Socket = J1939SoftSocket  # type: ignore[assignment]
