# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2026 Ben Gardiner <ben.l.gardiner@gmail.com>

"""SAE J1939 Automotive Network Protocol Support.

This package provides protocol definitions, network discovery / scanner tools,
diagnostic messaging (DM), and 64-bit NAME decoder for SAE J1939 heavy-duty
commercial vehicle networks.
"""

from scapy.contrib.automotive.j1939.j1939_dm import (
    J1939_DM1,
    J1939_DM2,
    J1939_DM3,
    J1939_DM4,
    J1939_DM5,
    J1939_DM11,
    J1939_DM12,
    J1939_DM13,
    J1939_DM14,
    J1939_DM15,
    J1939_DM16,
    J1939_DM19,
    J1939_DM20,
    J1939_DM21,
    J1939_DM23,
    J1939_DM24,
    J1939_DM25,
    J1939_DM26,
    J1939_DM27,
    J1939_DM28,
    J1939_DM29,
    J1939_DM30,
    J1939_DM31,
    J1939_DM32,
    J1939_DM33,
    J1939_DM34,
    J1939_DM35,
    J1939_DTC,
    J1939_FLASH_STATUS,
    J1939_LAMP_STATUS,
    J1939_PGN_DM1,
    J1939_PGN_DM2,
    J1939_PGN_DM3,
    J1939_PGN_DM4,
    J1939_PGN_DM5,
    J1939_PGN_DM11,
    J1939_PGN_DM12,
    J1939_PGN_DM13,
    J1939_PGN_DM14,
    J1939_PGN_DM15,
    J1939_PGN_DM16,
    J1939_PGN_DM19,
    J1939_PGN_DM20,
    J1939_PGN_DM21,
    J1939_PGN_DM23,
    J1939_PGN_DM24,
    J1939_PGN_DM25,
    J1939_PGN_DM26,
    J1939_PGN_DM27,
    J1939_PGN_DM28,
    J1939_PGN_DM29,
    J1939_PGN_DM30,
    J1939_PGN_DM31,
    J1939_PGN_DM32,
    J1939_PGN_DM33,
    J1939_PGN_DM34,
    J1939_PGN_DM35,
    send_dm14_request,
    sniff_dm1,
)
from scapy.contrib.automotive.j1939.j1939_dm_scanner import (
    DMScanResult,
    J1939_DM_PGNS,
    j1939_scan_dm,
    j1939_scan_dm_pgn,
)
from scapy.contrib.automotive.j1939.j1939_scanner import (
    J1939_DEFAULT_BITRATE,
    J1939_DEFAULT_BUSLOAD,
    J1939_DIAGADAPTERS_ADDRESSES,
    J1939_PF_ACK,
    J1939_PF_ADDRESS_CLAIMED,
    J1939_PF_DIAG_A,
    J1939_PF_DIAG_B,
    J1939_PF_REQUEST,
    J1939_PF_XCP,
    J1939_PGN_ACK,
    J1939_PGN_ADDRESS_CLAIMED,
    J1939_PGN_DIAG_A,
    J1939_PGN_DIAG_B,
    J1939_PGN_ECU_ID,
    J1939_PGN_REQUEST,
    J1939_PGN_TP_CM,
    J1939_PGN_TP_DT,
    J1939_TP_CM_PF,
    J1939_XCP_SRC_ADDRS,
    J1939ScanResult,
    SCAN_METHODS,
    SockOrFactory,
    j1939_can_id,
    j1939_decode_can_id,
    j1939_inter_probe_delay,
    j1939_pre_probe_flush,
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
from scapy.contrib.j1939 import (
    J1939,
    J1939NativeSocket,
    J1939Request,
    J1939SoftSocket,
    J1939_CAN,
    J1939_GLOBAL_ADDRESS,
    J1939_NULL_ADDRESS,
    J1939_PGN_BROADCAST,
    J1939_TP_CTRL_ABORT,
    J1939_TP_CTRL_ACK,
    J1939_TP_CTRL_BAM,
    J1939_TP_CTRL_CTS,
    J1939_TP_CTRL_RTS,
    can_id_to_j1939,
    j1939_can_id_from_fields,
    j1939_log,
    j1939_pgn_from_fields,
)
from scapy.supersocket import SuperSocket


class _J1939SocketMeta(type):
    """Metaclass that creates J1939Socket as an alias to the preferred socket class.

    Returns :class:`~scapy.contrib.j1939.J1939NativeSocket` on Linux when the kernel
    ``CAN_J1939`` module is available and a string interface name is given, or
    :class:`~scapy.contrib.j1939.J1939SoftSocket` when a CAN socket instance is provided
    or on non-Linux platforms.
    """

    def __call__(cls, *args, **kwargs):
        # type: (...) -> SuperSocket
        if args and isinstance(args[0], str):
            try:
                return J1939NativeSocket(*args, **kwargs)
            except (ImportError, OSError):
                pass
        return J1939SoftSocket(*args, **kwargs)


class J1939Socket(SuperSocket, metaclass=_J1939SocketMeta):
    """Unified J1939 socket interface.

    Automatically dispatches to :class:`~scapy.contrib.j1939.J1939NativeSocket` (Linux
    kernel SocketCAN J1939) or :class:`~scapy.contrib.j1939.J1939SoftSocket` (Python
    userspace TP implementation) depending on the arguments and platform.

    Usage::

        # On Linux with CAN_J1939 kernel support (interface name string):
        sock = J1939Socket("can0", src_addr=0x10)

        # On any platform using a raw CAN socket instance:
        can_sock = NativeCANSocket("can0")
        sock = J1939Socket(can_sock, src_addr=0x10)
    """

    pass


__all__ = [
    "DMScanResult",
    "J1939",
    "J1939NativeSocket",
    "J1939Request",
    "J1939Socket",
    "J1939SoftSocket",
    "J1939_CAN",
    "J1939_DEFAULT_BITRATE",
    "J1939_DEFAULT_BUSLOAD",
    "J1939_DIAGADAPTERS_ADDRESSES",
    "J1939_DM1",
    "J1939_DM2",
    "J1939_DM3",
    "J1939_DM4",
    "J1939_DM5",
    "J1939_DM11",
    "J1939_DM12",
    "J1939_DM13",
    "J1939_DM14",
    "J1939_DM15",
    "J1939_DM16",
    "J1939_DM19",
    "J1939_DM20",
    "J1939_DM21",
    "J1939_DM23",
    "J1939_DM24",
    "J1939_DM25",
    "J1939_DM26",
    "J1939_DM27",
    "J1939_DM28",
    "J1939_DM29",
    "J1939_DM30",
    "J1939_DM31",
    "J1939_DM32",
    "J1939_DM33",
    "J1939_DM34",
    "J1939_DM35",
    "J1939_DM_PGNS",
    "J1939_DTC",
    "J1939_FLASH_STATUS",
    "J1939_GLOBAL_ADDRESS",
    "J1939_LAMP_STATUS",
    "J1939_NULL_ADDRESS",
    "J1939_PF_ACK",
    "J1939_PF_ADDRESS_CLAIMED",
    "J1939_PF_DIAG_A",
    "J1939_PF_DIAG_B",
    "J1939_PF_REQUEST",
    "J1939_PF_XCP",
    "J1939_PGN_ACK",
    "J1939_PGN_ADDRESS_CLAIMED",
    "J1939_PGN_BROADCAST",
    "J1939_PGN_DIAG_A",
    "J1939_PGN_DIAG_B",
    "J1939_PGN_DM1",
    "J1939_PGN_DM2",
    "J1939_PGN_DM3",
    "J1939_PGN_DM4",
    "J1939_PGN_DM5",
    "J1939_PGN_DM11",
    "J1939_PGN_DM12",
    "J1939_PGN_DM13",
    "J1939_PGN_DM14",
    "J1939_PGN_DM15",
    "J1939_PGN_DM16",
    "J1939_PGN_DM19",
    "J1939_PGN_DM20",
    "J1939_PGN_DM21",
    "J1939_PGN_DM23",
    "J1939_PGN_DM24",
    "J1939_PGN_DM25",
    "J1939_PGN_DM26",
    "J1939_PGN_DM27",
    "J1939_PGN_DM28",
    "J1939_PGN_DM29",
    "J1939_PGN_DM30",
    "J1939_PGN_DM31",
    "J1939_PGN_DM32",
    "J1939_PGN_DM33",
    "J1939_PGN_DM34",
    "J1939_PGN_DM35",
    "J1939_PGN_ECU_ID",
    "J1939_PGN_REQUEST",
    "J1939_PGN_TP_CM",
    "J1939_PGN_TP_DT",
    "J1939_TP_CM_PF",
    "J1939_TP_CTRL_ABORT",
    "J1939_TP_CTRL_ACK",
    "J1939_TP_CTRL_BAM",
    "J1939_TP_CTRL_CTS",
    "J1939_TP_CTRL_RTS",
    "J1939_XCP_SRC_ADDRS",
    "J1939ScanResult",
    "SCAN_METHODS",
    "SockOrFactory",
    "can_id_to_j1939",
    "j1939_can_id",
    "j1939_can_id_from_fields",
    "j1939_decode_can_id",
    "j1939_inter_probe_delay",
    "j1939_log",
    "j1939_pgn_from_fields",
    "j1939_pre_probe_flush",
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
    "send_dm14_request",
    "sniff_dm1",
]
