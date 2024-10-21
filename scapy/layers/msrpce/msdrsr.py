# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-DRSR] Directory Replication Service (DRS) Remote Protocol
"""

import uuid
from scapy.packet import Packet
from scapy.fields import LEIntField, FlagsField, UUIDField, UTCTimeField

from scapy.layers.msrpce.raw.ms_drsr import UUID
from scapy.layers.msrpce.raw.ms_drsr import *  # noqa: F403,F401

# [MS-DRSR] sect 5.39 DRS_EXTENSIONS_INT


class DRS_EXTENSIONS_INT(Packet):
    fields_desc = [
        FlagsField(
            "dwFlags",
            0,
            -32,
            {
                0x00000001: "BASE",
                0x00000002: "ASYNCREPL",
                0x00000004: "REMOVEAPI",
                0x00000008: "MOVEREQ_V2",
                0x00000010: "GETCHG_DEFLATE",
                0x00000020: "DCINFO_V1",
                0x00000040: "RESTORE_USN_OPTIMIZATION",
                0x00000080: "ADDENTRY",
                0x00000100: "KCC_EXECUTE",
                0x00000200: "ADDENTRY_V2",
                0x00000400: "LINKED_VALUE_REPLICATION",
                0x00000800: "DCINFO_V2",
                0x00001000: "INSTANCE_TYPE_NOT_REQ_ON_MOD",
                0x00002000: "CRYPTO_BIND",
                0x00004000: "GET_REPL_INFO",
                0x00008000: "STRONG_ENCRYPTION",
                0x00010000: "DCINFO_VFFFFFFFF",
                0x00020000: "TRANSITIVE_MEMBERSHIP",
                0x00040000: "ADD_SID_HISTORY",
                0x00080000: "POST_BETA3",
                0x00100000: "GETCHGREQ_V5",
                0x00200000: "GETMEMBERSHIPS2",
                0x00400000: "GETCHGREQ_V6",
                0x00800000: "NONDOMAIN_NCS",
                0x01000000: "GETCHGREQ_V8",
                0x02000000: "GETCHGREPLY_V5",
                0x04000000: "GETCHGREPLY_V6",
                0x08000000: "WHISTLER_BETA3",
                0x10000000: "W2K3_DEFLATE",
                0x20000000: "GETCHGREQ_V10",
                0x40000000: "R2",
                0x80000000: "R3",
            },
        ),
        UUIDField("SiteObjGuid", None, uuid_fmt=UUIDField.FORMAT_LE),
        LEIntField("Pid", 0),
        UTCTimeField("dwReplEpoch", None, fmt="<I"),
        FlagsField(
            "dwFlagsExt",
            0,
            -32,
            {
                0x00000001: "ADAM",
                0x00000002: "LH_BETA2",
                0x00000004: "RECYCLE_BIN",
                0x00000100: "GETCHGREPLY_V9",
                0x00000400: "RPC_CORRELATIONID_1",
            },
        ),
        UUIDField("ConfigObjGuid", None, uuid_fmt=UUIDField.FORMAT_LE),
        LEIntField("dwExtCaps", 0),
    ]


# [MS-DRSR] sect 5.138 NTDSAPI_CLIENT_GUID

NTDSAPI_CLIENT_GUID = UUID(uuid.UUID("{e24d201a-4fd6-11d1-a3da-0000f875ae0d}").bytes_le)
