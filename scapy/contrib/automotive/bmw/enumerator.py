# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = BMW specific enumerators
# scapy.contrib.status = loads


from scapy.packet import Packet
from scapy.compat import Any, Iterable
from scapy.contrib.automotive.scanner.enumerator import _AutomotiveTestCaseScanResult  # noqa: E501
from scapy.contrib.automotive.uds import UDS
from scapy.contrib.automotive.bmw.definitions import DEV_JOB
from scapy.contrib.automotive.uds_scan import UDS_Enumerator


class BMW_DevJobEnumerator(UDS_Enumerator):
    _description = "Available DevelopmentJobs by Identifier " \
                   "and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (UDS() / DEV_JOB(identifier=x) for x in scan_range)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x: %s" % \
               (tup[1].identifier, tup[1].sprintf("%DEV_JOB.identifier%"))
