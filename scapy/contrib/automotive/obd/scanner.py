# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.korb@e-mundo.de>
# Copyright (C) Friedrich Feigel <friedrich.feigel@e-mundo.de>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = OnBoardDiagnosticScanner
# scapy.contrib.status = loads

import copy

from scapy.contrib.automotive.obd.obd import OBD, OBD_S03, OBD_S07, OBD_S0A, \
    OBD_S01, OBD_S06, OBD_S08, OBD_S09, OBD_NR, OBD_S02, OBD_S02_Record
from scapy.config import conf
from scapy.packet import Packet
from scapy.themes import BlackAndWhite

from scapy.contrib.automotive.scanner.enumerator import ServiceEnumerator, \
    _AutomotiveTestCaseScanResult, _AutomotiveTestCaseFilteredScanResult
from scapy.contrib.automotive.scanner.executor import \
    AutomotiveTestCaseExecutor
from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC, \
    _SocketUnion

# Typing imports
from typing import (
    List,
    Type,
    Any,
    Iterable,
)


class OBD_Enumerator(ServiceEnumerator):
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'full_scan': (bool, None),
    })

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param bool full_scan: Specifies if the entire scan range is tested, or
                               if the bitmask with supported identifiers is
                               queried and only supported identifiers
                               are scanned."""

    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        return resp.response_code

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        return OBD_NR(response_code=nrc).sprintf("%OBD_NR.response_code%")

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return response.sprintf("NR: %OBD_NR.response_code%")

    @property
    def filtered_results(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        return self.results_with_positive_response


class OBD_Service_Enumerator(OBD_Enumerator):
    """
    Base class for OBD_Service_Enumerators
    """

    def get_supported(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> List[int]
        super(OBD_Service_Enumerator, self).execute(
            socket, state, scan_range=range(0, 0xff, 0x20),
            exit_scan_on_first_negative_response=True, **kwargs)

        supported = list()
        for _, _, r, _, _ in self.results_with_positive_response:
            dr = r.data_records[0]
            key = next(iter((dr.lastlayer().fields.keys())))
            try:
                supported += [int(i[-2:], 16) for i in
                              getattr(dr, key, ["xxx00"])]
            except TypeError:
                pass
        return list(set([i for i in supported if i % 0x20]))

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        full_scan = kwargs.pop("full_scan", False)  # type: bool
        if full_scan:
            super(OBD_Service_Enumerator, self).execute(socket, state, **kwargs)
        else:
            supported_pids = self.get_supported(socket, state, **kwargs)
            del self._request_iterators[state]
            super(OBD_Service_Enumerator, self).execute(
                socket, state, scan_range=supported_pids, **kwargs)

    execute.__doc__ = OBD_Enumerator._supported_kwargs_doc

    @staticmethod
    def print_payload(resp):
        # type: (Packet) -> str
        backup_ct = conf.color_theme
        conf.color_theme = BlackAndWhite()
        load = repr(resp.data_records[0].lastlayer())
        conf.color_theme = backup_ct
        return load

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], self.print_payload)


class OBD_DTC_Enumerator(OBD_Enumerator):
    @staticmethod
    def print_payload(resp):
        # type: (Packet) -> str
        backup_ct = conf.color_theme
        conf.color_theme = BlackAndWhite()
        load = repr(resp.dtcs)
        conf.color_theme = backup_ct
        return load


class OBD_S03_Enumerator(OBD_DTC_Enumerator):
    _description = "Available DTCs in OBD service 03"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [OBD() / OBD_S03()]

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 03"

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is None:
            return "Timeout"
        else:
            return "NR" if resp.service == 0x7f else "%d DTCs" % resp.count


class OBD_S07_Enumerator(OBD_DTC_Enumerator):
    _description = "Available DTCs in OBD service 07"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [OBD() / OBD_S07()]

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 07"


class OBD_S0A_Enumerator(OBD_DTC_Enumerator):
    _description = "Available DTCs in OBD service 10"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [OBD() / OBD_S0A()]

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 0A"


class OBD_S01_Enumerator(OBD_Service_Enumerator):
    """OBD_S01_Enumerator"""

    _description = "Available data in OBD service 01"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))  # type: Iterable[int]  # noqa: E501
        return (OBD() / OBD_S01(pid=[x]) for x in scan_range)

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 01"

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is None:
            return "Timeout"
        else:
            return "NR" if resp.service == 0x7f else \
                "%s" % resp.data_records[0].lastlayer().name


class OBD_S02_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 02"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))  # type: Iterable[int]  # noqa: E501
        return (OBD() / OBD_S02(requests=[OBD_S02_Record(pid=[x])])
                for x in scan_range)

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 02"

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is None:
            return "Timeout"
        else:
            return "NR" if resp.service == 0x7f else \
                "%s" % resp.data_records[0].lastlayer().name


class OBD_S06_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 06"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))  # type: Iterable[int]  # noqa: E501
        return (OBD() / OBD_S06(mid=[x]) for x in scan_range)

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 06"

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        req = tup[1]
        resp = tup[2]
        if resp is None:
            return "Timeout"
        else:
            return "NR" if resp.service == 0x7f else \
                "0x%02x %s" % (
                    req.mid[0],
                    resp.data_records[0].sprintf("%OBD_S06_PR_Record.mid%"))


class OBD_S08_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 08"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))  # type: Iterable[int]  # noqa: E501
        return (OBD() / OBD_S08(tid=[x]) for x in scan_range)

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 08"

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is None:
            return "Timeout"
        else:
            return "NR" if resp.service == 0x7f else "0x%02x %s" % (
                tup[1].tid[0], resp.data_records[0].lastlayer().name)


class OBD_S09_Enumerator(OBD_Service_Enumerator):
    _description = "Available data in OBD service 09"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))  # type: Iterable[int]  # noqa: E501
        return (OBD() / OBD_S09(iid=[x]) for x in scan_range)

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Service 09"

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is None:
            return "Timeout"
        else:
            return "NR" if resp.service == 0x7f else \
                "0x%02x %s" % (tup[1].iid[0],
                               resp.data_records[0].lastlayer().name)


class OBD_Scanner(AutomotiveTestCaseExecutor):
    @property
    def enumerators(self):
        # type: () -> List[AutomotiveTestCaseABC]
        return self.configuration.test_cases

    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [OBD_S01_Enumerator, OBD_S02_Enumerator, OBD_S06_Enumerator,
                OBD_S08_Enumerator, OBD_S09_Enumerator, OBD_S03_Enumerator,
                OBD_S07_Enumerator, OBD_S0A_Enumerator]
