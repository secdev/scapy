# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = UDS AutomotiveTestCaseExecutor
# scapy.contrib.status = loads

import struct
import random
import time
import itertools
import copy
import inspect

from collections import defaultdict
from typing import Sequence

from scapy.compat import Dict, Optional, List, Type, Any, Iterable, \
    cast, Union, NamedTuple, orb, Set
from scapy.contrib.automotive import log_automotive
from scapy.packet import Raw, Packet
import scapy.libs.six as six
from scapy.error import Scapy_Exception
from scapy.contrib.automotive.uds import UDS, UDS_NR, UDS_DSC, UDS_TP, \
    UDS_RDBI, UDS_WDBI, UDS_SA, UDS_RC, UDS_IOCBI, UDS_RMBA, UDS_ER, \
    UDS_TesterPresentSender, UDS_CC, UDS_RDBPI, UDS_RD, UDS_TD

from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.scanner.enumerator import ServiceEnumerator, \
    _AutomotiveTestCaseScanResult, _AutomotiveTestCaseFilteredScanResult, \
    StateGeneratingServiceEnumerator
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC, \
    _SocketUnion, _TransitionTuple, StateGenerator
from scapy.contrib.automotive.scanner.configuration import \
    AutomotiveTestCaseExecutorConfiguration  # noqa: E501
from scapy.contrib.automotive.scanner.graph import _Edge
from scapy.contrib.automotive.scanner.staged_test_case import StagedAutomotiveTestCase  # noqa: E501
from scapy.contrib.automotive.scanner.executor import AutomotiveTestCaseExecutor  # noqa: E501

# TODO: Refactor this import
from scapy.contrib.automotive.uds_ecu_states import *  # noqa: F401, F403

if six.PY34:
    from abc import ABC
else:
    from abc import ABCMeta

    ABC = ABCMeta('ABC', (), {})  # type: ignore

# Definition outside the class UDS_RMBASequentialEnumerator
# to allow pickling
_PointOfInterest = NamedTuple("_PointOfInterest", [
    ("memory_address", int),
    ("direction", bool),
    # True = increasing / upward, False = decreasing / downward  # noqa: E501
    ("memorySizeLen", int),
    ("memoryAddressLen", int),
    ("memorySize", int)])


class UDS_Enumerator(ServiceEnumerator, ABC):
    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        return resp.negativeResponseCode

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        return UDS_NR(negativeResponseCode=nrc).sprintf(
            "%UDS_NR.negativeResponseCode%")

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], "PR: Supported")

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return response.sprintf("NR: %UDS_NR.negativeResponseCode%")


class UDS_DSCEnumerator(UDS_Enumerator, StateGeneratingServiceEnumerator):
    _description = "Available sessions"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'delay_state_change': (int, lambda x: x >= 0),
        'overwrite_timeout': (bool, None)
    })
    _supported_kwargs["scan_range"] = (
        (list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param int delay_state_change: Specifies an additional delay after
                                       after a session is modified from
                                       the transition function. In unit-test
                                       scenarios, this delay should be set to
                                       zero.
        :param bool overwrite_timeout: True by default. This enumerator
                                       overwrites the timeout argument, since
                                       most ECUs take some time until a session
                                       is changed. This ensures that more
                                       results are gathered by default. In
                                       unit-test scenarios, this value should
                                       be set to False, in order to use the
                                       timeout specified by the 'timeout'
                                       argument."""

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        session_range = kwargs.pop("scan_range", range(2, 0x100))
        return UDS() / UDS_DSC(diagnosticSessionType=session_range)

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None

        # fix configuration in kwargs to avoid overwrite from user
        kwargs["exit_if_service_not_supported"] = False
        kwargs["retry_if_busy_returncode"] = False

        # Apply a fixed timeout for this execute.
        # Unit-tests may want to overwrite the timeout to speed up testing
        if kwargs.pop("overwrite_timeout", True):
            kwargs["timeout"] = 3

        super(UDS_DSCEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (
            tup[1].diagnosticSessionType,
            tup[1].sprintf("%UDS_DSC.diagnosticSessionType%"))

    @staticmethod
    def enter_state(socket,  # type: _SocketUnion
                    configuration,  # type: AutomotiveTestCaseExecutorConfiguration  # noqa: E501
                    request  # type: Packet
                    ):  # type: (...) -> bool
        try:
            timeout = configuration[UDS_DSCEnumerator.__name__]["timeout"]
        except KeyError:
            timeout = 3
        ans = socket.sr1(request, timeout=timeout, verbose=False)
        if ans is not None:
            if configuration.verbose:
                log_automotive.debug(
                    "Try to enter session req: %s, resp: %s" %
                    (repr(request), repr(ans)))
            return cast(int, ans.service) != 0x7f
        else:
            return False

    def get_new_edge(self,
                     socket,  # type: _SocketUnion
                     config  # type: AutomotiveTestCaseExecutorConfiguration
                     ):  # type: (...) -> Optional[_Edge]
        edge = super(UDS_DSCEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            # Force TesterPresent if session is changed
            new_state.tp = 1  # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock,  # type: _SocketUnion
                            conf,  # type: AutomotiveTestCaseExecutorConfiguration  # noqa: E501
                            kwargs  # type: Dict[str, Any]
                            ):  # type: (...) -> bool
        UDS_TPEnumerator.enter(sock, conf, kwargs)
        # Wait 5 seconds, since some ECUs require time
        # to switch to the bootloader
        try:
            delay = conf[UDS_DSCEnumerator.__name__]["delay_state_change"]
        except KeyError:
            delay = 5
        time.sleep(delay)
        state_changed = UDS_DSCEnumerator.enter_state(
            sock, conf, kwargs["req"])
        if not state_changed:
            UDS_TPEnumerator.cleanup(sock, conf)
        return state_changed

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return UDS_DSCEnumerator.enter_state_with_tp, {
            "req": self._results[-1].req,
            "desc": "DSC=%d" % self._results[-1].req.diagnosticSessionType
        }, UDS_TPEnumerator.cleanup


class UDS_TPEnumerator(UDS_Enumerator, StateGeneratingServiceEnumerator):
    _description = "TesterPresent supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [UDS() / UDS_TP()]

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "TesterPresent:"

    @staticmethod
    def enter(socket,  # type: _SocketUnion
              configuration,  # type: AutomotiveTestCaseExecutorConfiguration
              _  # type: Dict[str, Any]
              ):  # type: (...) -> bool
        if configuration.unittest:
            configuration["tps"] = None
            socket.sr1(UDS() / UDS_TP(), timeout=0.1, verbose=False)
            return True

        UDS_TPEnumerator.cleanup(socket, configuration)
        configuration["tps"] = UDS_TesterPresentSender(socket)
        configuration["tps"].start()
        return True

    @staticmethod
    def cleanup(_, configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        try:
            configuration["tps"].stop()
            configuration["tps"] = None
        except (AttributeError, KeyError) as e:
            log_automotive.debug("Cleanup TP-Sender Error: %s", e)
        return True

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return self.enter, {"desc": "TP"}, self.cleanup


class UDS_EREnumerator(UDS_Enumerator):
    _description = "ECUReset supported"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        reset_type = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_ER(resetType=reset_type))

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (
            tup[1].resetType, tup[1].sprintf("%UDS_ER.resetType%"))


class UDS_CCEnumerator(UDS_Enumerator):
    _description = "CommunicationControl supported"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        control_type = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_CC(
            controlType=control_type, communicationType0=1,
            communicationType2=15))

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (
            tup[1].controlType, tup[1].sprintf("%UDS_CC.controlType%"))


class UDS_RDBPIEnumerator(UDS_Enumerator):
    _description = "ReadDataByPeriodicIdentifier supported"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = (
        (list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        pdid = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_RDBPI(
            transmissionMode=1, periodicDataIdentifier=pdid))

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is not None:
            return "0x%02x %s: %s" % (
                tup[1].periodicDataIdentifier,
                tup[1].sprintf("%UDS_RDBPI.periodicDataIdentifier%"),
                resp.dataRecord)
        else:
            return "0x%02x %s: No response" % (
                tup[1].periodicDataIdentifier,
                tup[1].sprintf("%UDS_RDBPI.periodicDataIdentifier%"))


class UDS_ServiceEnumerator(UDS_Enumerator):
    _description = "Available services and negative response per state"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        # Only generate services with unset positive response bit (0x40) as
        # default scan_range
        scan_range = kwargs.pop("scan_range",
                                (x for x in range(0x100) if not x & 0x40))
        return (UDS(service=x) for x in scan_range)

    def _evaluate_response(self,
                           state,  # type: EcuState
                           request,  # type: Packet
                           response,  # type: Optional[Packet]
                           **kwargs  # type: Optional[Dict[str, Any]]
                           ):  # type: (...) -> bool
        if response and response.service == 0x51:
            log_automotive.warning(
                "ECUResetPositiveResponse detected! This might have changed "
                "the state of the ECU under test.")

        # remove args from kwargs since they will be overwritten
        kwargs["exit_if_service_not_supported"] = False  # type: ignore

        return super(UDS_ServiceEnumerator, self)._evaluate_response(
            state, request, response, **kwargs)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (tup[1].service, tup[1].sprintf("%UDS.service%"))


class UDS_RDBIEnumerator(UDS_Enumerator):
    _description = "Readable data identifier per state"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x10000 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (UDS() / UDS_RDBI(identifiers=[x]) for x in scan_range)

    @staticmethod
    def print_information(resp):
        # type: (Packet) -> str
        load = bytes(resp)[3:] if len(resp) > 3 else "No data available"
        return "PR: %s" % load

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x: %s" % (tup[1].identifiers[0],
                               tup[1].sprintf("%UDS_RDBI.identifiers%")[1:-1])

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], self.print_information)


class UDS_RDBISelectiveEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rnd_to_seq(rdbi_random,  # type: AutomotiveTestCaseABC
                               _  # type: AutomotiveTestCaseABC
                               ):  # type: (...) -> Dict[str, Any]
        rdbi_random = cast(UDS_Enumerator, rdbi_random)
        identifiers_with_positive_response = \
            [p.resp.dataIdentifier
             for p in rdbi_random.results_with_positive_response]

        scan_range = UDS_RDBISelectiveEnumerator. \
            points_to_blocks(identifiers_with_positive_response)
        return {"scan_range": scan_range}

    @staticmethod
    def points_to_blocks(pois):
        # type: (Sequence[int]) -> Iterable[int]

        if len(pois) == 0:
            # quick path for better performance
            return []

        block_size = UDS_RDBIRandomEnumerator.block_size
        generators = []
        for start in range(0, 2 ** 16, block_size):
            end = start + block_size
            pr_in_block = any((start <= identifier < end
                               for identifier in pois))
            if pr_in_block:
                generators.append(range(start, end))
        scan_range = list(itertools.chain.from_iterable(generators))
        return scan_range

    def __init__(self):
        # type: () -> None
        super(UDS_RDBISelectiveEnumerator, self).__init__(
            [UDS_RDBIRandomEnumerator(), UDS_RDBIEnumerator()],
            [None, self.__connector_rnd_to_seq])


class UDS_RDBIRandomEnumerator(UDS_RDBIEnumerator):
    _supported_kwargs = copy.copy(UDS_RDBIEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'probe_start': (int, lambda x: 0 <= x <= 0xffff),
        'probe_end': (int, lambda x: 0 <= x <= 0xffff)
    })
    block_size = 2 ** 6

    _supported_kwargs_doc = UDS_RDBIEnumerator._supported_kwargs_doc + """
        :param int probe_start: Specifies the start identifier for probing.
        :param int probe_end: Specifies the end identifier for probing."""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(UDS_RDBIRandomEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]

        samples_per_block = {
            4: 29, 5: 22, 6: 19, 8: 11, 9: 11, 10: 13, 11: 14, 12: 31, 13: 4,
            14: 26, 16: 30, 17: 4, 18: 20, 19: 5, 20: 49, 21: 54, 22: 9, 23: 4,
            24: 10, 25: 8, 28: 6, 29: 3, 32: 11, 36: 4, 37: 3, 40: 9, 41: 9,
            42: 3, 44: 2, 47: 3, 48: 4, 49: 3, 52: 8, 64: 35, 66: 2, 68: 24,
            69: 19, 70: 30, 71: 28, 72: 16, 73: 4, 74: 6, 75: 27, 76: 41,
            77: 11, 78: 6, 81: 2, 88: 3, 90: 2, 92: 16, 97: 15, 98: 20, 100: 6,
            101: 5, 102: 5, 103: 10, 106: 10, 108: 4, 124: 3, 128: 7, 136: 15,
            137: 14, 138: 27, 139: 10, 148: 9, 150: 2, 152: 2, 168: 23,
            169: 15, 170: 16, 171: 16, 172: 2, 176: 3, 177: 4, 178: 2, 187: 2,
            232: 3, 235: 2, 240: 8, 252: 25, 256: 7, 257: 2, 287: 6, 290: 2,
            316: 2, 319: 3, 323: 3, 324: 19, 326: 2, 327: 2, 330: 4, 331: 10,
            332: 3, 334: 8, 338: 3, 832: 6, 833: 2, 900: 4, 956: 4, 958: 3,
            964: 12, 965: 13, 966: 34, 967: 3, 972: 10, 1000: 3, 1012: 23,
            1013: 14, 1014: 15
        }
        to_scan = []
        block_size = UDS_RDBIRandomEnumerator.block_size

        probe_start = kwargs.pop("probe_start", 0)
        probe_end = kwargs.pop("probe_end", 0x10000)
        probe_range = range(probe_start, probe_end, block_size)

        for block_index, start in enumerate(probe_range):
            end = start + block_size
            count_samples = samples_per_block.get(block_index, 1)
            to_scan += random.sample(range(start, end), count_samples)

        # Use locality effect
        # If an identifier brought a positive response in any state,
        # it is likely that in another state it is available as well
        positive_identifiers = [t.resp.dataIdentifier for t in
                                self.results_with_positive_response]
        to_scan += positive_identifiers

        # make all identifiers unique with set()
        # Sort for better logs
        to_scan = sorted(list(set(to_scan)))
        return (UDS() / UDS_RDBI(identifiers=[x]) for x in to_scan)


class UDS_WDBIEnumerator(UDS_Enumerator):
    _description = "Writeable data identifier per state"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'rdbi_enumerator': (UDS_RDBIEnumerator, None)
    })
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param rdbi_enumerator: Specifies an instance of an UDS_RDBIEnumerator
                                which is used to extract possible data
                                identifiers.
        :type rdbi_enumerator: UDS_RDBIEnumerator"""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(UDS_WDBIEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        rdbi_enumerator = kwargs.pop("rdbi_enumerator", None)

        if rdbi_enumerator is None:
            log_automotive.debug("Use entire scan range")
            return (UDS() / UDS_WDBI(dataIdentifier=x) for x in scan_range)
        elif isinstance(rdbi_enumerator, UDS_RDBIEnumerator):
            log_automotive.debug("Selective scan based on RDBI results")
            return (UDS() / UDS_WDBI(dataIdentifier=t.resp.dataIdentifier) /
                    Raw(load=bytes(t.resp)[3:])
                    for t in rdbi_enumerator.results_with_positive_response
                    if len(bytes(t.resp)) >= 3)
        else:
            raise Scapy_Exception("rdbi_enumerator has to be an instance "
                                  "of UDS_RDBIEnumerator")

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x: %s" % (tup[1].dataIdentifier,
                               tup[1].sprintf("%UDS_WDBI.dataIdentifier%"))

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], "PR: Writeable")


class UDS_WDBISelectiveEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rdbi_to_wdbi(rdbi,  # type: AutomotiveTestCaseABC
                                 _  # type: AutomotiveTestCaseABC
                                 ):  # type: (...) -> Dict[str, Any]
        return {"rdbi_enumerator": rdbi}

    def __init__(self):
        # type: () -> None
        super(UDS_WDBISelectiveEnumerator, self).__init__(
            [UDS_RDBIEnumerator(), UDS_WDBIEnumerator()],
            [None, self.__connector_rdbi_to_wdbi])


class UDS_SAEnumerator(UDS_Enumerator):
    _description = "Available security seeds with access type and state"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(1, 256, 2))
        return (UDS() / UDS_SA(securityAccessType=x) for x in scan_range)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return tup[1].securityAccessType

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], lambda r: "PR: %s" % r.securitySeed)

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        if cast(ServiceEnumerator, self)._retry_pkt[state]:
            # this is a retry execute. Wait much longer than usual because
            # a required time delay not expired could have been received
            # on the previous attempt
            if not global_configuration.unittest:
                time.sleep(11)

    def _evaluate_retry(self,
                        state,  # type: EcuState
                        request,  # type: Packet
                        response,  # type: Packet
                        **kwargs  # type: Optional[Dict[str, Any]]
                        ):  # type: (...) -> bool

        if super(UDS_SAEnumerator, self)._evaluate_retry(
                state, request, response, **kwargs):
            return True

        if response.service == 0x7f and \
                self._get_negative_response_code(response) in [0x24, 0x37]:
            log_automotive.debug(
                "Retry %s because requiredTimeDelayNotExpired or "
                "requestSequenceError received",
                repr(request))
            return super(UDS_SAEnumerator, self)._populate_retry(
                state, request)
        return False

    def _evaluate_response(self,
                           state,  # type: EcuState
                           request,  # type: Packet
                           response,  # type: Optional[Packet]
                           **kwargs  # type: Optional[Dict[str, Any]]
                           ):  # type: (...) -> bool
        if super(UDS_SAEnumerator, self)._evaluate_response(
                state, request, response, **kwargs):
            return True

        if response is not None and \
                response.service == 0x67 and \
                response.securityAccessType % 2 == 1:
            log_automotive.debug("Seed received. Leave scan to try a key")
            return True
        return False

    @staticmethod
    def get_seed_pkt(sock, level=1, record=b""):
        # type: (_SocketUnion, int, bytes) -> Optional[Packet]
        req = UDS() / UDS_SA(securityAccessType=level,
                             securityAccessDataRecord=record)
        for _ in range(10):
            seed = sock.sr1(req, timeout=5, verbose=False)
            if seed is None:
                return None
            elif seed.service == 0x7f and \
                    UDS_Enumerator._get_negative_response_code(seed) != 0x37:
                log_automotive.info(
                    "Security access no seed! NR: %s", repr(seed))
                return None

            elif seed.service == 0x7f and seed.negativeResponseCode == 0x37:
                log_automotive.info("Security access retry to get seed")
                time.sleep(10)
                continue
            else:
                return seed
        return None

    @staticmethod
    def evaluate_security_access_response(res, seed, key):
        # type: (Optional[Packet], Packet, Optional[Packet]) -> bool
        if res is None or res.service == 0x7f:
            log_automotive.info(repr(seed))
            log_automotive.info(repr(key))
            log_automotive.info(repr(res))
            log_automotive.info("Security access error!")
            return False
        else:
            log_automotive.info("Security access granted!")
            return True


class UDS_SA_XOR_Enumerator(UDS_SAEnumerator, StateGenerator):
    _description = "XOR SecurityAccess supported"
    _transition_function_args = dict()  # type: Dict[_Edge, Dict[str, Any]]

    @staticmethod
    def get_key_pkt(seed, level=1):
        # type: (Packet, int) -> Optional[Packet]

        def key_function_int(s):
            # type: (int) -> int
            return 0xffffffff & ~s

        def key_function_short(s):
            # type: (int) -> int
            return 0xffff & ~s

        try:
            s = seed.securitySeed
        except AttributeError:
            return None

        fmt = None
        key_function = None  # Optional[Callable[[int], int]]

        if len(s) == 2:
            fmt = "H"
            key_function = key_function_short

        if len(s) == 4:
            fmt = "I"
            key_function = key_function_int

        if key_function is not None and fmt is not None:
            key = struct.pack(fmt, key_function(struct.unpack(fmt, s)[0]))
            return cast(Packet, UDS() / UDS_SA(securityAccessType=level + 1,
                                               securityKey=key))
        else:
            return None

    def get_security_access(self, sock, level=1, seed_pkt=None):
        # type: (_SocketUnion, int, Optional[Packet]) -> bool
        log_automotive.info(
            "Try bootloader security access for level %d" % level)
        if seed_pkt is None:
            seed_pkt = self.get_seed_pkt(sock, level)
            if not seed_pkt:
                return False

        if not any(seed_pkt.securitySeed):
            log_automotive.info(
                "Security access for level %d already granted!" % level)
            return True

        key_pkt = self.get_key_pkt(seed_pkt, level)
        if key_pkt is None:
            return False

        try:
            res = sock.sr1(key_pkt, timeout=5, verbose=False)
            if sock.closed:
                log_automotive.critical("Socket closed during scan.")
                raise Scapy_Exception("Socket closed during scan")
        except (OSError, ValueError, Scapy_Exception) as e:
            try:
                last_seed_req = self._results[-1].req
                last_state = self._results[-1].state
                if not self._populate_retry(last_state, last_seed_req):
                    log_automotive.exception(
                        "Exception during retry. This is bad")
            except IndexError:
                log_automotive.warning("Couldn't populate retry.")
            raise e

        return self.evaluate_security_access_response(
            res, seed_pkt, key_pkt)

    def transition_function(self, sock, _, kwargs):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, Dict[str, Any]) -> bool  # noqa: E501
        if six.PY3:
            spec = inspect.getfullargspec(self.get_security_access)
        else:
            spec = inspect.getargspec(self.get_security_access)

        func_kwargs = {k: kwargs[k] for k in spec.args if k in kwargs.keys()}
        return self.get_security_access(sock, **func_kwargs)

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        last_resp = self._results[-1].resp
        last_state = self._results[-1].state

        if last_resp is None or last_resp.service == 0x7f:
            return None

        try:
            if last_resp.service != 0x67 or \
                    last_resp.securityAccessType % 2 != 1:
                return None

            seed = last_resp
            sec_lvl = seed.securityAccessType

            if self.get_security_access(socket, sec_lvl, seed):
                log_automotive.debug("Security Access found.")
                # create edge
                new_state = copy.copy(last_state)
                new_state.security_level = seed.securityAccessType + 1  # type: ignore  # noqa: E501
                if last_state == new_state:
                    return None
                edge = (last_state, new_state)
                self._transition_function_args[edge] = \
                    {"level": sec_lvl, "desc": "SA=%d" % sec_lvl}
                return edge
        except AttributeError:
            pass

        return None

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return self.transition_function, \
            self._transition_function_args[edge], None


class UDS_RCEnumerator(UDS_Enumerator):
    _description = "Available RoutineControls and negative response per state"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'type_list': (list, lambda x: max(x) < 0x100 and min(x) >= 0)
    })
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x10000 and min(x) >= 0)

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param list type_list: A list of RoutineControlTypes which should
                               be enumerated. Possible values = [1, 2, 3].
                               """

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        type_list = kwargs.pop("type_list", [1, 2, 3])
        scan_range = kwargs.pop("scan_range", range(0x10000))

        return (
            UDS() / UDS_RC(routineControlType=rc_type,
                           routineIdentifier=data_id)
            for rc_type, data_id in itertools.product(type_list, scan_range)
        )

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x-%d: %s" % (
            tup[1].routineIdentifier, tup[1].routineControlType,
            tup[1].sprintf("%UDS_RC.routineIdentifier%"))


class UDS_RCStartEnumerator(UDS_RCEnumerator):
    _description = "Available RoutineControls and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        if "type_list" in kwargs:
            raise KeyError("'type_list' already set in kwargs.")
        kwargs["type_list"] = [1]
        return super(UDS_RCStartEnumerator, self). \
            _get_initial_requests(**kwargs)


class UDS_RCSelectiveEnumerator(StagedAutomotiveTestCase):
    # Used to expand points to both sites
    # So, the total block size will be 253 * 2 = 506
    expansion_width = 253

    @staticmethod
    def points_to_ranges(pois):
        # type: (Iterable[int]) -> Iterable[int]
        expansion_width = UDS_RCSelectiveEnumerator.expansion_width
        generators = []
        for identifier in pois:
            start = max(identifier - expansion_width, 0)
            end = min(identifier + expansion_width + 1, 0x10000)
            generators.append(range(start, end))
        ranges_with_overlaps = itertools.chain.from_iterable(generators)
        return sorted(set(ranges_with_overlaps))

    @staticmethod
    def __connector_start_to_rest(rc_start, _rc_stop):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        rc_start = cast(UDS_Enumerator, rc_start)
        identifiers_with_pr = [resp.routineIdentifier for _, _, resp, _, _
                               in rc_start.results_with_positive_response]
        scan_range = UDS_RCSelectiveEnumerator.points_to_ranges(
            identifiers_with_pr)

        return {"type_list": [2, 3],
                "scan_range": scan_range}

    def __init__(self):
        # type: () -> None
        super(UDS_RCSelectiveEnumerator, self).__init__(
            [UDS_RCStartEnumerator(), UDS_RCEnumerator()],
            [None, self.__connector_start_to_rest])


class UDS_IOCBIEnumerator(UDS_Enumerator):
    _description = "Available Input Output Controls By Identifier " \
                   "and negative response per state"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x10000 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (UDS() / UDS_IOCBI(dataIdentifier=x) for x in scan_range)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        resp = tup[2]
        if resp is not None:
            return "0x%04x: %s" % \
                   (tup[1].dataIdentifier,
                    resp.controlStatusRecord)
        else:
            return "0x%04x: No response" % tup[1].dataIdentifier


class UDS_RMBAEnumeratorABC(UDS_Enumerator):
    _description = "Readable Memory Addresses " \
                   "and negative response per state"

    @staticmethod
    def get_addr(pkt):
        # type: (UDS_RMBA) -> int
        """
        Helper function to get the memoryAddress from a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        :return: memory address of the request
        """
        return getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)

    @staticmethod
    def set_addr(pkt, addr):
        # type: (UDS_RMBA, int) -> None
        """
        Helper function to set the memoryAddress of a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        :param addr: memory address to be set
        """
        setattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen, addr)

    @staticmethod
    def get_size(pkt):
        # type: (UDS_RMBA) -> int
        """
        Helper function to gets the memorySize of a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        """
        return getattr(pkt, "memorySize%d" % pkt.memorySizeLen)

    @staticmethod
    def set_size(pkt, size):
        # type: (UDS_RMBA, int) -> None
        """
        Helper function to set the memorySize of a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        :param size: memory size to be set
        """
        set_size = min(2 ** (pkt.memorySizeLen * 8) - 1, size)
        setattr(pkt, "memorySize%d" % pkt.memorySizeLen, set_size)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x" % self.get_addr(tup[1])

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], lambda r: "PR: %s" % r.dataRecord)


class UDS_RMBARandomEnumerator(UDS_RMBAEnumeratorABC):
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'unittest': (bool, None)
    })
    del _supported_kwargs["scan_range"]

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param bool unittest: Enables smaller search space for unit-test
                              scenarios. This saves execution time."""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(UDS_RMBARandomEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    @staticmethod
    def _random_memory_addr_pkt(addr_len=None, size_len=None, size=None):
        # type: (Optional[int], Optional[int], Optional[int]) -> Packet
        pkt = UDS() / UDS_RMBA()  # type: Packet
        pkt.memorySizeLen = size_len or random.randint(1, 4)
        pkt.memoryAddressLen = addr_len or random.randint(1, 4)
        UDS_RMBARandomEnumerator.set_size(pkt, size or 4)
        UDS_RMBARandomEnumerator.set_addr(
            pkt, random.randint(
                0, (2 ** (8 * pkt.memoryAddressLen) - 1)) & 0xfffffff0)
        return pkt

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        if kwargs.get("unittest", False):
            return itertools.chain(
                (self._random_memory_addr_pkt(addr_len=2, size_len=2) for _ in range(100)),  # noqa: E501
                (self._random_memory_addr_pkt(addr_len=3) for _ in range(2)),
                (self._random_memory_addr_pkt(addr_len=4) for _ in range(2)))

        return itertools.chain(
            (self._random_memory_addr_pkt(addr_len=1) for _ in range(100)),
            (self._random_memory_addr_pkt(addr_len=2) for _ in range(500)),
            (self._random_memory_addr_pkt(addr_len=3) for _ in range(1000)),
            (self._random_memory_addr_pkt(addr_len=4) for _ in range(5000)))


class UDS_RMBASequentialEnumerator(UDS_RMBAEnumeratorABC):
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'points_of_interest': (list, None)
    })

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param list points_of_interest: A list of _PointOfInterest objects as
                                        starting points for sequential search.
                                        """

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(UDS_RMBASequentialEnumerator, self).execute(
            socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def __init__(self):
        # type: () -> None
        super(UDS_RMBASequentialEnumerator, self).__init__()
        self.__points_of_interest = defaultdict(
            list)  # type: Dict[EcuState, List[_PointOfInterest]]  # noqa: E501
        self.__initial_points_of_interest = None  # type: Optional[List[_PointOfInterest]]  # noqa: E501

    def _get_memory_addresses_from_results(self, results):
        # type: (Union[List[_AutomotiveTestCaseScanResult], List[_AutomotiveTestCaseFilteredScanResult]]) -> Set[int]  # noqa: E501
        mem_areas = list()
        for tup in results:
            resp = tup.resp
            if resp is not None and resp.service == 0x23:
                mem_areas += [
                    range(self.get_addr(tup.req),
                          self.get_addr(tup.req) + len(resp.dataRecord))]
            else:
                mem_areas += [
                    range(self.get_addr(tup.req), self.get_addr(tup.req) + 16)]

        return set(list(itertools.chain.from_iterable(mem_areas)))

    def __pois_to_requests(self, pois):
        # type: (List[_PointOfInterest]) -> List[Packet]
        tested_addrs = self._get_memory_addresses_from_results(
            self.results_with_response)
        testing_addrs = set()
        new_requests = list()

        for addr, upward, mem_size_len, mem_addr_len, mem_size in pois:
            for i in range(0, mem_size * 50, mem_size):
                if upward:
                    addr = min(addr + i, 2 ** (8 * mem_addr_len) - 1)
                else:
                    addr = max(addr - i, 0)

                if addr not in tested_addrs and \
                        (addr, mem_size) not in testing_addrs:
                    pkt = UDS() / UDS_RMBA(memorySizeLen=mem_size_len,
                                           memoryAddressLen=mem_addr_len)
                    self.set_size(pkt, mem_size)
                    self.set_addr(pkt, addr)
                    new_requests.append(pkt)
                    testing_addrs.add((addr, mem_size))

        return new_requests

    def __request_to_pois(self, req, resp):
        # type: (Packet, Optional[Packet]) -> List[_PointOfInterest]

        addr = self.get_addr(req)
        size = self.get_size(req)
        msl = req.memorySizeLen
        mal = req.memoryAddressLen

        if (resp is None or resp.service == 0x7f) and size > 1:
            size = size // 2

            return [
                _PointOfInterest(addr, True, msl, mal, size),
                _PointOfInterest(addr, False, msl, mal, size)]

        if resp is not None and resp.service == 0x23:
            return [
                _PointOfInterest(addr + size, True, msl, mal, size),
                _PointOfInterest(addr - size, False, msl, mal, size)]

        return []

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501

        if self.__initial_points_of_interest is None:
            self.__initial_points_of_interest = \
                global_configuration[self.__class__.__name__].get(
                    "points_of_interest", list())

        if not self.__points_of_interest[state]:
            # Transfer initial pois to current state pois
            self.__points_of_interest[state] = \
                self.__initial_points_of_interest

        new_requests = self.__pois_to_requests(
            self.__points_of_interest[state])

        if len(new_requests):
            self._state_completed[state] = False
            self._request_iterators[state] = new_requests
            self.__points_of_interest[state] = list()
        else:
            self._request_iterators[state] = list()

    def _evaluate_response(self,
                           state,  # type: EcuState
                           request,  # type: Packet
                           response,  # type: Optional[Packet]
                           **kwargs  # type: Optional[Dict[str, Any]]
                           ):  # type: (...) -> bool  # noqa: E501
        self.__points_of_interest[state] += \
            self.__request_to_pois(request, response)
        return super(UDS_RMBASequentialEnumerator, self)._evaluate_response(
            state, request, response, **kwargs)

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        s = super(UDS_RMBASequentialEnumerator, self).show(
            dump, filtered, verbose) or ""

        try:
            from intelhex import IntelHex

            ih = IntelHex()
            for tup in self.results_with_positive_response:
                for i, b in enumerate(tup.resp.dataRecord):
                    addr = self.get_addr(tup.req)
                    ih[addr + i] = orb(b)

            ih.tofile("RMBA_dump.hex", format="hex")
        except ImportError:
            err_msg = "Install 'intelhex' to create a hex file of the memory"
            log_automotive.exception(err_msg)
            with open("RMBA_dump.hex", "w") as file:
                file.write(err_msg)

        if dump:
            return s + "\n"
        else:
            print(s)
            return None


class UDS_RMBAEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rand_to_seq(rand, _):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        points_of_interest = list()  # type: List[_PointOfInterest]
        rand = cast(UDS_RMBARandomEnumerator, rand)
        for tup in rand.results_with_positive_response:
            points_of_interest += \
                [_PointOfInterest(UDS_RMBAEnumeratorABC.get_addr(tup.req),
                                  True, tup.req.memorySizeLen,
                                  tup.req.memoryAddressLen, 0x80),
                 _PointOfInterest(UDS_RMBAEnumeratorABC.get_addr(tup.req),
                                  False, tup.req.memorySizeLen,
                                  tup.req.memoryAddressLen, 0x80)]

        return {"points_of_interest": points_of_interest}

    def __init__(self):
        # type: () -> None
        super(UDS_RMBAEnumerator, self).__init__(
            [UDS_RMBARandomEnumerator(), UDS_RMBASequentialEnumerator()],
            [None, self.__connector_rand_to_seq])


class UDS_RDEnumerator(UDS_Enumerator):
    _description = "RequestDownload supported"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'unittest': (bool, None)
    })

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param bool unittest: Enables smaller search space for unit-test
                              scenarios. This safes execution time."""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(UDS_RDEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    @staticmethod
    def _random_memory_addr_pkt(addr_len=None):  # noqa: E501
        # type: (Optional[int]) -> Packet
        pkt = UDS() / UDS_RD()  # type: Packet
        pkt.dataFormatIdentifiers = random.randint(0, 16)
        pkt.memorySizeLen = random.randint(1, 4)
        pkt.memoryAddressLen = addr_len or random.randint(1, 4)
        UDS_RMBARandomEnumerator.set_size(pkt, 0x10)
        addr = random.randint(0, 2 ** (8 * pkt.memoryAddressLen) - 1) & \
            (0xffffffff << (4 * pkt.memoryAddressLen))
        UDS_RMBARandomEnumerator.set_addr(pkt, addr)
        return pkt

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        if kwargs.get("unittest", False):
            return itertools.chain(
                (self._random_memory_addr_pkt(addr_len=1) for _ in range(100)),
                (self._random_memory_addr_pkt(addr_len=2) for _ in range(500)))

        return itertools.chain(
            (self._random_memory_addr_pkt(addr_len=1) for _ in range(100)),
            (self._random_memory_addr_pkt(addr_len=2) for _ in range(500)),
            (self._random_memory_addr_pkt(addr_len=3) for _ in range(1000)),
            (self._random_memory_addr_pkt(addr_len=4) for _ in range(5000)))

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x" % UDS_RMBAEnumeratorABC.get_addr(tup[1])


class UDS_TDEnumerator(UDS_Enumerator):
    _description = "TransferData supported"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs["scan_range"] = \
        ((list, tuple, range), lambda x: max(x) < 0x100 and min(x) >= 0)

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        cnt = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_TD(blockSequenceCounter=cnt))

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (
            tup[1].blockSequenceCounter,
            tup[1].sprintf("%UDS_TD.blockSequenceCounter%"))


class UDS_Scanner(AutomotiveTestCaseExecutor):
    """
    Example:
        >>> def reconnect():
        >>>     return UDS_DoIPSocket("169.254.186.237")
        >>>
        >>> es = [UDS_ServiceEnumerator, UDS_DSCEnumerator]
        >>>
        >>> def reset():
        >>>     reconnect().sr1(UDS()/UDS_ER(resetType="hardReset"),
        >>>                     verbose=False, timeout=1)
        >>>
        >>> s = UDS_Scanner(reconnect(), reconnect_handler=reconnect,
        >>>                 reset_handler=reset, test_cases=es,
        >>>                 UDS_DSCEnumerator_kwargs={
        >>>                     "timeout": 20,
        >>>                     "overwrite_timeout": False,
        >>>                     "scan_range": [1, 3]})
        >>>
        >>> try:
        >>>     s.scan()
        >>> except KeyboardInterrupt:
        >>>     pass
        >>>
        >>> s.show_testcases_status()
        >>> s.show_testcases()
    """

    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [UDS_ServiceEnumerator, UDS_DSCEnumerator, UDS_TPEnumerator,
                UDS_SAEnumerator, UDS_WDBISelectiveEnumerator,
                UDS_RMBAEnumerator, UDS_RCEnumerator, UDS_IOCBIEnumerator]
