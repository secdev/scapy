# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = GMLAN AutomotiveTestCaseExecutor Utilities
# scapy.contrib.status = loads

import abc
import random
import time
import copy

from collections import defaultdict

from scapy.compat import Optional, List, Type, Any, Tuple, Iterable, Dict, \
    cast, Callable, orb
from scapy.contrib.automotive import log_automotive
from scapy.packet import Packet
import scapy.libs.six as six
from scapy.config import conf
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception
from scapy.contrib.automotive.gm.gmlanutils import GMLAN_InitDiagnostics, \
    GMLAN_TesterPresentSender
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SA, GMLAN_RD, \
    GMLAN_TD, GMLAN_RMBA, GMLAN_RDBI, GMLAN_RDBPI, GMLAN_IDO, \
    GMLAN_NR, GMLAN_WDBI, GMLAN_DC, GMLAN_PM
from scapy.contrib.automotive.ecu import EcuState

from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC, \
    _SocketUnion, _TransitionTuple, StateGenerator
from scapy.contrib.automotive.scanner.enumerator import ServiceEnumerator, \
    _AutomotiveTestCaseScanResult, StateGeneratingServiceEnumerator
from scapy.contrib.automotive.scanner.configuration import \
    AutomotiveTestCaseExecutorConfiguration
from scapy.contrib.automotive.scanner.graph import _Edge
from scapy.contrib.automotive.scanner.staged_test_case import \
    StagedAutomotiveTestCase
from scapy.contrib.automotive.scanner.executor import \
    AutomotiveTestCaseExecutor

# TODO: Refactor this import
from scapy.contrib.automotive.gm.gmlan_ecu_states import *  # noqa: F401, F403


__all__ = ["GMLAN_Scanner", "GMLAN_ServiceEnumerator", "GMLAN_RDBIEnumerator",
           "GMLAN_RDBPIEnumerator", "GMLAN_RMBAEnumerator",
           "GMLAN_TPEnumerator", "GMLAN_IDOEnumerator", "GMLAN_PMEnumerator",
           "GMLAN_RDEnumerator", "GMLAN_TDEnumerator", "GMLAN_WDBIEnumerator",
           "GMLAN_SAEnumerator", "GMLAN_WDBISelectiveEnumerator",
           "GMLAN_DCEnumerator"]


@six.add_metaclass(abc.ABCMeta)
class GMLAN_Enumerator(ServiceEnumerator):
    """
    Abstract base class for GMLAN service enumerators. This class
    implements GMLAN specific functions.
    """
    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        return resp.returnCode

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        return GMLAN_NR(returnCode=nrc).sprintf("%GMLAN_NR.returnCode%")

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return response.sprintf("NR: %GMLAN_NR.returnCode%")

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2])

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError("Overwrite this method")


class GMLAN_ServiceEnumerator(GMLAN_Enumerator, StateGeneratingServiceEnumerator):  # noqa: E501
    """
    This enumerator scans for all services identifiers of GMLAN. During this
    scan, corrupted packets might be sent to an ECU and mainly negative
    responses will be received.
    """
    _description = "Available services and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        services = set(x & ~0x40 for x in range(0x100))
        services.remove(0x10)  # Remove InitiateDiagnosticOperation service
        services.remove(0x3E)  # Remove TesterPresent service
        services.remove(0xa5)  # Remove ProgrammingMode service
        services.remove(0x34)  # Remove RequestDownload
        return (GMLAN(service=x) for x in services)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (
            tup[1].service, tup[1].sprintf("%GMLAN.service%"))


class GMLAN_TPEnumerator(GMLAN_Enumerator, StateGeneratingServiceEnumerator):
    """
    Performs a check if TesterPresent is available. If a positive response is
    received, a new system state is generated and returned.
    """
    _description = "TesterPresent supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN(service=0x3E)]

    @staticmethod
    def enter(socket,  # type: _SocketUnion
              configuration,  # type: AutomotiveTestCaseExecutorConfiguration
              kwargs  # type: Dict[str, Any]
              ):
        # type: (...) -> bool
        if configuration.unittest:
            configuration["tps"] = None
            socket.sr1(GMLAN(service=0x3E), timeout=0.1, verbose=False)
            return True

        GMLAN_TPEnumerator.cleanup(socket, configuration)
        configuration["tps"] = GMLAN_TesterPresentSender(
            cast(SuperSocket, socket))
        configuration["tps"].start()
        return True

    @staticmethod
    def cleanup(_, configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        try:
            if configuration["tps"]:
                configuration["tps"].stop()
                configuration["tps"] = None
        except KeyError:
            pass
        return True

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return self.enter, {"desc": "TP"}, self.cleanup

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "TesterPresent:"


class GMLAN_IDOEnumerator(GMLAN_Enumerator, StateGeneratingServiceEnumerator):
    _description = "InitiateDiagnosticOperation supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN() / GMLAN_IDO(subfunction=2)]

    @staticmethod
    def enter_diagnostic_session(socket):
        # type: (_SocketUnion) -> bool
        ans = socket.sr1(
            GMLAN() / GMLAN_IDO(subfunction=2), timeout=5, verbose=False)
        if ans is not None and ans.service == 0x7f:
            log_automotive.debug(
                "InitiateDiagnosticOperation received negative response!\n"
                "%s", repr(ans))
        return ans is not None and ans.service != 0x7f

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        edge = super(GMLAN_IDOEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            new_state.tp = 1  # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf, kwargs):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, Dict[str, Any]) -> bool  # noqa: E501
        GMLAN_TPEnumerator.enter(sock, conf, kwargs)
        if GMLAN_IDOEnumerator.enter_diagnostic_session(sock):
            return True
        else:
            GMLAN_TPEnumerator.cleanup(sock, conf)
            return False

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return self.enter_state_with_tp, {"desc": "IDO_TP"}, GMLAN_TPEnumerator.cleanup  # noqa: E501

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "InitiateDiagnosticOperation:"


class GMLAN_RDBIEnumerator(GMLAN_Enumerator):
    _description = "Readable data identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))
        return (GMLAN() / GMLAN_RDBI(dataIdentifier=x) for x in scan_range)

    @staticmethod
    def print_information(resp):
        # type: (Packet) -> str
        load = bytes(resp)[2:] if len(resp) > 3 else b"No data available"
        return "PR: %r" % ((load[:17] + b"...") if len(load) > 20 else load)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x: %s" % (tup[1].dataIdentifier,
                               tup[1].sprintf("%GMLAN_RDBI.dataIdentifier%"))

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], self.print_information)


class GMLAN_WDBIEnumerator(GMLAN_Enumerator):
    _description = "Writeable data identifier per state"
    _supported_kwargs = copy.copy(GMLAN_Enumerator._supported_kwargs)
    _supported_kwargs.update({
        'rdbi_enumerator': (GMLAN_RDBIEnumerator, None)
    })

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param rdbi_enumerator: Specifies an instance of a GMLAN_RDBIEnumerator
                                which is used to extract possible data
                                identifiers.
        :type rdbi_enumerator: GMLAN_RDBIEnumerator"""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(GMLAN_WDBIEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))
        rdbi_enumerator = kwargs.pop("rdbi_enumerator", None)
        if rdbi_enumerator is None:
            return (GMLAN() / GMLAN_WDBI(dataIdentifier=x) for x in scan_range)
        elif isinstance(rdbi_enumerator, GMLAN_RDBIEnumerator):
            return (GMLAN() / GMLAN_WDBI(dataIdentifier=t.resp.dataIdentifier,
                                         dataRecord=bytes(t.resp)[2:])
                    for t in rdbi_enumerator.filtered_results
                    if t.resp.service != 0x7f and len(bytes(t.resp)) >= 2)
        else:
            raise Scapy_Exception("rdbi_enumerator has to be an instance "
                                  "of GMLAN_RDBIEnumerator")

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % (tup[1].dataIdentifier,
                               tup[1].sprintf("%GMLAN_WDBI.dataIdentifier%"))

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], "PR: Writeable")


class GMLAN_WDBISelectiveEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rdbi_to_wdbi(rdbi, _):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        return {"rdbi_enumerator": rdbi}

    def __init__(self):
        # type: () -> None
        super(GMLAN_WDBISelectiveEnumerator, self).__init__(
            [GMLAN_RDBIEnumerator(), GMLAN_WDBIEnumerator()],
            [None, self.__connector_rdbi_to_wdbi])


class GMLAN_SAEnumerator(GMLAN_Enumerator, StateGenerator):
    _description = "SecurityAccess supported"
    _transition_function_args = dict()  # type: Dict[_Edge, Tuple[int, Optional[Callable[[int], int]]]]  # noqa: E501
    _supported_kwargs = copy.copy(GMLAN_Enumerator._supported_kwargs)
    _supported_kwargs.update({
        'keyfunction': (None, None)
    })

    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param keyfunction: Specifies a function to generate the key from a
                            given seed.
        :type keyfunction: Callable[[int], int]"""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(GMLAN_SAEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(1, 10, 2))
        return (GMLAN() / GMLAN_SA(subfunction=x) for x in scan_range)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "Subfunction %02d" % tup[1].subfunction

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], lambda r: "PR: %s" % r.securitySeed)

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        if cast(ServiceEnumerator, self)._retry_pkt[state] and \
                not global_configuration.unittest:
            # this is a retry execute. Wait much longer than usual because
            # a required time delay not expired could have been received
            # on the previous attempt
            time.sleep(11)

    def _evaluate_retry(self,
                        state,  # type: EcuState
                        request,  # type: Packet
                        response,  # type: Packet
                        **kwargs  # type: Optional[Dict[str, Any]]
                        ):  # type: (...) -> bool

        if super(GMLAN_SAEnumerator, self)._evaluate_retry(
                state, request, response, **kwargs):
            return True

        if response.service == 0x7f and \
                self._get_negative_response_code(response) in [0x22, 0x37]:
            log_automotive.debug(
                "Retry %s because requiredTimeDelayNotExpired or "
                "requestSequenceError received",
                repr(request))
            return super(GMLAN_SAEnumerator, self)._populate_retry(
                state, request)
        return False

    def _evaluate_response(self,
                           state,  # type: EcuState
                           request,  # type: Packet
                           response,  # type: Optional[Packet]
                           **kwargs  # type: Optional[Dict[str, Any]]
                           ):  # type: (...) -> bool
        if super(GMLAN_SAEnumerator, self)._evaluate_response(
                state, request, response, **kwargs):
            return True

        if response is not None and \
                response.service == 0x67 and response.subfunction % 2 == 1:
            log_automotive.debug("Seed received. Leave scan to try a key")
            return True
        return False

    @staticmethod
    def get_seed_pkt(sock, level=1):
        # type: (_SocketUnion, int) -> Optional[Packet]
        req = GMLAN() / GMLAN_SA(subfunction=level)
        for _ in range(10):
            seed = sock.sr1(req, timeout=5, verbose=False)
            if seed is None:
                return None
            elif seed.service == 0x7f and \
                    GMLAN_Enumerator._get_negative_response_code(seed) != 0x37:
                log_automotive.info(
                    "Security access no seed! NR: %s", repr(seed))
                return None

            elif seed.service == 0x7f and \
                    GMLAN_Enumerator._get_negative_response_code(seed) == 0x37:
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
            log_automotive.debug(repr(seed))
            log_automotive.debug(repr(key))
            log_automotive.debug(repr(res))
            log_automotive.info("Security access error!")
            return False
        else:
            log_automotive.info("Security access granted!")
            return True

    @staticmethod
    def get_key_pkt(seed, keyfunction, level=1):
        # type: (Packet, Callable[[int], int], int) -> Optional[Packet]
        try:
            s = seed.securitySeed
        except AttributeError:
            return None

        return cast(Packet, GMLAN() / GMLAN_SA(subfunction=level + 1,
                                               securityKey=keyfunction(s)))

    @staticmethod
    def get_security_access(sock, level=1, seed_pkt=None, keyfunction=None):
        # type: (_SocketUnion, int, Optional[Packet], Optional[Callable[[int], int]]) -> bool  # noqa: E501
        log_automotive.info(
            "Try bootloader security access for level %d" % level)
        if seed_pkt is None:
            seed_pkt = GMLAN_SAEnumerator.get_seed_pkt(sock, level)
            if not seed_pkt:
                return False

        if keyfunction is None:
            return False

        key_pkt = GMLAN_SAEnumerator.get_key_pkt(seed_pkt, keyfunction, level)
        if key_pkt is None:
            return False

        res = sock.sr1(key_pkt, timeout=5, verbose=False)
        return GMLAN_SAEnumerator.evaluate_security_access_response(
            res, seed_pkt, key_pkt)

    @staticmethod
    def transition_function(sock, _, kwargs):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, Dict[str, Any]) -> bool  # noqa: E501
        return GMLAN_SAEnumerator.get_security_access(
            sock, level=kwargs["sec_level"], keyfunction=kwargs["keyfunction"])

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        last_resp = self._results[-1].resp
        last_state = self._results[-1].state

        if last_resp is None or last_resp.service == 0x7f:
            return None

        try:
            if last_resp.service != 0x67 or \
                    last_resp.subfunction % 2 != 1:
                return None

            seed = last_resp
            sec_lvl = seed.subfunction
            kf = config[self.__class__.__name__].get("keyfunction", None)

            if self.get_security_access(socket, level=sec_lvl,
                                        seed_pkt=seed, keyfunction=kf):
                log_automotive.debug("Security Access found.")
                # create edge
                new_state = copy.copy(last_state)
                new_state.security_level = seed.subfunction + 1  # type: ignore  # noqa: E501
                if last_state == new_state:
                    return None
                edge = (last_state, new_state)
                self._transition_function_args[edge] = (sec_lvl, kf)
                return edge
        except AttributeError:
            pass

        return None

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return self.transition_function, {
            "sec_level": self._transition_function_args[edge][0],
            "keyfunction": self._transition_function_args[edge][1],
            "desc": "SA=%d" % self._transition_function_args[edge][0]}, None


class GMLAN_RDEnumerator(GMLAN_Enumerator, StateGeneratingServiceEnumerator):
    _description = "RequestDownload supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN() / GMLAN_RD(memorySize=0x10)]

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "RequestDownload:"


class GMLAN_PMEnumerator(GMLAN_Enumerator, StateGeneratingServiceEnumerator):
    _description = "ProgrammingMode supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError()

    def execute(self, socket, state, timeout=1, execution_time=1200, **kwargs):
        # type: (_SocketUnion, EcuState, int, int, Any) -> None
        supported = GMLAN_InitDiagnostics(
            cast(SuperSocket, socket), timeout=20,
            unittest=kwargs.get("unittest", False))
        # TODO: Refactor result storage
        if supported:
            self._store_result(
                state, GMLAN() / GMLAN_PM(), GMLAN(service=0xE5))
        else:
            self._store_result(
                state, GMLAN() / GMLAN_PM(),
                GMLAN() / GMLAN_NR(returnCode=0x11, requestServiceId=0xA5))

        self._state_completed[state] = True

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        edge = super(GMLAN_PMEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            new_state.tp = 1  # type: ignore
            new_state.communication_control = 1  # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf, kwargs):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, Dict[str, Any]) -> bool  # noqa: E501
        GMLAN_TPEnumerator.enter(sock, conf, kwargs)
        res = GMLAN_InitDiagnostics(cast(SuperSocket, sock), timeout=20,
                                    unittest=conf.unittest)
        if not res:
            GMLAN_TPEnumerator.cleanup(sock, conf)
            return False
        else:
            return True

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        return self.enter_state_with_tp, {"desc": "PM_TP"}, \
            GMLAN_TPEnumerator.cleanup

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "ProgrammingMode:"


class GMLAN_RDBPIEnumerator(GMLAN_Enumerator):
    _description = "Readable parameter identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (GMLAN() / GMLAN_RDBPI(identifiers=[x]) for x in scan_range)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x: %s" % (
            tup[1].identifiers[0],
            tup[1].sprintf("%GMLAN_RDBPI.identifiers%")[1:-1])

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], GMLAN_RDBIEnumerator.print_information)


class GMLAN_RMBAEnumerator(GMLAN_Enumerator):
    _description = "Readable Memory Addresses and negative response per state"

    _supported_kwargs = copy.copy(GMLAN_Enumerator._supported_kwargs)
    _supported_kwargs.update({
        'probe_width': (int, lambda x: x >= 0),
        'random_probes_len': (int, lambda x: x >= 0),
        'sequential_probes_len': (int, lambda x: x >= 0)
    })

    _supported_kwargs_doc = GMLAN_Enumerator._supported_kwargs_doc + """
        :param int probe_width: Memory size of a probe.
        :param int random_probes_len: Number of probes.
        :param int sequential_probes_len: Size of a memory block during
                                          sequential probing."""

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        super(GMLAN_RMBAEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def __init__(self):
        # type: () -> None
        super(GMLAN_RMBAEnumerator, self).__init__()
        self.random_probe_finished = defaultdict(bool)  # type: Dict[EcuState, bool]  # noqa: E501
        self.points_of_interest = defaultdict(list)  # type: Dict[EcuState, List[Tuple[int, bool]]]  # noqa: E501
        self.probe_width = 0x10  # defines the memorySize of a request
        self.highest_possible_addr = \
            2 ** (8 * conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']) - 1
        self.random_probes_len = \
            min(10 ** conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme'],
                0x5000)
        self.sequential_probes_len = \
            10 ** (conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme'])

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        self.probe_width = kwargs.pop("probe_width", self.probe_width)
        self.random_probes_len = \
            kwargs.pop("random_probes_len", self.random_probes_len)
        self.sequential_probes_len = \
            kwargs.pop("sequential_probes_len", self.sequential_probes_len)
        addresses = random.sample(
            range(0, self.highest_possible_addr, self.probe_width),
            self.random_probes_len)
        scan_range = kwargs.pop("scan_range", addresses)
        return (GMLAN() / GMLAN_RMBA(memoryAddress=x,
                                     memorySize=self.probe_width)
                for x in scan_range)

    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        if not self._state_completed[state]:
            return

        if not self.random_probe_finished[state]:
            log_automotive.info("Random memory probing finished")
            self.random_probe_finished[state] = True
            for tup in [t for t in self.results_with_positive_response
                        if t.state == state]:
                self.points_of_interest[state].append(
                    (tup.req.memoryAddress, True))
                self.points_of_interest[state].append(
                    (tup.req.memoryAddress, False))

        if not len(self.points_of_interest[state]):
            return

        log_automotive.info(
            "Create %d memory points for sequential probing" %
            len(self.points_of_interest[state]))

        tested_addrs = [tup.req.memoryAddress for tup in self.results]
        pos_addrs = [tup.req.memoryAddress for tup in
                     self.results_with_positive_response if tup.state == state]

        new_requests = list()
        new_points_of_interest = list()

        for poi, upward in self.points_of_interest[state]:
            if poi not in pos_addrs:
                continue
            temp_new_requests = list()
            for i in range(
                    self.probe_width,
                    self.sequential_probes_len + self.probe_width,
                    self.probe_width):
                if upward:
                    new_addr = min(poi + i, self.highest_possible_addr)
                else:
                    new_addr = max(poi - i, 0)

                if new_addr not in tested_addrs:
                    pkt = GMLAN() / GMLAN_RMBA(memoryAddress=new_addr,
                                               memorySize=self.probe_width)
                    temp_new_requests.append(pkt)

            if len(temp_new_requests):
                new_points_of_interest.append(
                    (temp_new_requests[-1].memoryAddress, upward))
                new_requests += temp_new_requests

        self.points_of_interest[state] = list()

        if len(new_requests):
            self._state_completed[state] = False
            self._request_iterators[state] = new_requests
            self.points_of_interest[state] = new_points_of_interest
            log_automotive.info(
                "Created %d pkts for sequential probing" %
                len(new_requests))

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        s = super(GMLAN_RMBAEnumerator, self).show(dump, filtered, verbose)
        try:
            from intelhex import IntelHex

            ih = IntelHex()
            for tup in self.results_with_positive_response:
                for i, b in enumerate(tup.resp.dataRecord):
                    ih[tup.req.memoryAddress + i] = orb(b)

            ih.tofile("RMBA_dump.hex", format="hex")
        except ImportError:
            log_automotive.warning(
                "Install 'intelhex' to create a hex file of the memory")

        if dump and s is not None:
            return s + "\n"
        else:
            print(s)
            return None

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x" % tup[1].memoryAddress

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return self._get_label(tup[2], lambda r: "PR: %s" % r.dataRecord)


class GMLAN_TDEnumerator(GMLAN_Enumerator):
    _description = "Transfer Data support and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x1ff))
        temp = conf.contribs["GMLAN"]['GMLAN_ECU_AddressingScheme']
        # Shift operations to eliminate addresses not aligned to 4
        max_addr = (2 ** (temp * 8) - 1) >> 2
        addresses = (random.randint(0, max_addr) << 2 for _ in scan_range)
        return (GMLAN() / GMLAN_TD(subfunction=0, startingAddress=x)
                for x in addresses)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%04x" % tup[1].startingAddress


class GMLAN_DCEnumerator(GMLAN_Enumerator):
    _description = "DeviceControl supported per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))
        return (GMLAN() / GMLAN_DC(CPIDNumber=x) for x in scan_range)

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        return "0x%02x: %s" % \
               (tup[1].CPIDNumber, tup[1].sprintf("%GMLAN_DC.CPIDNumber%"))


# ########################## GMLAN SCANNER ###################################

class GMLAN_Scanner(AutomotiveTestCaseExecutor):
    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [GMLAN_ServiceEnumerator, GMLAN_TPEnumerator,
                GMLAN_IDOEnumerator, GMLAN_PMEnumerator,
                GMLAN_RDEnumerator, GMLAN_SAEnumerator, GMLAN_TDEnumerator,
                GMLAN_RMBAEnumerator,
                GMLAN_WDBISelectiveEnumerator, GMLAN_DCEnumerator]
