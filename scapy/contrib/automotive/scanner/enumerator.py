# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = ServiceEnumerator definitions
# scapy.contrib.status = library


import abc
import threading
import time
import copy
from collections import defaultdict, OrderedDict
from itertools import chain

from scapy.compat import Any, Union, List, Optional, Iterable, \
    Dict, Tuple, Set, Callable, cast, NamedTuple, orb
from scapy.contrib.automotive import log_automotive
from scapy.error import Scapy_Exception
from scapy.utils import make_lined_table, EDecimal
import scapy.libs.six as six
from scapy.packet import Packet
from scapy.contrib.automotive.ecu import EcuState, EcuResponse
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCase, \
    StateGenerator, _SocketUnion, _TransitionTuple
from scapy.contrib.automotive.scanner.configuration import \
    AutomotiveTestCaseExecutorConfiguration
from scapy.contrib.automotive.scanner.graph import _Edge

# Definition outside the class ServiceEnumerator to allow pickling
_AutomotiveTestCaseScanResult = NamedTuple(
    "_AutomotiveTestCaseScanResult",
    [("state", EcuState),
     ("req", Packet),
     ("resp", Optional[Packet]),
     ("req_ts", Union[EDecimal, float]),
     ("resp_ts", Optional[Union[EDecimal, float]])])

_AutomotiveTestCaseFilteredScanResult = NamedTuple(
    "_AutomotiveTestCaseFilteredScanResult",
    [("state", EcuState),
     ("req", Packet),
     ("resp", Packet),
     ("req_ts", Union[EDecimal, float]),
     ("resp_ts", Union[EDecimal, float])])


@six.add_metaclass(abc.ABCMeta)
class ServiceEnumerator(AutomotiveTestCase):
    """
    Base class for ServiceEnumerators of automotive diagnostic protocols
    """

    _supported_kwargs = copy.copy(AutomotiveTestCase._supported_kwargs)
    _supported_kwargs.update({
        'timeout': ((int, float), lambda x: x > 0),
        'count': (int, lambda x: x >= 0),
        'execution_time': (int, None),
        'state_allow_list': ((list, EcuState), None),
        'state_block_list': ((list, EcuState), None),
        'retry_if_none_received': (bool, None),
        'exit_if_no_answer_received': (bool, None),
        'exit_if_service_not_supported': (bool, None),
        'exit_scan_on_first_negative_response': (bool, None),
        'retry_if_busy_returncode': (bool, None),
        'stop_event': (threading._Event if six.PY2 else threading.Event, None),  # type: ignore  # noqa: E501
        'debug': (bool, None),
        'scan_range': ((list, tuple, range), None),
        'unittest': (bool, None)
    })

    _supported_kwargs_doc = AutomotiveTestCase._supported_kwargs_doc + """
        :param timeout: Timeout until a response will arrive after a request
        :type timeout: integer or float
        :param integer count: Number of request to be sent in one execution
        :param int execution_time: Time in seconds until the execution of
                                   this enumerator is stopped.
        :param state_allow_list: List of EcuState objects or EcuState object
                                 in which the the execution of this enumerator
                                 is allowed. If provided, other states will not
                                 be executed.
        :type state_allow_list: EcuState or list
        :param state_block_list: List of EcuState objects or EcuState object
                                 in which the the execution of this enumerator
                                 is blocked.
        :type state_block_list: EcuState or list
        :param bool retry_if_none_received: Specifies if a request will be send
                                            again, if None was received
                                            (usually because of a timeout).
        :param bool exit_if_no_answer_received: Specifies to finish the
                                                execution of this enumerator
                                                once None is  received.
        :param bool exit_if_service_not_supported: Specifies to finish the
                                                   execution of this
                                                   enumerator, once the
                                                   negative return code
                                                   'serviceNotSupported' is
                                                   received.
        :param bool exit_scan_on_first_negative_response: Specifies to finish
                                                          the execution once a
                                                          negative response is
                                                          received.
        :param bool retry_if_busy_returncode: Specifies to retry a request, if
                                              the 'busyRepeatRequest' negative
                                              response code is received.
        :param bool debug: Enables debug functions during execute.
        :param Event stop_event: Signals immediate stop of the execution.
        :param scan_range: Specifies the identifiers to be scanned.
        :type scan_range: list or tuple or range or iterable"""

    def __init__(self):
        # type: () -> None
        super(ServiceEnumerator, self).__init__()
        self._result_packets = OrderedDict()  # type: Dict[bytes, Packet]
        self._results = list()  # type: List[_AutomotiveTestCaseScanResult]
        self._request_iterators = dict()  # type: Dict[EcuState, Iterable[Packet]]  # noqa: E501
        self._retry_pkt = defaultdict(list)  # type: Dict[EcuState, Union[Packet, Iterable[Packet]]]  # noqa: E501
        self._negative_response_blacklist = [0x10, 0x11]  # type: List[int]
        self._requests_per_state_estimated = None  # type: Optional[int]

    @staticmethod
    @abc.abstractmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        raise NotImplementedError()

    @staticmethod
    @abc.abstractmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        raise NotImplementedError()

    def _get_table_entry_x(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        """
        Provides a table entry for the column which gets print during `show()`.
        :param tup: A results tuple
        :return: A string which describes the state
        """
        return str(tup[0])

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        """
        Provides a table entry for the line which gets print during `show()`.
        :param tup: A results tuple
        :return: A string which describes the request
        """
        return repr(tup[1])

    def _get_table_entry_z(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        """
        Provides a table entry for the field which gets print during `show()`.
        :param tup: A results tuple
        :return: A string which describes the response
        """
        return repr(tup[2])

    @staticmethod
    @abc.abstractmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        raise NotImplementedError()

    @abc.abstractmethod
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError("Overwrite this method")

    def __reduce__(self):  # type: ignore
        f, t, d = super(ServiceEnumerator, self).__reduce__()  # type: ignore
        try:
            for k, v in six.iteritems(d["_request_iterators"]):
                d["_request_iterators"][k] = list(v)
        except KeyError:
            pass

        try:
            for k in d["_retry_pkt"]:
                d["_retry_pkt"][k] = list(self._get_retry_iterator(k))
        except KeyError:
            pass
        return f, t, d

    @property
    def negative_response_blacklist(self):
        # type: () -> List[int]
        return self._negative_response_blacklist

    @property
    def completed(self):
        # type: () -> bool
        if len(self._results):
            return all([self.has_completed(s) for s in self.scanned_states])
        else:
            return super(ServiceEnumerator, self).completed

    def _store_result(self, state, req, res):
        # type: (EcuState, Packet, Optional[Packet]) -> None
        if bytes(req) not in self._result_packets:
            self._result_packets[bytes(req)] = req

        if res and bytes(res) not in self._result_packets:
            self._result_packets[bytes(res)] = res

        self._results.append(_AutomotiveTestCaseScanResult(
            state,
            self._result_packets[bytes(req)],
            self._result_packets[bytes(res)] if res is not None else None,
            req.sent_time or 0.0,
            res.time if res is not None else None))

    def _get_retry_iterator(self, state):
        # type: (EcuState) -> Iterable[Packet]
        retry_entry = self._retry_pkt[state]
        if isinstance(retry_entry, Packet):
            log_automotive.debug("Provide retry packet")
            return [retry_entry]
        else:
            log_automotive.debug("Provide retry iterator")
            # assume self.retry_pkt is a generator or list
            return retry_entry

    def _get_initial_request_iterator(self, state, **kwargs):
        # type: (EcuState, Any) -> Iterable[Packet]
        if state not in self._request_iterators:
            self._request_iterators[state] = iter(
                self._get_initial_requests(**kwargs))

        return self._request_iterators[state]

    def _get_request_iterator(self, state, **kwargs):
        # type: (EcuState, Optional[Dict[str, Any]]) -> Iterable[Packet]
        return chain(self._get_retry_iterator(state),
                     self._get_initial_request_iterator(state, **kwargs))

    def _prepare_runtime_estimation(self, **kwargs):
        # type: (Optional[Dict[str, Any]]) -> None
        if self._requests_per_state_estimated is None:
            try:
                initial_requests = self._get_initial_requests(**kwargs)
                self._requests_per_state_estimated = len(list(initial_requests))
            except NotImplementedError:
                pass

    def runtime_estimation(self):
        # type: () -> Optional[Tuple[int, int, float]]
        if self._requests_per_state_estimated is None:
            return None

        pkts_tbs = max(
            len(self.scanned_states) * self._requests_per_state_estimated, 1)
        pkts_snt = len(self.results)

        return pkts_tbs, pkts_snt, float(pkts_snt) / pkts_tbs

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        self.check_kwargs(kwargs)
        timeout = kwargs.pop('timeout', 1)
        count = kwargs.pop('count', None)
        execution_time = kwargs.pop("execution_time", 1200)
        stop_event = kwargs.pop("stop_event", None)  # type: Optional[threading.Event]  # noqa: E501

        self._prepare_runtime_estimation(**kwargs)

        state_block_list = kwargs.get('state_block_list', list())

        if state_block_list and state in state_block_list:
            self._state_completed[state] = True
            log_automotive.debug("State %s in block list!", repr(state))
            return

        state_allow_list = kwargs.get('state_allow_list', list())

        if state_allow_list and state not in state_allow_list:
            self._state_completed[state] = True
            log_automotive.debug("State %s not in allow list!",
                                 repr(state))
            return

        it = self._get_request_iterator(state, **kwargs)

        # log_automotive.debug("[i] Using iterator %s in state %s", it, state)

        start_time = time.time()
        log_automotive.debug(
            "Start execution of enumerator: %s", time.ctime(start_time))

        for req in it:
            res = self.sr1_with_retry_on_error(req, socket, state, timeout)

            self._store_result(state, req, res)

            if self._evaluate_response(state, req, res, **kwargs):
                log_automotive.debug(
                    "Stop test_case execution because of response evaluation")
                return

            if count is not None:
                count -= 1
                if count <= 0:
                    log_automotive.debug(
                        "Finished execution count of enumerator")
                    return

            if (start_time + execution_time) < time.time():
                log_automotive.debug(
                    "[i] Finished execution time of enumerator: %s",
                    time.ctime())
                return

            if stop_event is not None and stop_event.is_set():
                log_automotive.info(
                    "Stop test_case execution because of stop event")
                return

        log_automotive.info("Finished iterator execution")
        self._state_completed[state] = True
        log_automotive.debug("States completed %s",
                             repr(self._state_completed))

    execute.__doc__ = _supported_kwargs_doc

    def sr1_with_retry_on_error(self, req, socket, state, timeout):
        # type: (Packet, _SocketUnion, EcuState, int) -> Optional[Packet]
        try:
            res = socket.sr1(req, timeout=timeout, verbose=False,
                             chainEX=True, chainCC=True)
        except (OSError, ValueError, Scapy_Exception) as e:
            if not self._populate_retry(state, req):
                log_automotive.exception(
                    "Exception during retry. This is bad")
            raise e
        return res

    def _evaluate_response(self,
                           state,  # type: EcuState
                           request,  # type: Packet
                           response,  # type: Optional[Packet]
                           **kwargs  # type: Optional[Dict[str, Any]]
                           ):  # type: (...) -> bool
        """
        Evaluates the response and determines if the current scan execution
        should be stopped.
        :param state: Current state of the ECU under test
        :param request: Sent request
        :param response: Received response
        :param kwargs: Arguments to modify the behavior of this function.
                       Supported arguments:
                         - retry_if_none_received: True/False
                         - exit_if_no_answer_received: True/False
                         - exit_if_service_not_supported: True/False
                         - exit_scan_on_first_negative_response: True/False
                         - retry_if_busy_returncode: True/False
        :return: True, if current execution needs to be interrupted.
                 False, if enumerator should proceed with the execution.
        """
        if response is None:
            if cast(bool, kwargs.pop("retry_if_none_received", False)):
                log_automotive.debug(
                    "Retry %s because None received", repr(request))
                return self._populate_retry(state, request)
            return cast(bool, kwargs.pop("exit_if_no_answer_received", False))

        if self._evaluate_negative_response_code(
                state, response, **kwargs):
            # leave current execution, because of a negative response code
            return True

        if self._evaluate_retry(state, request, response, **kwargs):
            # leave current execution, because a retry was set
            return True

        # cleanup retry packet
        self._retry_pkt[state] = []

        return self._evaluate_ecu_state_modifications(state, request, response)

    def _evaluate_ecu_state_modifications(self,
                                          state,  # type: EcuState
                                          request,  # type: Packet
                                          response,  # type: Packet
                                          ):  # type: (...) -> bool
        if EcuState.is_modifier_pkt(response):
            if state != EcuState.get_modified_ecu_state(
                    response, request, state):
                log_automotive.debug(
                    "Exit execute. Ecu state was modified!")
                return True
        return False

    def _evaluate_negative_response_code(self,
                                         state,  # type: EcuState
                                         response,  # type: Packet
                                         **kwargs  # type: Optional[Dict[str, Any]]  # noqa: E501
                                         ):  # type: (...) -> bool
        exit_if_service_not_supported = \
            kwargs.pop("exit_if_service_not_supported", False)
        exit_scan_on_first_negative_response = \
            kwargs.pop("exit_scan_on_first_negative_response", False)

        if exit_scan_on_first_negative_response and response.service == 0x7f:
            return True

        if exit_if_service_not_supported and response.service == 0x7f:
            response_code = self._get_negative_response_code(response)
            if response_code in [0x11, 0x7f]:
                names = {0x11: "serviceNotSupported",
                         0x7f: "serviceNotSupportedInActiveSession"}
                log_automotive.debug(
                    "Exit execute because negative response %s received!",
                    names[response_code])
                # execute of current state is completed,
                # since a serviceNotSupported negative response was received
                self._state_completed[state] = True
                # stop current execute and exit
                return True
        return False

    def _populate_retry(self,
                        state,  # type: EcuState
                        request,  # type: Packet
                        ):  # type: (...) -> bool
        """
        Populates internal storage with request for a retry.

        :param state: Current state
        :param request: Request which needs a retry
        :return: True, if storage was populated. If False is returned, the
                 retry storage is still populated. This indicates that the
                 current execution was already a retry execution.
        """

        if not self._get_retry_iterator(state):
            # This was no retry since the retry_pkt is None
            self._retry_pkt[state] = request
            log_automotive.debug(
                "Exit execute. Retry packet next time!")
            return True
        else:
            # This was a unsuccessful retry, continue execute
            log_automotive.debug("Unsuccessful retry!")
            return False

    def _evaluate_retry(self,
                        state,  # type: EcuState
                        request,  # type: Packet
                        response,  # type: Packet
                        **kwargs  # type: Optional[Dict[str, Any]]
                        ):  # type: (...) -> bool
        retry_if_busy_returncode = \
            kwargs.pop("retry_if_busy_returncode", True)

        if retry_if_busy_returncode and response.service == 0x7f \
                and self._get_negative_response_code(response) == 0x21:
            log_automotive.debug(
                "Retry %s because retry_if_busy_returncode received",
                repr(request))
            return self._populate_retry(state, request)
        return False

    def _compute_statistics(self):
        # type: () -> List[Tuple[str, str, str]]
        data_sets = [("all", self._results)]

        for state in self._state_completed.keys():
            data_sets.append((repr(state),
                              [r for r in self._results if r.state == state]))

        stats = list()  # type: List[Tuple[str, str, str]]

        for desc, data in data_sets:
            answered = [cast(_AutomotiveTestCaseFilteredScanResult, r)
                        for r in data if r.resp is not None and
                        r.resp_ts is not None]
            unanswered = [r for r in data if r.resp is None]
            answertimes = [float(x.resp_ts) - float(x.req_ts)
                           for x in answered]
            answertimes_nr = [float(x.resp_ts) - float(x.req_ts)
                              for x in answered if x.resp.service == 0x7f]
            answertimes_pr = [float(x.resp_ts) - float(x.req_ts)
                              for x in answered if x.resp.service != 0x7f]

            nrs = [r.resp for r in answered if r.resp.service == 0x7f]
            stats.append((desc, "num_answered", str(len(answered))))
            stats.append((desc, "num_unanswered", str(len(unanswered))))
            stats.append((desc, "num_negative_resps", str(len(nrs))))

            for postfix, times in zip(
                    ["", "_nr", "_pr"],
                    [answertimes, answertimes_nr, answertimes_pr]):
                try:
                    ma = str(round(max(times), 5))
                except ValueError:
                    ma = "-"

                try:
                    mi = str(round(min(times), 5))
                except ValueError:
                    mi = "-"

                try:
                    avg = str(round(sum(times) / len(times), 5))
                except (ValueError, ZeroDivisionError):
                    avg = "-"

                stats.append((desc, "answertime_min" + postfix, mi))
                stats.append((desc, "answertime_max" + postfix, ma))
                stats.append((desc, "answertime_avg" + postfix, avg))

        return stats

    def _show_statistics(self, **kwargs):
        # type: (Any) -> str
        stats = self._compute_statistics()

        s = "%d requests were sent, %d answered, %d unanswered" % \
            (len(self._results),
             len(self.results_with_response),
             len(self.results_without_response)) + "\n"

        s += "Statistics per state\n"
        s += make_lined_table(stats, lambda x: x, dump=True, sortx=str,
                              sorty=str) or ""

        return s + "\n"

    def _prepare_negative_response_blacklist(self):
        # type: () -> None
        nrc_dict = defaultdict(int)  # type: Dict[int, int]
        for nr in self.results_with_negative_response:
            nrc_dict[self._get_negative_response_code(nr.resp)] += 1

        total_nr_count = len(self.results_with_negative_response)
        for nrc, nr_count in nrc_dict.items():
            if nrc not in self.negative_response_blacklist and \
                    nr_count > 30 and (nr_count / total_nr_count) > 0.3:
                log_automotive.info("Added NRC 0x%02x to filter", nrc)
                self.negative_response_blacklist.append(nrc)

            if nrc in self.negative_response_blacklist and nr_count < 10:
                log_automotive.info("Removed NRC 0x%02x to filter", nrc)
                self.negative_response_blacklist.remove(nrc)

    @property
    def results(self):
        # type: () -> List[_AutomotiveTestCaseScanResult]
        return self._results

    @property
    def results_with_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        filtered_results = list()
        for r in self._results:
            if r.resp is None:
                continue
            if r.resp_ts is None:
                continue
            fr = cast(_AutomotiveTestCaseFilteredScanResult, r)
            filtered_results.append(fr)
        return filtered_results

    @property
    def filtered_results(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        filtered_results = self.results_with_positive_response

        for r in self.results_with_negative_response:
            nrc = self._get_negative_response_code(r.resp)
            if nrc not in self.negative_response_blacklist:
                filtered_results.append(r)
        return filtered_results

    @property
    def scanned_states(self):
        # type: () -> Set[EcuState]
        """
        Helper function to get all sacnned states in results
        :return: all scanned states
        """
        return set([tup.state for tup in self._results])

    @property
    def results_with_negative_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        """
        Helper function to get all results with negative response
        :return: all results with negative response
        """
        return [r for r in self.results_with_response
                if r.resp and r.resp.service == 0x7f]

    @property
    def results_with_positive_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        """
        Helper function to get all results with positive response
        :return: all results with positive response
        """
        return [r for r in self.results_with_response  # noqa: E501
                if r.resp and r.resp.service != 0x7f]

    @property
    def results_without_response(self):
        # type: () -> List[_AutomotiveTestCaseScanResult]
        """
        Helper function to get all results without response
        :return: all results without response
        """
        return [r for r in self._results if r.resp is None]

    def _show_negative_response_details(self, **kwargs):
        # type: (Any) -> str
        nrc_dict = defaultdict(int)  # type: Dict[int, int]
        for nr in self.results_with_negative_response:
            nrc_dict[self._get_negative_response_code(nr.resp)] += 1

        s = "These negative response codes were received " + \
            " ".join([hex(c) for c in nrc_dict.keys()]) + "\n"
        for nrc, nr_count in nrc_dict.items():
            s += "\tNRC 0x%02x: %s received %d times" % (
                nrc, self._get_negative_response_desc(nrc), nr_count)
            s += "\n"

        return s + "\n"

    def _show_negative_response_information(self, **kwargs):
        # type: (Any) -> str
        filtered = kwargs.get("filtered", True)
        s = "%d negative responses were received\n" % \
            len(self.results_with_negative_response)

        s += "\n"

        s += self._show_negative_response_details(**kwargs) or "" + "\n"
        if filtered and len(self.negative_response_blacklist):
            s += "The following negative response codes are blacklisted: %s\n" \
                 % [self._get_negative_response_desc(nr)
                    for nr in self.negative_response_blacklist]

        return s + "\n"

    def _show_results_information(self, **kwargs):
        # type: (Any) -> str
        def _get_table_entry(
                tup  # type: _AutomotiveTestCaseScanResult
        ):  # type: (...) -> Tuple[str, str, str]
            return self._get_table_entry_x(tup), \
                self._get_table_entry_y(tup), \
                self._get_table_entry_z(tup)

        filtered = kwargs.get("filtered", True)
        s = "=== No data to display ===\n"
        data = self._results if not filtered else self.filtered_results  # type: Union[List[_AutomotiveTestCaseScanResult], List[_AutomotiveTestCaseFilteredScanResult]]  # noqa: E501
        if len(data):
            s = make_lined_table(
                data, _get_table_entry, dump=True, sortx=str) or ""

        return s + "\n"

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        if filtered:
            self._prepare_negative_response_blacklist()

        show_functions = [self._show_header,
                          self._show_statistics,
                          self._show_negative_response_information,
                          self._show_results_information]

        if verbose:
            show_functions.append(self._show_state_information)

        s = "\n".join(x(filtered=filtered) for x in show_functions)

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def _get_label(self, response, positive_case="PR: PositiveResponse"):
        # type: (Optional[Packet], Union[Callable[[Packet], str], str]) -> str
        if response is None:
            return "Timeout"
        elif orb(bytes(response)[0]) == 0x7f:
            return self._get_negative_response_label(response)
        else:
            if isinstance(positive_case, six.string_types):
                return cast(str, positive_case)
            elif callable(positive_case):
                return positive_case(response)
            else:
                raise Scapy_Exception("Unsupported Type for positive_case. "
                                      "Provide a string or a function.")

    @property
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        supported_resps = list()
        all_responses = [p for p in self._result_packets.values()
                         if orb(bytes(p)[0]) & 0x40]
        for resp in all_responses:
            states = list(set([t.state for t in self.results_with_response
                               if t.resp == resp]))
            supported_resps.append(EcuResponse(state=states, responses=resp))
        return supported_resps


@six.add_metaclass(abc.ABCMeta)
class StateGeneratingServiceEnumerator(ServiceEnumerator, StateGenerator):
    def __init__(self):
        # type: () -> None
        super(StateGeneratingServiceEnumerator, self).__init__()

        # Internal storage of request packets for a certain Edge. If an edge
        # is found during the evaluation of the last result of the
        # ServiceEnumerator, the according request of the result tuple is
        # stored together with the new Edge.
        self._edge_requests = dict()  # type: Dict[_Edge, Packet]

    def get_new_edge(self,
                     socket,  # type: _SocketUnion
                     config  # type: AutomotiveTestCaseExecutorConfiguration
                     ):
        # type: (...) -> Optional[_Edge]
        """
        Basic identification of a new edge. The last response is evaluated.
        If this response packet can modify the state of an Ecu, this new
        state is returned, otherwise None.

        :param socket: Socket to the DUT (unused)
        :param config: Global configuration of the executor (unused)
        :return: tuple of old EcuState and new EcuState, or None
        """
        try:
            state, req, resp, _, _ = cast(ServiceEnumerator, self).results[-1]
        except IndexError:
            return None

        if resp is not None and EcuState.is_modifier_pkt(resp):
            new_state = EcuState.get_modified_ecu_state(resp, req, state)
            if new_state == state:
                return None
            else:
                edge = (state, new_state)
                self._edge_requests[edge] = req
                return edge
        else:
            return None

    @staticmethod
    def transition_function(
            sock,  # type: _SocketUnion
            config,  # type: AutomotiveTestCaseExecutorConfiguration
            kwargs  # type: Dict[str, Any]
    ):
        # type: (...) -> bool
        """
        Very basic transition function. This function sends a given request
        in kwargs and evaluates the response.

        :param sock: Connection to the DUT
        :param config: Global configuration of the executor (unused)
        :param kwargs: Dictionary with arguments. This function only uses
                       the argument *"req"* which must contain a Packet,
                       causing an EcuState transition of the DUT.
        :return: True in case of a successful transition, else False
        """
        req = kwargs.get("req", None)
        if req is None:
            return False

        try:
            res = sock.sr1(req, timeout=20, verbose=False, chainEX=True)
            return res is not None and res.service != 0x7f
        except (OSError, ValueError, Scapy_Exception) as e:
            log_automotive.exception(
                "Exception in transition function: %s", e)
            return False

    def get_transition_function_description(self, edge):
        # type: (_Edge) -> str
        return repr(self._edge_requests[edge])

    def get_transition_function_kwargs(self, edge):
        # type: (_Edge) -> Dict[str, Any]
        req = self._edge_requests[edge]
        kwargs = {
            "desc": self.get_transition_function_description(edge),
            "req": req
        }
        return kwargs

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        try:
            return self.transition_function, \
                self.get_transition_function_kwargs(edge), None
        except KeyError:
            return None
