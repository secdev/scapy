# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = AutomotiveTestCaseExecutor base class
# scapy.contrib.status = library

import abc
import time

from itertools import product

from scapy.compat import Any, Union, List, Optional, \
    Dict, Callable, Type, cast
from scapy.contrib.automotive.scanner.graph import Graph
from scapy.error import Scapy_Exception, log_interactive
from scapy.supersocket import SuperSocket
from scapy.utils import make_lined_table, SingleConversationSocket
import scapy.modules.six as six
from scapy.contrib.automotive.ecu import EcuState, EcuResponse, Ecu
from scapy.contrib.automotive.scanner.configuration import \
    AutomotiveTestCaseExecutorConfiguration
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC, \
    _SocketUnion, _CleanupCallable, StateGenerator, TestCaseGenerator


@six.add_metaclass(abc.ABCMeta)
class AutomotiveTestCaseExecutor:
    """
    Base class for different automotive scanners. This class handles
    the connection to a scan target, ensures the execution of all it's
    test cases, and stores the system state machine


    :param socket: A socket object to communicate with the scan target
    :param reset_handler: A function to reset the scan target
    :param reconnect_handler: In case the communication needs to be
                              established after a reset, provide a
                              reconnect function which returns a socket object
    :param test_cases: A list of TestCase instances or classes
    :param kwargs: Arguments for the internal
                   AutomotiveTestCaseExecutorConfiguration instance
    """
    @property
    def __initial_ecu_state(self):
        # type: () -> EcuState
        return EcuState(session=1)

    def __init__(
            self,
            socket,  # type: _SocketUnion
            reset_handler=None,  # type: Optional[Callable[[], None]]
            reconnect_handler=None,  # type: Optional[Callable[[], _SocketUnion]]  # noqa: E501
            test_cases=None,  # type: Optional[List[Union[AutomotiveTestCaseABC, Type[AutomotiveTestCaseABC]]]]  # noqa: E501
            **kwargs  # type: Optional[Dict[str, Any]]
    ):  # type: (...) -> None

        # The TesterPresentSender can interfere with a test_case, since a
        # target may only allow one request at a time.
        # The SingleConversationSocket prevents interleaving requests.
        if not isinstance(socket, SingleConversationSocket):
            self.socket = SingleConversationSocket(socket)
        else:
            self.socket = socket

        self.target_state = self.__initial_ecu_state
        self.reset_handler = reset_handler
        self.reconnect_handler = reconnect_handler

        self.cleanup_functions = list()  # type: List[_CleanupCallable]

        self.configuration = AutomotiveTestCaseExecutorConfiguration(
            test_cases or self.default_test_case_clss, **kwargs)

        self.configuration.state_graph.add_edge(
            (self.__initial_ecu_state, self.__initial_ecu_state))

    def __reduce__(self):  # type: ignore
        f, t, d = super(AutomotiveTestCaseExecutor, self).__reduce__()  # type: ignore  # noqa: E501
        try:
            del d["socket"]
        except KeyError:
            pass
        try:
            del d["reset_handler"]
        except KeyError:
            pass
        try:
            del d["reconnect_handler"]
        except KeyError:
            pass
        return f, t, d

    @property
    @abc.abstractmethod
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        raise NotImplementedError()

    @property
    def state_graph(self):
        # type: () -> Graph
        return self.configuration.state_graph

    @property
    def state_paths(self):
        # type: () -> List[List[EcuState]]
        """
        Returns all state paths. A path is represented by a list of EcuState
        objects.
        :return: A list of paths.
        """
        paths = [Graph.dijkstra(self.state_graph, self.__initial_ecu_state, s)
                 for s in self.state_graph.nodes
                 if s != self.__initial_ecu_state]
        return sorted(
            [p for p in paths if p is not None] + [[self.__initial_ecu_state]],
            key=lambda x: x[-1])

    @property
    def final_states(self):
        # type: () -> List[EcuState]
        """
        Returns a list with all final states. A final state is the last
        state of a path.
        :return:
        """
        return [p[-1] for p in self.state_paths]

    @property
    def scan_completed(self):
        # type: () -> bool
        return all(t.has_completed(s) for t, s in
                   product(self.configuration.test_cases, self.final_states))

    def reset_target(self):
        # type: () -> None
        log_interactive.info("[i] Target reset")
        if self.reset_handler:
            self.reset_handler()
        self.target_state = self.__initial_ecu_state

    def reconnect(self):
        # type: () -> None
        if self.reconnect_handler:
            try:
                self.socket.close()
            except Exception as e:
                log_interactive.debug(
                    "[i] Exception '%s' during socket.close", e)

            log_interactive.info("[i] Target reconnect")
            socket = self.reconnect_handler()
            if not isinstance(socket, SingleConversationSocket):
                self.socket = SingleConversationSocket(socket)
            else:
                self.socket = socket

        if self.socket.closed:
            raise Scapy_Exception(
                "Socket closed even after reconnect. Stop scan!")

    def execute_test_case(self, test_case):
        # type: (AutomotiveTestCaseABC) -> None
        """
        This function ensures the correct execution of a testcase, including
        the pre_execute, execute and post_execute.
        Finally the testcase is asked if a new edge or a new testcase was
        generated.
        :param test_case: A test case to be executed
        :return: None
        """
        test_case.pre_execute(
            self.socket, self.target_state, self.configuration)

        try:
            test_case_kwargs = self.configuration[test_case.__class__.__name__]
        except KeyError:
            test_case_kwargs = dict()

        log_interactive.debug("[i] Execute test_case %s with args %s",
                              test_case.__class__.__name__, test_case_kwargs)

        test_case.execute(self.socket, self.target_state, **test_case_kwargs)
        test_case.post_execute(
            self.socket, self.target_state, self.configuration)

        if isinstance(test_case, StateGenerator):
            edge = test_case.get_new_edge(self.socket, self.configuration)
            if edge:
                log_interactive.debug("Edge found %s", edge)
                tf = test_case.get_transition_function(self.socket, edge)
                self.state_graph.add_edge(edge, tf)

        if isinstance(test_case, TestCaseGenerator):
            new_test_case = test_case.get_generated_test_case()
            if new_test_case:
                log_interactive.debug("Testcase generated %s", new_test_case)
                self.configuration.add_test_case(new_test_case)

    def scan(self, timeout=None):
        # type: (Optional[int]) -> None
        """
        Executes all testcases for a given time.
        :param timeout: Time for execution.
        :return: None
        """
        kill_time = time.time() + (timeout or 0xffffffff)
        while kill_time > time.time():
            test_case_executed = False
            log_interactive.debug("[i] Scan paths %s", self.state_paths)
            for p, test_case in product(
                    self.state_paths, self.configuration.test_cases):
                log_interactive.info("[i] Scan path %s", p)
                terminate = kill_time < time.time()
                if terminate:
                    log_interactive.debug(
                        "[-] Execution time exceeded. Terminating scan!")
                    break

                final_state = p[-1]
                if test_case.has_completed(final_state):
                    log_interactive.debug("[+] State %s for %s completed",
                                          repr(final_state), test_case)
                    continue

                try:
                    if not self.enter_state_path(p):
                        log_interactive.error(
                            "[-] Error entering path %s", p)
                        continue
                    log_interactive.info(
                        "[i] Execute %s for path %s", str(test_case), p)
                    self.execute_test_case(test_case)
                    test_case_executed = True
                except (OSError, ValueError, Scapy_Exception) as e:
                    log_interactive.critical("[-] Exception: %s", e)
                    if self.configuration.debug:
                        raise e
                    if cast(SuperSocket, self.socket).closed and \
                            self.reconnect_handler is None:
                        log_interactive.critical(
                            "Socket went down. Need to leave scan")
                        raise e
                finally:
                    self.cleanup_state()

            if not test_case_executed:
                log_interactive.info(
                    "[i] Execute failure or scan completed. Exit scan!")
                break

        self.cleanup_state()
        self.reset_target()

    def enter_state_path(self, path):
        # type: (List[EcuState]) -> bool
        """
        Resets and reconnects to a target and applies all transition functions
        to traversal a given path.
        :param path: Path to be applied to the scan target.
        :return: True, if all transition functions could be executed.
        """
        if path[0] != self.__initial_ecu_state:
            raise Scapy_Exception(
                "Initial state of path not equal reset state of the target")

        self.reset_target()
        self.reconnect()

        if len(path) == 1:
            return True

        for next_state in path[1:]:
            edge = (self.target_state, next_state)
            if not self.enter_state(*edge):
                self.state_graph.downrate_edge(edge)
                self.cleanup_state()
                return False
        return True

    def enter_state(self, prev_state, next_state):
        # type: (EcuState, EcuState) -> bool
        """
        Obtains a transition function from the system state graph and executes
        it. On success, the cleanup function is added for a later cleanup of
        the new state.
        :param prev_state: Current state
        :param next_state: Desired state
        :return: True, if state could be changed successful
        """
        edge = (prev_state, next_state)
        funcs = self.state_graph.get_transition_tuple_for_edge(edge)

        if funcs is None:
            log_interactive.error("[!] No transition function for %s", edge)
            return False

        trans_func, trans_kwargs, clean_func = funcs
        state_changed = trans_func(
            self.socket, self.configuration, trans_kwargs)
        if state_changed:
            self.target_state = next_state

            if clean_func is not None:
                self.cleanup_functions += [clean_func]
            return True
        else:
            log_interactive.info("[-] Transition for edge %s failed", edge)
            return False

    def cleanup_state(self):
        # type: () -> None
        """
        Executes all collected cleanup functions from a traversed path
        :return: None
        """
        for f in self.cleanup_functions:
            if not callable(f):
                continue
            try:
                if not f(self.socket, self.configuration):
                    log_interactive.info(
                        "[-] Cleanup function %s failed", repr(f))
            except (OSError, ValueError, Scapy_Exception) as e:
                log_interactive.critical("[!] Exception during cleanup: %s", e)

        self.cleanup_functions = list()

    def show_testcases(self):
        # type: () -> None
        for t in self.configuration.test_cases:
            t.show()

    def show_testcases_status(self):
        # type: () -> None
        data = list()
        for t in self.configuration.test_cases:
            for s in self.state_graph.nodes:
                data += [(repr(s), t.__class__.__name__, t.has_completed(s))]
        make_lined_table(data, lambda tup: (tup[0], tup[1], tup[2]))

    @property
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        """
        Returns a sorted list of supported responses, gathered from all
        enumerators. The sort is done in a way
        to provide the best possible results, if this list of supported
        responses is used to simulate an real world Ecu with the
        EcuAnsweringMachine object.
        :return: A sorted list of EcuResponse objects
        """
        supported_responses = list()
        for tc in self.configuration.test_cases:
            supported_responses += tc.supported_responses

        supported_responses.sort(key=Ecu.sort_key_func)
        return supported_responses
