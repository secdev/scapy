# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = Staged AutomotiveTestCase base classes
# scapy.contrib.status = library


from scapy.compat import Any, List, Optional, Dict, Callable, cast, \
    TYPE_CHECKING, Tuple
from scapy.contrib.automotive import log_automotive
from scapy.contrib.automotive.scanner.graph import _Edge
from scapy.contrib.automotive.ecu import EcuState, EcuResponse, Ecu
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC, \
    TestCaseGenerator, StateGenerator, _SocketUnion

if TYPE_CHECKING:
    from scapy.contrib.automotive.scanner.test_case import _TransitionTuple
    from scapy.contrib.automotive.scanner.configuration import \
        AutomotiveTestCaseExecutorConfiguration

# type definitions
_TestCaseConnectorCallable = \
    Callable[[AutomotiveTestCaseABC, AutomotiveTestCaseABC], Dict[str, Any]]


class StagedAutomotiveTestCase(AutomotiveTestCaseABC, TestCaseGenerator, StateGenerator):  # noqa: E501
    """ Helper object to build a pipeline of TestCases. This allows to combine
    TestCases and to execute them after each other. Custom connector functions
    can be used to exchange and manipulate the configuration of a subsequent
    TestCase.

    :param test_cases: A list of objects following the AutomotiveTestCaseABC
        interface
    :param connectors: A list of connector functions. A connector function
        takes two TestCase objects and returns a dictionary which is provided
        to the second TestCase as kwargs of the execute function.


    Example:
        >>> class MyTestCase2(AutomotiveTestCaseABC):
        >>>     pass
        >>>
        >>> class MyTestCase1(AutomotiveTestCaseABC):
        >>>     pass
        >>>
        >>> def connector(testcase1, testcase2):
        >>>     scan_range = len(testcase1.results)
        >>>     return {"verbose": True, "scan_range": scan_range}
        >>>
        >>> tc1 = MyTestCase1()
        >>> tc2 = MyTestCase2()
        >>> pipeline = StagedAutomotiveTestCase([tc1, tc2], [None, connector])
    """

    # Delay the increment of a stage after the current stage is finished
    # has_completed() has to be called five times in order to increment the
    # current stage. This ensures, that the current stage is executed for
    # all possible states of the DUT, and no state is missed for the first
    # TestCase.
    __delay_stages = 5

    def __init__(self,
                 test_cases,  # type: List[AutomotiveTestCaseABC]
                 connectors=None  # type: Optional[List[Optional[_TestCaseConnectorCallable]]]  # noqa: E501
                 ):  # type: (...) -> None
        super(StagedAutomotiveTestCase, self).__init__()
        self.__test_cases = test_cases
        self.__connectors = connectors
        self.__stage_index = 0
        self.__completion_delay = 0
        self.__current_kwargs = None  # type: Optional[Dict[str, Any]]

    def __getitem__(self, item):
        # type: (int) -> AutomotiveTestCaseABC
        return self.__test_cases[item]

    def __len__(self):
        # type: () -> int
        return len(self.__test_cases)

    # TODO: Fix unit tests and remove this function
    def __reduce__(self):  # type: ignore
        f, t, d = super(StagedAutomotiveTestCase, self).__reduce__()  # type: ignore  # noqa: E501
        try:
            del d["_StagedAutomotiveTestCase__connectors"]
        except KeyError:
            pass
        return f, t, d

    @property
    def test_cases(self):
        # type: () -> List[AutomotiveTestCaseABC]
        return self.__test_cases

    @property
    def current_test_case(self):
        # type: () -> AutomotiveTestCaseABC
        return self[self.__stage_index]

    @property
    def current_connector(self):
        # type: () -> Optional[_TestCaseConnectorCallable]
        if not self.__connectors:
            return None
        else:
            return self.__connectors[self.__stage_index]

    @property
    def previous_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        return self.__test_cases[self.__stage_index - 1] if \
            self.__stage_index > 0 else None

    def get_generated_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        try:
            test_case = cast(TestCaseGenerator, self.current_test_case)
            return test_case.get_generated_test_case()
        except AttributeError:
            return None

    def get_new_edge(self,
                     socket,  # type: _SocketUnion
                     config  # type: AutomotiveTestCaseExecutorConfiguration
                     ):  # type: (...) -> Optional[_Edge]
        try:
            test_case = cast(StateGenerator, self.current_test_case)
            return test_case.get_new_edge(socket, config)
        except AttributeError:
            return None

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        try:
            test_case = cast(StateGenerator, self.current_test_case)
            return test_case.get_transition_function(socket, edge)
        except AttributeError:
            return None

    def has_completed(self, state):
        # type: (EcuState) -> bool
        if not (self.current_test_case.has_completed(state) and
                self.current_test_case.completed):
            # current test_case not fully completed
            # reset completion delay, since new states could have been appeared
            self.__completion_delay = 0
            return False

        # current stage is finished. We have to increase the stage
        if self.__completion_delay < StagedAutomotiveTestCase.__delay_stages:
            # First we wait five more iteration of the executor
            # Maybe one more execution reveals new states of other
            # test_cases
            self.__completion_delay += 1
            return False

        # current test_case is fully completed
        elif self.__stage_index == len(self.__test_cases) - 1:
            # this test_case was the last test_case... nothing to do
            return True

        else:
            # We waited more iterations and no new state appeared,
            # let's enter the next stage
            log_automotive.info(
                "Staged AutomotiveTestCase %s completed",
                self.current_test_case.__class__.__name__)
            self.__stage_index += 1
            self.__completion_delay = 0
        return False

    def pre_execute(self,
                    socket,  # type: _SocketUnion
                    state,  # type: EcuState
                    global_configuration  # type: AutomotiveTestCaseExecutorConfiguration  # noqa: E501
                    ):  # type: (...) -> None
        test_case_cls = self.current_test_case.__class__
        try:
            self.__current_kwargs = global_configuration[
                test_case_cls.__name__]
        except KeyError:
            self.__current_kwargs = dict()
            global_configuration[test_case_cls.__name__] = \
                self.__current_kwargs

        if callable(self.current_connector) and self.__stage_index > 0:
            if self.previous_test_case:
                con = self.current_connector  # type: _TestCaseConnectorCallable  # noqa: E501
                con_kwargs = con(self.previous_test_case,
                                 self.current_test_case)
                if self.__current_kwargs is not None and con_kwargs is not None:  # noqa: E501
                    self.__current_kwargs.update(con_kwargs)

        log_automotive.debug("Stage AutomotiveTestCase %s kwargs: %s",
                             self.current_test_case.__class__.__name__,
                             self.__current_kwargs)

        self.current_test_case.pre_execute(socket, state, global_configuration)

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        kwargs.update(self.__current_kwargs or dict())
        self.current_test_case.execute(socket, state, **kwargs)

    def post_execute(self,
                     socket,  # type: _SocketUnion
                     state,  # type: EcuState
                     global_configuration  # type: AutomotiveTestCaseExecutorConfiguration  # noqa: E501
                     ):  # type: (...) -> None
        self.current_test_case.post_execute(
            socket, state, global_configuration)

    @staticmethod
    def _show_headline(headline, sep="="):
        # type: (str, str) -> str
        s = "\n\n" + sep * (len(headline) + 10) + "\n"
        s += " " * 5 + headline + "\n"
        s += sep * (len(headline) + 10) + "\n"
        return s + "\n"

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        s = self._show_headline("AutomotiveTestCase Pipeline", "=")
        for idx, t in enumerate(self.__test_cases):
            s += self._show_headline(
                "AutomotiveTestCase Stage %d" % idx, "-")
            s += t.show(True, filtered, verbose) or ""

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    @property
    def completed(self):
        # type: () -> bool
        return all(e.completed for e in self.__test_cases) and \
            self.__completion_delay >= StagedAutomotiveTestCase.__delay_stages

    @property
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        supported_responses = list()
        for tc in self.test_cases:
            supported_responses += tc.supported_responses

        supported_responses.sort(key=Ecu.sort_key_func)
        return supported_responses

    def runtime_estimation(self):
        # type: () -> Optional[Tuple[int, int, float]]

        if hasattr(self.current_test_case, "runtime_estimation"):
            cur_est = self.current_test_case.runtime_estimation()  # type: ignore
            if cur_est:
                return len(self.test_cases), \
                    self.__stage_index, \
                    float(self.__stage_index) / len(self.test_cases) + \
                    cur_est[2] / len(self.test_cases)

        return len(self.test_cases), \
            self.__stage_index, \
            float(self.__stage_index) / len(self.test_cases)
