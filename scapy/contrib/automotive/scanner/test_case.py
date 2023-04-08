# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = TestCase base class definitions
# scapy.contrib.status = library


import abc
from collections import defaultdict

from scapy.utils import make_lined_table, SingleConversationSocket
from scapy.supersocket import SuperSocket
from scapy.contrib.automotive.scanner.graph import _Edge
from scapy.contrib.automotive.ecu import EcuState, EcuResponse
from scapy.error import Scapy_Exception


# Typing imports
from typing import (
    Any,
    Union,
    List,
    Optional,
    Dict,
    Tuple,
    Set,
    Callable,
    TYPE_CHECKING,
)
if TYPE_CHECKING:
    from scapy.contrib.automotive.scanner.configuration import AutomotiveTestCaseExecutorConfiguration  # noqa: E501


# type definitions
_SocketUnion = Union[SuperSocket, SingleConversationSocket]
_TransitionCallable = Callable[[_SocketUnion, "AutomotiveTestCaseExecutorConfiguration", Dict[str, Any]], bool]  # noqa: E501
_CleanupCallable = Callable[[_SocketUnion, "AutomotiveTestCaseExecutorConfiguration"], bool]  # noqa: E501
_TransitionTuple = Tuple[_TransitionCallable, Dict[str, Any], Optional[_CleanupCallable]]  # noqa: E501


class AutomotiveTestCaseABC(metaclass=abc.ABCMeta):
    """
    Base class for "TestCase" objects. In automotive scanners, these TestCase
    objects are used for individual tasks, for example enumerating over one
    kind of functionality of the protocol. It is also possible, that
    these TestCase objects execute complex tests on an ECU.
    The TestCaseExecuter object has a list of TestCases. The executer
    manipulates a device under test (DUT), to enter a certain state. In this
    state, the TestCase object gets executed.
    """

    _supported_kwargs = {}  # type: Dict[str, Tuple[Any, Optional[Callable[[Any], bool]]]]  # noqa: E501
    _supported_kwargs_doc = ""

    @abc.abstractmethod
    def has_completed(self, state):
        # type: (EcuState) -> bool
        """
        Tells if this TestCase was executed for a certain state
        :param state: State of interest
        :return: True, if TestCase was executed in the questioned state
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def pre_execute(self,
                    socket,  # type: _SocketUnion
                    state,  # type: EcuState
                    global_configuration  # type: AutomotiveTestCaseExecutorConfiguration  # noqa: E501
                    ):  # type: (...) -> None
        """
        Will be executed previously to ``execute``. This function can be used
        to manipulate the configuration passed to execute.

        :param socket: Socket object with the connection to a DUT
        :param state: Current state of the DUT
        :param global_configuration: Configuration of the TestCaseExecutor
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        """
        Executes this TestCase for a given state

        :param socket: Socket object with the connection to a DUT
        :param state: Current state of the DUT
        :param kwargs: Local configuration of the TestCasesExecutor
        :return:
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def post_execute(self,
                     socket,  # type: _SocketUnion
                     state,  # type: EcuState
                     global_configuration  # type: AutomotiveTestCaseExecutorConfiguration  # noqa: E501
                     ):  # type: (...) -> None
        """
        Will be executed subsequently to ``execute``. This function can be used
        for additional evaluations after the ``execute``.

        :param socket: Socket object with the connection to a DUT
        :param state: Current state of the DUT
        :param global_configuration: Configuration of the TestCaseExecutor
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        """
        Shows results of TestCase

        :param dump: If True, the results will be returned; If False, the
                     results will be printed.
        :param filtered: If True, the negative responses will be filtered
                         dynamically.
        :param verbose: If True, additional information will be provided.
        :return: test results of TestCase if parameter ``dump`` is True,
                 else ``None``
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def completed(self):
        # type: () -> bool
        """
        Tells if this TestCase is completely executed
        :return: True, if TestCase is completely executed
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        """
        Tells the supported responses in TestCase
        :return: The list of supported responses
        """
        raise NotImplementedError


class AutomotiveTestCase(AutomotiveTestCaseABC):
    """ Base class for TestCases"""

    _description = "AutomotiveTestCase"
    _supported_kwargs = AutomotiveTestCaseABC._supported_kwargs
    _supported_kwargs_doc = AutomotiveTestCaseABC._supported_kwargs_doc

    def __init__(self):
        # type: () -> None
        self._state_completed = defaultdict(bool)  # type: Dict[EcuState, bool]

    def has_completed(self, state):
        # type: (EcuState) -> bool
        return self._state_completed[state]

    @classmethod
    def check_kwargs(cls, kwargs):
        # type: (Dict[str, Any]) -> None
        for k, v in kwargs.items():
            if k not in cls._supported_kwargs.keys():
                raise Scapy_Exception(
                    "Keyword-Argument %s not supported for %s" %
                    (k, cls.__name__))
            ti, vf = cls._supported_kwargs[k]
            if ti is not None and not isinstance(v, ti):
                raise Scapy_Exception(
                    "Keyword-Value '%s' is not instance of type %s" %
                    (k, str(ti)))
            if vf is not None and not vf(v):
                raise Scapy_Exception(
                    "Validation Error: '%s: %s' is not in the allowed "
                    "value range" % (k, str(v))
                )

    @property
    def completed(self):
        # type: () -> bool
        return all(v for _, v in self._state_completed.items())

    @property
    def scanned_states(self):
        # type: () -> Set[EcuState]
        """
        Helper function to get all scanned states
        :return: all scanned states
        """
        return set(self._state_completed.keys())

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        pass

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        raise NotImplementedError()

    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        pass

    def _show_header(self, **kwargs):
        # type: (Any) -> str
        s = "\n\n" + "=" * (len(self._description) + 10) + "\n"
        s += " " * 5 + self._description + "\n"
        s += "-" * (len(self._description) + 10) + "\n"

        return s + "\n"

    def _show_state_information(self, **kwargs):
        # type: (Any) -> str
        completed = [(state, self._state_completed[state])
                     for state in self.scanned_states]
        return make_lined_table(
            completed, lambda x, y: ("Scan state completed", x, y),
            dump=True) or ""

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]

        s = self._show_header()

        if verbose:
            s += self._show_state_information()

        if dump:
            return s + "\n"
        else:
            print(s)
            return None


class TestCaseGenerator(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_generated_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        raise NotImplementedError()


class StateGenerator(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        raise NotImplementedError

    @abc.abstractmethod
    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        """

        :param socket: Socket to target
        :param edge: Tuple of EcuState objects for the requested
                     transition function
        :return: Returns an optional tuple consisting of a transition function,
                 a keyword arguments dictionary for the transition function
                 and a cleanup function. Both functions
                 take a Socket and the TestCaseExecutor configuration as
                 arguments and return True if the execution was successful.
                 The first function is the state enter function, the second
                 function is a cleanup function
        """
        raise NotImplementedError
