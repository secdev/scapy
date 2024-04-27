# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = AutomotiveTestCaseExecutorConfiguration
# scapy.contrib.status = library

import inspect
from threading import Event

from scapy.contrib.automotive import log_automotive
from scapy.contrib.automotive.scanner.graph import Graph
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC
from scapy.contrib.automotive.scanner.staged_test_case import StagedAutomotiveTestCase  # noqa: E501

# Typing imports
from typing import (
    Any,
    Union,
    List,
    Type,
    Set,
    cast,
)


class AutomotiveTestCaseExecutorConfiguration(object):
    """
    Configuration storage for AutomotiveTestCaseExecutor.

    The following keywords are used in the AutomotiveTestCaseExecutor:
        verbose: Enables verbose output and logging
        debug:  Will raise Exceptions on internal errors

    :param test_cases: List of AutomotiveTestCase classes or instances.
                       Classes will get instantiated in this initializer.
    :param kwargs: Configuration for every AutomotiveTestCase in test_cases
                   and for the AutomotiveTestCaseExecutor. TestCase local
                   configuration and global configuration for all TestCase
                   objects are possible. All keyword arguments given will
                   be stored for every TestCase. To define a local
                   configuration for one TestCase only, the keyword
                   arguments need to be provided in a dictionary.
                   To assign a configuration dictionary to a TestCase, the
                   keyword need to identify the TestCase by the following
                   pattern.
                   ``MyTestCase_kwargs={"someConfig": 42}``
                   The keyword is composed from the TestCase class name and
                   the postfix '_kwargs'.

    Example:
        >>> config = AutomotiveTestCaseExecutorConfiguration([MyTestCase], global_config=42, MyTestCase_kwargs={"localConfig": 1337})  # noqa: E501
    """
    def __setitem__(self, key, value):
        # type: (Any, Any) -> None
        self.__dict__[key] = value

    def __getitem__(self, key):
        # type: (Any) -> Any
        return self.__dict__[key]

    def _generate_test_case_config(self, test_case_cls):
        # type: (Type[AutomotiveTestCaseABC]) -> None
        # try to get config from kwargs
        if test_case_cls in self.test_case_clss:
            return

        self.test_case_clss.add(test_case_cls)

        kwargs_name = test_case_cls.__name__ + "_kwargs"
        self.__setattr__(test_case_cls.__name__, self.global_kwargs.pop(
            kwargs_name, dict()))

        # apply global config
        val = self.__getattribute__(test_case_cls.__name__)
        for kwargs_key, kwargs_val in self.global_kwargs.items():
            if "_kwargs" in kwargs_key:
                continue
            if kwargs_key not in val.keys():
                val[kwargs_key] = kwargs_val
        self.__setattr__(test_case_cls.__name__, val)

    def add_test_case(self, test_case):
        # type: (Union[AutomotiveTestCaseABC, Type[AutomotiveTestCaseABC], StagedAutomotiveTestCase, Type[StagedAutomotiveTestCase]]) -> None  # noqa: E501
        if inspect.isclass(test_case):
            test_case_class = cast(Union[Type[AutomotiveTestCaseABC],
                                         Type[StagedAutomotiveTestCase]],
                                   test_case)
            if issubclass(test_case_class, StagedAutomotiveTestCase):
                self.add_test_case(test_case_class())  # type: ignore
            elif issubclass(test_case_class, AutomotiveTestCaseABC):
                self.add_test_case(test_case_class())
            else:
                raise TypeError(
                    "Provided class is not in "
                    "Union[Type[AutomotiveTestCaseABC], "
                    "Type[StagedAutomotiveTestCase]]")

        elif isinstance(test_case, AutomotiveTestCaseABC):
            self.test_cases.append(test_case)
            self._generate_test_case_config(test_case.__class__)
            if isinstance(test_case, StagedAutomotiveTestCase):
                self.stages.append(test_case)
                for tc in test_case.test_cases:
                    self.staged_test_cases.append(tc)
                    self._generate_test_case_config(tc.__class__)
        else:
            raise TypeError(
                "Provided instance or class of "
                "StagedAutomotiveTestCase or AutomotiveTestCaseABC")

    def __init__(self, test_cases, **kwargs):
        # type: (Union[List[Union[AutomotiveTestCaseABC, Type[AutomotiveTestCaseABC]]], List[Type[AutomotiveTestCaseABC]]], Any) -> None  # noqa: E501
        self.verbose = kwargs.get("verbose", False)
        self.debug = kwargs.get("debug", False)
        self.unittest = kwargs.pop("unittest", False)
        self.delay_enter_state = kwargs.pop("delay_enter_state", 0)
        self.state_graph = Graph()
        self.test_cases = list()  # type: List[AutomotiveTestCaseABC]
        self.stages = list()  # type: List[StagedAutomotiveTestCase]
        self.staged_test_cases = list()  # type: List[AutomotiveTestCaseABC]
        self.test_case_clss = set()  # type: Set[Type[AutomotiveTestCaseABC]]
        self.stop_event = Event()
        self.global_kwargs = kwargs
        self.global_kwargs["stop_event"] = self.stop_event

        for tc in test_cases:
            self.add_test_case(tc)

        log_automotive.debug("The following configuration was created")
        log_automotive.debug(self.__dict__)

    def __reduce__(self):  # type: ignore
        f, t, d = super(AutomotiveTestCaseExecutorConfiguration, self).__reduce__()  # type: ignore  # noqa: E501

        try:
            del d["tps"]
        except KeyError:
            pass

        try:
            del d["stop_event"]
        except KeyError:
            pass

        try:
            del d["global_kwargs"]["stop_event"]
        except KeyError:
            pass

        for tc in d["test_cases"]:
            try:
                del d[tc.__class__.__name__]["stop_event"]
            except KeyError:
                pass

        for tc in d["staged_test_cases"]:
            try:
                del d[tc.__class__.__name__]["stop_event"]
            except KeyError:
                pass

        try:
            del d["global_kwargs"]["stop_event"]
        except KeyError:
            pass

        return f, t, d
