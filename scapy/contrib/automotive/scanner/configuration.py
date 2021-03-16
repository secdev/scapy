# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = AutomotiveTestCaseExecutorConfiguration
# scapy.contrib.status = library

from scapy.compat import Any, Union, List, Type
from scapy.contrib.automotive.scanner.graph import Graph
from scapy.error import log_interactive
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC
from scapy.contrib.automotive.scanner.staged_test_case import StagedAutomotiveTestCase  # noqa: E501


class AutomotiveTestCaseExecutorConfiguration(object):
    """
    Configuration storage for AutomotiveTestCaseExecutor.

    The following keywords are used in the AutomotiveTestCaseExecutor:
        verbose: Enables verbose output and logging
        debug:  Will raise Exceptions on internal errors
        delay_state_change: After a state change, a defined time is waited

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

    def __init__(self, test_cases, **kwargs):
        # type: (Union[List[Union[AutomotiveTestCaseABC, Type[AutomotiveTestCaseABC]]], List[Type[AutomotiveTestCaseABC]]], Any) -> None  # noqa: E501
        self.verbose = kwargs.get("verbose", False)
        self.debug = kwargs.get("debug", False)
        self.delay_state_change = kwargs.get("delay_state_change", 0.5)
        self.state_graph = Graph()

        # test_case can be a mix of classes or instances
        self.test_cases = \
            [e() for e in test_cases if not isinstance(e, AutomotiveTestCaseABC)]  # type: List[AutomotiveTestCaseABC]  # noqa: E501
        self.test_cases += \
            [e for e in test_cases if isinstance(e, AutomotiveTestCaseABC)]

        self.stages = [e for e in self.test_cases
                       if isinstance(e, StagedAutomotiveTestCase)]

        self.staged_test_cases = \
            [i for sublist in [e.test_cases for e in self.stages]
             for i in sublist]

        self.test_case_clss = set([
            case.__class__ for case in set(self.staged_test_cases +
                                           self.test_cases)])

        for cls in self.test_case_clss:
            kwargs_name = cls.__name__ + "_kwargs"
            self.__setattr__(cls.__name__, kwargs.pop(kwargs_name, dict()))

        for cls in self.test_case_clss:
            val = self.__getattribute__(cls.__name__)
            for kwargs_key, kwargs_val in kwargs.items():
                if kwargs_key not in val.keys():
                    val[kwargs_key] = kwargs_val
            self.__setattr__(cls.__name__, val)

        log_interactive.debug("The following configuration was created")
        log_interactive.debug(self.__dict__)
