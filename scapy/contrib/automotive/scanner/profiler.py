# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# This program is published under a GPLv2 license

# scapy.contrib.description = Profiler for AutomotiveTestCaseExecutor
# scapy.contrib.status = library

import time
import functools

from scapy.compat import Any, Optional, Callable


class Profiler:
    # For the profiling we'll use the unix time
    # candump is using the same and thus it would be matchable

    # _candump_fmt_date = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    # _filename_milestone = "milestones-%s.csv" % _candump_fmt_date
    # _filename_profiling = "profiling-%s.csv" % _candump_fmt_date
    _filename_milestone = "milestones.csv"
    _filename_profiling = "profiling.csv"

    _first = True
    enabled = True

    def __init__(self, state, enum=None):
        # type: (Any, Optional[Any]) -> None
        # We use the csv format
        # If len(p) > 1, it would contain a ','
        # For example: "[1, 2, 3]"
        # Thus we replace all ',' with a ';' to avoid this
        self.state = str(state).replace(",", ";")
        self.enum = str(enum or state).replace(",", ";")
        self.start_time = time.time()

        if Profiler._first and Profiler.enabled:
            Profiler._first = False
            with open(Profiler._filename_profiling, mode="a") as f:  # noqa: E501
                # Writing header
                # Not required for milestone file because this is parsed
                # manually instead of using `read_csv` of plotly
                f.write("state,enumerator,start,end\n")

    @classmethod
    def write_milestone(cls, name):
        # type: (str) -> None
        if not cls.enabled:
            return
        with open(cls._filename_milestone, mode="a") as f:
            f.write("%s,%f\n" % (name, time.time()))

    def __enter__(self):
        # type: () -> Profiler
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # type: (Any, Any, Any) -> None
        if not Profiler.enabled:
            return
        with open(Profiler._filename_profiling, mode="a") as f:
            f.write("%s,%s,%f,%f\n" % (
                self.state, self.enum, self.start_time, time.time()))


def profile(state, enum=None):
    # type: (Any, Optional[Any]) -> Callable[[Callable[..., Any]], Callable[..., Any]]  # noqa: E501
    def profile_decorator(func):
        # type: (Callable[..., Any]) -> Callable[..., Any]
        @functools.wraps(func)
        def wrapper_profiled(*args, **kwargs):  # type: ignore
            with Profiler(state, enum):
                value = func(*args, **kwargs)
            return value

        return wrapper_profiled
    return profile_decorator
