# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter

"""
Automata with states, transitions and actions.

TODO:
    - add documentation for ioevent, as_supersocket...
"""

import ctypes
import itertools
import logging
import os
import random
import socket
import sys
import threading
import time
import traceback
import types

import select
from collections import deque

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.data import MTU
from scapy.error import log_runtime, warning
from scapy.interfaces import _GlobInterfaceType
from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.supersocket import SuperSocket, StreamSocket
from scapy.utils import do_graph

# Typing imports
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)
from scapy.compat import DecoratorCallable


# winsock.h
FD_READ = 0x00000001


def select_objects(inputs, remain):
    # type: (Iterable[Any], Union[float, int, None]) -> List[Any]
    """
    Select objects. Same than:
    ``select.select(inputs, [], [], remain)``

    But also works on Windows, only on objects whose fileno() returns
    a Windows event. For simplicity, just use `ObjectPipe()` as a queue
    that you can select on whatever the platform is.

    If you want an object to be always included in the output of
    select_objects (i.e. it's not selectable), just make fileno()
    return a strictly negative value.

    Example:

        >>> a, b = ObjectPipe("a"), ObjectPipe("b")
        >>> b.send("test")
        >>> select_objects([a, b], 1)
        [b]

    :param inputs: objects to process
    :param remain: timeout. If 0, poll. If None, block.
    """
    if not WINDOWS:
        return select.select(inputs, [], [], remain)[0]
    inputs = list(inputs)
    events = []
    created = []
    results = set()
    for i in inputs:
        if getattr(i, "__selectable_force_select__", False):
            # Native socket.socket object. We would normally use select.select.
            evt = ctypes.windll.ws2_32.WSACreateEvent()
            created.append(evt)
            res = ctypes.windll.ws2_32.WSAEventSelect(
                ctypes.c_void_p(i.fileno()),
                evt,
                FD_READ
            )
            if res == 0:
                # Was a socket
                events.append(evt)
            else:
                # Fallback to normal event
                events.append(i.fileno())
        elif i.fileno() < 0:
            # Special case: On Windows, we consider that an object that returns
            # a negative fileno (impossible), is always readable. This is used
            # in very few places but important (e.g. PcapReader), where we have
            # no valid fileno (and will stop on EOFError).
            results.add(i)
            remain = 0
        else:
            events.append(i.fileno())
    if events:
        # 0xFFFFFFFF = INFINITE
        remainms = int(remain * 1000 if remain is not None else 0xFFFFFFFF)
        if len(events) == 1:
            res = ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_void_p(events[0]),
                remainms
            )
        else:
            # Sadly, the only way to emulate select() is to first check
            # if any object is available using WaitForMultipleObjects
            # then poll the others.
            res = ctypes.windll.kernel32.WaitForMultipleObjects(
                len(events),
                (ctypes.c_void_p * len(events))(
                    *events
                ),
                False,
                remainms
            )
        if res != 0xFFFFFFFF and res != 0x00000102:  # Failed or Timeout
            results.add(inputs[res])
            if len(events) > 1:
                # Now poll the others, if any
                for i, evt in enumerate(events):
                    res = ctypes.windll.kernel32.WaitForSingleObject(
                        ctypes.c_void_p(evt),
                        0  # poll: don't wait
                    )
                    if res == 0:
                        results.add(inputs[i])
    # Cleanup created events, if any
    for evt in created:
        ctypes.windll.ws2_32.WSACloseEvent(evt)
    return list(results)


_T = TypeVar("_T")


class ObjectPipe(Generic[_T]):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        self.name = name or "ObjectPipe"
        self.closed = False
        self.__rd, self.__wr = os.pipe()
        self.__queue = deque()  # type: Deque[_T]
        if WINDOWS:
            self._wincreate()

    if WINDOWS:
        def _wincreate(self):
            # type: () -> None
            self._fd = cast(int, ctypes.windll.kernel32.CreateEventA(
                None, True, False,
                ctypes.create_string_buffer(b"ObjectPipe %f" % random.random())
            ))

        def _winset(self):
            # type: () -> None
            if ctypes.windll.kernel32.SetEvent(ctypes.c_void_p(self._fd)) == 0:
                warning(ctypes.FormatError(ctypes.GetLastError()))

        def _winreset(self):
            # type: () -> None
            if ctypes.windll.kernel32.ResetEvent(ctypes.c_void_p(self._fd)) == 0:
                warning(ctypes.FormatError(ctypes.GetLastError()))

        def _winclose(self):
            # type: () -> None
            if ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(self._fd)) == 0:
                warning(ctypes.FormatError(ctypes.GetLastError()))

    def fileno(self):
        # type: () -> int
        if WINDOWS:
            return self._fd
        return self.__rd

    def send(self, obj):
        # type: (_T) -> int
        self.__queue.append(obj)
        if WINDOWS:
            self._winset()
        os.write(self.__wr, b"X")
        return 1

    def write(self, obj):
        # type: (_T) -> None
        self.send(obj)

    def empty(self):
        # type: () -> bool
        return not bool(self.__queue)

    def flush(self):
        # type: () -> None
        pass

    def recv(self, n=0, options=socket.MsgFlag(0)):
        # type: (Optional[int], socket.MsgFlag) -> Optional[_T]
        if self.closed:
            raise EOFError
        if options & socket.MSG_PEEK:
            if self.__queue:
                return self.__queue[0]
            return None
        os.read(self.__rd, 1)
        elt = self.__queue.popleft()
        if WINDOWS and not self.__queue:
            self._winreset()
        return elt

    def read(self, n=0):
        # type: (Optional[int]) -> Optional[_T]
        return self.recv(n)

    def clear(self):
        # type: () -> None
        if not self.closed:
            while not self.empty():
                self.recv()

    def close(self):
        # type: () -> None
        if not self.closed:
            self.closed = True
            os.close(self.__rd)
            os.close(self.__wr)
            if WINDOWS:
                try:
                    self._winclose()
                except ImportError:
                    # Python is shutting down
                    pass

    def __repr__(self):
        # type: () -> str
        return "<%s at %s>" % (self.name, id(self))

    def __del__(self):
        # type: () -> None
        self.close()

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        # Only handle ObjectPipes
        results = []
        for s in sockets:
            if s.closed:  # allow read to trigger EOF
                results.append(s)
        if results:
            return results
        return select_objects(sockets, remain)


class Message:
    type = None        # type: str
    pkt = None         # type: Packet
    result = None      # type: str
    state = None       # type: Message
    exc_info = None    # type: Union[Tuple[None, None, None], Tuple[BaseException, Exception, types.TracebackType]] # noqa: E501

    def __init__(self, **args):
        # type: (Any) -> None
        self.__dict__.update(args)

    def __repr__(self):
        # type: () -> str
        return "<Message %s>" % " ".join(
            "%s=%r" % (k, v)
            for k, v in self.__dict__.items()
            if not k.startswith("_")
        )


class Timer():
    def __init__(self, time, prio=0, autoreload=False):
        # type: (Union[int, float], int, bool) -> None
        self._timeout = float(time)  # type: float
        self._time = 0  # type: float
        self._just_expired = True
        self._expired = True
        self._prio = prio
        self._func = _StateWrapper()
        self._autoreload = autoreload

    def get(self):
        # type: () -> float
        return self._timeout

    def set(self, val):
        # type: (float) -> None
        self._timeout = val

    def _reset(self):
        # type: () -> None
        self._time = self._timeout
        self._expired = False
        self._just_expired = False

    def _reset_just_expired(self):
        # type: () -> None
        self._just_expired = False

    def _running(self):
        # type: () -> bool
        return self._time > 0

    def _remaining(self):
        # type: () -> float
        return max(self._time, 0)

    def _decrement(self, time):
        # type: (float) -> None
        self._time -= time
        if self._time <= 0:
            if not self._expired:
                self._just_expired = True
                if self._autoreload:
                    # take overshoot into account
                    self._time = self._timeout + self._time
                else:
                    self._expired = True
                    self._time = 0

    def __lt__(self, obj):
        # type: (Timer) -> bool
        return ((self._time < obj._time) if self._time != obj._time
                else (self._prio < obj._prio))

    def __gt__(self, obj):
        # type: (Timer) -> bool
        return ((self._time > obj._time) if self._time != obj._time
                else (self._prio > obj._prio))

    def __eq__(self, obj):
        # type: (Any) -> bool
        if not isinstance(obj, Timer):
            raise NotImplementedError()
        return (self._time == obj._time) and (self._prio == obj._prio)

    def __repr__(self):
        # type: () -> str
        return "<Timer %f(%f)>" % (self._time, self._timeout)


class _TimerList():
    def __init__(self):
        # type: () -> None
        self.timers = []  # type: list[Timer]

    def add_timer(self, timer):
        # type: (Timer) -> None
        self.timers.append(timer)

    def reset(self):
        # type: () -> None
        for t in self.timers:
            t._reset()

    def decrement(self, time):
        # type: (float) -> None
        for t in self.timers:
            t._decrement(time)

    def expired(self):
        # type: () -> list[Timer]
        lst = [t for t in self.timers if t._just_expired]
        lst.sort(key=lambda x: x._prio, reverse=True)
        for t in lst:
            t._reset_just_expired()
        return lst

    def until_next(self):
        # type: () -> Optional[float]
        try:
            return min([t._remaining() for t in self.timers if t._running()])
        except ValueError:
            return None  # None means blocking

    def count(self):
        # type: () -> int
        return len(self.timers)

    def __iter__(self):
        # type: () -> Iterator[Timer]
        return self.timers.__iter__()

    def __repr__(self):
        # type: () -> str
        return self.timers.__repr__()


class _instance_state:
    def __init__(self, instance):
        # type: (Any) -> None
        self.__self__ = instance.__self__
        self.__func__ = instance.__func__
        self.__self__.__class__ = instance.__self__.__class__

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self.__func__, attr)

    def __call__(self, *args, **kargs):
        # type: (Any, Any) -> Any
        return self.__func__(self.__self__, *args, **kargs)

    def breaks(self):
        # type: () -> Any
        return self.__self__.add_breakpoints(self.__func__)

    def intercepts(self):
        # type: () -> Any
        return self.__self__.add_interception_points(self.__func__)

    def unbreaks(self):
        # type: () -> Any
        return self.__self__.remove_breakpoints(self.__func__)

    def unintercepts(self):
        # type: () -> Any
        return self.__self__.remove_interception_points(self.__func__)


##############
#  Automata  #
##############

class _StateWrapper:
    __name__ = None             # type: str
    atmt_type = None            # type: str
    atmt_state = None           # type: str
    atmt_initial = None         # type: int
    atmt_final = None           # type: int
    atmt_stop = None            # type: int
    atmt_error = None           # type: int
    atmt_origfunc = None        # type: _StateWrapper
    atmt_prio = None            # type: int
    atmt_as_supersocket = None  # type: Optional[str]
    atmt_condname = None        # type: str
    atmt_ioname = None          # type: str
    atmt_timeout = None         # type: Timer
    atmt_cond = None            # type: Dict[str, int]
    __code__ = None             # type: types.CodeType
    __call__ = None             # type: Callable[..., ATMT.NewStateRequested]


class ATMT:
    STATE = "State"
    ACTION = "Action"
    CONDITION = "Condition"
    RECV = "Receive condition"
    TIMEOUT = "Timeout condition"
    EOF = "EOF condition"
    IOEVENT = "I/O event"

    class NewStateRequested(Exception):
        def __init__(self, state_func, automaton, *args, **kargs):
            # type: (Any, ATMT, Any, Any) -> None
            self.func = state_func
            self.state = state_func.atmt_state
            self.initial = state_func.atmt_initial
            self.error = state_func.atmt_error
            self.stop = state_func.atmt_stop
            self.final = state_func.atmt_final
            Exception.__init__(self, "Request state [%s]" % self.state)
            self.automaton = automaton
            self.args = args
            self.kargs = kargs
            self.action_parameters()  # init action parameters

        def action_parameters(self, *args, **kargs):
            # type: (Any, Any) -> ATMT.NewStateRequested
            self.action_args = args
            self.action_kargs = kargs
            return self

        def run(self):
            # type: () -> Any
            return self.func(self.automaton, *self.args, **self.kargs)

        def __repr__(self):
            # type: () -> str
            return "NewStateRequested(%s)" % self.state

    @staticmethod
    def state(initial=0,    # type: int
              final=0,      # type: int
              stop=0,       # type: int
              error=0       # type: int
              ):
        # type: (...) -> Callable[[DecoratorCallable], DecoratorCallable]
        def deco(f, initial=initial, final=final):
            # type: (_StateWrapper, int, int) -> _StateWrapper
            f.atmt_type = ATMT.STATE
            f.atmt_state = f.__name__
            f.atmt_initial = initial
            f.atmt_final = final
            f.atmt_stop = stop
            f.atmt_error = error

            def _state_wrapper(self, *args, **kargs):
                # type: (ATMT, Any, Any) -> ATMT.NewStateRequested
                return ATMT.NewStateRequested(f, self, *args, **kargs)

            state_wrapper = cast(_StateWrapper, _state_wrapper)
            state_wrapper.__name__ = "%s_wrapper" % f.__name__
            state_wrapper.atmt_type = ATMT.STATE
            state_wrapper.atmt_state = f.__name__
            state_wrapper.atmt_initial = initial
            state_wrapper.atmt_final = final
            state_wrapper.atmt_stop = stop
            state_wrapper.atmt_error = error
            state_wrapper.atmt_origfunc = f
            return state_wrapper
        return deco  # type: ignore

    @staticmethod
    def action(cond, prio=0):
        # type: (Any, int) -> Callable[[_StateWrapper, _StateWrapper], _StateWrapper]  # noqa: E501
        def deco(f, cond=cond):
            # type: (_StateWrapper, _StateWrapper) -> _StateWrapper
            if not hasattr(f, "atmt_type"):
                f.atmt_cond = {}
            f.atmt_type = ATMT.ACTION
            f.atmt_cond[cond.atmt_condname] = prio
            return f
        return deco

    @staticmethod
    def condition(state, prio=0):
        # type: (Any, int) -> Callable[[_StateWrapper, _StateWrapper], _StateWrapper]  # noqa: E501
        def deco(f, state=state):
            # type: (_StateWrapper, _StateWrapper) -> Any
            f.atmt_type = ATMT.CONDITION
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_prio = prio
            return f
        return deco

    @staticmethod
    def receive_condition(state, prio=0):
        # type: (_StateWrapper, int) -> Callable[[_StateWrapper, _StateWrapper], _StateWrapper]  # noqa: E501
        def deco(f, state=state):
            # type: (_StateWrapper, _StateWrapper) -> _StateWrapper
            f.atmt_type = ATMT.RECV
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_prio = prio
            return f
        return deco

    @staticmethod
    def ioevent(state,                  # type: _StateWrapper
                name,                   # type: str
                prio=0,                 # type: int
                as_supersocket=None     # type: Optional[str]
                ):
        # type: (...) -> Callable[[_StateWrapper, _StateWrapper], _StateWrapper]  # noqa: E501
        def deco(f, state=state):
            # type: (_StateWrapper, _StateWrapper) -> _StateWrapper
            f.atmt_type = ATMT.IOEVENT
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_ioname = name
            f.atmt_prio = prio
            f.atmt_as_supersocket = as_supersocket
            return f
        return deco

    @staticmethod
    def timeout(state, timeout):
        # type: (_StateWrapper, Union[int, float]) -> Callable[[_StateWrapper, _StateWrapper, Timer], _StateWrapper]  # noqa: E501
        def deco(f, state=state, timeout=Timer(timeout)):
            # type: (_StateWrapper, _StateWrapper, Timer) -> _StateWrapper
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_timeout._func = f
            f.atmt_condname = f.__name__
            return f
        return deco

    @staticmethod
    def timer(state, timeout, prio=0):
        # type: (_StateWrapper, Union[float, int], int) -> Callable[[_StateWrapper, _StateWrapper, Timer], _StateWrapper]  # noqa: E501
        def deco(f, state=state, timeout=Timer(timeout, prio=prio, autoreload=True)):
            # type: (_StateWrapper, _StateWrapper, Timer) -> _StateWrapper
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_timeout._func = f
            f.atmt_condname = f.__name__
            return f
        return deco

    @staticmethod
    def eof(state):
        # type: (_StateWrapper) -> Callable[[_StateWrapper, _StateWrapper], _StateWrapper]  # noqa: E501
        def deco(f, state=state):
            # type: (_StateWrapper, _StateWrapper) -> _StateWrapper
            f.atmt_type = ATMT.EOF
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            return f
        return deco


class _ATMT_Command:
    RUN = "RUN"
    NEXT = "NEXT"
    FREEZE = "FREEZE"
    STOP = "STOP"
    FORCESTOP = "FORCESTOP"
    END = "END"
    EXCEPTION = "EXCEPTION"
    SINGLESTEP = "SINGLESTEP"
    BREAKPOINT = "BREAKPOINT"
    INTERCEPT = "INTERCEPT"
    ACCEPT = "ACCEPT"
    REPLACE = "REPLACE"
    REJECT = "REJECT"


class _ATMT_supersocket(SuperSocket):
    def __init__(self,
                 name,          # type: str
                 ioevent,       # type: str
                 automaton,     # type: Type[Automaton]
                 proto,         # type: Callable[[bytes], Any]
                 *args,         # type: Any
                 **kargs        # type: Any
                 ):
        # type: (...) -> None
        self.name = name
        self.ioevent = ioevent
        self.proto = proto
        # write, read
        self.spa, self.spb = ObjectPipe[Any]("spa"), \
            ObjectPipe[Any]("spb")
        kargs["external_fd"] = {ioevent: (self.spa, self.spb)}
        kargs["is_atmt_socket"] = True
        kargs["atmt_socket"] = self.name
        self.atmt = automaton(*args, **kargs)
        self.atmt.runbg()

    def send(self, s):
        # type: (Any) -> int
        return self.spa.send(s)

    def fileno(self):
        # type: () -> int
        return self.spb.fileno()

    # note: _ATMT_supersocket may return bytes in certain cases, which
    # is expected. We cheat on typing.
    def recv(self, n=MTU, **kwargs):  # type: ignore
        # type: (int, **Any) -> Any
        r = self.spb.recv(n)
        if self.proto is not None and r is not None:
            r = self.proto(r, **kwargs)
        return r

    def close(self):
        # type: () -> None
        if not self.closed:
            self.atmt.stop()
            self.atmt.destroy()
            self.spa.close()
            self.spb.close()
            self.closed = True

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        return select_objects(sockets, remain)


class _ATMT_to_supersocket:
    def __init__(self, name, ioevent, automaton):
        # type: (str, str, Type[Automaton]) -> None
        self.name = name
        self.ioevent = ioevent
        self.automaton = automaton

    def __call__(self, proto, *args, **kargs):
        # type: (Callable[[bytes], Any], Any, Any) -> _ATMT_supersocket
        return _ATMT_supersocket(
            self.name, self.ioevent, self.automaton,
            proto, *args, **kargs
        )


class Automaton_metaclass(type):
    def __new__(cls, name, bases, dct):
        # type: (str, Tuple[Any], Dict[str, Any]) -> Type[Automaton]
        cls = super(Automaton_metaclass, cls).__new__(  # type: ignore
            cls, name, bases, dct
        )
        cls.states = {}
        cls.recv_conditions = {}    # type: Dict[str, List[_StateWrapper]]
        cls.conditions = {}         # type: Dict[str, List[_StateWrapper]]
        cls.ioevents = {}           # type: Dict[str, List[_StateWrapper]]
        cls.timeout = {}            # type: Dict[str, _TimerList]
        cls.eofs = {}               # type: Dict[str, _StateWrapper]
        cls.actions = {}            # type: Dict[str, List[_StateWrapper]]
        cls.initial_states = []     # type: List[_StateWrapper]
        cls.stop_state = None       # type: Optional[_StateWrapper]
        cls.ionames = []
        cls.iosupersockets = []

        members = {}
        classes = [cls]
        while classes:
            c = classes.pop(0)  # order is important to avoid breaking method overloading  # noqa: E501
            classes += list(c.__bases__)
            for k, v in c.__dict__.items():  # type: ignore
                if k not in members:
                    members[k] = v

        decorated = [v for v in members.values()
                     if hasattr(v, "atmt_type")]

        for m in decorated:
            if m.atmt_type == ATMT.STATE:
                s = m.atmt_state
                cls.states[s] = m
                cls.recv_conditions[s] = []
                cls.ioevents[s] = []
                cls.conditions[s] = []
                cls.timeout[s] = _TimerList()
                if m.atmt_initial:
                    cls.initial_states.append(m)
                if m.atmt_stop:
                    if cls.stop_state is not None:
                        raise ValueError("There can only be a single stop state !")
                    cls.stop_state = m
            elif m.atmt_type in [ATMT.CONDITION, ATMT.RECV, ATMT.TIMEOUT, ATMT.IOEVENT, ATMT.EOF]:  # noqa: E501
                cls.actions[m.atmt_condname] = []

        for m in decorated:
            if m.atmt_type == ATMT.CONDITION:
                cls.conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.RECV:
                cls.recv_conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.EOF:
                cls.eofs[m.atmt_state] = m
            elif m.atmt_type == ATMT.IOEVENT:
                cls.ioevents[m.atmt_state].append(m)
                cls.ionames.append(m.atmt_ioname)
                if m.atmt_as_supersocket is not None:
                    cls.iosupersockets.append(m)
            elif m.atmt_type == ATMT.TIMEOUT:
                cls.timeout[m.atmt_state].add_timer(m.atmt_timeout)
            elif m.atmt_type == ATMT.ACTION:
                for co in m.atmt_cond:
                    cls.actions[co].append(m)

        for v in itertools.chain(
            cls.conditions.values(),
            cls.recv_conditions.values(),
            cls.ioevents.values()
        ):
            v.sort(key=lambda x: x.atmt_prio)
        for condname, actlst in cls.actions.items():
            actlst.sort(key=lambda x: x.atmt_cond[condname])

        for ioev in cls.iosupersockets:
            setattr(cls, ioev.atmt_as_supersocket,
                    _ATMT_to_supersocket(
                        ioev.atmt_as_supersocket,
                        ioev.atmt_ioname,
                        cast(Type["Automaton"], cls)))

        # Inject signature
        try:
            import inspect
            cls.__signature__ = inspect.signature(cls.parse_args)  # type: ignore  # noqa: E501
        except (ImportError, AttributeError):
            pass

        return cast(Type["Automaton"], cls)

    def build_graph(self):
        # type: () -> str
        s = 'digraph "%s" {\n' % self.__class__.__name__

        se = ""  # Keep initial nodes at the beginning for better rendering
        for st in self.states.values():
            if st.atmt_initial:
                se = ('\t"%s" [ style=filled, fillcolor=blue, shape=box, root=true];\n' % st.atmt_state) + se  # noqa: E501
            elif st.atmt_final:
                se += '\t"%s" [ style=filled, fillcolor=green, shape=octagon ];\n' % st.atmt_state  # noqa: E501
            elif st.atmt_error:
                se += '\t"%s" [ style=filled, fillcolor=red, shape=octagon ];\n' % st.atmt_state  # noqa: E501
            elif st.atmt_stop:
                se += '\t"%s" [ style=filled, fillcolor=orange, shape=box, root=true ];\n' % st.atmt_state  # noqa: E501
        s += se

        for st in self.states.values():
            names = list(
                st.atmt_origfunc.__code__.co_names +
                st.atmt_origfunc.__code__.co_consts
            )
            while names:
                n = names.pop()
                if n in self.states:
                    s += '\t"%s" -> "%s" [ color=green ];\n' % (st.atmt_state, n)
                elif n in self.__dict__:
                    # function indirection
                    if callable(self.__dict__[n]):
                        names.extend(self.__dict__[n].__code__.co_names)
                        names.extend(self.__dict__[n].__code__.co_consts)

        for c, sty, k, v in (
            [("purple", "solid", k, v) for k, v in self.conditions.items()] +
            [("red", "solid", k, v) for k, v in self.recv_conditions.items()] +
            [("orange", "solid", k, v) for k, v in self.ioevents.items()] +
            [("black", "dashed", k, [v]) for k, v in self.eofs.items()]
        ):
            for f in v:
                names = list(f.__code__.co_names + f.__code__.co_consts)
                while names:
                    n = names.pop()
                    if n in self.states:
                        line = f.atmt_condname
                        for x in self.actions[f.atmt_condname]:
                            line += "\\l>[%s]" % x.__name__
                        s += '\t"%s" -> "%s" [label="%s", color=%s, style=%s];\n' % (
                            k,
                            n,
                            line,
                            c,
                            sty,
                        )
                    elif n in self.__dict__:
                        # function indirection
                        if callable(self.__dict__[n]) and hasattr(self.__dict__[n], "__code__"):  # noqa: E501
                            names.extend(self.__dict__[n].__code__.co_names)
                            names.extend(self.__dict__[n].__code__.co_consts)
        for k, timers in self.timeout.items():
            for timer in timers:
                for n in (timer._func.__code__.co_names +
                          timer._func.__code__.co_consts):
                    if n in self.states:
                        line = "%s/%.1fs" % (timer._func.atmt_condname,
                                             timer.get())
                        for x in self.actions[timer._func.atmt_condname]:
                            line += "\\l>[%s]" % x.__name__
                        s += '\t"%s" -> "%s" [label="%s",color=blue];\n' % (k, n, line)  # noqa: E501
        s += "}\n"
        return s

    def graph(self, **kargs):
        # type: (Any) -> Optional[str]
        s = self.build_graph()
        return do_graph(s, **kargs)


class Automaton(metaclass=Automaton_metaclass):
    states = {}             # type: Dict[str, _StateWrapper]
    state = None            # type: ATMT.NewStateRequested
    recv_conditions = {}    # type: Dict[str, List[_StateWrapper]]
    conditions = {}         # type: Dict[str, List[_StateWrapper]]
    eofs = {}               # type: Dict[str, _StateWrapper]
    ioevents = {}           # type: Dict[str, List[_StateWrapper]]
    timeout = {}            # type: Dict[str, _TimerList]
    actions = {}            # type: Dict[str, List[_StateWrapper]]
    initial_states = []     # type: List[_StateWrapper]
    stop_state = None       # type: Optional[_StateWrapper]
    ionames = []            # type: List[str]
    iosupersockets = []     # type: List[SuperSocket]

    # used for spawn()
    pkt_cls = conf.raw_layer
    socketcls = StreamSocket

    # Internals
    def __init__(self, *args, **kargs):
        # type: (Any, Any) -> None
        external_fd = kargs.pop("external_fd", {})
        if "sock" in kargs:
            # We use a bi-directional sock
            self.sock = kargs["sock"]
        else:
            # Separate sockets
            self.sock = None
            self.send_sock_class = kargs.pop("ll", conf.L3socket)
            self.recv_sock_class = kargs.pop("recvsock", conf.L2listen)
        self.listen_sock = None  # type: Optional[SuperSocket]
        self.send_sock = None  # type: Optional[SuperSocket]
        self.is_atmt_socket = kargs.pop("is_atmt_socket", False)
        self.atmt_socket = kargs.pop("atmt_socket", None)
        self.started = threading.Lock()
        self.threadid = None                # type: Optional[int]
        self.breakpointed = None
        self.breakpoints = set()            # type: Set[_StateWrapper]
        self.interception_points = set()    # type: Set[_StateWrapper]
        self.intercepted_packet = None      # type: Union[None, Packet]
        self.debug_level = 0
        self.init_args = args
        self.init_kargs = kargs
        self.io = type.__new__(type, "IOnamespace", (), {})
        self.oi = type.__new__(type, "IOnamespace", (), {})
        self.cmdin = ObjectPipe[Message]("cmdin")
        self.cmdout = ObjectPipe[Message]("cmdout")
        self.ioin = {}
        self.ioout = {}
        self.packets = PacketList()                 # type: PacketList
        for n in self.__class__.ionames:
            extfd = external_fd.get(n)
            if not isinstance(extfd, tuple):
                extfd = (extfd, extfd)
            ioin, ioout = extfd
            if ioin is None:
                ioin = ObjectPipe("ioin")
            else:
                ioin = self._IO_fdwrapper(ioin, None)
            if ioout is None:
                ioout = ObjectPipe("ioout")
            else:
                ioout = self._IO_fdwrapper(None, ioout)

            self.ioin[n] = ioin
            self.ioout[n] = ioout
            ioin.ioname = n
            ioout.ioname = n
            setattr(self.io, n, self._IO_mixer(ioout, ioin))
            setattr(self.oi, n, self._IO_mixer(ioin, ioout))

        for stname in self.states:
            setattr(self, stname,
                    _instance_state(getattr(self, stname)))

        self.start()

    def parse_args(self, debug=0, store=0, **kargs):
        # type: (int, int, Any) -> None
        self.debug_level = debug
        if debug:
            conf.logLevel = logging.DEBUG
        self.socket_kargs = kargs
        self.store_packets = store

    @classmethod
    def spawn(cls,
              port: int,
              iface: Optional[_GlobInterfaceType] = None,
              bg: bool = False,
              **kwargs: Any) -> Optional[socket.socket]:
        """
        Spawn a TCP server that listens for connections and start the automaton
        for each new client.

        :param port: the port to listen to
        :param bg: background mode? (default: False)

        Note that in background mode, you shall close the TCP server as such::

            srv = MyAutomaton.spawn(8080, bg=True)
            srv.shutdown(socket.SHUT_RDWR)  # important
            srv.close()
        """
        from scapy.arch import get_if_addr
        # create server sock and bind it
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_ip = get_if_addr(iface or conf.iface)
        try:
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        ssock.bind((local_ip, port))
        ssock.listen(5)
        clients = []
        if kwargs.get("verb", True):
            print(conf.color_theme.green(
                "Server %s started listening on %s" % (
                    cls.__name__,
                    (local_ip, port),
                )
            ))

        def _run() -> None:
            # Wait for clients forever
            try:
                while True:
                    atmt_server = None
                    clientsocket, address = ssock.accept()
                    if kwargs.get("verb", True):
                        print(conf.color_theme.gold(
                            "\u2503 Connection received from %s" % repr(address)
                        ))
                    try:
                        # Start atmt class with socket
                        if cls.socketcls is not None:
                            sock = cls.socketcls(clientsocket, cls.pkt_cls)
                        else:
                            sock = clientsocket
                        atmt_server = cls(
                            sock=sock,
                            iface=iface, **kwargs
                        )
                    except OSError:
                        if atmt_server is not None:
                            atmt_server.destroy()
                        if kwargs.get("verb", True):
                            print("X Connection aborted.")
                        if kwargs.get("debug", 0) > 0:
                            traceback.print_exc()
                        continue
                    clients.append((atmt_server, clientsocket))
                    # start atmt
                    atmt_server.runbg()
                    # housekeeping
                    for atmt, clientsocket in clients:
                        if not atmt.isrunning():
                            atmt.destroy()
            except KeyboardInterrupt:
                print("X Exiting.")
                ssock.shutdown(socket.SHUT_RDWR)
            except OSError:
                print("X Server closed.")
                if kwargs.get("debug", 0) > 0:
                    traceback.print_exc()
            finally:
                for atmt, clientsocket in clients:
                    try:
                        atmt.forcestop(wait=False)
                        atmt.destroy()
                    except Exception:
                        pass
                    try:
                        clientsocket.shutdown(socket.SHUT_RDWR)
                        clientsocket.close()
                    except Exception:
                        pass
                ssock.close()
        if bg:
            # Background
            threading.Thread(target=_run).start()
            return ssock
        else:
            # Non-background
            _run()
            return None

    def master_filter(self, pkt):
        # type: (Packet) -> bool
        return True

    def my_send(self, pkt, **kwargs):
        # type: (Packet, **Any) -> None
        if not self.send_sock:
            raise ValueError("send_sock is None !")
        self.send_sock.send(pkt, **kwargs)

    def update_sock(self, sock):
        # type: (SuperSocket) -> None
        """
        Update the socket used by the automata.
        Typically used in an eof event to reconnect.
        """
        self.sock = sock
        if self.listen_sock is not None:
            self.listen_sock = self.sock
        if self.send_sock:
            self.send_sock = self.sock

    def timer_by_name(self, name):
        # type: (str) -> Optional[Timer]
        for _, timers in self.timeout.items():
            for timer in timers:  # type: Timer
                if timer._func.atmt_condname == name:
                    return timer
        return None

    # Utility classes and exceptions
    class _IO_fdwrapper:
        def __init__(self,
                     rd,  # type: Union[int, ObjectPipe[bytes], None]
                     wr  # type: Union[int, ObjectPipe[bytes], None]
                     ):
            # type: (...) -> None
            self.rd = rd
            self.wr = wr
            if isinstance(self.rd, socket.socket):
                self.__selectable_force_select__ = True

        def fileno(self):
            # type: () -> int
            if isinstance(self.rd, int):
                return self.rd
            elif self.rd:
                return self.rd.fileno()
            return 0

        def read(self, n=65535):
            # type: (int) -> Optional[bytes]
            if isinstance(self.rd, int):
                return os.read(self.rd, n)
            elif self.rd:
                return self.rd.recv(n)
            return None

        def write(self, msg):
            # type: (bytes) -> int
            if isinstance(self.wr, int):
                return os.write(self.wr, msg)
            elif self.wr:
                return self.wr.send(msg)
            return 0

        def recv(self, n=65535):
            # type: (int) -> Optional[bytes]
            return self.read(n)

        def send(self, msg):
            # type: (bytes) -> int
            return self.write(msg)

    class _IO_mixer:
        def __init__(self,
                     rd,  # type: ObjectPipe[Any]
                     wr,  # type: ObjectPipe[Any]
                     ):
            # type: (...) -> None
            self.rd = rd
            self.wr = wr

        def fileno(self):
            # type: () -> Any
            if isinstance(self.rd, ObjectPipe):
                return self.rd.fileno()
            return self.rd

        def recv(self, n=None):
            # type: (Optional[int]) -> Any
            return self.rd.recv(n)

        def read(self, n=None):
            # type: (Optional[int]) -> Any
            return self.recv(n)

        def send(self, msg):
            # type: (str) -> int
            return self.wr.send(msg)

        def write(self, msg):
            # type: (str) -> int
            return self.send(msg)

    class AutomatonException(Exception):
        def __init__(self, msg, state=None, result=None):
            # type: (str, Optional[Message], Optional[str]) -> None
            Exception.__init__(self, msg)
            self.state = state
            self.result = result

    class AutomatonError(AutomatonException):
        pass

    class ErrorState(AutomatonException):
        pass

    class Stuck(AutomatonException):
        pass

    class AutomatonStopped(AutomatonException):
        pass

    class Breakpoint(AutomatonStopped):
        pass

    class Singlestep(AutomatonStopped):
        pass

    class InterceptionPoint(AutomatonStopped):
        def __init__(self, msg, state=None, result=None, packet=None):
            # type: (str, Optional[Message], Optional[str], Optional[Packet]) -> None
            Automaton.AutomatonStopped.__init__(self, msg, state=state, result=result)
            self.packet = packet

    class CommandMessage(AutomatonException):
        pass

    # Services
    def debug(self, lvl, msg):
        # type: (int, str) -> None
        if self.debug_level >= lvl:
            log_runtime.debug(msg)

    def isrunning(self):
        # type: () -> bool
        return self.started.locked()

    def send(self, pkt, **kwargs):
        # type: (Packet, **Any) -> None
        if self.state.state in self.interception_points:
            self.debug(3, "INTERCEPT: packet intercepted: %s" % pkt.summary())
            self.intercepted_packet = pkt
            self.cmdout.send(
                Message(type=_ATMT_Command.INTERCEPT,
                        state=self.state, pkt=pkt)
            )
            cmd = self.cmdin.recv()
            if not cmd:
                self.debug(3, "CANCELLED")
                return
            self.intercepted_packet = None
            if cmd.type == _ATMT_Command.REJECT:
                self.debug(3, "INTERCEPT: packet rejected")
                return
            elif cmd.type == _ATMT_Command.REPLACE:
                pkt = cmd.pkt
                self.debug(3, "INTERCEPT: packet replaced by: %s" % pkt.summary())  # noqa: E501
            elif cmd.type == _ATMT_Command.ACCEPT:
                self.debug(3, "INTERCEPT: packet accepted")
            else:
                raise self.AutomatonError("INTERCEPT: unknown verdict: %r" % cmd.type)  # noqa: E501
        self.my_send(pkt, **kwargs)
        self.debug(3, "SENT : %s" % pkt.summary())

        if self.store_packets:
            self.packets.append(pkt.copy())

    def __iter__(self):
        # type: () -> Automaton
        return self

    def __del__(self):
        # type: () -> None
        self.destroy()

    def _run_condition(self, cond, *args, **kargs):
        # type: (_StateWrapper, Any, Any) -> None
        try:
            self.debug(5, "Trying %s [%s]" % (cond.atmt_type, cond.atmt_condname))  # noqa: E501
            cond(self, *args, **kargs)
        except ATMT.NewStateRequested as state_req:
            self.debug(2, "%s [%s] taken to state [%s]" % (cond.atmt_type, cond.atmt_condname, state_req.state))  # noqa: E501
            if cond.atmt_type == ATMT.RECV:
                if self.store_packets:
                    self.packets.append(args[0])
            for action in self.actions[cond.atmt_condname]:
                self.debug(2, "   + Running action [%s]" % action.__name__)
                action(self, *state_req.action_args, **state_req.action_kargs)
            raise
        except Exception as e:
            self.debug(2, "%s [%s] raised exception [%s]" % (cond.atmt_type, cond.atmt_condname, e))  # noqa: E501
            raise
        else:
            self.debug(2, "%s [%s] not taken" % (cond.atmt_type, cond.atmt_condname))  # noqa: E501

    def _do_start(self, *args, **kargs):
        # type: (Any, Any) -> None
        ready = threading.Event()
        _t = threading.Thread(
            target=self._do_control,
            args=(ready,) + (args),
            kwargs=kargs,
            name="scapy.automaton _do_start"
        )
        _t.daemon = True
        _t.start()
        ready.wait()

    def _do_control(self, ready, *args, **kargs):
        # type: (threading.Event, Any, Any) -> None
        with self.started:
            self.threadid = threading.current_thread().ident
            if self.threadid is None:
                self.threadid = 0

            # Update default parameters
            a = args + self.init_args[len(args):]
            k = self.init_kargs.copy()
            k.update(kargs)
            self.parse_args(*a, **k)

            # Start the automaton
            self.state = self.initial_states[0](self)
            self.send_sock = self.sock or self.send_sock_class(**self.socket_kargs)
            if self.recv_conditions:
                # Only start a receiving socket if we have at least one recv_conditions
                self.listen_sock = self.sock or self.recv_sock_class(**self.socket_kargs)  # noqa: E501
            self.packets = PacketList(name="session[%s]" % self.__class__.__name__)

            singlestep = True
            iterator = self._do_iter()
            self.debug(3, "Starting control thread [tid=%i]" % self.threadid)
            # Sync threads
            ready.set()
            try:
                while True:
                    c = self.cmdin.recv()
                    if c is None:
                        return None
                    self.debug(5, "Received command %s" % c.type)
                    if c.type == _ATMT_Command.RUN:
                        singlestep = False
                    elif c.type == _ATMT_Command.NEXT:
                        singlestep = True
                    elif c.type == _ATMT_Command.FREEZE:
                        continue
                    elif c.type == _ATMT_Command.STOP:
                        if self.stop_state:
                            # There is a stop state
                            self.state = self.stop_state()
                            iterator = self._do_iter()
                        else:
                            # Act as FORCESTOP
                            break
                    elif c.type == _ATMT_Command.FORCESTOP:
                        break
                    while True:
                        state = next(iterator)
                        if isinstance(state, self.CommandMessage):
                            break
                        elif isinstance(state, self.Breakpoint):
                            c = Message(type=_ATMT_Command.BREAKPOINT, state=state)  # noqa: E501
                            self.cmdout.send(c)
                            break
                        if singlestep:
                            c = Message(type=_ATMT_Command.SINGLESTEP, state=state)  # noqa: E501
                            self.cmdout.send(c)
                            break
            except (StopIteration, RuntimeError):
                c = Message(type=_ATMT_Command.END,
                            result=self.final_state_output)
                self.cmdout.send(c)
            except Exception as e:
                exc_info = sys.exc_info()
                self.debug(3, "Transferring exception from tid=%i:\n%s" % (self.threadid, "".join(traceback.format_exception(*exc_info))))  # noqa: E501
                m = Message(type=_ATMT_Command.EXCEPTION, exception=e, exc_info=exc_info)  # noqa: E501
                self.cmdout.send(m)
            self.debug(3, "Stopping control thread (tid=%i)" % self.threadid)
            self.threadid = None
            if self.listen_sock:
                self.listen_sock.close()
            if self.send_sock:
                self.send_sock.close()

    def _do_iter(self):
        # type: () -> Iterator[Union[Automaton.AutomatonException, Automaton.AutomatonStopped, ATMT.NewStateRequested, None]] # noqa: E501
        while True:
            try:
                self.debug(1, "## state=[%s]" % self.state.state)

                # Entering a new state. First, call new state function
                if self.state.state in self.breakpoints and self.state.state != self.breakpointed:  # noqa: E501
                    self.breakpointed = self.state.state
                    yield self.Breakpoint("breakpoint triggered on state %s" % self.state.state,  # noqa: E501
                                          state=self.state.state)
                self.breakpointed = None
                state_output = self.state.run()
                if self.state.error:
                    raise self.ErrorState("Reached %s: [%r]" % (self.state.state, state_output),  # noqa: E501
                                          result=state_output, state=self.state.state)  # noqa: E501
                if self.state.final:
                    self.final_state_output = state_output
                    return

                if state_output is None:
                    state_output = ()
                elif not isinstance(state_output, list):
                    state_output = state_output,

                timers = self.timeout[self.state.state]
                # If there are commandMessage, we should skip immediate
                # conditions.
                if not select_objects([self.cmdin], 0):
                    # Then check immediate conditions
                    for cond in self.conditions[self.state.state]:
                        self._run_condition(cond, *state_output)

                    # If still there and no conditions left, we are stuck!
                    if (len(self.recv_conditions[self.state.state]) == 0 and
                        len(self.ioevents[self.state.state]) == 0 and
                            timers.count() == 0):
                        raise self.Stuck("stuck in [%s]" % self.state.state,
                                         state=self.state.state,
                                         result=state_output)

                # Finally listen and pay attention to timeouts
                timers.reset()
                time_previous = time.time()

                fds = [self.cmdin]  # type: List[Union[SuperSocket, ObjectPipe[Any]]]
                select_func = select_objects
                if self.listen_sock and self.recv_conditions[self.state.state]:
                    fds.append(self.listen_sock)
                    select_func = self.listen_sock.select  # type: ignore
                for ioev in self.ioevents[self.state.state]:
                    fds.append(self.ioin[ioev.atmt_ioname])
                while True:
                    time_current = time.time()
                    timers.decrement(time_current - time_previous)
                    time_previous = time_current
                    for timer in timers.expired():
                        self._run_condition(timer._func, *state_output)
                    remain = timers.until_next()

                    self.debug(5, "Select on %r" % fds)
                    r = select_func(fds, remain)
                    self.debug(5, "Selected %r" % r)
                    for fd in r:
                        self.debug(5, "Looking at %r" % fd)
                        if fd == self.cmdin:
                            yield self.CommandMessage("Received command message")  # noqa: E501
                        elif fd == self.listen_sock:
                            try:
                                pkt = self.listen_sock.recv()
                            except EOFError:
                                # Socket was closed abruptly. This will likely only
                                # ever happen when a client socket is passed to the
                                # automaton (not the case when the automaton is
                                # listening on a promiscuous conf.L2sniff)
                                self.listen_sock.close()
                                # False so that it is still reset by update_sock
                                self.listen_sock = False  # type: ignore
                                fds.remove(fd)
                                if self.state.state in self.eofs:
                                    # There is an eof state
                                    eof = self.eofs[self.state.state]
                                    self.debug(2, "Condition EOF [%s] taken" % eof.__name__)  # noqa: E501
                                    raise self.eofs[self.state.state](self)
                                else:
                                    # There isn't. Therefore, it's a closing condition.
                                    raise EOFError("Socket ended arbruptly.")
                            if pkt is not None:
                                if self.master_filter(pkt):
                                    self.debug(3, "RECVD: %s" % pkt.summary())  # noqa: E501
                                    for rcvcond in self.recv_conditions[self.state.state]:  # noqa: E501
                                        self._run_condition(rcvcond, pkt, *state_output)  # noqa: E501
                                else:
                                    self.debug(4, "FILTR: %s" % pkt.summary())  # noqa: E501
                        else:
                            self.debug(3, "IOEVENT on %s" % fd.ioname)
                            for ioevt in self.ioevents[self.state.state]:
                                if ioevt.atmt_ioname == fd.ioname:
                                    self._run_condition(ioevt, fd, *state_output)  # noqa: E501

            except ATMT.NewStateRequested as state_req:
                self.debug(2, "switching from [%s] to [%s]" % (self.state.state, state_req.state))  # noqa: E501
                self.state = state_req
                yield state_req

    def __repr__(self):
        # type: () -> str
        return "<Automaton %s [%s]>" % (
            self.__class__.__name__,
            ["HALTED", "RUNNING"][self.isrunning()]
        )

    # Public API
    def add_interception_points(self, *ipts):
        # type: (Any) -> None
        for ipt in ipts:
            if hasattr(ipt, "atmt_state"):
                ipt = ipt.atmt_state
            self.interception_points.add(ipt)

    def remove_interception_points(self, *ipts):
        # type: (Any) -> None
        for ipt in ipts:
            if hasattr(ipt, "atmt_state"):
                ipt = ipt.atmt_state
            self.interception_points.discard(ipt)

    def add_breakpoints(self, *bps):
        # type: (Any) -> None
        for bp in bps:
            if hasattr(bp, "atmt_state"):
                bp = bp.atmt_state
            self.breakpoints.add(bp)

    def remove_breakpoints(self, *bps):
        # type: (Any) -> None
        for bp in bps:
            if hasattr(bp, "atmt_state"):
                bp = bp.atmt_state
            self.breakpoints.discard(bp)

    def start(self, *args, **kargs):
        # type: (Any, Any) -> None
        if self.isrunning():
            raise ValueError("Already started")
        # Start the control thread
        self._do_start(*args, **kargs)

    def run(self,
            resume=None,    # type: Optional[Message]
            wait=True       # type: Optional[bool]
            ):
        # type: (...) -> Any
        if resume is None:
            resume = Message(type=_ATMT_Command.RUN)
        self.cmdin.send(resume)
        if wait:
            try:
                c = self.cmdout.recv()
                if c is None:
                    return None
            except KeyboardInterrupt:
                self.cmdin.send(Message(type=_ATMT_Command.FREEZE))
                return None
            if c.type == _ATMT_Command.END:
                return c.result
            elif c.type == _ATMT_Command.INTERCEPT:
                raise self.InterceptionPoint("packet intercepted", state=c.state.state, packet=c.pkt)  # noqa: E501
            elif c.type == _ATMT_Command.SINGLESTEP:
                raise self.Singlestep("singlestep state=[%s]" % c.state.state, state=c.state.state)  # noqa: E501
            elif c.type == _ATMT_Command.BREAKPOINT:
                raise self.Breakpoint("breakpoint triggered on state [%s]" % c.state.state, state=c.state.state)  # noqa: E501
            elif c.type == _ATMT_Command.EXCEPTION:
                # this code comes from the `six` module (`.reraise()`)
                # to raise an exception with specified exc_info.
                value = c.exc_info[0]() if c.exc_info[1] is None else c.exc_info[1]  # type: ignore  # noqa: E501
                if value.__traceback__ is not c.exc_info[2]:
                    raise value.with_traceback(c.exc_info[2])
                raise value
        return None

    def runbg(self, resume=None, wait=False):
        # type: (Optional[Message], Optional[bool]) -> None
        self.run(resume, wait)

    def __next__(self):
        # type: () -> Any
        return self.run(resume=Message(type=_ATMT_Command.NEXT))

    def _flush_inout(self):
        # type: () -> None
        # Flush command pipes
        for cmd in [self.cmdin, self.cmdout]:
            cmd.clear()

    def destroy(self):
        # type: () -> None
        """
        Destroys a stopped Automaton: this cleanups all opened file descriptors.
        Required on PyPy for instance where the garbage collector behaves differently.
        """
        if not hasattr(self, "started"):
            return  # was never started.
        if self.isrunning():
            raise ValueError("Can't close running Automaton ! Call stop() beforehand")
        # Close command pipes
        self.cmdin.close()
        self.cmdout.close()
        self._flush_inout()
        # Close opened ioins/ioouts
        for i in itertools.chain(self.ioin.values(), self.ioout.values()):
            if isinstance(i, ObjectPipe):
                i.close()

    def stop(self, wait=True):
        # type: (bool) -> None
        try:
            self.cmdin.send(Message(type=_ATMT_Command.STOP))
        except OSError:
            pass
        if wait:
            with self.started:
                self._flush_inout()

    def forcestop(self, wait=True):
        # type: (bool) -> None
        try:
            self.cmdin.send(Message(type=_ATMT_Command.FORCESTOP))
        except OSError:
            pass
        if wait:
            with self.started:
                self._flush_inout()

    def restart(self, *args, **kargs):
        # type: (Any, Any) -> None
        self.stop()
        self.start(*args, **kargs)

    def accept_packet(self,
                      pkt=None,     # type: Optional[Packet]
                      wait=False    # type: Optional[bool]
                      ):
        # type: (...) -> Any
        rsm = Message()
        if pkt is None:
            rsm.type = _ATMT_Command.ACCEPT
        else:
            rsm.type = _ATMT_Command.REPLACE
            rsm.pkt = pkt
        return self.run(resume=rsm, wait=wait)

    def reject_packet(self,
                      wait=False    # type: Optional[bool]
                      ):
        # type: (...) -> Any
        rsm = Message(type=_ATMT_Command.REJECT)
        return self.run(resume=rsm, wait=wait)
