# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

from __future__ import print_function
import os
import subprocess
import time
import scapy.libs.six as six
from threading import Lock, Thread

from scapy.automaton import (
    Message,
    ObjectPipe,
    select_objects,
)
from scapy.consts import WINDOWS
from scapy.error import log_runtime, warning
from scapy.config import conf
from scapy.utils import get_temp_file, do_graph

from scapy.compat import (
    Any,
    Callable,
    Dict,
    Iterable,
    Optional,
    Set,
    Tuple,
    Union,
    Type,
    TypeVar,
    _Generic_metaclass,
    cast,
)


class PipeEngine(ObjectPipe[str]):
    pipes = {}  # type: Dict[str, Type[Pipe]]

    @classmethod
    def list_pipes(cls):
        # type: () -> None
        for pn, pc in sorted(cls.pipes.items()):
            doc = pc.__doc__ or ""
            if doc:
                doc = doc.splitlines()[0]
            print("%20s: %s" % (pn, doc))

    @classmethod
    def list_pipes_detailed(cls):
        # type: () -> None
        for pn, pc in sorted(cls.pipes.items()):
            if pc.__doc__:
                print("###### %s\n %s" % (pn, pc.__doc__))
            else:
                print("###### %s" % pn)

    def __init__(self, *pipes):
        # type: (*Pipe) -> None
        ObjectPipe.__init__(self, "PipeEngine")
        self.active_pipes = set()  # type: Set[Pipe]
        self.active_sources = set()  # type: Set[Union[Source, PipeEngine]]
        self.active_drains = set()  # type: Set[Pipe]
        self.active_sinks = set()  # type: Set[Pipe]
        self._add_pipes(*pipes)
        self.thread_lock = Lock()
        self.command_lock = Lock()
        self.thread = None  # type: Optional[Thread]

    def __getattr__(self, attr):
        # type: (str) -> Callable[..., Pipe]
        if attr.startswith("spawn_"):
            dname = attr[6:]
            if dname in self.pipes:
                def f(*args, **kargs):
                    # type: (*Any, **Any) -> Pipe
                    k = self.pipes[dname]
                    p = k(*args, **kargs)  # type: Pipe
                    self.add(p)
                    return p
                return f
        raise AttributeError(attr)

    def _read_cmd(self):
        # type: () -> str
        return self.recv()  # type: ignore

    def _write_cmd(self, _cmd):
        # type: (str) -> None
        self.send(_cmd)

    def add_one_pipe(self, pipe):
        # type: (Pipe) -> None
        self.active_pipes.add(pipe)
        if isinstance(pipe, Source):
            self.active_sources.add(pipe)
        if isinstance(pipe, Drain):
            self.active_drains.add(pipe)
        if isinstance(pipe, Sink):
            self.active_sinks.add(pipe)

    def get_pipe_list(self, pipe):
        # type: (Pipe) -> Set[Any]
        def flatten(p,  # type: Any
                    li,  # type: Set[Pipe]
                    ):
            # type: (...) -> None
            li.add(p)
            for q in p.sources | p.sinks | p.high_sources | p.high_sinks:
                if q not in li:
                    flatten(q, li)
        pl = set()  # type: Set[Pipe]
        flatten(pipe, pl)
        return pl

    def _add_pipes(self, *pipes):
        # type: (*Pipe) -> Set[Pipe]
        pl = set()
        for p in pipes:
            pl |= self.get_pipe_list(p)
        pl -= self.active_pipes
        for q in pl:
            self.add_one_pipe(q)
        return pl

    def run(self):
        # type: () -> None
        log_runtime.debug("Pipe engine thread started.")
        try:
            for p in self.active_pipes:
                p.start()
            sources = self.active_sources
            sources.add(self)
            exhausted = set([])  # type: Set[Union[Source, PipeEngine]]
            RUN = True
            STOP_IF_EXHAUSTED = False
            while RUN and (not STOP_IF_EXHAUSTED or len(sources) > 1):
                fds = select_objects(sources, 0.5)
                for fd in fds:
                    if fd is self:
                        cmd = self._read_cmd()
                        if cmd == "X":
                            RUN = False
                            break
                        elif cmd == "B":
                            STOP_IF_EXHAUSTED = True
                        elif cmd == "A":
                            sources = self.active_sources - exhausted
                            sources.add(self)
                        else:
                            warning("Unknown internal pipe engine command: %r."
                                    " Ignoring.", cmd)
                    elif fd in sources:
                        try:
                            fd.deliver()
                        except Exception as e:
                            log_runtime.exception("piping from %s failed: %s",
                                                  fd.name, e)
                        else:
                            if fd.exhausted():
                                exhausted.add(fd)
                                sources.remove(fd)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                for p in self.active_pipes:
                    p.stop()
            finally:
                self.thread_lock.release()
                log_runtime.debug("Pipe engine thread stopped.")

    def start(self):
        # type: () -> None
        if self.thread_lock.acquire(False):
            _t = Thread(target=self.run, name="scapy.pipetool.PipeEngine")
            _t.daemon = True
            _t.start()
            self.thread = _t
        else:
            log_runtime.debug("Pipe engine already running")

    def wait_and_stop(self):
        # type: () -> None
        self.stop(_cmd="B")

    def stop(self, _cmd="X"):
        # type: (str) -> None
        try:
            with self.command_lock:
                if self.thread is not None:
                    self._write_cmd(_cmd)
                    self.thread.join()
                    try:
                        self.thread_lock.release()
                    except Exception:
                        pass
                else:
                    log_runtime.debug("Pipe engine thread not running")
        except KeyboardInterrupt:
            print("Interrupted by user.")

    def add(self, *pipes):
        # type: (*Pipe) -> None
        _pipes = self._add_pipes(*pipes)
        with self.command_lock:
            if self.thread is not None:
                for p in _pipes:
                    p.start()
                self._write_cmd("A")

    def graph(self, **kargs):
        # type: (Any) -> None
        g = ['digraph "pipe" {', "\tnode [shape=rectangle];", ]
        for p in self.active_pipes:
            g.append('\t"%i" [label="%s"];' % (id(p), p.name))
        g.append("")
        g.append("\tedge [color=blue, arrowhead=vee];")
        for p in self.active_pipes:
            for s in p.sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(s)))
        g.append("")
        g.append("\tedge [color=purple, arrowhead=veevee];")
        for p in self.active_pipes:
            for hs in p.high_sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(hs)))
        g.append("")
        g.append("\tedge [color=red, arrowhead=diamond];")
        for p in self.active_pipes:
            for ts in p.trigger_sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(ts)))
        g.append('}')
        graph = "\n".join(g)
        do_graph(graph, **kargs)


class _PipeMeta(_Generic_metaclass):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[Pipe]
        c = cast('Type[Pipe]',
                 super(_PipeMeta, cls).__new__(cls, name, bases, dct))
        PipeEngine.pipes[name] = c
        return c


_S = TypeVar("_S", bound="Sink")
_TS = TypeVar("_TS", bound="TriggerSink")


@six.add_metaclass(_PipeMeta)
class Pipe:
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        self.sources = set()  # type: Set['Pipe']
        self.sinks = set()  # type: Set['Sink']
        self.high_sources = set()  # type: Set['Pipe']
        self.high_sinks = set()  # type: Set['Sink']
        self.trigger_sources = set()  # type: Set['Pipe']
        self.trigger_sinks = set()  # type: Set['TriggerSink']
        if name is None:
            name = "%s" % (self.__class__.__name__)
        self.name = name

    def _send(self, msg):
        # type: (Any) -> None
        for s in self.sinks:
            s.push(msg)

    def _high_send(self, msg):
        # type: (Any) -> None
        for s in self.high_sinks:
            s.high_push(msg)

    def _trigger(self, msg=None):
        # type: (Any) -> None
        for s in self.trigger_sinks:
            s.on_trigger(msg)

    def __gt__(self, other):
        # type: (_S) -> _S
        self.sinks.add(other)
        other.sources.add(self)
        return other

    def __rshift__(self, other):
        # type: (_S) -> _S
        self.high_sinks.add(other)
        other.high_sources.add(self)
        return other

    def __xor__(self, other):
        # type: (_TS) -> _TS
        self.trigger_sinks.add(other)
        other.trigger_sources.add(self)
        return other

    def __hash__(self):
        # type: () -> int
        return object.__hash__(self)

    def __eq__(self, other):
        # type: (Any) -> bool
        return object.__eq__(self, other)

    def __repr__(self):
        # type: () -> str
        ct = conf.color_theme
        s = "%s%s" % (ct.punct("<"), ct.layer_name(self.name))
        if self.sources or self.sinks:
            s += " %s" % ct.punct("[")
            if self.sources:
                s += "%s%s" % (ct.punct(",").join(ct.field_name(s.name) for s in self.sources),  # noqa: E501
                               ct.field_value(">"))
            s += ct.layer_name("#")
            if self.sinks:
                s += "%s%s" % (ct.field_value(">"),
                               ct.punct(",").join(ct.field_name(s.name) for s in self.sinks))  # noqa: E501
            s += ct.punct("]")

        if self.high_sources or self.high_sinks:
            s += " %s" % ct.punct("[")
            if self.high_sources:
                s += "%s%s" % (ct.punct(",").join(ct.field_name(s.name) for s in self.high_sources),  # noqa: E501
                               ct.field_value(">>"))
            s += ct.layer_name("#")
            if self.high_sinks:
                s += "%s%s" % (ct.field_value(">>"),
                               ct.punct(",").join(ct.field_name(s.name) for s in self.high_sinks))  # noqa: E501
            s += ct.punct("]")

        if self.trigger_sources or self.trigger_sinks:
            s += " %s" % ct.punct("[")
            if self.trigger_sources:
                s += "%s%s" % (ct.punct(",").join(ct.field_name(s.name) for s in self.trigger_sources),  # noqa: E501
                               ct.field_value("^"))
            s += ct.layer_name("#")
            if self.trigger_sinks:
                s += "%s%s" % (ct.field_value("^"),
                               ct.punct(",").join(ct.field_name(s.name) for s in self.trigger_sinks))  # noqa: E501
            s += ct.punct("]")

        s += ct.punct(">")
        return s

    def start(self):
        # type: () -> None
        pass

    def stop(self):
        # type: () -> None
        pass


class Source(Pipe, ObjectPipe[Any]):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        Pipe.__init__(self, name=name)
        ObjectPipe.__init__(self, name)
        self.is_exhausted = False

    def _read_message(self):
        # type: () -> Message
        return Message()

    def deliver(self):
        # type: () -> None
        msg = self._read_message
        self._send(msg)

    def exhausted(self):
        # type: () -> bool
        return self.is_exhausted


class Drain(Pipe):
    """Repeat messages from low/high entries to (resp.) low/high exits

    .. code::

         +-------+
      >>-|-------|->>
         |       |
       >-|-------|->
         +-------+
    """

    def push(self, msg):
        # type: (Any) -> None
        self._send(msg)

    def high_push(self, msg):
        # type: (Any) -> None
        self._high_send(msg)


class Sink(Pipe):
    """
    Does nothing; interface to extend for custom sinks.

    All sinks have the following constructor parameters:

    :param name: a human-readable name for the element
    :type name: str
    """
    def push(self, msg):
        # type: (Any) -> None
        """
        Called by :py:class:`PipeEngine` when there is a new message for the
        low entry.

        :param msg: The message data
        :returns: None
        :rtype: None
        """
        pass

    def high_push(self, msg):
        # type: (Any) -> None
        """
        Called by :py:class:`PipeEngine` when there is a new message for the
        high entry.

        :param msg: The message data
        :returns: None
        :rtype: None
        """
        pass

    def __lt__(self, other):
        # type: (_S) -> _S
        other.sinks.add(self)
        self.sources.add(other)
        return other

    def __lshift__(self, other):
        # type: (_S) -> _S
        self.high_sources.add(other)
        other.high_sinks.add(self)
        return other

    def __floordiv__(self, other):
        # type: (_S) -> _S
        self >> other
        other >> self
        return other

    def __mod__(self, other):
        # type: (_S) -> _S
        self > other
        other > self
        return other


class TriggerSink(Sink):
    def on_trigger(self, msg):
        # type: (Any) -> None
        pass


class AutoSource(Source):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        Source.__init__(self, name=name)

    def _gen_data(self, msg):
        # type: (str) -> None
        ObjectPipe.send(self, (msg, False, False))

    def _gen_high_data(self, msg):
        # type: (str) -> None
        ObjectPipe.send(self, (msg, True, False))

    def _exhaust(self):
        # type: () -> None
        ObjectPipe.send(self, (None, None, True))

    def deliver(self):
        # type: () -> None
        msg, high, exhaust = self.recv()  # type: ignore
        if exhaust:
            pass
        if high:
            self._high_send(msg)
        else:
            self._send(msg)


class ThreadGenSource(AutoSource):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        AutoSource.__init__(self, name=name)
        self.RUN = False

    def generate(self):
        # type: () -> None
        pass

    def start(self):
        # type: () -> None
        self.RUN = True
        Thread(target=self.generate,
               name="scapy.pipetool.ThreadGenSource").start()

    def stop(self):
        # type: () -> None
        self.RUN = False


class ConsoleSink(Sink):
    """Print messages on low and high entries to ``stdout``

    .. code::

         +-------+
      >>-|--.    |->>
         | print |
       >-|--'    |->
         +-------+
    """

    def push(self, msg):
        # type: (str) -> None
        print(">" + repr(msg))

    def high_push(self, msg):
        # type: (str) -> None
        print(">>" + repr(msg))


class RawConsoleSink(Sink):
    """Print messages on low and high entries, using os.write

    .. code::

         +-------+
      >>-|--.    |->>
         | write |
       >-|--'    |->
         +-------+

    :param newlines: Include a new-line character after printing each packet.
                     Defaults to True.
    :type newlines: bool
    """

    def __init__(self, name=None, newlines=True):
        # type: (Optional[str], bool) -> None
        Sink.__init__(self, name=name)
        self.newlines = newlines
        self._write_pipe = 1

    def push(self, msg):
        # type: (str) -> None
        if self.newlines:
            msg += "\n"
        os.write(self._write_pipe, msg.encode("utf8"))

    def high_push(self, msg):
        # type: (str) -> None
        if self.newlines:
            msg += "\n"
        os.write(self._write_pipe, msg.encode("utf8"))


class CLIFeeder(AutoSource):
    """Send messages from python command line:

    .. code::

         +--------+
      >>-|        |->>
         | send() |
       >-|   `----|->
         +--------+
    """

    def send(self, msg):
        # type: (str) -> int
        self._gen_data(msg)
        return 1

    def close(self):
        # type: () -> None
        self.is_exhausted = True


class CLIHighFeeder(CLIFeeder):
    """Send messages from python command line to high output:

    .. code::

         +--------+
      >>-|   .----|->>
         | send() |
       >-|        |->
         +--------+
    """

    def send(self, msg):
        # type: (Any) -> int
        self._gen_high_data(msg)
        return 1


class PeriodicSource(ThreadGenSource):
    """Generage messages periodically on low exit:

    .. code::

         +-------+
      >>-|       |->>
         | msg,T |
       >-|  `----|->
         +-------+
    """

    def __init__(self, msg, period, period2=0, name=None):
        # type: (Union[Iterable[Any], Any], int, int, Optional[str]) -> None
        ThreadGenSource.__init__(self, name=name)
        if not isinstance(msg, (list, set, tuple)):
            self.msg = [msg]  # type: Iterable[Any]
        else:
            self.msg = msg
        self.period = period
        self.period2 = period2

    def generate(self):
        # type: () -> None
        while self.RUN:
            empty_gen = True
            for m in self.msg:
                empty_gen = False
                self._gen_data(m)
                time.sleep(self.period)
            if empty_gen:
                self.is_exhausted = True
                self._exhaust()
            time.sleep(self.period2)


class TermSink(Sink):
    """
    Prints messages on the low and high entries, on a separate terminal (xterm
    or cmd).

    .. code::

         +-------+
      >>-|--.    |->>
         | print |
       >-|--'    |->
         +-------+

    :param keepterm: Leave the terminal window open after :py:meth:`~Pipe.stop`
                     is called. Defaults to True.
    :type keepterm: bool
    :param newlines: Include a new-line character after printing each packet.
                     Defaults to True.
    :type newlines: bool
    :param openearly: Automatically starts the terminal when the constructor is
                      called, rather than waiting for :py:meth:`~Pipe.start`.
                      Defaults to True.
    :type openearly: bool
    """

    def __init__(self, name=None, keepterm=True, newlines=True,
                 openearly=True):
        # type: (Optional[str], bool, bool, bool) -> None
        Sink.__init__(self, name=name)
        self.keepterm = keepterm
        self.newlines = newlines
        self.openearly = openearly
        self.opened = False
        if self.openearly:
            self.start()

    if WINDOWS:
        def _start_windows(self):
            # type: () -> None
            if not self.opened:
                self.opened = True
                self.__f = get_temp_file()
                open(self.__f, "a").close()
                self.name = "Scapy" if self.name is None else self.name
                # Start a powershell in a new window and print the PID
                cmd = "$app = Start-Process PowerShell -ArgumentList '-command &{$host.ui.RawUI.WindowTitle=\\\"%s\\\";Get-Content \\\"%s\\\" -wait}' -passthru; echo $app.Id" % (self.name, self.__f.replace("\\", "\\\\"))  # noqa: E501
                proc = subprocess.Popen(
                    [
                        getattr(conf.prog, "powershell"),
                        cmd
                    ],
                    stdout=subprocess.PIPE
                )
                output, _ = proc.communicate()
                # This is the process PID
                self.pid = int(output)
                print("PID: %d" % self.pid)

        def _stop_windows(self):
            # type: () -> None
            if not self.keepterm:
                self.opened = False
                # Recipe to kill process with PID
                # http://code.activestate.com/recipes/347462-terminating-a-subprocess-on-windows/
                import ctypes
                PROCESS_TERMINATE = 1
                handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, self.pid)  # noqa: E501
                ctypes.windll.kernel32.TerminateProcess(handle, -1)
                ctypes.windll.kernel32.CloseHandle(handle)
    else:
        def _start_unix(self):
            # type: () -> None
            if not self.opened:
                self.opened = True
                rdesc, self.wdesc = os.pipe()
                cmd = ["xterm"]
                if self.name is not None:
                    cmd.extend(["-title", self.name])
                if self.keepterm:
                    cmd.append("-hold")
                cmd.extend(["-e", "cat <&%d" % rdesc])
                self.proc = subprocess.Popen(cmd, close_fds=False)
                os.close(rdesc)

        def _stop_unix(self):
            # type: () -> None
            if not self.keepterm:
                self.opened = False
                self.proc.kill()
                self.proc.wait()

    def start(self):
        # type: () -> None
        if WINDOWS:
            return self._start_windows()
        else:
            return self._start_unix()

    def stop(self):
        # type: () -> None
        if WINDOWS:
            return self._stop_windows()
        else:
            return self._stop_unix()

    def _print(self, s):
        # type: (str) -> None
        if self.newlines:
            s += "\n"
        if WINDOWS:
            wdesc = open(self.__f, "a")
            wdesc.write(s)
            wdesc.close()
        else:
            os.write(self.wdesc, s.encode())

    def push(self, msg):
        # type: (str) -> None
        self._print(str(msg))

    def high_push(self, msg):
        # type: (str) -> None
        self._print(str(msg))


class QueueSink(Sink):
    """
    Collects messages on the low and high entries into a :py:class:`Queue`.
    Messages are dequeued with :py:meth:`recv`.
    Both high and low entries share the same :py:class:`Queue`.

    .. code::

         +-------+
      >>-|--.    |->>
         | queue |
       >-|--'    |->
         +-------+
    """

    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        Sink.__init__(self, name=name)
        self.q = six.moves.queue.Queue()

    def push(self, msg):
        # type: (Any) -> None
        self.q.put(msg)

    def high_push(self, msg):
        # type: (Any) -> None
        self.q.put(msg)

    def recv(self, block=True, timeout=None):
        # type: (bool, Optional[int]) -> Optional[Any]
        """
        Reads the next message from the queue.

        If no message is available in the queue, returns None.

        :param block: Blocks execution until a packet is available in the
                      queue. Defaults to True.
        :type block: bool
        :param timeout: Controls how long to wait if ``block=True``. If None
                        (the default), this method will wait forever. If a
                        non-negative number, this is a number of seconds to
                        wait before giving up (and returning None).
        :type timeout: None, int or float
        """
        try:
            return self.q.get(block=block, timeout=timeout)
        except six.moves.queue.Empty:
            return None


class TransformDrain(Drain):
    """Apply a function to messages on low and high entry:

    .. code::

         +-------+
      >>-|--[f]--|->>
         |       |
       >-|--[f]--|->
         +-------+
    """

    def __init__(self, f, name=None):
        # type: (Callable[[Any], None], Optional[str]) -> None
        Drain.__init__(self, name=name)
        self.f = f

    def push(self, msg):
        # type: (Any) -> None
        self._send(self.f(msg))

    def high_push(self, msg):
        # type: (Any) -> None
        self._high_send(self.f(msg))


class UpDrain(Drain):
    """Repeat messages from low entry to high exit:

    .. code::

         +-------+
      >>-|    ,--|->>
         |   /   |
       >-|--'    |->
         +-------+
    """

    def push(self, msg):
        # type: (Any) -> None
        self._high_send(msg)

    def high_push(self, msg):
        # type: (Any) -> None
        pass


class DownDrain(Drain):
    r"""Repeat messages from high entry to low exit:

    .. code::

         +-------+
      >>-|--.    |->>
         |   \   |
       >-|    `--|->
         +-------+
    """

    def push(self, msg):
        # type: (Any) -> None
        pass

    def high_push(self, msg):
        # type: (Any) -> None
        self._send(msg)
