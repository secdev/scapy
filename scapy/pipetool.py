#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

from __future__ import print_function
import os
import subprocess
import collections
import time
import scapy.modules.six as six
from threading import Lock, Thread

from scapy.automaton import Message, select_objects, SelectableObject
from scapy.consts import WINDOWS
from scapy.error import log_interactive, warning
from scapy.config import conf
from scapy.utils import get_temp_file, do_graph


class PipeEngine(SelectableObject):
    pipes = {}

    @classmethod
    def list_pipes(cls):
        for pn, pc in sorted(cls.pipes.items()):
            doc = pc.__doc__ or ""
            if doc:
                doc = doc.splitlines()[0]
            print("%20s: %s" % (pn, doc))

    @classmethod
    def list_pipes_detailed(cls):
        for pn, pc in sorted(cls.pipes.items()):
            if pc.__doc__:
                print("###### %s\n %s" % (pn, pc.__doc__))
            else:
                print("###### %s" % pn)

    def __init__(self, *pipes):
        self.active_pipes = set()
        self.active_sources = set()
        self.active_drains = set()
        self.active_sinks = set()
        self._add_pipes(*pipes)
        self.thread_lock = Lock()
        self.command_lock = Lock()
        self.__fd_queue = collections.deque()
        self.__fdr, self.__fdw = os.pipe()
        self.thread = None

    def __getattr__(self, attr):
        if attr.startswith("spawn_"):
            dname = attr[6:]
            if dname in self.pipes:
                def f(*args, **kargs):
                    k = self.pipes[dname]
                    p = k(*args, **kargs)
                    self.add(p)
                    return p
                return f
        raise AttributeError(attr)

    def check_recv(self):
        """As select.select is not available, we check if there
        is some data to read by using a list that stores pointers."""
        return len(self.__fd_queue) > 0

    def fileno(self):
        return self.__fdr

    def _read_cmd(self):
        os.read(self.__fdr, 1)
        return self.__fd_queue.popleft()

    def _write_cmd(self, _cmd):
        self.__fd_queue.append(_cmd)
        os.write(self.__fdw, b"X")
        self.call_release()

    def add_one_pipe(self, pipe):
        self.active_pipes.add(pipe)
        if isinstance(pipe, Source):
            self.active_sources.add(pipe)
        if isinstance(pipe, Drain):
            self.active_drains.add(pipe)
        if isinstance(pipe, Sink):
            self.active_sinks.add(pipe)

    def get_pipe_list(self, pipe):
        def flatten(p, l):
            l.add(p)
            for q in p.sources | p.sinks | p.high_sources | p.high_sinks:
                if q not in l:
                    flatten(q, l)
        pl = set()
        flatten(pipe, pl)
        return pl

    def _add_pipes(self, *pipes):
        pl = set()
        for p in pipes:
            pl |= self.get_pipe_list(p)
        pl -= self.active_pipes
        for q in pl:
            self.add_one_pipe(q)
        return pl

    def run(self):
        log_interactive.info("Pipe engine thread started.")
        try:
            for p in self.active_pipes:
                p.start()
            sources = self.active_sources
            sources.add(self)
            exhausted = set([])
            RUN = True
            STOP_IF_EXHAUSTED = False
            while RUN and (not STOP_IF_EXHAUSTED or len(sources) > 1):
                fds = select_objects(sources, 2)
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
                            warning("Unknown internal pipe engine command: %r. Ignoring." % cmd)  # noqa: E501
                    elif fd in sources:
                        try:
                            fd.deliver()
                        except Exception as e:
                            log_interactive.exception("piping from %s failed: %s" % (fd.name, e))  # noqa: E501
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
                log_interactive.info("Pipe engine thread stopped.")

    def start(self):
        if self.thread_lock.acquire(0):
            _t = Thread(target=self.run)
            _t.setDaemon(True)
            _t.start()
            self.thread = _t
        else:
            warning("Pipe engine already running")

    def wait_and_stop(self):
        self.stop(_cmd="B")

    def stop(self, _cmd="X"):
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
                    warning("Pipe engine thread not running")
        except KeyboardInterrupt:
            print("Interrupted by user.")

    def add(self, *pipes):
        pipes = self._add_pipes(*pipes)
        with self.command_lock:
            if self.thread is not None:
                for p in pipes:
                    p.start()
                self._write_cmd("A")

    def graph(self, **kargs):
        g = ['digraph "pipe" {', "\tnode [shape=rectangle];", ]
        for p in self.active_pipes:
            g.append('\t"%i" [label="%s"];' % (id(p), p.name))
        g.append("")
        g.append("\tedge [color=blue, arrowhead=vee];")
        for p in self.active_pipes:
            for q in p.sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(q)))
        g.append("")
        g.append("\tedge [color=purple, arrowhead=veevee];")
        for p in self.active_pipes:
            for q in p.high_sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(q)))
        g.append("")
        g.append("\tedge [color=red, arrowhead=diamond];")
        for p in self.active_pipes:
            for q in p.trigger_sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(q)))
        g.append('}')
        graph = "\n".join(g)
        do_graph(graph, **kargs)


class _ConnectorLogic(object):
    def __init__(self):
        self.sources = set()
        self.sinks = set()
        self.high_sources = set()
        self.high_sinks = set()
        self.trigger_sources = set()
        self.trigger_sinks = set()

    def __lt__(self, other):
        other.sinks.add(self)
        self.sources.add(other)
        return other

    def __gt__(self, other):
        self.sinks.add(other)
        other.sources.add(self)
        return other

    def __eq__(self, other):
        self > other
        other > self
        return other

    def __lshift__(self, other):
        self.high_sources.add(other)
        other.high_sinks.add(self)
        return other

    def __rshift__(self, other):
        self.high_sinks.add(other)
        other.high_sources.add(self)
        return other

    def __floordiv__(self, other):
        self >> other
        other >> self
        return other

    def __xor__(self, other):
        self.trigger_sinks.add(other)
        other.trigger_sources.add(self)
        return other

    def __hash__(self):
        return object.__hash__(self)


class _PipeMeta(type):
    def __new__(cls, name, bases, dct):
        c = type.__new__(cls, name, bases, dct)
        PipeEngine.pipes[name] = c
        return c


class Pipe(six.with_metaclass(_PipeMeta, _ConnectorLogic)):
    def __init__(self, name=None):
        _ConnectorLogic.__init__(self)
        if name is None:
            name = "%s" % (self.__class__.__name__)
        self.name = name

    def _send(self, msg):
        for s in self.sinks:
            s.push(msg)

    def _high_send(self, msg):
        for s in self.high_sinks:
            s.high_push(msg)

    def _trigger(self, msg=None):
        for s in self.trigger_sinks:
            s.on_trigger(msg)

    def __repr__(self):
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


class Source(Pipe, SelectableObject):
    def __init__(self, name=None):
        Pipe.__init__(self, name=name)
        self.is_exhausted = False

    def _read_message(self):
        return Message()

    def deliver(self):
        msg = self._read_message
        self._send(msg)

    def fileno(self):
        return None

    def check_recv(self):
        return False

    def exhausted(self):
        return self.is_exhausted

    def start(self):
        pass

    def stop(self):
        pass


class Drain(Pipe):
    """Repeat messages from low/high entries to (resp.) low/high exits
     +-------+
  >>-|-------|->>
     |       |
   >-|-------|->
     +-------+
"""

    def push(self, msg):
        self._send(msg)

    def high_push(self, msg):
        self._high_send(msg)

    def start(self):
        pass

    def stop(self):
        pass


class Sink(Pipe):
    def push(self, msg):
        pass

    def high_push(self, msg):
        pass

    def start(self):
        pass

    def stop(self):
        pass


class AutoSource(Source, SelectableObject):
    def __init__(self, name=None):
        Source.__init__(self, name=name)
        self.__fdr, self.__fdw = os.pipe()
        self._queue = collections.deque()

    def fileno(self):
        return self.__fdr

    def check_recv(self):
        return len(self._queue) > 0

    def _gen_data(self, msg):
        self._queue.append((msg, False))
        self._wake_up()

    def _gen_high_data(self, msg):
        self._queue.append((msg, True))
        self._wake_up()

    def _wake_up(self):
        os.write(self.__fdw, b"X")
        self.call_release()

    def deliver(self):
        os.read(self.__fdr, 1)
        try:
            msg, high = self._queue.popleft()
        except IndexError:  # empty queue. Exhausted source
            pass
        else:
            if high:
                self._high_send(msg)
            else:
                self._send(msg)


class ThreadGenSource(AutoSource):
    def __init__(self, name=None):
        AutoSource.__init__(self, name=name)
        self.RUN = False

    def generate(self):
        pass

    def start(self):
        self.RUN = True
        Thread(target=self.generate).start()

    def stop(self):
        self.RUN = False


class ConsoleSink(Sink):
    """Print messages on low and high entries
     +-------+
  >>-|--.    |->>
     | print |
   >-|--'    |->
     +-------+
"""

    def push(self, msg):
        print(">%r" % msg)

    def high_push(self, msg):
        print(">>%r" % msg)


class RawConsoleSink(Sink):
    """Print messages on low and high entries, using os.write
     +-------+
  >>-|--.    |->>
     | write |
   >-|--'    |->
     +-------+
"""

    def __init__(self, name=None, newlines=True):
        Sink.__init__(self, name=name)
        self.newlines = newlines
        self._write_pipe = 1

    def push(self, msg):
        if self.newlines:
            msg += "\n"
        os.write(self._write_pipe, msg.encode("utf8"))

    def high_push(self, msg):
        if self.newlines:
            msg += "\n"
        os.write(self._write_pipe, msg.encode("utf8"))


class CLIFeeder(AutoSource):
    """Send messages from python command line
     +--------+
  >>-|        |->>
     | send() |
   >-|   `----|->
     +--------+
"""

    def send(self, msg):
        self._gen_data(msg)

    def close(self):
        self.is_exhausted = True


class CLIHighFeeder(CLIFeeder):
    """Send messages from python command line to high output
     +--------+
  >>-|   .----|->>
     | send() |
   >-|        |->
     +--------+
"""

    def send(self, msg):
        self._gen_high_data(msg)


class PeriodicSource(ThreadGenSource):
    """Generage messages periodically on low exit
     +-------+
  >>-|       |->>
     | msg,T |
   >-|  `----|->
     +-------+
"""

    def __init__(self, msg, period, period2=0, name=None):
        ThreadGenSource.__init__(self, name=name)
        if not isinstance(msg, (list, set, tuple)):
            msg = [msg]
        self.msg = msg
        self.period = period
        self.period2 = period2

    def generate(self):
        while self.RUN:
            empty_gen = True
            for m in self.msg:
                empty_gen = False
                self._gen_data(m)
                time.sleep(self.period)
            if empty_gen:
                self.is_exhausted = True
                self._wake_up()
            time.sleep(self.period2)


class TermSink(Sink):
    """Print messages on low and high entries on a separate terminal
     +-------+
  >>-|--.    |->>
     | print |
   >-|--'    |->
     +-------+
"""

    def __init__(self, name=None, keepterm=True, newlines=True, openearly=True):  # noqa: E501
        Sink.__init__(self, name=name)
        self.keepterm = keepterm
        self.newlines = newlines
        self.openearly = openearly
        self.opened = False
        if self.openearly:
            self.start()

    def _start_windows(self):
        if not self.opened:
            self.opened = True
            self.__f = get_temp_file()
            open(self.__f, "a").close()
            self.name = "Scapy" if self.name is None else self.name
            # Start a powershell in a new window and print the PID
            cmd = "$app = Start-Process PowerShell -ArgumentList '-command &{$host.ui.RawUI.WindowTitle=\\\"%s\\\";Get-Content \\\"%s\\\" -wait}' -passthru; echo $app.Id" % (self.name, self.__f.replace("\\", "\\\\"))  # noqa: E501
            proc = subprocess.Popen([conf.prog.powershell, cmd], stdout=subprocess.PIPE)  # noqa: E501
            output, _ = proc.communicate()
            # This is the process PID
            self.pid = int(output)
            print("PID: %d" % self.pid)

    def _start_unix(self):
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

    def start(self):
        if WINDOWS:
            return self._start_windows()
        else:
            return self._start_unix()

    def _stop_windows(self):
        if not self.keepterm:
            self.opened = False
            # Recipe to kill process with PID
            # http://code.activestate.com/recipes/347462-terminating-a-subprocess-on-windows/
            import ctypes
            PROCESS_TERMINATE = 1
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, self.pid)  # noqa: E501
            ctypes.windll.kernel32.TerminateProcess(handle, -1)
            ctypes.windll.kernel32.CloseHandle(handle)

    def _stop_unix(self):
        if not self.keepterm:
            self.opened = False
            self.proc.kill()
            self.proc.wait()

    def stop(self):
        if WINDOWS:
            return self._stop_windows()
        else:
            return self._stop_unix()

    def _print(self, s):
        if self.newlines:
            s += "\n"
        if WINDOWS:
            wdesc = open(self.__f, "a")
            wdesc.write(s)
            wdesc.close()
        else:
            os.write(self.wdesc, s.encode())

    def push(self, msg):
        self._print(str(msg))

    def high_push(self, msg):
        self._print(str(msg))


class QueueSink(Sink):
    """Collect messages from high and low entries and queue them. Messages are unqueued with the .recv() method.  # noqa: E501
     +-------+
  >>-|--.    |->>
     | queue |
   >-|--'    |->
     +-------+
"""

    def __init__(self, name=None):
        Sink.__init__(self, name=name)
        self.q = six.moves.queue.Queue()

    def push(self, msg):
        self.q.put(msg)

    def high_push(self, msg):
        self.q.put(msg)

    def recv(self):
        while True:
            try:
                return self.q.get(True, timeout=0.1)
            except six.moves.queue.Empty:
                pass


class TransformDrain(Drain):
    """Apply a function to messages on low and high entry
     +-------+
  >>-|--[f]--|->>
     |       |
   >-|--[f]--|->
     +-------+
"""

    def __init__(self, f, name=None):
        Drain.__init__(self, name=name)
        self.f = f

    def push(self, msg):
        self._send(self.f(msg))

    def high_push(self, msg):
        self._high_send(self.f(msg))


class UpDrain(Drain):
    """Repeat messages from low entry to high exit
     +-------+
  >>-|    ,--|->>
     |   /   |
   >-|--'    |->
     +-------+
"""

    def push(self, msg):
        self._high_send(msg)

    def high_push(self, msg):
        pass


class DownDrain(Drain):
    r"""Repeat messages from high entry to low exit
     +-------+
  >>-|--.    |->>
     |   \   |
   >-|    `--|->
     +-------+
"""

    def push(self, msg):
        pass

    def high_push(self, msg):
        self._send(msg)
