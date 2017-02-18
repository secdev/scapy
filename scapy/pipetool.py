#! /usr/bin/env python

## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os, thread, select
import subprocess
import itertools
import collections
import time
import Queue
import scapy.utils

from scapy.error import log_interactive, warning
from scapy.config import conf

class PipeEngine:
    pipes = {}
    @classmethod
    def list_pipes(cls):
        for pn,pc in sorted(cls.pipes.items()):
            doc = pc.__doc__ or ""
            if doc:
                doc = doc.splitlines()[0]
            print "%20s: %s" % (pn, doc)
    @classmethod
    def list_pipes_detailed(cls):
        for pn,pc in sorted(cls.pipes.items()):
            if pc.__doc__:
                print "###### %s\n %s" % (pn ,pc.__doc__)
            else:
                print "###### %s" % pn
    
    def __init__(self, *pipes):
        self.active_pipes = set()
        self.active_sources = set()
        self.active_drains = set()
        self.active_sinks = set()
        self._add_pipes(*pipes)
        self.thread_lock = thread.allocate_lock()
        self.command_lock = thread.allocate_lock()
        self.__fdr,self.__fdw = os.pipe()
        self.threadid = None
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
            for q in p.sources|p.sinks|p.high_sources|p.high_sinks:
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
            sources.add(self.__fdr)
            exhausted = set([])
            RUN=True
            STOP_IF_EXHAUSTED = False
            while RUN and (not STOP_IF_EXHAUSTED or len(sources) > 1):
                fds,fdo,fde=select.select(sources,[],[])
                for fd in fds:
                    if fd is self.__fdr:
                        cmd = os.read(self.__fdr,1)
                        if cmd == "X":
                            RUN=False
                            break
                        elif cmd == "B":
                            STOP_IF_EXHAUSTED = True
                        elif cmd == "A":
                            sources = self.active_sources-exhausted
                            sources.add(self.__fdr)
                        else:
                            warning("Unknown internal pipe engine command: %r. Ignoring." % cmd)
                    elif fd in sources:
                        try:
                            fd.deliver()
                        except Exception,e:
                            log_interactive.exception("piping from %s failed: %s" % (fd.name, e))
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
            self.threadid = thread.start_new_thread(self.run,())
        else:
            warning("Pipe engine already running")
    def wait_and_stop(self):
        self.stop(_cmd="B")
    def stop(self, _cmd="X"):
        try:
            with self.command_lock:
                if self.threadid is not None:
                    os.write(self.__fdw, _cmd)
                    while not self.thread_lock.acquire(0):
                        time.sleep(0.01) # interruptible wait for thread to terminate
                    self.thread_lock.release() # (not using .join() because it needs 'threading' module)
                else:
                    warning("Pipe engine thread not running")
        except KeyboardInterrupt:
            print "Interrupted by user."

    def add(self, *pipes):
        pipes = self._add_pipes(*pipes)
        with self.command_lock:
            if self.threadid is not None:
                for p in pipes:
                    p.start()
                os.write(self.__fdw, "A")
    
    def graph(self,**kargs):
        g=['digraph "pipe" {',"\tnode [shape=rectangle];",]
        for p in self.active_pipes:
            g.append('\t"%i" [label="%s"];' % (id(p), p.name))
        g.append("")
        g.append("\tedge [color=blue, arrowhead=vee];")
        for p in self.active_pipes:
            for q in p.sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(q)))
        g.append("")
        g.append("\tedge [color=red, arrowhead=veevee];")
        for p in self.active_pipes:
            for q in p.high_sinks:
                g.append('\t"%i" -> "%i" [color="red"];' % (id(p), id(q)))
        g.append('}')
        graph = "\n".join(g)
        scapy.utils.do_graph(graph, **kargs) 


class _ConnectorLogic(object):
    def __init__(self):
        self.sources = set()
        self.sinks = set()
        self.high_sources = set()
        self.high_sinks = set()

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


class Pipe(_ConnectorLogic):
    class __metaclass__(type):
        def __new__(cls, name, bases, dct):
            c = type.__new__(cls, name, bases, dct)
            PipeEngine.pipes[name] = c
            return c
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

    def __repr__(self):
        ct = conf.color_theme
        s = "%s%s" % (ct.punct("<"), ct.layer_name(self.name))
        if self.sources or self.sinks:
            s+= " %s" % ct.punct("[")
            if self.sources:
                s+="%s%s" %  (ct.punct(",").join(ct.field_name(s.name) for s in self.sources),
                              ct.field_value(">"))
            s += ct.layer_name("#")
            if self.sinks:
                s+="%s%s" % (ct.field_value(">"),
                             ct.punct(",").join(ct.field_name(s.name) for s in self.sinks))
            s += ct.punct("]")

        if self.high_sources or self.high_sinks:
            s+= " %s" % ct.punct("[")
            if self.high_sources:
                s+="%s%s" %  (ct.punct(",").join(ct.field_name(s.name) for s in self.high_sources),
                              ct.field_value(">>"))
            s += ct.layer_name("#")
            if self.high_sinks:
                s+="%s%s" % (ct.field_value(">>"),
                             ct.punct(",").join(ct.field_name(s.name) for s in self.high_sinks))
            s += ct.punct("]")


        s += ct.punct(">")
        return s

class Source(Pipe):
    def __init__(self, name=None):
        Pipe.__init__(self, name=name)
        self.is_exhausted = False
    def _read_message(self):
        from scapy.automaton import Message
        return Message()
    def deliver(self):
        msg = self._read_message
        self._send(msg)
    def fileno(self):
        return None
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


class AutoSource(Source):
    def __init__(self, name=None):
        Source.__init__(self, name=name)
        self.__fdr,self.__fdw = os.pipe()
        self._queue = collections.deque()
    def fileno(self):
        return self.__fdr
    def _gen_data(self, msg):
        self._queue.append((msg,False))
        self._wake_up()
    def _gen_high_data(self, msg):
        self._queue.append((msg,True))
        self._wake_up()
    def _wake_up(self):
        os.write(self.__fdw,"x")
    def deliver(self):
        os.read(self.__fdr,1)
        try:
            msg,high = self._queue.popleft()
        except IndexError: #empty queue. Exhausted source
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
        thread.start_new_thread(self.generate,())
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
        print ">%r" % msg
    def high_push(self, msg):
        print ">>%r" % msg

class RawConsoleSink(Sink):
    """Print messages on low and high entries
     +-------+
  >>-|--.    |->>
     | write |
   >-|--'    |->
     +-------+
"""
    def __init__(self, name=None, newlines=True):
        Sink.__init__(self, name=name)
        self.newlines = newlines
    def push(self, msg):
        if self.newlines:
            msg += "\n"
        os.write(1, str(msg))
    def high_push(self, msg):
        if self.newlines:
            msg += "\n"
        os.write(1, str(msg))

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
        ThreadGenSource.__init__(self,name=name)
        if not hasattr(msg, "__iter__"):
            msg=[msg]
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
    def __init__(self, name=None, keepterm=True, newlines=True, openearly=True):
        Sink.__init__(self, name=name)
        self.keepterm = keepterm
        self.newlines = newlines
        self.openearly = openearly
        self.opened = False
        if self.openearly:
            self.start()

    def start(self):
        if not self.opened:
            self.opened = True
            self.__r,self.__w = os.pipe()
            cmd = ["xterm"]
            if self.name is not None:
                cmd.extend(["-title",self.name])
            if self.keepterm:
                cmd.append("-hold")
            cmd.extend(["-e", "cat 0<&%i" % self.__r])
            self.__p = subprocess.Popen(cmd)
            os.close(self.__r)
    def stop(self):
        if not self.keepterm:
            self.opened = False
            os.close(self.__w)
            self.__p.kill()
            self.__p.wait()
    def _print(self, s):
        if self.newlines:
            s+="\n"
        os.write(self.__w, s)
            
    def push(self, msg):
        self._print(str(msg))
    def high_push(self, msg):
        self._print(str(msg))
    

class QueueSink(Sink):
    """Collect messages from high and low entries and queue them. Messages are unqueued with the .recv() method.
     +-------+
  >>-|--.    |->>
     | queue |
   >-|--'    |->
     +-------+
"""
    def __init__(self, name=None):
        Sink.__init__(self, name=name)
        self.q = Queue.Queue()
    def push(self, msg):
        self.q.put(msg)
    def high_push(self, msg):
        self.q.put(msg)
    def recv(self):
        while True:
            try:
                return self.q.get(True, timeout=0.1)
            except Queue.Empty:
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
    """Repeat messages from high entry to low exit
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
        

def _testmain():
    s = PeriodicSource("hello", 1, name="src")
    d1 = Drain(name="d1")
    c = ConsoleSink(name="c")
    tf = TransformDrain(lambda x:"Got %r" % x)
    t = TermSink(name="t", keepterm=False)

    s > d1 > c
    d1 > tf > t

    p = PipeEngine(s)

    p.graph(type="png",target="> /tmp/pipe.png")

    p.start()
    print p.threadid
    time.sleep(5)
    p.stop()


if __name__ == "__main__":
    _testmain()
