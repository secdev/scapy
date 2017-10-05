## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from __future__ import print_function
import socket
from scapy.modules.six.moves.queue import Queue, Empty
from scapy.pipetool import Source,Drain,Sink
from scapy.config import conf
from scapy.compat import *
from scapy.utils import PcapReader, PcapWriter
from scapy.automaton import recv_error

class SniffSource(Source):
    """Read packets from an interface and send them to low exit.
     +-----------+
  >>-|           |->>
     |           |
   >-|  [iface]--|->
     +-----------+
"""
    def __init__(self, iface=None, filter=None, name=None):
        Source.__init__(self, name=name)
        self.iface = iface
        self.filter = filter
    def start(self):
        self.s = conf.L2listen(iface=self.iface, filter=self.filter)
    def stop(self):
        self.s.close()
    def fileno(self):
        return self.s.fileno()
    def check_recv(self):
        return True
    def deliver(self):
        try:
            self._send(self.s.recv())
        except recv_error:
            if not WINDOWS:
                raise

class RdpcapSource(Source):
    """Read packets from a PCAP file send them to low exit.
     +----------+
  >>-|          |->>
     |          |
   >-|  [pcap]--|->
     +----------+
"""
    def __init__(self, fname, name=None):
        Source.__init__(self, name=name)
        self.fname = fname
        self.f = PcapReader(self.fname)
    def start(self):
        print("start")
        self.f = PcapReader(self.fname)
        self.is_exhausted = False
    def stop(self):
        print("stop")
        self.f.close()
    def fileno(self):
        return self.f.fileno()
    def check_recv(self):
        return True
    def deliver(self):    
        p = self.f.recv()
        print("deliver %r" % p)
        if p is None:
            self.is_exhausted = True
        else:
            self._send(p)


class InjectSink(Sink):
    """Packets received on low input are injected to an interface
     +-----------+
  >>-|           |->>
     |           |
   >-|--[iface]  |->
     +-----------+
"""
    def __init__(self, iface=None, name=None):
        Sink.__init__(self, name=name)
        if iface == None:
            iface = conf.iface
        self.iface = iface
    def start(self):
        self.s = conf.L2socket(iface=self.iface)
    def stop(self):
        self.s.close()
    def push(self, msg):
        self.s.send(msg)

class Inject3Sink(InjectSink):
    def start(self):
        self.s = conf.L3socket(iface=self.iface)
    
    
class WrpcapSink(Sink):
    """Packets received on low input are written to PCA file
     +----------+
  >>-|          |->>
     |          |
   >-|--[pcap]  |->
     +----------+
"""
    def __init__(self, fname, name=None):
        Sink.__init__(self, name=name)
        self.f = PcapWriter(fname)
    def stop(self):
        self.f.flush()
        self.f.close()
    def push(self, msg):
        self.f.write(msg)
        

class UDPDrain(Drain):
    """UDP payloads received on high entry are sent over UDP
     +-------------+
  >>-|--[payload]--|->>
     |      X      |
   >-|----[UDP]----|->
     +-------------+
"""
    def __init__(self, ip="127.0.0.1", port=1234):
        Drain.__init__(self)
        self.ip = ip
        self.port = port

    def push(self, msg):
        from scapy.layers.inet import IP, UDP
        if IP in msg and msg[IP].proto == 17 and UDP in msg:
            payload = msg[UDP].payload
            self._high_send(raw(payload))
    def high_push(self, msg):
        from scapy.layers.inet import IP, UDP
        p = IP(dst=self.ip)/UDP(sport=1234,dport=self.port)/msg
        self._send(p)
        

class FDSourceSink(Source):
    """Use a file descriptor as source and sink
     +-------------+
  >>-|             |->>
     |             |
   >-|-[file desc]-|->
     +-------------+
"""
    def __init__(self, fd, name=None):
        Source.__init__(self, name=name)
        self.fd = fd
    def push(self, msg):
        self.fd.write(msg)
    def fileno(self):
        return self.fd.fileno()
    def deliver(self):
        self._send(self.fd.read())


class TCPConnectPipe(Source):
    """TCP connect to addr:port and use it as source and sink
     +-------------+
  >>-|             |->>
     |             |
   >-|-[addr:port]-|->
     +-------------+
"""
    __selectable_force_select__ = True
    def __init__(self, addr="", port=0, name=None):
        Source.__init__(self, name=name)
        self.addr = addr
        self.port = port
        self.fd = None
    def start(self):
        self.fd = socket.socket()
        self.fd.connect((self.addr,self.port))
    def stop(self):
        if self.fd:
            self.fd.close()
    def push(self, msg):
        self.fd.send(msg)
    def fileno(self):
        return self.fd.fileno()
    def deliver(self):
        try:
            msg = self.fd.recv(65536)
        except socket.error:
            self.stop()
            raise
        if msg:
            self._send(msg)

class TCPListenPipe(TCPConnectPipe):
    """TCP listen on [addr:]port and use first connection as source and sink ; send peer address to high output
     +------^------+
  >>-|    +-[peer]-|->>
     |   /         |
   >-|-[addr:port]-|->
     +-------------+
"""
    __selectable_force_select__ = True
    def __init__(self, addr="", port=0, name=None):
        TCPConnectPipe.__init__(self, addr, port, name)
        self.connected = False
        self.q = Queue()
    def start(self):
        self.connected = False
        self.fd = socket.socket()
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fd.bind((self.addr,self.port))
        self.fd.listen(1)
    def push(self, msg):
        if self.connected:
            self.fd.send(msg)
        else:
            self.q.put(msg)
    def deliver(self):
        if self.connected:
            try:
                msg = self.fd.recv(65536)
            except socket.error:
                self.stop()
                raise
            if msg:
                self._send(msg)
        else:
            fd,frm = self.fd.accept()
            self._high_send(frm)
            self.fd.close()
            self.fd = fd
            self.connected = True
            self._trigger(frm)
            while True:
                try:
                    self.fd.send(self.q.get(block=False))
                except Empty:
                    break


class TriggeredMessage(Drain):
    """Send a preloaded message when triggered and trigger in chain
     +------^------+
  >>-|      | /----|->>
     |      |/     |
   >-|-[ message ]-|->
     +------^------+
"""
    def __init__(self, msg, name=None):
        Drain.__init__(self, name=name)
        self.msg = msg
    def on_trigger(self, trigmsg):
        self._send(self.msg)
        self._high_send(self.msg)
        self._trigger(trigmsg)

class TriggerDrain(Drain):
    """Pass messages and trigger when a condition is met
     +------^------+
  >>-|-[condition]-|->>
     |      |      |
   >-|-[condition]-|->
     +-------------+
"""
    def __init__(self, f, name=None):
        Drain.__init__(self, name=name)
        self.f = f
    def push(self, msg):
        v = self.f(msg)
        if v:
            self._trigger(v)
        self._send(msg)
    def high_push(self, msg):
        v = self.f(msg)
        if v:
            self._trigger(v)
        self._high_send(msg)

class TriggeredValve(Drain):
    """Let messages alternatively pass or not, changing on trigger
     +------^------+
  >>-|-[pass/stop]-|->>
     |      |      |
   >-|-[pass/stop]-|->
     +------^------+
"""
    def __init__(self, start_state=True, name=None):
        Drain.__init__(self, name=name)
        self.opened = start_state
    def push(self, msg):
        if self.opened:
            self._send(msg)
    def high_push(self, msg):
        if self.opened:
            self._high_send(msg)
    def on_trigger(self, msg):
        self.opened ^= True
        self._trigger(msg)

class TriggeredQueueingValve(Drain):
    """Let messages alternatively pass or queued, changing on trigger
     +------^-------+
  >>-|-[pass/queue]-|->>
     |      |       |
   >-|-[pass/queue]-|->
     +------^-------+
"""
    def __init__(self, start_state=True, name=None):
        Drain.__init__(self, name=name)
        self.opened = start_state
        self.q = Queue()
    def start(self):
        self.q = Queue()
    def push(self, msg):
        if self.opened:
            self._send(msg)
        else:
            self.q.put((True,msg))
    def high_push(self, msg):
        if self.opened:
            self._send(msg)
        else:
            self.q.put((False,msg))
    def on_trigger(self, msg):
        self.opened ^= True
        self._trigger(msg)
        while True:
            try:
                low,msg = self.q.get(block=False)
            except Empty:
                break
            else:
                if low:
                    self._send(msg)
                else:
                    self._high_send(msg)

class TriggeredSwitch(Drain):
    """Let messages alternatively high or low, changing on trigger
     +------^------+
  >>-|-\    |    /-|->>
     |  [up/down]  |
   >-|-/    |    \-|->
     +------^------+
"""
    def __init__(self, start_state=True, name=None):
        Drain.__init__(self, name=name)
        self.low = start_state
    def push(self, msg):
        if self.low:
            self._send(msg)
        else:
            self._high_send(msg)
    high_push = push
    def on_trigger(self, msg):
        self.low ^= True
        self._trigger(msg)
