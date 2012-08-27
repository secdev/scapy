## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from pipetool import Source,Drain,Sink
from config import conf


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
    def deliver(self):
        self._send(self.s.recv())

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
        print "start"
        self.f = PcapReader(self.fname)
        self.is_exhausted = False
    def stop(self):
        print "stop"
        self.f.close()
    def fileno(self):
        return self.f.fileno()
    def deliver(self):    
        p = self.f.recv()
        print "deliver %r" % p
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
    def push(self, msg):
        self.f.write(msg)
        

class UDPDrain(Drain):
    """Apply a function to messages on low and high entry
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
        if IP in msg and msg[IP].proto == 17 and UDP in msg:
            payload = msg[UDP].payload
            self._high_send(str(payload))
    def high_push(self, msg):
        p = IP(dst=self.ip)/UDP(sport=1234,dport=self.port)/msg
        self._send(p)
        
