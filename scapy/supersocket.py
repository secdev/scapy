## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
SuperSocket.
"""

import socket,time
from config import conf
from data import *
from scapy.error import warning, log_runtime

class _SuperSocket_metaclass(type):
    def __repr__(self):
        if self.desc is not None:
            return "<%s: %s>" % (self.__name__,self.desc)
        else:
            return "<%s>" % self.__name__


class SuperSocket:
    __metaclass__ = _SuperSocket_metaclass
    desc = None
    closed=0
    def __init__(self, family=socket.AF_INET,type=socket.SOCK_STREAM, proto=0):
        self.ins = socket.socket(family, type, proto)
        self.outs = self.ins
        self.promisc=None
    def send(self, x):
        sx = str(x)
        if hasattr(x, "sent_time"):
            x.sent_time = time.time()
        return self.outs.send(sx)
    def recv(self, x=MTU):
        return conf.raw_layer(self.ins.recv(x))
    def fileno(self):
        return self.ins.fileno()
    def close(self):
        if self.closed:
            return
        self.closed=1
        if self.ins != self.outs:
            if self.outs and self.outs.fileno() != -1:
                self.outs.close()
        if self.ins and self.ins.fileno() != -1:
            self.ins.close()
    def sr(self, *args, **kargs):
        return sendrecv.sndrcv(self, *args, **kargs)
    def sr1(self, *args, **kargs):        
        a,b = sendrecv.sndrcv(self, *args, **kargs)
        if len(a) > 0:
            return a[0][1]
        else:
            return None
    def sniff(self, *args, **kargs):
        return sendrecv.sniff(opened_socket=self, *args, **kargs)

class L3RawSocket(SuperSocket):
    desc = "Layer 3 using Raw sockets (PF_INET/SOCK_RAW)"
    def __init__(self, type = ETH_P_IP, filter=None, iface=None, promisc=None, nofilter=0):
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        if iface is not None:
            self.ins.bind((iface, type))
    def recv(self, x=MTU):
        pkt, sa_ll = self.ins.recvfrom(x)
        if sa_ll[2] == socket.PACKET_OUTGOING:
            return None
        if sa_ll[3] in conf.l2types:
            cls = conf.l2types[sa_ll[3]]
            lvl = 2
        elif sa_ll[1] in conf.l3types:
            cls = conf.l3types[sa_ll[1]]
            lvl = 3
        else:
            cls = conf.default_l2
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s" % (sa_ll[0],sa_ll[1],sa_ll[3],cls.name))
            lvl = 3

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = conf.raw_layer(pkt)
        if lvl == 2:
            pkt = pkt.payload
            
        if pkt is not None:
            from arch import get_last_packet_timestamp
            pkt.time = get_last_packet_timestamp(self.ins)
        return pkt
    def send(self, x):
        try:
            sx = str(x)
            x.sent_time = time.time()
            self.outs.sendto(sx,(x.dst,0))
        except socket.error,msg:
            log_runtime.error(msg)

class SimpleSocket(SuperSocket):
    desc = "wrapper arround a classic socket"
    def __init__(self, sock):
        self.ins = sock
        self.outs = sock


class StreamSocket(SimpleSocket):
    desc = "transforms a stream socket into a layer 2"
    def __init__(self, sock, basecls=None):
        if basecls is None:
            basecls = conf.raw_layer
        SimpleSocket.__init__(self, sock)
        self.basecls = basecls
        
    def recv(self, x=MTU):
        pkt = self.ins.recv(x, socket.MSG_PEEK)
        x = len(pkt)
        if x == 0:
            raise socket.error((100,"Underlying stream socket tore down"))
        pkt = self.basecls(pkt)
        pad = pkt.getlayer(conf.padding_layer)
        if pad is not None and pad.underlayer is not None:
            del(pad.underlayer.payload)
        while pad is not None and not isinstance(pad, NoPayload):
            x -= len(pad.load)
            pad = pad.payload
        self.ins.recv(x)
        return pkt
        


if conf.L3socket is None:
    conf.L3socket = L3RawSocket

import sendrecv
