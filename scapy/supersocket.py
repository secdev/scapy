## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import socket,time,os,struct
from select import select
from packet import Raw
from data import *
from config import conf
from arch import PCAP,DNET,get_if_list,set_promisc,get_last_packet_timestamp,attach_filter

def flush_fd(fd):
    if type(fd) is not int:
        fd = fd.fileno()
    while 1:
        r,w,e = select([fd],[],[],0)
        if r:
            os.read(fd,MTU)
        else:
            break

class SuperSocket:
    closed=0
    def __init__(self, family=socket.AF_INET,type=socket.SOCK_STREAM, proto=0):
        self.ins = socket.socket(family, type, proto)
        self.outs = self.ins
        self.promisc=None
    def send(self, x):
        sx = str(x)
        x.sent_time = time.time()
        return self.outs.send(sx)
    def recv(self, x):
        return Raw(self.ins.recv(x))
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
    def bind_in(self, addr):
        self.ins.bind(addr)
    def bind_out(self, addr):
        self.outs.bind(addr)


class L3RawSocket(SuperSocket):
    def __init__(self, type = ETH_P_IP, filter=None, iface=None, promisc=None, nofilter=0):
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
    def recv(self, x):
        return Ether(self.ins.recv(x)).payload
    def send(self, x):
        try:
            sx = str(x)
            x.sent_time = time.time()
            self.outs.sendto(sx,(x.dst,0))
        except socket.error,msg:
            log_runtime.error(msg)
        


class L3PacketSocket(SuperSocket):
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
        self.type = type
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        flush_fd(self.ins)
        if iface:
            self.ins.bind((iface, type))
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        if promisc is None:
            promisc = conf.promisc
        self.promisc = promisc
        if self.promisc:
            if iface is None:
                self.iff = get_if_list()
            else:
                if iface.__class__ is list:
                    self.iff = iface
                else:
                    self.iff = [iface]
            for i in self.iff:
                set_promisc(self.ins, i)
    def close(self):
        if self.closed:
            return
        self.closed=1
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)
    def recv(self, x):
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
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            cls = Ether
            lvl = 2

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        if lvl == 2:
            pkt = pkt.payload
            
        if pkt is not None:
            pkt.time = get_last_packet_timestamp(self.ins)
        return pkt
    
    def send(self, x):
        iff,a,gw  = x.route()
        if iff is None:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        sn = self.outs.getsockname()
        ll = lambda x:x
        if sn[3] in (ARPHDR_PPP,ARPHDR_TUN):
            sdto = (iff, ETH_P_IP)
        if sn[3] in conf.l2types:
            ll = lambda x:conf.l2types[sn[3]]()/x
        try:
            sx = str(ll(x))
            x.sent_time = time.time()
            self.outs.sendto(sx, sdto)
        except socket.error,msg:
            x.sent_time = time.time()  # bad approximation
            if conf.auto_fragment and msg[0] == 90:
                for p in fragment(x):
                    self.outs.sendto(str(ll(p)), sdto)
            else:
                raise
                    



class L2Socket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
        if iface is None:
            iface = conf.iface
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        flush_fd(self.ins)
        if not nofilter: 
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        self.ins.bind((iface, type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = self.ins
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        sa_ll = self.outs.getsockname()
        if sa_ll[3] in conf.l2types:
            self.LL = conf.l2types[sa_ll[3]]
        elif sa_ll[1] in conf.l3types:
            self.LL = conf.l3types[sa_ll[1]]
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            self.LL = Ether
            
    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        if sa_ll[2] == socket.PACKET_OUTGOING:
            return None
        try:
            q = self.LL(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            q = Raw(pkt)
        q.time = get_last_packet_timestamp(self.ins)
        return q


class L2ListenSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None, nofilter=0):
        self.type = type
        self.outs = None
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        flush_fd(self.ins)
        if iface is not None:
            self.ins.bind((iface, type))
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        if iface is None:
            self.iff = get_if_list()
        else:
            if iface.__class__ is list:
                self.iff = iface
            else:
                self.iff = [iface]
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    def close(self):
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)

    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        if sa_ll[3] in conf.l2types :
            cls = conf.l2types[sa_ll[3]]
        elif sa_ll[1] in conf.l3types:
            cls = conf.l3types[sa_ll[1]]
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            cls = Ether

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = get_last_packet_timestamp(self.ins)
        return pkt
    
    def send(self, x):
        raise Scapy_Exception("Can't send anything with L2ListenSocket")



class L3dnetSocket(SuperSocket):
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
        self.iflist = {}
        self.ins = pcap.pcapObject()
        if iface is None:
            iface = conf.iface
        self.iface = iface
        self.ins.open_live(iface, 1600, 0, 100)
        try:
            ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
        except:
            pass
        if nofilter:
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                filter = "ether proto %i" % type
            else:
                filter = None
        else:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                if filter:
                    filter = "(ether proto %i) and (%s)" % (type,filter)
                else:
                    filter = "ether proto %i" % type
        if filter:
            self.ins.setfilter(filter, 0, 0)
    def send(self, x):
        iff,a,gw  = x.route()
        if iff is None:
            iff = conf.iface
        ifs = self.iflist.get(iff)
        if ifs is None:
            self.iflist[iff] = ifs = dnet.eth(iff)
        sx = str(Ether()/x)
        x.sent_time = time.time()
        ifs.send(sx)
    def recv(self,x=MTU):
        ll = self.ins.datalink()
        if ll in conf.l2types:
            cls = conf.l2types[ll]
        else:
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using Ethernet" % (self.iface, ll))
            cls = Ether

        pkt = self.ins.next()
        if pkt is not None:
            l,pkt,ts = pkt
        if pkt is None:
            return

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = ts
        return pkt.payload

    def nonblock_recv(self):
        self.ins.setnonblock(1)
        p = self.recv()
        self.ins.setnonblock(0)
        return p

    def close(self):
        if hasattr(self, "ins"):
            del(self.ins)
        if hasattr(self, "outs"):
            del(self.outs)

class L2dnetSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
        if iface is None:
            iface = conf.iface
        self.iface = iface
        self.ins = pcap.pcapObject()
        self.ins.open_live(iface, 1600, 0, 100)
        try:
            ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
        except:
            pass
        if nofilter:
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                filter = "ether proto %i" % type
            else:
                filter = None
        else:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                if filter:
                    filter = "(ether proto %i) and (%s)" % (type,filter)
                else:
                    filter = "ether proto %i" % type
        if filter:
            self.ins.setfilter(filter, 0, 0)
        self.outs = dnet.eth(iface)
    def recv(self,x):
        ll = self.ins.datalink()
        if ll in conf.l2types:
            cls = conf.l2types[ll]
        else:
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using Ethernet" % (self.iface, ll))
            cls = Ether

        pkt = self.ins.next()
        if pkt is not None:
            l,pkt,ts = pkt
        if pkt is None:
            return
        
        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = ts
        return pkt

    def nonblock_recv(self):
        self.ins.setnonblock(1)
        p = self.recv(MTU)
        self.ins.setnonblock(0)
        return p

    def close(self):
        if hasattr(self, "ins"):
            del(self.ins)
        if hasattr(self, "outs"):
            del(self.outs)
    
    
    


class L2pcapListenSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
        self.type = type
        self.outs = None
        self.ins = pcap.pcapObject()
        self.iface = iface
        if iface is None:
            iface = conf.iface
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        self.ins.open_live(iface, 1600, self.promisc, 100)
        try:
            ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
        except:
            pass
        if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter:
                self.ins.setfilter(filter, 0, 0)

    def close(self):
        del(self.ins)
        
    def recv(self, x):
        ll = self.ins.datalink()
        if ll in conf.l2types:
            cls = conf.l2types[ll]
        else:
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using Ethernet" % (self.iface, ll))
            cls = Ether

        pkt = None
        while pkt is None:
            pkt = self.ins.next()
            if pkt is not None:
                l,pkt,ts = pkt
        
        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = Raw(pkt)
        pkt.time = ts
        return pkt

    def send(self, x):
        raise Scapy_Exception("Can't send anything with L2pcapListenSocket")


class SimpleSocket(SuperSocket):
    def __init__(self, sock):
        self.ins = sock
        self.outs = sock


class StreamSocket(SimpleSocket):
    def __init__(self, sock, basecls=Raw):
        SimpleSocket.__init__(self, sock)
        self.basecls = basecls
        
    def recv(self, x=MTU):
        pkt = self.ins.recv(x, socket.MSG_PEEK)
        x = len(pkt)
        pkt = self.basecls(pkt)
        pad = pkt[Padding]
        if pad is not None and pad.underlayer is not None:
            del(pad.underlayer.payload)
        while pad is not None and not isinstance(pad, NoPayload):
            x -= len(pad.load)
            pad = pad.payload
        self.ins.recv(x)
        return pkt
        

conf.L3socket = L3PacketSocket
conf.L2socket = L2Socket
conf.L2listen = L2ListenSocket

if PCAP:
    conf.L2listen=L2pcapListenSocket
    if DNET:
        conf.L3socket=L3dnetSocket
        conf.L2socket=L2dnetSocket

