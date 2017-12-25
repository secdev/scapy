## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
SuperSocket.
"""

from __future__ import absolute_import
import os
import socket
import subprocess
import struct
import time

from scapy.config import conf
from scapy.consts import LINUX, OPENBSD, BSD, DARWIN, WINDOWS
from scapy.data import *
from scapy.compat import *
from scapy.error import warning, log_runtime
import scapy.modules.six as six
import scapy.packet
from scapy.utils import PcapReader, tcpdump

class _SuperSocket_metaclass(type):
    def __repr__(self):
        if self.desc is not None:
            return "<%s: %s>" % (self.__name__,self.desc)
        else:
            return "<%s>" % self.__name__


class SuperSocket(six.with_metaclass(_SuperSocket_metaclass)):
    desc = None
    closed=0
    def __init__(self, family=socket.AF_INET,type=socket.SOCK_STREAM, proto=0):
        self.ins = socket.socket(family, type, proto)
        self.outs = self.ins
        self.promisc=None
    def send(self, x):
        sx = raw(x)
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
        self.closed = True
        if hasattr(self, "outs"):
            if not hasattr(self, "ins") or self.ins != self.outs:
                if self.outs and self.outs.fileno() != -1:
                    self.outs.close()
        if hasattr(self, "ins"):
            if self.ins and self.ins.fileno() != -1:
                self.ins.close()
    def sr(self, *args, **kargs):
        from scapy import sendrecv
        return sendrecv.sndrcv(self, *args, **kargs)
    def sr1(self, *args, **kargs):        
        from scapy import sendrecv
        a,b = sendrecv.sndrcv(self, *args, **kargs)
        if len(a) > 0:
            return a[0][1]
        else:
            return None
    def sniff(self, *args, **kargs):
        from scapy import sendrecv
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
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3], cls.name)
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
            from scapy.arch import get_last_packet_timestamp
            pkt.time = get_last_packet_timestamp(self.ins)
        return pkt
    def send(self, x):
        try:
            sx = raw(x)
            x.sent_time = time.time()
            self.outs.sendto(sx,(x.dst,0))
        except socket.error as msg:
            log_runtime.error(msg)

class SimpleSocket(SuperSocket):
    desc = "wrapper around a classic socket"
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
        from scapy.packet import NoPayload
        while pad is not None and not isinstance(pad, NoPayload):
            x -= len(pad.load)
            pad = pad.payload
        self.ins.recv(x)
        return pkt

class SSLStreamSocket(StreamSocket):
    desc = "similar usage than StreamSocket but specialized for handling SSL-wrapped sockets"

    def __init__(self, sock, basecls=None):
        self._buf = b""
        super(SSLStreamSocket, self).__init__(sock, basecls)

    #65535, the default value of x is the maximum length of a TLS record
    def recv(self, x=65535):
        pkt = None
        if self._buf != b"":
            try:
                pkt = self.basecls(self._buf)
            except:
                # We assume that the exception is generated by a buffer underflow
                pass

        if not pkt:
            buf = self.ins.recv(x)
            if len(buf) == 0:
                raise socket.error((100,"Underlying stream socket tore down"))
            self._buf += buf

        x = len(self._buf)
        pkt = self.basecls(self._buf)
        pad = pkt.getlayer(conf.padding_layer)

        if pad is not None and pad.underlayer is not None:
            del(pad.underlayer.payload)
        while pad is not None and not isinstance(pad, scapy.packet.NoPayload):
            x -= len(pad.load)
            pad = pad.payload
        self._buf = self._buf[x:]
        return pkt


class L2ListenTcpdump(SuperSocket):
    desc = "read packets at layer 2 using tcpdump"

    def __init__(self, iface=None, promisc=None, filter=None, nofilter=False,
                 prog=None, *arg, **karg):
        self.outs = None
        args = ['-w', '-', '-s', '65535']
        if iface is not None:
            if WINDOWS:
                try:
                    args.extend(['-i', iface.pcap_name])
                except AttributeError:
                    args.extend(['-i', iface])
            else:
                args.extend(['-i', iface])
        elif WINDOWS or DARWIN:
            args.extend(['-i', conf.iface.pcap_name if WINDOWS else conf.iface])
        if not promisc:
            args.append('-p')
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
        if filter is not None:
            args.append(filter)
        self.tcpdump_proc = tcpdump(None, prog=prog, args=args, getproc=True)
        self.ins = PcapReader(self.tcpdump_proc.stdout)
    def recv(self, x=MTU):
        return self.ins.recv(x)
    def close(self):
        SuperSocket.close(self)
        self.tcpdump_proc.kill()


class TunTapInterface(SuperSocket):
    """A socket to act as the host's peer of a tun / tap interface.

    """
    desc = "Act as the host's peer of a tun / tap interface"

    def __init__(self, iface=None, mode_tun=None, *arg, **karg):
        self.iface = conf.iface if iface is None else iface
        self.mode_tun = ("tun" in iface) if mode_tun is None else mode_tun
        self.closed = True
        self.open()

    def __enter__(self):
        return self

    def __del__(self):
        self.close()

    def __exit__(self, *_):
        self.close()

    def open(self):
        """Open the TUN or TAP device."""
        if not self.closed:
            return
        self.outs = self.ins = open(
            "/dev/net/tun" if LINUX else ("/dev/%s" % self.iface), "r+b",
            buffering=0
        )
        if LINUX:
            from fcntl import ioctl
            # TUNSETIFF = 0x400454ca
            # IFF_TUN = 0x0001
            # IFF_TAP = 0x0002
            # IFF_NO_PI = 0x1000
            ioctl(self.ins, 0x400454ca, struct.pack(
                "16sH", raw(self.iface), 0x0001 if self.mode_tun else 0x1002,
            ))
        self.closed = False

    def __call__(self, *arg, **karg):
        """Needed when using an instantiated TunTapInterface object for
conf.L2listen, conf.L2socket or conf.L3socket.

        """
        return self

    def recv(self, x=MTU):
        if self.mode_tun:
            data = os.read(self.ins.fileno(), x + 4)
            proto = struct.unpack('!H', data[2:4])[0]
            return conf.l3types.get(proto, conf.raw_layer)(data[4:])
        return conf.l2types.get(1, conf.raw_layer)(
            os.read(self.ins.fileno(), x)
        )

    def send(self, x):
        sx = raw(x)
        if hasattr(x, "sent_time"):
            x.sent_time = time.time()
        if self.mode_tun:
            try:
                proto = conf.l3types[type(x)]
            except KeyError:
                log_runtime.warning(
                    "Cannot find layer 3 protocol value to send %s in "
                    "conf.l3types, using 0",
                    x.name if hasattr(x, "name") else type(x).__name__
                )
                proto = 0
            sx = struct.pack('!HH', 0, proto) + sx
        try:
            os.write(self.outs.fileno(), sx)
        except socket.error:
            log_runtime.error("%s send", self.__class__.__name__, exc_info=True)


if conf.L3socket is None:
    conf.L3socket = L3RawSocket
