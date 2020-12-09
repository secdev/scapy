# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SuperSocket.
"""

from __future__ import absolute_import
from select import select, error as select_error
import ctypes
import errno
import socket
import struct
import time

from scapy.config import conf
from scapy.consts import DARWIN, WINDOWS
from scapy.data import MTU, ETH_P_IP, SOL_PACKET, SO_TIMESTAMPNS
from scapy.compat import raw
from scapy.error import warning, log_runtime
from scapy.interfaces import network_name
import scapy.modules.six as six
import scapy.packet
from scapy.utils import PcapReader, tcpdump


# Utils

class _SuperSocket_metaclass(type):
    def __repr__(self):
        if self.desc is not None:
            return "<%s: %s>" % (self.__name__, self.desc)
        else:
            return "<%s>" % self.__name__


# Used to get ancillary data
PACKET_AUXDATA = 8
ETH_P_8021Q = 0x8100
TP_STATUS_VLAN_VALID = 1 << 4


class tpacket_auxdata(ctypes.Structure):
    _fields_ = [
        ("tp_status", ctypes.c_uint),
        ("tp_len", ctypes.c_uint),
        ("tp_snaplen", ctypes.c_uint),
        ("tp_mac", ctypes.c_ushort),
        ("tp_net", ctypes.c_ushort),
        ("tp_vlan_tci", ctypes.c_ushort),
        ("tp_padding", ctypes.c_ushort),
    ]


# SuperSocket

class SuperSocket(six.with_metaclass(_SuperSocket_metaclass)):
    desc = None
    closed = 0
    nonblocking_socket = False
    auxdata_available = False

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):  # noqa: E501
        self.ins = socket.socket(family, type, proto)
        self.outs = self.ins
        self.promisc = None

    def send(self, x):
        sx = raw(x)
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        return self.outs.send(sx)

    if six.PY2:
        def _recv_raw(self, sock, x):
            """Internal function to receive a Packet"""
            pkt, sa_ll = sock.recvfrom(x)
            return pkt, sa_ll, None
    else:
        def _recv_raw(self, sock, x):
            """Internal function to receive a Packet,
            and process ancillary data.
            """
            timestamp = None
            if not self.auxdata_available:
                pkt, _, _, sa_ll = sock.recvmsg(x)
                return pkt, sa_ll, timestamp
            flags_len = socket.CMSG_LEN(4096)
            pkt, ancdata, flags, sa_ll = sock.recvmsg(x, flags_len)
            if not pkt:
                return pkt, sa_ll, timestamp
            for cmsg_lvl, cmsg_type, cmsg_data in ancdata:
                # Check available ancillary data
                if (cmsg_lvl == SOL_PACKET and cmsg_type == PACKET_AUXDATA):
                    # Parse AUXDATA
                    try:
                        auxdata = tpacket_auxdata.from_buffer_copy(cmsg_data)
                    except ValueError:
                        # Note: according to Python documentation, recvmsg()
                        #       can return a truncated message. A ValueError
                        #       exception likely indicates that Auxiliary
                        #       Data is not supported by the Linux kernel.
                        return pkt, sa_ll, timestamp
                    if auxdata.tp_vlan_tci != 0 or \
                            auxdata.tp_status & TP_STATUS_VLAN_VALID:
                        # Insert VLAN tag
                        tag = struct.pack(
                            "!HH",
                            ETH_P_8021Q,
                            auxdata.tp_vlan_tci
                        )
                        pkt = pkt[:12] + tag + pkt[12:]
                elif cmsg_lvl == socket.SOL_SOCKET and \
                        cmsg_type == SO_TIMESTAMPNS:
                    length = len(cmsg_data)
                    if length == 16:  # __kernel_timespec
                        tmp = struct.unpack("ll", cmsg_data)
                    elif length == 8:  # timespec
                        tmp = struct.unpack("ii", cmsg_data)
                    else:
                        log_runtime.warning("Unknown timespec format.. ?!")
                        continue
                    timestamp = tmp[0] + tmp[1] * 1e-9
            return pkt, sa_ll, timestamp

    def recv_raw(self, x=MTU):
        """Returns a tuple containing (cls, pkt_data, time)"""
        return conf.raw_layer, self.ins.recv(x), None

    def recv(self, x=MTU):
        cls, val, ts = self.recv_raw(x)
        if not val or not cls:
            return
        try:
            pkt = cls(val)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                from scapy.sendrecv import debug
                debug.crashed_on = (cls, val)
                raise
            pkt = conf.raw_layer(val)
        if ts:
            pkt.time = ts
        return pkt

    def fileno(self):
        return self.ins.fileno()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if getattr(self, "outs", None):
            if getattr(self, "ins", None) != self.outs:
                if WINDOWS or self.outs.fileno() != -1:
                    self.outs.close()
        if getattr(self, "ins", None):
            if WINDOWS or self.ins.fileno() != -1:
                self.ins.close()

    def sr(self, *args, **kargs):
        from scapy import sendrecv
        return sendrecv.sndrcv(self, *args, **kargs)

    def sr1(self, *args, **kargs):
        from scapy import sendrecv
        a, b = sendrecv.sndrcv(self, *args, **kargs)
        if len(a) > 0:
            return a[0][1]
        else:
            return None

    def sniff(self, *args, **kargs):
        from scapy import sendrecv
        return sendrecv.sniff(opened_socket=self, *args, **kargs)

    def tshark(self, *args, **kargs):
        from scapy import sendrecv
        return sendrecv.tshark(opened_socket=self, *args, **kargs)

    def am(self, cls, *args, **kwargs):
        """
        Creates an AnsweringMachine associated with this socket.

        :param cls: A subclass of AnsweringMachine to instantiate
        """
        return cls(*args, opened_socket=self, socket=self, **kwargs)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        """This function is called during sendrecv() routine to select
        the available sockets.

        :param sockets: an array of sockets that need to be selected
        :returns: an array of sockets that were selected and
            the function to be called next to get the packets (i.g. recv)
        """
        try:
            inp, _, _ = select(sockets, [], [], remain)
        except (IOError, select_error) as exc:
            # select.error has no .errno attribute
            if not exc.args or exc.args[0] != errno.EINTR:
                raise
        return inp, None

    def __del__(self):
        """Close the socket"""
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Close the socket"""
        self.close()


class L3RawSocket(SuperSocket):
    desc = "Layer 3 using Raw sockets (PF_INET/SOCK_RAW)"

    def __init__(self, type=ETH_P_IP, filter=None, iface=None, promisc=None, nofilter=0):  # noqa: E501
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # noqa: E501
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))  # noqa: E501
        self.iface = iface
        if iface is not None:
            iface = network_name(iface)
            self.ins.bind((iface, type))
        if not six.PY2:
            try:
                # Receive Auxiliary Data (VLAN tags)
                self.ins.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
                self.ins.setsockopt(
                    socket.SOL_SOCKET,
                    SO_TIMESTAMPNS,
                    1
                )
                self.auxdata_available = True
            except OSError:
                # Note: Auxiliary Data is only supported since
                #       Linux 2.6.21
                msg = "Your Linux Kernel does not support Auxiliary Data!"
                log_runtime.info(msg)

    def recv(self, x=MTU):
        pkt, sa_ll, ts = self._recv_raw(self.ins, x)
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
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3], cls.name)  # noqa: E501
            lvl = 3

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                raise
            pkt = conf.raw_layer(pkt)
        if lvl == 2:
            pkt = pkt.payload

        if pkt is not None:
            if ts is None:
                from scapy.arch import get_last_packet_timestamp
                ts = get_last_packet_timestamp(self.ins)
            pkt.time = ts
        return pkt

    def send(self, x):
        try:
            sx = raw(x)
            x.sent_time = time.time()
            return self.outs.sendto(sx, (x.dst, 0))
        except socket.error as msg:
            log_runtime.error(msg)


class SimpleSocket(SuperSocket):
    desc = "wrapper around a classic socket"

    def __init__(self, sock):
        self.ins = sock
        self.outs = sock


class StreamSocket(SimpleSocket):
    desc = "transforms a stream socket into a layer 2"
    nonblocking_socket = True

    def __init__(self, sock, basecls=None):
        if basecls is None:
            basecls = conf.raw_layer
        SimpleSocket.__init__(self, sock)
        self.basecls = basecls

    def recv(self, x=MTU):
        pkt = self.ins.recv(x, socket.MSG_PEEK)
        x = len(pkt)
        if x == 0:
            return None
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
    desc = "similar usage than StreamSocket but specialized for handling SSL-wrapped sockets"  # noqa: E501

    def __init__(self, sock, basecls=None):
        self._buf = b""
        super(SSLStreamSocket, self).__init__(sock, basecls)

    # 65535, the default value of x is the maximum length of a TLS record
    def recv(self, x=65535):
        pkt = None
        if self._buf != b"":
            try:
                pkt = self.basecls(self._buf)
            except Exception:
                # We assume that the exception is generated by a buffer underflow  # noqa: E501
                pass

        if not pkt:
            buf = self.ins.recv(x)
            if len(buf) == 0:
                raise socket.error((100, "Underlying stream socket tore down"))
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
        if iface is None and (WINDOWS or DARWIN):
            iface = conf.iface
        self.iface = iface
        if iface is not None:
            args.extend(['-i', network_name(iface)])
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

    @staticmethod
    def select(sockets, remain=None):
        if (WINDOWS or DARWIN):
            return sockets, None
        return SuperSocket.select(sockets, remain=remain)
