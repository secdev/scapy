# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
SuperSocket.
"""

from select import select, error as select_error
import ctypes
import errno
import socket
import struct
import time

from scapy.config import conf
from scapy.consts import DARWIN, WINDOWS
from scapy.data import (
    MTU,
    ETH_P_IP,
    ETH_P_IPV6,
    SOL_PACKET,
    SO_TIMESTAMPNS,
)
from scapy.compat import raw
from scapy.error import warning, log_runtime
from scapy.interfaces import network_name
from scapy.packet import Packet, NoPayload
from scapy.plist import (
    PacketList,
    SndRcvList,
    _PacketIterable,
)
from scapy.utils import PcapReader, tcpdump

# Typing imports
from scapy.interfaces import _GlobInterfaceType
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    cast,
)

# Utils


class _SuperSocket_metaclass(type):
    desc = None   # type: Optional[str]

    def __repr__(self):
        # type: () -> str
        if self.desc is not None:
            return "<%s: %s>" % (self.__name__, self.desc)
        else:
            return "<%s>" % self.__name__


# Used to get ancillary data
PACKET_AUXDATA = 8
ETH_P_8021Q = 0x8100
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6


class tpacket_auxdata(ctypes.Structure):
    _fields_ = [
        ("tp_status", ctypes.c_uint),
        ("tp_len", ctypes.c_uint),
        ("tp_snaplen", ctypes.c_uint),
        ("tp_mac", ctypes.c_ushort),
        ("tp_net", ctypes.c_ushort),
        ("tp_vlan_tci", ctypes.c_ushort),
        ("tp_vlan_tpid", ctypes.c_ushort),
    ]  # type: List[Tuple[str, Any]]


# SuperSocket

class SuperSocket(metaclass=_SuperSocket_metaclass):
    closed = False  # type: bool
    nonblocking_socket = False  # type: bool
    auxdata_available = False   # type: bool

    def __init__(self,
                 family=socket.AF_INET,  # type: int
                 type=socket.SOCK_STREAM,  # type: int
                 proto=0,  # type: int
                 iface=None,  # type: Optional[_GlobInterfaceType]
                 **kwargs  # type: Any
                 ):
        # type: (...) -> None
        self.ins = socket.socket(family, type, proto)  # type: socket.socket
        self.outs = self.ins  # type: Optional[socket.socket]
        self.promisc = conf.sniff_promisc
        self.iface = iface or conf.iface

    def send(self, x):
        # type: (Packet) -> int
        """Sends a `Packet` object

        :param x: `Packet` to be send
        :return: Number of bytes that have been sent
        """
        sx = raw(x)
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        if self.outs:
            return self.outs.send(sx)
        else:
            return 0

    if WINDOWS:
        def _recv_raw(self, sock, x):
            # type: (socket.socket, int) -> Tuple[bytes, Any, Optional[float]]
            """Internal function to receive a Packet.

            :param sock: Socket object from which data are received
            :param x: Number of bytes to be received
            :return: Received bytes, address information and no timestamp
            """
            pkt, sa_ll = sock.recvfrom(x)
            return pkt, sa_ll, None
    else:
        def _recv_raw(self, sock, x):
            # type: (socket.socket, int) -> Tuple[bytes, Any, Optional[float]]
            """Internal function to receive a Packet,
            and process ancillary data.

            :param sock: Socket object from which data are received
            :param x: Number of bytes to be received
            :return: Received bytes, address information and an optional timestamp
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
                        tpid = ETH_P_8021Q
                        if auxdata.tp_status & TP_STATUS_VLAN_TPID_VALID:
                            tpid = auxdata.tp_vlan_tpid
                        tag = struct.pack(
                            "!HH",
                            tpid,
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
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)


        :param x: Maximum number of bytes to be received, defaults to MTU
        :return: A tuple, consisting of a Packet type, the received data,
                 and a timestamp
        """
        return conf.raw_layer, self.ins.recv(x), None

    def recv(self, x=MTU, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        """Receive a Packet according to the `basecls` of this socket

        :param x: Maximum number of bytes to be received, defaults to MTU
        :return: The received `Packet` object, or None
        """
        cls, val, ts = self.recv_raw(x)
        if not val or not cls:
            return None
        try:
            pkt = cls(val, **kwargs)  # type: Packet
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
        # type: () -> int
        return self.ins.fileno()

    def close(self):
        # type: () -> None
        """Gracefully close this socket
        """
        if self.closed:
            return
        self.closed = True
        if getattr(self, "outs", None):
            if getattr(self, "ins", None) != self.outs:
                if self.outs and self.outs.fileno() != -1:
                    self.outs.close()
        if getattr(self, "ins", None):
            if self.ins.fileno() != -1:
                self.ins.close()

    def sr(self, *args, **kargs):
        # type: (Any, Any) -> Tuple[SndRcvList, PacketList]
        """Send and Receive multiple packets
        """
        from scapy import sendrecv
        return sendrecv.sndrcv(self, *args, **kargs)

    def sr1(self, *args, **kargs):
        # type: (Any, Any) -> Optional[Packet]
        """Send one packet and receive one answer
        """
        from scapy import sendrecv
        ans = sendrecv.sndrcv(self, *args, **kargs)[0]  # type: SndRcvList
        if len(ans) > 0:
            pkt = ans[0][1]  # type: Packet
            return pkt
        else:
            return None

    def sniff(self, *args, **kargs):
        # type: (Any, Any) -> PacketList
        from scapy import sendrecv
        return sendrecv.sniff(opened_socket=self, *args, **kargs)

    def tshark(self, *args, **kargs):
        # type: (Any, Any) -> None
        from scapy import sendrecv
        sendrecv.tshark(opened_socket=self, *args, **kargs)

    # TODO: use 'scapy.ansmachine.AnsweringMachine' when typed
    def am(self,
           cls,  # type: Type[Any]
           *args,  # type: Any
           **kwargs  # type: Any
           ):
        # type: (...) -> Any
        """
        Creates an AnsweringMachine associated with this socket.

        :param cls: A subclass of AnsweringMachine to instantiate
        """
        return cls(*args, opened_socket=self, socket=self, **kwargs)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
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
        return inp

    def __del__(self):
        # type: () -> None
        """Close the socket"""
        self.close()

    def __enter__(self):
        # type: () -> SuperSocket
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # type: (Optional[Type[BaseException]], Optional[BaseException], Optional[Any]) -> None  # noqa: E501
        """Close the socket"""
        self.close()


if not WINDOWS:
    class L3RawSocket(SuperSocket):
        desc = "Layer 3 using Raw sockets (PF_INET/SOCK_RAW)"

        def __init__(self,
                     type=ETH_P_IP,  # type: int
                     filter=None,  # type: Optional[str]
                     iface=None,  # type: Optional[_GlobInterfaceType]
                     promisc=None,  # type: Optional[bool]
                     nofilter=0  # type: int
                     ):
            # type: (...) -> None
            self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # noqa: E501
            self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))  # noqa: E501
            if iface is not None:
                iface = network_name(iface)
                self.iface = iface
                self.ins.bind((iface, type))
            else:
                self.iface = "any"
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

        def recv(self, x=MTU, **kwargs):
            # type: (int, **Any) -> Optional[Packet]
            data, sa_ll, ts = self._recv_raw(self.ins, x)
            if sa_ll[2] == socket.PACKET_OUTGOING:
                return None
            if sa_ll[3] in conf.l2types:
                cls = conf.l2types.num2layer[sa_ll[3]]  # type: Type[Packet]
                lvl = 2
            elif sa_ll[1] in conf.l3types:
                cls = conf.l3types.num2layer[sa_ll[1]]
                lvl = 3
            else:
                cls = conf.default_l2
                warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3], cls.name)  # noqa: E501
                lvl = 3

            try:
                pkt = cls(data, **kwargs)
            except KeyboardInterrupt:
                raise
            except Exception:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(data)

            if lvl == 2:
                pkt = pkt.payload

            if pkt is not None:
                if ts is None:
                    from scapy.arch.linux import get_last_packet_timestamp
                    ts = get_last_packet_timestamp(self.ins)
                pkt.time = ts
            return pkt

        def send(self, x):
            # type: (Packet) -> int
            try:
                sx = raw(x)
                if self.outs:
                    x.sent_time = time.time()
                    return self.outs.sendto(
                        sx,
                        (x.dst, 0)
                    )
            except AttributeError:
                raise ValueError(
                    "Missing 'dst' attribute in the first layer to be "
                    "sent using a native L3 socket ! (make sure you passed the "
                    "IP layer)"
                )
            except socket.error as msg:
                log_runtime.error(msg)
            return 0

    class L3RawSocket6(L3RawSocket):
        def __init__(self,
                     type: int = ETH_P_IPV6,
                     filter: Optional[str] = None,
                     iface: Optional[_GlobInterfaceType] = None,
                     promisc: Optional[bool] = None,
                     nofilter: bool = False) -> None:
            # NOTE: if fragmentation is needed, it will be done by the kernel (RFC 2292)  # noqa: E501
            self.outs = socket.socket(
                socket.AF_INET6,
                socket.SOCK_RAW,
                socket.IPPROTO_RAW
            )
            self.ins = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(type)
            )
            self.iface = cast(_GlobInterfaceType, iface)


class SimpleSocket(SuperSocket):
    desc = "wrapper around a classic socket"
    __selectable_force_select__ = True

    def __init__(self, sock, basecls=None):
        # type: (socket.socket, Optional[Type[Packet]]) -> None
        self.ins = sock
        self.outs = sock
        if basecls is None:
            basecls = conf.raw_layer
        self.basecls = basecls

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]
        return self.basecls, self.ins.recv(x), None

    if WINDOWS:
        @staticmethod
        def select(sockets, remain=None):
            # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
            from scapy.automaton import select_objects
            return select_objects(sockets, remain)


class StreamSocket(SimpleSocket):
    """
    Wrap a stream socket into a layer 2 SuperSocket

    :param sock: the socket to wrap
    :param basecls: the base class packet to use to dissect the packet
    """
    desc = "transforms a stream socket into a layer 2"

    def __init__(self,
                 sock,  # type: socket.socket
                 basecls=None,  # type: Optional[Type[Packet]]
                 ):
        # type: (...) -> None
        from scapy.sessions import streamcls
        self.rcvcls = streamcls(basecls or conf.raw_layer)
        self.metadata: Dict[str, Any] = {}
        self.streamsession: Dict[str, Any] = {}
        self._buf = b""
        super(StreamSocket, self).__init__(sock, basecls=basecls)

    def recv(self, x=None, **kwargs):
        # type: (Optional[int], Any) -> Optional[Packet]
        if x is None:
            x = MTU
        # Block but in PEEK mode
        data = self.ins.recv(x, socket.MSG_PEEK)
        if data == b"":
            raise EOFError
        x = len(data)
        pkt = self.rcvcls(self._buf + data, self.metadata, self.streamsession)
        if pkt is None:  # Incomplete packet.
            self._buf += self.ins.recv(x)
            return self.recv(x)
        self.metadata.clear()
        # Strip any madding
        pad = pkt.getlayer(conf.padding_layer)
        if pad is not None and pad.underlayer is not None:
            del pad.underlayer.payload
        while pad is not None and not isinstance(pad, NoPayload):
            x -= len(pad.load)
            pad = pad.payload
        # Only receive the packet length
        self.ins.recv(x)
        self._buf = b""
        return pkt


class SSLStreamSocket(StreamSocket):
    desc = "similar usage than StreamSocket but specialized for handling SSL-wrapped sockets"  # noqa: E501

    # Basically StreamSocket but we can't PEEK

    def __init__(self, sock, basecls=None):
        # type: (socket.socket, Optional[Type[Packet]]) -> None
        from scapy.sessions import TCPSession
        self.sess = TCPSession(app=True)
        super(SSLStreamSocket, self).__init__(sock, basecls)

    # 65535, the default value of x is the maximum length of a TLS record
    def recv(self, x=None, **kwargs):
        # type: (Optional[int], **Any) -> Optional[Packet]
        if x is None:
            x = MTU
        # Block
        try:
            data = self.ins.recv(x)
        except OSError:
            raise EOFError
        try:
            pkt = self.sess.process(data, cls=self.basecls)  # type: ignore
        except struct.error:
            # Buffer underflow
            pkt = None
        if data == b"" and not pkt:
            raise EOFError
        if not pkt:
            return self.recv(x)
        return pkt

    @staticmethod
    def select(sockets, remain=None):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        queued = [
            x
            for x in sockets
            if isinstance(x, SSLStreamSocket) and x.sess.data
        ]
        if queued:
            return queued  # type: ignore
        return super(SSLStreamSocket, SSLStreamSocket).select(sockets, remain=remain)


class L2ListenTcpdump(SuperSocket):
    desc = "read packets at layer 2 using tcpdump"

    def __init__(self,
                 iface=None,  # type: Optional[_GlobInterfaceType]
                 promisc=None,  # type: Optional[bool]
                 filter=None,  # type: Optional[str]
                 nofilter=False,  # type: bool
                 prog=None,  # type: Optional[str]
                 quiet=False,  # type: bool
                 *arg,  # type: Any
                 **karg  # type: Any
                 ):
        # type: (...) -> None
        self.outs = None
        args = ['-w', '-', '-s', '65535']
        self.iface = "any"
        if iface is None and (WINDOWS or DARWIN):
            self.iface = iface = conf.iface
        if promisc is None:
            promisc = conf.sniff_promisc
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
        self.tcpdump_proc = tcpdump(
            None, prog=prog, args=args, getproc=True, quiet=quiet)
        self.reader = PcapReader(self.tcpdump_proc.stdout)
        self.ins = self.reader  # type: ignore

    def recv(self, x=MTU, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        return self.reader.recv(x, **kwargs)

    def close(self):
        # type: () -> None
        SuperSocket.close(self)
        self.tcpdump_proc.kill()

    @staticmethod
    def select(sockets, remain=None):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        if (WINDOWS or DARWIN):
            return sockets
        return SuperSocket.select(sockets, remain=remain)


# More abstract objects

class IterSocket(SuperSocket):
    desc = "wrapper around an iterable"
    nonblocking_socket = True

    def __init__(self, obj):
        # type: (_PacketIterable) -> None
        if not obj:
            self.iter = iter([])  # type: Iterator[Packet]
        elif isinstance(obj, IterSocket):
            self.iter = obj.iter
        elif isinstance(obj, SndRcvList):
            def _iter(obj=cast(SndRcvList, obj)):
                # type: (SndRcvList) -> Iterator[Packet]
                for s, r in obj:
                    if s.sent_time:
                        s.time = s.sent_time
                    yield s
                    yield r
            self.iter = _iter()
        elif isinstance(obj, (list, PacketList)):
            if isinstance(obj[0], bytes):
                self.iter = iter(obj)
            else:
                self.iter = (y for x in obj for y in x)
        else:
            self.iter = obj.__iter__()

    @staticmethod
    def select(sockets, remain=None):
        # type: (List[SuperSocket], Any) -> List[SuperSocket]
        return sockets

    def recv(self, x=None, **kwargs):
        # type: (Optional[int], Any) -> Optional[Packet]
        try:
            pkt = next(self.iter)
            return pkt.__class__(bytes(pkt), **kwargs)
        except StopIteration:
            raise EOFError

    def close(self):
        # type: () -> None
        pass
