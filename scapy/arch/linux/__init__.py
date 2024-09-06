# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Linux specific functions.
"""


from fcntl import ioctl
from select import select

import ctypes
import os
import socket
import struct
import subprocess
import sys
import time

from scapy.compat import raw
from scapy.consts import LINUX
from scapy.arch.common import compile_filter
from scapy.config import conf
from scapy.data import MTU, ETH_P_ALL, SOL_PACKET, SO_ATTACH_FILTER, \
    SO_TIMESTAMPNS
from scapy.error import (
    ScapyInvalidPlatformException,
    Scapy_Exception,
    log_runtime,
    warning,
)
from scapy.interfaces import (
    InterfaceProvider,
    NetworkInterface,
    _GlobInterfaceType,
    network_name,
    resolve_iface,
)
from scapy.libs.structures import sock_fprog
from scapy.packet import Packet, Padding
from scapy.supersocket import SuperSocket

# re-export
from scapy.arch.common import get_if_raw_addr, read_nameservers  # noqa: F401
from scapy.arch.linux.rtnetlink import (  # noqa: F401
    read_routes,
    read_routes6,
    in6_getifaddr,
    _get_if_list,
)

# Typing imports
from typing import (
    Any,
    Dict,
    List,
    NoReturn,
    Optional,
    Tuple,
    Type,
    Union,
)

# From sockios.h
SIOCGIFHWADDR = 0x8927          # Get hardware address
SIOCGIFADDR = 0x8915          # get PA address
SIOCGIFNETMASK = 0x891b          # get network PA mask
SIOCGIFNAME = 0x8910          # get iface name
SIOCSIFLINK = 0x8911          # set iface channel
SIOCGIFCONF = 0x8912          # get iface list
SIOCGIFFLAGS = 0x8913          # get flags
SIOCSIFFLAGS = 0x8914          # set flags
SIOCGIFINDEX = 0x8933          # name -> if_index mapping
SIOCGIFCOUNT = 0x8938          # get number of devices
SIOCGSTAMP = 0x8906          # get packet timestamp (as a timeval)

# From if.h
IFF_UP = 0x1               # Interface is up.
IFF_BROADCAST = 0x2        # Broadcast address valid.
IFF_DEBUG = 0x4            # Turn on debugging.
IFF_LOOPBACK = 0x8         # Is a loopback net.
IFF_POINTOPOINT = 0x10     # Interface is point-to-point link.
IFF_NOTRAILERS = 0x20      # Avoid use of trailers.
IFF_RUNNING = 0x40         # Resources allocated.
IFF_NOARP = 0x80           # No address resolution protocol.
IFF_PROMISC = 0x100        # Receive all packets.

# From netpacket/packet.h
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_RECV_OUTPUT = 3
PACKET_RX_RING = 5
PACKET_STATISTICS = 6
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
PACKET_MR_ALLMULTI = 2

# From net/route.h
RTF_UP = 0x0001  # Route usable
RTF_REJECT = 0x0200

# From if_packet.h
PACKET_HOST = 0  # To us
PACKET_BROADCAST = 1  # To all
PACKET_MULTICAST = 2  # To group
PACKET_OTHERHOST = 3  # To someone else
PACKET_OUTGOING = 4  # Outgoing of any type
PACKET_LOOPBACK = 5  # MC/BRD frame looped back
PACKET_USER = 6  # To user space
PACKET_KERNEL = 7  # To kernel space
PACKET_AUXDATA = 8
PACKET_FASTROUTE = 6  # Fastrouted frame
# Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space


# Utils

def attach_filter(sock, bpf_filter, iface):
    # type: (socket.socket, str, _GlobInterfaceType) -> None
    """
    Compile bpf filter and attach it to a socket

    :param sock: the python socket
    :param bpf_filter: the bpf string filter to compile
    :param iface: the interface used to compile
    """
    bp = compile_filter(bpf_filter, iface)
    if conf.use_pypy and sys.pypy_version_info <= (7, 3, 2):  # type: ignore
        # PyPy < 7.3.2 has a broken behavior
        # https://foss.heptapod.net/pypy/pypy/-/issues/3298
        bp = struct.pack(  # type: ignore
            'HL',
            bp.bf_len, ctypes.addressof(bp.bf_insns.contents)
        )
    else:
        bp = sock_fprog(bp.bf_len, bp.bf_insns)  # type: ignore
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bp)


def set_promisc(s, iff, val=1):
    # type: (socket.socket, _GlobInterfaceType, int) -> None
    _iff = resolve_iface(iff)
    mreq = struct.pack("IHH8s", _iff.index, PACKET_MR_PROMISC, 0, b"")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)


# Interface provider


class LinuxInterfaceProvider(InterfaceProvider):
    name = "sys"

    def _is_valid(self, dev):
        # type: (NetworkInterface) -> bool
        return bool(dev.flags & IFF_UP)

    def load(self):
        # type: () -> Dict[str, NetworkInterface]
        data = {}
        for iface in _get_if_list().values():
            if_data = iface.copy()
            if_data.update({
                "network_name": iface["name"],
                "description": iface["name"],
                "ips": [x["address"] for x in iface["ips"]]
            })
            data[iface["name"]] = NetworkInterface(self, if_data)
        return data


conf.ifaces.register_provider(LinuxInterfaceProvider)

if os.uname()[4] in ['x86_64', 'aarch64']:
    def get_last_packet_timestamp(sock):
        # type: (socket.socket) -> float
        ts = ioctl(sock, SIOCGSTAMP, "1234567890123456")  # type: ignore
        s, us = struct.unpack("QQ", ts)  # type: Tuple[int, int]
        return s + us / 1000000.0
else:
    def get_last_packet_timestamp(sock):
        # type: (socket.socket) -> float
        ts = ioctl(sock, SIOCGSTAMP, "12345678")  # type: ignore
        s, us = struct.unpack("II", ts)  # type: Tuple[int, int]
        return s + us / 1000000.0


def _flush_fd(fd):
    # type: (int) -> None
    while True:
        r, w, e = select([fd], [], [], 0)
        if r:
            os.read(fd, MTU)
        else:
            break


class L2Socket(SuperSocket):
    desc = "read/write packets at layer 2 using Linux PF_PACKET sockets"

    def __init__(self,
                 iface=None,  # type: Optional[Union[str, NetworkInterface]]
                 type=ETH_P_ALL,  # type: int
                 promisc=None,  # type: Optional[Any]
                 filter=None,  # type: Optional[Any]
                 nofilter=0,  # type: int
                 monitor=None,  # type: Optional[Any]
                 ):
        # type: (...) -> None
        self.iface = network_name(iface or conf.iface)
        self.type = type
        self.promisc = conf.sniff_promisc if promisc is None else promisc
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                try:
                    attach_filter(self.ins, filter, self.iface)
                except (ImportError, Scapy_Exception) as ex:
                    raise Scapy_Exception("Cannot set filter: %s" % ex)
        if self.promisc:
            set_promisc(self.ins, self.iface)
        self.ins.bind((self.iface, type))
        _flush_fd(self.ins.fileno())
        self.ins.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            conf.bufsize
        )
        # Receive Auxiliary Data (VLAN tags)
        try:
            self.ins.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
            self.ins.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            self.auxdata_available = True
        except OSError:
            # Note: Auxiliary Data is only supported since
            #       Linux 2.6.21
            msg = "Your Linux Kernel does not support Auxiliary Data!"
            log_runtime.info(msg)
        if not isinstance(self, L2ListenSocket):
            self.outs = self.ins  # type: socket.socket
            self.outs.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
                conf.bufsize
            )
        else:
            self.outs = None  # type: ignore
        sa_ll = self.ins.getsockname()
        if sa_ll[3] in conf.l2types:
            self.LL = conf.l2types.num2layer[sa_ll[3]]
            self.lvl = 2
        elif sa_ll[1] in conf.l3types:
            self.LL = conf.l3types.num2layer[sa_ll[1]]
            self.lvl = 3
        else:
            self.LL = conf.default_l2
            self.lvl = 2
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3], self.LL.name)  # noqa: E501

    def close(self):
        # type: () -> None
        if self.closed:
            return
        try:
            if self.promisc and getattr(self, "ins", None):
                set_promisc(self.ins, self.iface, 0)
        except (AttributeError, OSError):
            pass
        SuperSocket.close(self)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Receives a packet, then returns a tuple containing (cls, pkt_data, time)"""  # noqa: E501
        pkt, sa_ll, ts = self._recv_raw(self.ins, x)
        if self.outs and sa_ll[2] == socket.PACKET_OUTGOING:
            return None, None, None
        if ts is None:
            ts = get_last_packet_timestamp(self.ins)
        return self.LL, pkt, ts

    def send(self, x):
        # type: (Packet) -> int
        try:
            return SuperSocket.send(self, x)
        except socket.error as msg:
            if msg.errno == 22 and len(x) < conf.min_pkt_size:
                padding = b"\x00" * (conf.min_pkt_size - len(x))
                if isinstance(x, Packet):
                    return SuperSocket.send(self, x / Padding(load=padding))
                else:
                    return SuperSocket.send(self, raw(x) + padding)
            raise


class L2ListenSocket(L2Socket):
    desc = "read packets at layer 2 using Linux PF_PACKET sockets. Also receives the packets going OUT"  # noqa: E501

    def send(self, x):
        # type: (Packet) -> NoReturn
        raise Scapy_Exception("Can't send anything with L2ListenSocket")


class L3PacketSocket(L2Socket):
    desc = "read/write packets at layer 3 using Linux PF_PACKET sockets"

    def __init__(self,
                 iface=None,  # type: Optional[Union[str, NetworkInterface]]
                 type=ETH_P_ALL,  # type: int
                 promisc=None,  # type: Optional[Any]
                 filter=None,  # type: Optional[Any]
                 nofilter=0,  # type: int
                 monitor=None,  # type: Optional[Any]
                 ):
        self.send_socks = {}
        super(L3PacketSocket, self).__init__(
            iface=iface,
            type=type,
            promisc=promisc,
            filter=filter,
            nofilter=nofilter,
            monitor=monitor,
        )
        self.filter = filter
        self.send_socks = {network_name(self.iface): self}

    def recv(self, x=MTU, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        pkt = SuperSocket.recv(self, x, **kwargs)
        if pkt and self.lvl == 2:
            pkt.payload.time = pkt.time
            return pkt.payload
        return pkt

    def send(self, x):
        # type: (Packet) -> int
        # Select the file descriptor to send the packet on.
        iff = x.route()[0]
        if iff is None:
            iff = network_name(conf.iface)
        type_x = type(x)
        if iff not in self.send_socks:
            self.send_socks[iff] = L3PacketSocket(
                iface=iff,
                type=conf.l3types.layer2num.get(type_x, self.type),
                filter=self.filter,
                promisc=self.promisc,
            )
        sock = self.send_socks[iff]
        fd = sock.outs
        if sock.lvl == 3:
            if not issubclass(sock.LL, type_x):
                warning("Incompatible L3 types detected using %s instead of %s !",
                        type_x, sock.LL)
                sock.LL = type_x
        if sock.lvl == 2:
            sx = bytes(sock.LL() / x)
        else:
            sx = bytes(x)
        # Now send.
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        try:
            return fd.send(sx)
        except socket.error as msg:
            if msg.errno == 22 and len(sx) < conf.min_pkt_size:
                return fd.send(
                    sx + b"\x00" * (conf.min_pkt_size - len(sx))
                )
            elif conf.auto_fragment and msg.errno == 90:
                i = 0
                for p in x.fragment():
                    i += fd.send(bytes(self.LL() / p))
                return i
            else:
                raise

    @staticmethod
    def select(sockets, remain=None):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        socks = []  # type: List[SuperSocket]
        for sock in sockets:
            if isinstance(sock, L3PacketSocket):
                socks += sock.send_socks.values()
            else:
                socks.append(sock)
        return L2Socket.select(socks, remain=remain)

    def close(self):
        # type: () -> None
        if self.closed:
            return
        super(L3PacketSocket, self).close()
        for fd in self.send_socks.values():
            if fd is not self:
                fd.close()


class VEthPair(object):
    """
    encapsulates a virtual Ethernet interface pair
    """

    def __init__(self, iface_name, peer_name):
        # type: (str, str) -> None
        if not LINUX:
            # ToDo: do we need a kernel version check here?
            raise ScapyInvalidPlatformException(
                'Virtual Ethernet interface pair only available on Linux'
            )

        self.ifaces = [iface_name, peer_name]

    def iface(self):
        # type: () -> str
        return self.ifaces[0]

    def peer(self):
        # type: () -> str
        return self.ifaces[1]

    def setup(self):
        # type: () -> None
        """
        create veth pair links
        :raises subprocess.CalledProcessError if operation fails
        """
        subprocess.check_call(['ip', 'link', 'add', self.ifaces[0], 'type', 'veth', 'peer', 'name', self.ifaces[1]])  # noqa: E501

    def destroy(self):
        # type: () -> None
        """
        remove veth pair links
        :raises subprocess.CalledProcessError if operation fails
        """
        subprocess.check_call(['ip', 'link', 'del', self.ifaces[0]])

    def up(self):
        # type: () -> None
        """
        set veth pair links up
        :raises subprocess.CalledProcessError if operation fails
        """
        for idx in [0, 1]:
            subprocess.check_call(["ip", "link", "set", self.ifaces[idx], "up"])  # noqa: E501

    def down(self):
        # type: () -> None
        """
        set veth pair links down
        :raises subprocess.CalledProcessError if operation fails
        """
        for idx in [0, 1]:
            subprocess.check_call(["ip", "link", "set", self.ifaces[idx], "down"])  # noqa: E501

    def __enter__(self):
        # type: () -> VEthPair
        self.setup()
        self.up()
        conf.ifaces.reload()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # type: (Any, Any, Any) -> None
        self.destroy()
        conf.ifaces.reload()
