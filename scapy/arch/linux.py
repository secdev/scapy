# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Linux specific functions.
"""

from __future__ import absolute_import


from fcntl import ioctl
from select import select

import array
import ctypes
import os
import socket
import struct
import subprocess
import sys
import time

import scapy.utils
import scapy.utils6
from scapy.compat import raw, plain_str
from scapy.consts import LINUX
from scapy.arch.common import (
    _iff_flags,
    compile_filter,
    get_if,
    get_if_raw_hwaddr,
)
from scapy.config import conf
from scapy.data import MTU, ETH_P_ALL, SOL_PACKET, SO_ATTACH_FILTER, \
    SO_TIMESTAMPNS
from scapy.error import (
    ScapyInvalidPlatformException,
    Scapy_Exception,
    log_loading,
    log_runtime,
    warning,
)
from scapy.interfaces import IFACES, InterfaceProvider, NetworkInterface, \
    network_name
from scapy.libs.structures import sock_fprog
from scapy.packet import Packet, Padding
from scapy.pton_ntop import inet_ntop
from scapy.supersocket import SuperSocket

import scapy.modules.six as six
from scapy.modules.six.moves import range

# Typing imports
from scapy.compat import (
    Any,
    Callable,
    Dict,
    List,
    NoReturn,
    Optional,
    Tuple,
    Type,
    Union,
)

# From bits/ioctls.h
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


def get_if_raw_addr(iff):
    # type: (Union[NetworkInterface, str]) -> bytes
    r"""
    Return the raw IPv4 address of an interface.
    If unavailable, returns b"\0\0\0\0"
    """
    try:
        return get_if(iff, SIOCGIFADDR)[20:24]
    except IOError:
        return b"\0\0\0\0"


def _get_if_list():
    # type: () -> List[str]
    """
    Function to read the interfaces from /proc/net/dev
    """
    try:
        f = open("/proc/net/dev", "rb")
    except IOError:
        try:
            f.close()
        except Exception:
            pass
        log_loading.critical("Can't open /proc/net/dev !")
        return []
    lst = []
    f.readline()
    f.readline()
    for line in f:
        lst.append(plain_str(line).split(":")[0].strip())
    f.close()
    return lst


def attach_filter(sock, bpf_filter, iface):
    # type: (socket.socket, str, Union[NetworkInterface, str]) -> None
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
        bp = struct.pack(
            'HL',
            bp.bf_len, ctypes.addressof(bp.bf_insns.contents)
        )
    else:
        bp = sock_fprog(bp.bf_len, bp.bf_insns)
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bp)


def set_promisc(s, iff, val=1):
    # type: (socket.socket, Union[NetworkInterface, str], int) -> None
    mreq = struct.pack("IHH8s", get_if_index(iff), PACKET_MR_PROMISC, 0, b"")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)


def get_alias_address(iface_name,  # type: str
                      ip_mask,  # type: int
                      gw_str,  # type: str
                      metric  # type: int
                      ):
    # type: (...) -> Optional[Tuple[int, int, str, str, str, int]]
    """
    Get the correct source IP address of an interface alias
    """

    # Detect the architecture
    if scapy.consts.IS_64BITS:
        offset, name_len = 16, 40
    else:
        offset, name_len = 32, 32

    # Retrieve interfaces structures
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names_ar = array.array('B', b'\0' * 4096)
    ifreq = ioctl(sck.fileno(), SIOCGIFCONF,
                  struct.pack("iL", len(names_ar), names_ar.buffer_info()[0]))

    # Extract interfaces names
    out = struct.unpack("iL", ifreq)[0]
    names_b = names_ar.tobytes() if six.PY3 else names_ar.tostring()
    names = [names_b[i:i + offset].split(b'\0', 1)[0] for i in range(0, out, name_len)]  # noqa: E501

    # Look for the IP address
    for ifname_b in names:
        ifname = plain_str(ifname_b)
        # Only look for a matching interface name
        if not ifname.startswith(iface_name):
            continue

        # Retrieve and convert addresses
        ifreq = ioctl(sck, SIOCGIFADDR, struct.pack("16s16x", ifname_b))
        ifaddr = struct.unpack(">I", ifreq[20:24])[0]  # type: int
        ifreq = ioctl(sck, SIOCGIFNETMASK, struct.pack("16s16x", ifname_b))
        msk = struct.unpack(">I", ifreq[20:24])[0]  # type: int

        # Get the full interface name
        if ':' in ifname:
            ifname = ifname[:ifname.index(':')]
        else:
            continue

        # Check if the source address is included in the network
        if (ifaddr & msk) == ip_mask:
            sck.close()
            return (ifaddr & msk, msk, gw_str, ifname,
                    scapy.utils.ltoa(ifaddr), metric)

    sck.close()
    return None


def read_routes():
    # type: () -> List[Tuple[int, int, str, str, str, int]]
    try:
        f = open("/proc/net/route", "rb")
    except IOError:
        log_loading.critical("Can't open /proc/net/route !")
        return []
    routes = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = ioctl(s, SIOCGIFADDR, struct.pack("16s16x", conf.loopback_name.encode("utf8")))  # noqa: E501
        addrfamily = struct.unpack("h", ifreq[16:18])[0]
        if addrfamily == socket.AF_INET:
            ifreq2 = ioctl(s, SIOCGIFNETMASK, struct.pack("16s16x", conf.loopback_name.encode("utf8")))  # noqa: E501
            msk = socket.ntohl(struct.unpack("I", ifreq2[20:24])[0])
            dst = socket.ntohl(struct.unpack("I", ifreq[20:24])[0]) & msk
            ifaddr = scapy.utils.inet_ntoa(ifreq[20:24])
            routes.append((dst, msk, "0.0.0.0", conf.loopback_name, ifaddr, 1))  # noqa: E501
        else:
            warning("Interface %s: unknown address family (%i)" % (conf.loopback_name, addrfamily))  # noqa: E501
    except IOError as err:
        if err.errno == 99:
            warning("Interface %s: no address assigned" % conf.loopback_name)  # noqa: E501
        else:
            warning("Interface %s: failed to get address config (%s)" % (conf.loopback_name, str(err)))  # noqa: E501

    for line_b in f.readlines()[1:]:
        line = plain_str(line_b)
        iff, dst_b, gw, flags_b, _, _, metric_b, msk_b, _, _, _ = line.split()
        flags = int(flags_b, 16)
        if flags & RTF_UP == 0:
            continue
        if flags & RTF_REJECT:
            continue
        try:
            ifreq = ioctl(s, SIOCGIFADDR, struct.pack("16s16x", iff.encode("utf8")))  # noqa: E501
        except IOError:  # interface is present in routing tables but does not have any assigned IP  # noqa: E501
            ifaddr = "0.0.0.0"
            ifaddr_int = 0
        else:
            addrfamily = struct.unpack("h", ifreq[16:18])[0]
            if addrfamily == socket.AF_INET:
                ifaddr = scapy.utils.inet_ntoa(ifreq[20:24])
                ifaddr_int = struct.unpack("!I", ifreq[20:24])[0]
            else:
                warning("Interface %s: unknown address family (%i)", iff, addrfamily)  # noqa: E501
                continue

        # Attempt to detect an interface alias based on addresses inconsistencies  # noqa: E501
        dst_int = socket.htonl(int(dst_b, 16)) & 0xffffffff
        msk_int = socket.htonl(int(msk_b, 16)) & 0xffffffff
        gw_str = scapy.utils.inet_ntoa(struct.pack("I", int(gw, 16)))
        metric = int(metric_b)

        route = (dst_int, msk_int, gw_str, iff, ifaddr, metric)
        if ifaddr_int & msk_int != dst_int:
            tmp_route = get_alias_address(iff, dst_int, gw_str, metric)
            if tmp_route:
                route = tmp_route
        routes.append(route)

    f.close()
    s.close()
    return routes

############
#   IPv6   #
############


def in6_getifaddr():
    # type: () -> List[Tuple[str, int, str]]
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'iface'.

    This is the list of all addresses of all interfaces available on
    the system.
    """
    ret = []  # type: List[Tuple[str, int, str]]
    try:
        fdesc = open("/proc/net/if_inet6", "rb")
    except IOError:
        return ret
    for line in fdesc:
        # addr, index, plen, scope, flags, ifname
        tmp = plain_str(line).split()
        addr = scapy.utils6.in6_ptop(
            b':'.join(
                struct.unpack('4s4s4s4s4s4s4s4s', tmp[0].encode())
            ).decode()
        )
        # (addr, scope, iface)
        ret.append((addr, int(tmp[3], 16), tmp[5]))
    fdesc.close()
    return ret


def read_routes6():
    # type: () -> List[Tuple[str, int, str, str, List[str], int]]
    try:
        f = open("/proc/net/ipv6_route", "rb")
    except IOError:
        return []
    # 1. destination network
    # 2. destination prefix length
    # 3. source network displayed
    # 4. source prefix length
    # 5. next hop
    # 6. metric
    # 7. reference counter (?!?)
    # 8. use counter (?!?)
    # 9. flags
    # 10. device name
    routes = []

    def proc2r(p):
        # type: (bytes) -> str
        ret = struct.unpack('4s4s4s4s4s4s4s4s', p)
        addr = b':'.join(ret).decode()
        return scapy.utils6.in6_ptop(addr)

    lifaddr = in6_getifaddr()
    for line in f.readlines():
        d_b, dp_b, _, _, nh_b, metric_b, rc, us, fl_b, dev_b = line.split()
        metric = int(metric_b, 16)
        fl = int(fl_b, 16)
        dev = plain_str(dev_b)

        if fl & RTF_UP == 0:
            continue
        if fl & RTF_REJECT:
            continue

        d = proc2r(d_b)
        dp = int(dp_b, 16)
        nh = proc2r(nh_b)

        cset = []  # candidate set (possible source addresses)
        if dev == conf.loopback_name:
            if d == '::':
                continue
            cset = ['::1']
        else:
            devaddrs = (x for x in lifaddr if x[2] == dev)
            cset = scapy.utils6.construct_source_candidate_set(d, dp, devaddrs)

        if len(cset) != 0:
            routes.append((d, dp, nh, dev, cset, metric))
    f.close()
    return routes


def get_if_index(iff):
    # type: (Union[NetworkInterface, str]) -> int
    return int(struct.unpack("I", get_if(iff, SIOCGIFINDEX)[16:20])[0])


class LinuxInterfaceProvider(InterfaceProvider):
    name = "sys"

    def _is_valid(self, dev):
        # type: (NetworkInterface) -> bool
        return bool(dev.flags & IFF_UP)

    def load(self):
        # type: () -> Dict[str, NetworkInterface]
        from scapy.fields import FlagValue
        data = {}
        ips = in6_getifaddr()
        for i in _get_if_list():
            ifflags = struct.unpack("16xH14x", get_if(i, SIOCGIFFLAGS))[0]
            index = get_if_index(i)
            mac = scapy.utils.str2mac(
                get_if_raw_hwaddr(i, siocgifhwaddr=SIOCGIFHWADDR)[1]
            )
            ip = None  # type: Optional[str]
            ip = inet_ntop(socket.AF_INET, get_if_raw_addr(i))
            if ip == "0.0.0.0":
                ip = None
            ifflags = FlagValue(ifflags, _iff_flags)
            if_data = {
                "name": i,
                "network_name": i,
                "description": i,
                "flags": ifflags,
                "index": index,
                "ip": ip,
                "ips": [x[0] for x in ips if x[2] == i] + [ip] if ip else [],
                "mac": mac
            }
            data[i] = NetworkInterface(self, if_data)
        return data


IFACES.register_provider(LinuxInterfaceProvider)

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
        if monitor is not None:
            log_runtime.info(
                "The 'monitor' argument has no effect on native linux sockets."
            )
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
                except ImportError as ex:
                    log_runtime.error("Cannot set filter: %s", ex)
        if self.promisc:
            set_promisc(self.ins, self.iface)
        self.ins.bind((self.iface, type))
        _flush_fd(self.ins.fileno())
        self.ins.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            conf.bufsize
        )
        if not six.PY2:
            # Receive Auxiliary Data (VLAN tags)
            try:
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
            if self.promisc and self.ins:
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

    def recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        pkt = SuperSocket.recv(self, x)
        if pkt and self.lvl == 2:
            pkt.payload.time = pkt.time
            return pkt.payload
        return pkt

    def send(self, x):
        # type: (Packet) -> int
        iff = x.route()[0]
        if iff is None:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        sn = self.outs.getsockname()
        ll = lambda x: x  # type: Callable[[Packet], Packet]
        type_x = type(x)
        if type_x in conf.l3types:
            sdto = (iff, conf.l3types.layer2num[type_x])
        if sn[3] in conf.l2types:
            ll = lambda x: conf.l2types.num2layer[sn[3]]() / x
        if self.lvl == 3 and type_x != self.LL:
            warning("Incompatible L3 types detected using %s instead of %s !",
                    type_x, self.LL)
            self.LL = type_x
        sx = raw(ll(x))
        x.sent_time = time.time()
        try:
            return self.outs.sendto(sx, sdto)
        except socket.error as msg:
            if msg.errno == 22 and len(sx) < conf.min_pkt_size:
                return self.outs.send(
                    sx + b"\x00" * (conf.min_pkt_size - len(sx))
                )
            elif conf.auto_fragment and msg.errno == 90:
                i = 0
                for p in x.fragment():
                    i += self.outs.sendto(raw(ll(p)), sdto)
                return i
            else:
                raise


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
