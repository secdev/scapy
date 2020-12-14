# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Linux specific functions.
"""

from __future__ import absolute_import


import array
import ctypes
from fcntl import ioctl
import os
from select import select
import socket
import struct
import sys
import time

import subprocess

from scapy.compat import raw, plain_str
from scapy.consts import LINUX
import scapy.utils
import scapy.utils6
from scapy.arch.common import get_if, compile_filter, _iff_flags
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

from scapy.arch.common import get_if_raw_hwaddr  # noqa: F401

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
    r"""
    Return the raw IPv4 address of an interface.
    If unavailable, returns b"\0\0\0\0"
    """
    try:
        return get_if(iff, SIOCGIFADDR)[20:24]
    except IOError:
        return b"\0\0\0\0"


def _get_if_list():
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
        line = plain_str(line)
        lst.append(line.split(":")[0].strip())
    f.close()
    return lst


def attach_filter(sock, bpf_filter, iface):
    """
    Compile bpf filter and attach it to a socket

    :param sock: the python socket
    :param bpf_filter: the bpf string filter to compile
    :param iface: the interface used to compile
    """
    bp = compile_filter(bpf_filter, iface)
    if conf.use_pypy and sys.pypy_version_info <= (7, 3, 2):
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
    mreq = struct.pack("IHH8s", get_if_index(iff), PACKET_MR_PROMISC, 0, b"")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)


def get_alias_address(iface_name, ip_mask, gw_str, metric):
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
    names = array.array('B', b'\0' * 4096)
    ifreq = ioctl(sck.fileno(), SIOCGIFCONF,
                  struct.pack("iL", len(names), names.buffer_info()[0]))

    # Extract interfaces names
    out = struct.unpack("iL", ifreq)[0]
    names = names.tobytes() if six.PY3 else names.tostring()
    names = [names[i:i + offset].split(b'\0', 1)[0] for i in range(0, out, name_len)]  # noqa: E501

    # Look for the IP address
    for ifname in names:
        # Only look for a matching interface name
        if not ifname.decode("utf8").startswith(iface_name):
            continue

        # Retrieve and convert addresses
        ifreq = ioctl(sck, SIOCGIFADDR, struct.pack("16s16x", ifname))
        ifaddr = struct.unpack(">I", ifreq[20:24])[0]
        ifreq = ioctl(sck, SIOCGIFNETMASK, struct.pack("16s16x", ifname))
        msk = struct.unpack(">I", ifreq[20:24])[0]

        # Get the full interface name
        ifname = plain_str(ifname)
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
    return


def read_routes():
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

    for line in f.readlines()[1:]:
        line = plain_str(line)
        iff, dst, gw, flags, _, _, metric, msk, _, _, _ = line.split()
        flags = int(flags, 16)
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
        dst_int = socket.htonl(int(dst, 16)) & 0xffffffff
        msk_int = socket.htonl(int(msk, 16)) & 0xffffffff
        gw_str = scapy.utils.inet_ntoa(struct.pack("I", int(gw, 16)))
        metric = int(metric)

        route = [dst_int, msk_int, gw_str, iff, ifaddr, metric]
        if ifaddr_int & msk_int != dst_int:
            tmp_route = get_alias_address(iff, dst_int, gw_str, metric)
            if tmp_route:
                route = tmp_route
        routes.append(tuple(route))

    f.close()
    s.close()
    return routes

############
#   IPv6   #
############


def in6_getifaddr():
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'iface'.

    This is the list of all addresses of all interfaces available on
    the system.
    """
    ret = []
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
        ret = struct.unpack('4s4s4s4s4s4s4s4s', p)
        ret = b':'.join(ret).decode()
        return scapy.utils6.in6_ptop(ret)

    lifaddr = in6_getifaddr()
    for line in f.readlines():
        d, dp, _, _, nh, metric, rc, us, fl, dev = line.split()
        metric = int(metric, 16)
        fl = int(fl, 16)
        dev = plain_str(dev)

        if fl & RTF_UP == 0:
            continue
        if fl & RTF_REJECT:
            continue

        d = proc2r(d)
        dp = int(dp, 16)
        nh = proc2r(nh)

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
    return int(struct.unpack("I", get_if(iff, SIOCGIFINDEX)[16:20])[0])


class LinuxInterfaceProvider(InterfaceProvider):
    name = "sys"

    def _is_valid(self, dev):
        return bool(dev.flags & IFF_UP)

    def load(self):
        from scapy.fields import FlagValue
        data = {}
        ips = in6_getifaddr()
        for i in _get_if_list():
            ifflags = struct.unpack("16xH14x", get_if(i, SIOCGIFFLAGS))[0]
            index = get_if_index(i)
            mac = scapy.utils.str2mac(
                get_if_raw_hwaddr(i, siocgifhwaddr=SIOCGIFHWADDR)[1]
            )
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
        ts = ioctl(sock, SIOCGSTAMP, "1234567890123456")
        s, us = struct.unpack("QQ", ts)
        return s + us / 1000000.0
else:
    def get_last_packet_timestamp(sock):
        ts = ioctl(sock, SIOCGSTAMP, "12345678")
        s, us = struct.unpack("II", ts)
        return s + us / 1000000.0


def _flush_fd(fd):
    if hasattr(fd, 'fileno'):
        fd = fd.fileno()
    while True:
        r, w, e = select([fd], [], [], 0)
        if r:
            os.read(fd, MTU)
        else:
            break


class L2Socket(SuperSocket):
    desc = "read/write packets at layer 2 using Linux PF_PACKET sockets"

    def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None,
                 nofilter=0, monitor=None):
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
                    attach_filter(self.ins, filter, iface)
                except ImportError as ex:
                    log_runtime.error("Cannot set filter: %s", ex)
        if self.promisc:
            set_promisc(self.ins, self.iface)
        self.ins.bind((self.iface, type))
        _flush_fd(self.ins)
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
        if isinstance(self, L2ListenSocket):
            self.outs = None
        else:
            self.outs = self.ins
            self.outs.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
                conf.bufsize
            )
        sa_ll = self.ins.getsockname()
        if sa_ll[3] in conf.l2types:
            self.LL = conf.l2types[sa_ll[3]]
            self.lvl = 2
        elif sa_ll[1] in conf.l3types:
            self.LL = conf.l3types[sa_ll[1]]
            self.lvl = 3
        else:
            self.LL = conf.default_l2
            self.lvl = 2
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3], self.LL.name)  # noqa: E501

    def close(self):
        if self.closed:
            return
        try:
            if self.promisc and self.ins:
                set_promisc(self.ins, self.iface, 0)
        except (AttributeError, OSError):
            pass
        SuperSocket.close(self)

    def recv_raw(self, x=MTU):
        """Receives a packet, then returns a tuple containing (cls, pkt_data, time)"""  # noqa: E501
        pkt, sa_ll, ts = self._recv_raw(self.ins, x)
        if self.outs and sa_ll[2] == socket.PACKET_OUTGOING:
            return None, None, None
        if ts is None:
            ts = get_last_packet_timestamp(self.ins)
        return self.LL, pkt, ts

    def send(self, x):
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
        raise Scapy_Exception("Can't send anything with L2ListenSocket")


class L3PacketSocket(L2Socket):
    desc = "read/write packets at layer 3 using Linux PF_PACKET sockets"

    def recv(self, x=MTU):
        pkt = SuperSocket.recv(self, x)
        if pkt and self.lvl == 2:
            pkt.payload.time = pkt.time
            return pkt.payload
        return pkt

    def send(self, x):
        iff = x.route()[0]
        if iff is None:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        sn = self.outs.getsockname()
        ll = lambda x: x
        type_x = type(x)
        if type_x in conf.l3types:
            sdto = (iff, conf.l3types[type_x])
        if sn[3] in conf.l2types:
            ll = lambda x: conf.l2types[sn[3]]() / x
        if self.lvl == 3 and type_x != self.LL:
            warning("Incompatible L3 types detected using %s instead of %s !",
                    type_x, self.LL)
            self.LL = type_x
        sx = raw(ll(x))
        x.sent_time = time.time()
        try:
            self.outs.sendto(sx, sdto)
        except socket.error as msg:
            if msg.errno == 22 and len(sx) < conf.min_pkt_size:
                self.outs.send(sx + b"\x00" * (conf.min_pkt_size - len(sx)))
            elif conf.auto_fragment and msg.errno == 90:
                for p in x.fragment():
                    self.outs.sendto(raw(ll(p)), sdto)
            else:
                raise


class VEthPair(object):
    """
    encapsulates a virtual Ethernet interface pair
    """

    def __init__(self, iface_name, peer_name):

        if not LINUX:
            # ToDo: do we need a kernel version check here?
            raise ScapyInvalidPlatformException(
                'Virtual Ethernet interface pair only available on Linux'
            )

        self.ifaces = [iface_name, peer_name]

    def iface(self):
        return self.ifaces[0]

    def peer(self):
        return self.ifaces[1]

    def setup(self):
        """
        create veth pair links
        :raises subprocess.CalledProcessError if operation fails
        """
        subprocess.check_call(['ip', 'link', 'add', self.ifaces[0], 'type', 'veth', 'peer', 'name', self.ifaces[1]])  # noqa: E501

    def destroy(self):
        """
        remove veth pair links
        :raises subprocess.CalledProcessError if operation fails
        """
        subprocess.check_call(['ip', 'link', 'del', self.ifaces[0]])

    def up(self):
        """
        set veth pair links up
        :raises subprocess.CalledProcessError if operation fails
        """
        for idx in [0, 1]:
            subprocess.check_call(["ip", "link", "set", self.ifaces[idx], "up"])  # noqa: E501

    def down(self):
        """
        set veth pair links down
        :raises subprocess.CalledProcessError if operation fails
        """
        for idx in [0, 1]:
            subprocess.check_call(["ip", "link", "set", self.ifaces[idx], "down"])  # noqa: E501

    def __enter__(self):
        self.setup()
        self.up()
        conf.ifaces.reload()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()
        conf.ifaces.reload()
