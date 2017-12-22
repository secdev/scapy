## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

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


from scapy.compat import *
from scapy.consts import LOOPBACK_NAME, IS_64BITS
import scapy.utils
import scapy.utils6
from scapy.packet import Packet, Padding
from scapy.config import conf
from scapy.data import *
from scapy.supersocket import SuperSocket
import scapy.arch
from scapy.error import warning, Scapy_Exception, log_interactive, log_loading
from scapy.arch.common import get_if, get_bpf_pointer
from scapy.modules.six.moves import range



# From bits/ioctls.h
SIOCGIFHWADDR  = 0x8927          # Get hardware address    
SIOCGIFADDR    = 0x8915          # get PA address          
SIOCGIFNETMASK = 0x891b          # get network PA mask     
SIOCGIFNAME    = 0x8910          # get iface name          
SIOCSIFLINK    = 0x8911          # set iface channel       
SIOCGIFCONF    = 0x8912          # get iface list          
SIOCGIFFLAGS   = 0x8913          # get flags               
SIOCSIFFLAGS   = 0x8914          # set flags               
SIOCGIFINDEX   = 0x8933          # name -> if_index mapping
SIOCGIFCOUNT   = 0x8938          # get number of devices
SIOCGSTAMP     = 0x8906          # get packet timestamp (as a timeval)

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
PACKET_ADD_MEMBERSHIP  = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_RECV_OUTPUT     = 3
PACKET_RX_RING         = 5
PACKET_STATISTICS      = 6
PACKET_MR_MULTICAST    = 0
PACKET_MR_PROMISC      = 1
PACKET_MR_ALLMULTI     = 2

# From bits/socket.h
SOL_PACKET = 263
# From asm/socket.h
SO_ATTACH_FILTER = 26

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
PACKET_FASTROUTE = 6  # Fastrouted frame
# Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space


with os.popen("%s -V 2> /dev/null" % conf.prog.tcpdump) as _f:
    if _f.close() >> 8 == 0x7f:
        log_loading.warning("Failed to execute tcpdump. Check it is installed and in the PATH")
        TCPDUMP=0
    else:
        TCPDUMP=1
del(_f)
    

def get_if_raw_hwaddr(iff):
    return struct.unpack("16xh6s8x",get_if(iff,SIOCGIFHWADDR))

def get_if_raw_addr(iff):
    try:
        return get_if(iff, SIOCGIFADDR)[20:24]
    except IOError:
        return b"\0\0\0\0"


def get_if_list():
    try:
        f=open("/proc/net/dev", "rb")
    except IOError:
        warning("Can't open /proc/net/dev !")
        return []
    lst = []
    f.readline()
    f.readline()
    for l in f:
        l = plain_str(l)
        lst.append(l.split(":")[0].strip())
    return lst
def get_working_if():
    for i in get_if_list():
        if i == LOOPBACK_NAME:                
            continue
        ifflags = struct.unpack("16xH14x",get_if(i,SIOCGIFFLAGS))[0]
        if ifflags & IFF_UP:
            return i
    return LOOPBACK_NAME

def attach_filter(s, bpf_filter, iface):
    # XXX We generate the filter on the interface conf.iface 
    # because tcpdump open the "any" interface and ppp interfaces
    # in cooked mode. As we use them in raw mode, the filter will not
    # work... one solution could be to use "any" interface and translate
    # the filter from cooked mode to raw mode
    # mode
    if not TCPDUMP:
        return
    try:
        f = os.popen("%s -i %s -ddd -s %d '%s'" % (
            conf.prog.tcpdump,
            conf.iface if iface is None else iface,
            MTU,
            bpf_filter,
        ))
    except OSError:
        log_interactive.warning("Failed to attach filter.",
                                exc_info=True)
        return
    lines = f.readlines()
    ret = f.close()
    if ret:
        log_interactive.warning(
            "Failed to attach filter: tcpdump returned %d", ret
        )
        return
    
    bp = get_bpf_pointer(lines)
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bp)

def set_promisc(s,iff,val=1):
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
    names = names.tostring()
    names = [names[i:i+offset].split(b'\0', 1)[0] for i in range(0, out, name_len)]

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
        f=open("/proc/net/route", "rb")
    except IOError:
        warning("Can't open /proc/net/route !")
        return []
    routes = []
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = ioctl(s, SIOCGIFADDR, struct.pack("16s16x", scapy.consts.LOOPBACK_NAME.encode("utf8")))
        addrfamily = struct.unpack("h", ifreq[16:18])[0]
        if addrfamily == socket.AF_INET:
            ifreq2 = ioctl(s, SIOCGIFNETMASK, struct.pack("16s16x", scapy.consts.LOOPBACK_NAME.encode("utf8")))
            msk = socket.ntohl(struct.unpack("I", ifreq2[20:24])[0])
            dst = socket.ntohl(struct.unpack("I", ifreq[20:24])[0]) & msk
            ifaddr = scapy.utils.inet_ntoa(ifreq[20:24])
            routes.append((dst, msk, "0.0.0.0", scapy.consts.LOOPBACK_NAME, ifaddr, 1))
        else:
            warning("Interface %s: unknown address family (%i)" % (scapy.consts.LOOPBACK_NAME, addrfamily))
    except IOError as err:
        if err.errno == 99:
            warning("Interface %s: no address assigned" % scapy.consts.LOOPBACK_NAME)
        else:
            warning("Interface %s: failed to get address config (%s)" % (scapy.consts.LOOPBACK_NAME, str(err)))

    for l in f.readlines()[1:]:
        l = plain_str(l)
        iff,dst,gw,flags,x,x,metric,msk,x,x,x = l.split()
        flags = int(flags,16)
        if flags & RTF_UP == 0:
            continue
        if flags & RTF_REJECT:
            continue
        try:
            ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x", iff.encode("utf8")))
        except IOError: # interface is present in routing tables but does not have any assigned IP
            ifaddr="0.0.0.0"
        else:
            addrfamily = struct.unpack("h",ifreq[16:18])[0]
            if addrfamily == socket.AF_INET:
                ifaddr = scapy.utils.inet_ntoa(ifreq[20:24])
            else:
                warning("Interface %s: unkown address family (%i)", iff, addrfamily)
                continue

        # Attempt to detect an interface alias based on addresses inconsistencies
        dst_int = socket.htonl(int(dst, 16)) & 0xffffffff
        msk_int = socket.htonl(int(msk, 16)) & 0xffffffff
        ifaddr_int = struct.unpack("!I", ifreq[20:24])[0]
        gw_str = scapy.utils.inet_ntoa(struct.pack("I", int(gw, 16)))
        metric = int(metric)

        if ifaddr_int & msk_int != dst_int:
            tmp_route = get_alias_address(iff, dst_int, gw_str, metric)
            if tmp_route:
                routes.append(tmp_route)
            else:
                routes.append((dst_int, msk_int, gw_str, iff, ifaddr, metric))

        else:
            routes.append((dst_int, msk_int, gw_str, iff, ifaddr, metric))
    
    f.close()
    return routes

############
### IPv6 ###
############

def in6_getifaddr():
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'ifcace'.

    This is the list of all addresses of all interfaces available on
    the system.
    """
    ret = []
    try:
        fdesc = open("/proc/net/if_inet6", "rb")
    except IOError as err:    
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
    return ret

def read_routes6():
    try:
        f = open("/proc/net/ipv6_route","rb")
    except IOError as err:
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
        ret = struct.unpack('4s4s4s4s4s4s4s4s', raw(p))
        ret = b':'.join(ret).decode()
        return scapy.utils6.in6_ptop(ret)
    
    lifaddr = in6_getifaddr() 
    for l in f.readlines():
        l = plain_str(l)
        d,dp,s,sp,nh,metric,rc,us,fl,dev = l.split()
        metric = int(metric, 16)
        fl = int(fl, 16)

        if fl & RTF_UP == 0:
            continue
        if fl & RTF_REJECT:
            continue

        d = proc2r(d) ; dp = int(dp, 16)
        s = proc2r(s) ; sp = int(sp, 16)
        nh = proc2r(nh)

        cset = [] # candidate set (possible source addresses)
        if dev == LOOPBACK_NAME:
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
    return int(struct.unpack("I",get_if(iff, SIOCGIFINDEX)[16:20])[0])

if os.uname()[4] in [ 'x86_64', 'aarch64' ]:
    def get_last_packet_timestamp(sock):
        ts = ioctl(sock, SIOCGSTAMP, "1234567890123456")
        s,us = struct.unpack("QQ",ts)
        return s+us/1000000.0
else:
    def get_last_packet_timestamp(sock):
        ts = ioctl(sock, SIOCGSTAMP, "12345678")
        s,us = struct.unpack("II",ts)
        return s+us/1000000.0


def _flush_fd(fd):
    if hasattr(fd, 'fileno'):
        fd = fd.fileno()
    while True:
        r,w,e = select([fd],[],[],0)
        if r:
            os.read(fd,MTU)
        else:
            break





class L3PacketSocket(SuperSocket):
    desc = "read/write packets at layer 3 using Linux PF_PACKET sockets"
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
        self.type = type
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if iface:
            self.ins.bind((iface, type))
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter, iface)
        _flush_fd(self.ins)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        self.promisc = conf.promisc if promisc is None else promisc
        if self.promisc:
            if iface is None:
                self.iff = get_if_list()
            elif isinstance(iface, list):
                self.iff = iface
            else:
                self.iff = [iface]
            for i in self.iff:
                set_promisc(self.ins, i)
    def close(self):
        if self.closed:
            return
        self.closed = 1
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)
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
            lvl = 2

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
        if type(x) in conf.l3types:
            sdto = (iff, conf.l3types[type(x)])
        if sn[3] in conf.l2types:
            ll = lambda x:conf.l2types[sn[3]]()/x
        sx = raw(ll(x))
        x.sent_time = time.time()
        try:
            self.outs.sendto(sx, sdto)
        except socket.error as msg:
            if msg[0] == 22 and len(sx) < conf.min_pkt_size:
                self.outs.send(sx + b"\x00" * (conf.min_pkt_size - len(sx)))
            elif conf.auto_fragment and msg[0] == 90:
                for p in x.fragment():
                    self.outs.sendto(raw(ll(p)), sdto)
            else:
                raise



class L2Socket(SuperSocket):
    desc = "read/write packets at layer 2 using Linux PF_PACKET sockets"
    def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None, nofilter=0):
        self.iface = conf.iface if iface is None else iface
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if not nofilter: 
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter, iface)
        self.promisc = conf.sniff_promisc if promisc is None else promisc
        if self.promisc:
            set_promisc(self.ins, self.iface)
        self.ins.bind((self.iface, type))
        _flush_fd(self.ins)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = self.ins
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        sa_ll = self.outs.getsockname()
        if sa_ll[3] in conf.l2types:
            self.LL = conf.l2types[sa_ll[3]]
        elif sa_ll[1] in conf.l3types:
            self.LL = conf.l3types[sa_ll[1]]
        else:
            self.LL = conf.default_l2
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3], self.LL.name)
    def close(self):
        if self.closed:
            return
        self.closed = 1
        if self.promisc:
            set_promisc(self.ins, self.iface, 0)
        SuperSocket.close(self)
    def recv(self, x=MTU):
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
            q = conf.raw_layer(pkt)
        q.time = get_last_packet_timestamp(self.ins)
        return q
    def send(self, x):
        try:
            return SuperSocket.send(self, x)
        except socket.error as msg:
            if msg[0] == 22 and len(x) < conf.min_pkt_size:
                padding = b"\x00" * (conf.min_pkt_size - len(x))
                if isinstance(x, Packet):
                    return SuperSocket.send(self, x / Padding(load=padding))
                else:
                    return SuperSocket.send(self, raw(x) + padding)
            raise


class L2ListenSocket(SuperSocket):
    desc = "read packets at layer 2 using Linux PF_PACKET sockets"
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None, nofilter=0):
        self.type = type
        self.outs = None
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if iface is not None:
            self.ins.bind((iface, type))
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter, iface)
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        if iface is None:
            self.iff = get_if_list()
        elif isinstance(iface, list):
            self.iff = iface
        else:
            self.iff = [iface]
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i)
        _flush_fd(self.ins)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    def close(self):
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)

    def recv(self, x=MTU):
        pkt, sa_ll = self.ins.recvfrom(x)
        if sa_ll[3] in conf.l2types :
            cls = conf.l2types[sa_ll[3]]
        elif sa_ll[1] in conf.l3types:
            cls = conf.l3types[sa_ll[1]]
        else:
            cls = conf.default_l2
            warning("Unable to guess type (interface=%s protocol=%#x "
                    "family=%i). Using %s", sa_ll[0], sa_ll[1], sa_ll[3],
                                              cls.name)

        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = conf.raw_layer(pkt)
        pkt.time = get_last_packet_timestamp(self.ins)
        pkt.direction = sa_ll[2]
        return pkt
    
    def send(self, x):
        raise Scapy_Exception("Can't send anything with L2ListenSocket")


conf.L3socket = L3PacketSocket
conf.L2socket = L2Socket
conf.L2listen = L2ListenSocket
