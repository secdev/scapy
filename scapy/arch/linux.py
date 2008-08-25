## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


from __future__ import with_statement
import sys,os,struct,socket,time
from fcntl import ioctl
import scapy.utils


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
SOL_SOCKET = 1

# From net/route.h
RTF_UP = 0x0001  # Route usable
RTF_REJECT = 0x0200



DNET=PCAP=0
LOOPBACK_NAME="lo"

with os.popen("tcpdump -V 2> /dev/null") as f:
    if f.close() >> 8 == 0x7f:
        log_loading.warning("Failed to execute tcpdump. Check it is installed and in the PATH")
        TCPDUMP=0
    else:
        TCPDUMP=1
        
    

def get_if_raw_hwaddr(iff):
    return struct.unpack("16xh6s8x",get_if(iff,SIOCGIFHWADDR))

def get_if_raw_addr(iff):
    try:
        return get_if(iff, SIOCGIFADDR)[20:24]
    except IOError:
        return "\0\0\0\0"


def get_if_list():
    f=open("/proc/net/dev","r")
    lst = []
    f.readline()
    f.readline()
    for l in f:
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
def attach_filter(s, filter):
    # XXX We generate the filter on the interface conf.iface 
    # because tcpdump open the "any" interface and ppp interfaces
    # in cooked mode. As we use them in raw mode, the filter will not
    # work... one solution could be to use "any" interface and translate
    # the filter from cooked mode to raw mode
    # mode
    if not TCPDUMP:
        return
    try:
        f = os.popen("%s -i %s -ddd -s 1600 '%s'" % (config.conf.prog.tcpdump,config.conf.iface,filter))
    except OSError,msg:
        log_interactive.warning("Failed to execute tcpdump: (%s)")
        return
    lines = f.readlines()
    if f.close():
        raise Scapy_Exception("Filter parse error")
    nb = int(lines[0])
    bpf = ""
    for l in lines[1:]:
        bpf += struct.pack("HBBI",*map(long,l.split()))

    # XXX. Argl! We need to give the kernel a pointer on the BPF,
    # python object header seems to be 20 bytes. 36 bytes for x86 64bits arch.
    if X86_64:
        bpfh = struct.pack("HL", nb, id(bpf)+36)
    else:
        bpfh = struct.pack("HI", nb, id(bpf)+20)  
    s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, bpfh)

def set_promisc(s,iff,val=1):
    mreq = struct.pack("IHH8s", get_if_index(iff), PACKET_MR_PROMISC, 0, "")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)



def read_routes():
    f=open("/proc/net/route","r")
    routes = []
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",LOOPBACK_NAME))
    addrfamily = struct.unpack("h",ifreq[16:18])[0]
    if addrfamily == socket.AF_INET:
        ifreq2 = ioctl(s, SIOCGIFNETMASK,struct.pack("16s16x",LOOPBACK_NAME))
        msk = socket.ntohl(struct.unpack("I",ifreq2[20:24])[0])
        dst = socket.ntohl(struct.unpack("I",ifreq[20:24])[0]) & msk
        ifaddr = scapy.utils.inet_ntoa(ifreq[20:24])
        routes.append((dst, msk, "0.0.0.0", LOOPBACK_NAME, ifaddr))
    else:
        warning("Interface lo: unkown address family (%i)"% addrfamily)

    for l in f.readlines()[1:]:
        iff,dst,gw,flags,x,x,x,msk,x,x,x = l.split()
        flags = int(flags,16)
        if flags & RTF_UP == 0:
            continue
        if flags & RTF_REJECT:
            continue
        try:
            ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",iff))
        except IOError: # interface is present in routing tables but does not have any assigned IP
            ifaddr="0.0.0.0"
        else:
            addrfamily = struct.unpack("h",ifreq[16:18])[0]
            if addrfamily == socket.AF_INET:
                ifaddr = scapy.utils.inet_ntoa(ifreq[20:24])
            else:
                warning("Interface %s: unkown address family (%i)"%(iff, addrfamily))
                continue
        routes.append((socket.htonl(long(dst,16))&0xffffffffL,
                       socket.htonl(long(msk,16))&0xffffffffL,
                       scapy.utils.inet_ntoa(struct.pack("I",long(gw,16))),
                       iff, ifaddr))
    
    f.close()
    return routes

def get_if(iff,cmd):
    s=socket.socket()
    ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
    s.close()
    return ifreq


def get_if_index(iff):
    return int(struct.unpack("I",get_if(iff, SIOCGIFINDEX)[16:20])[0])

def get_last_packet_timestamp(sock):
    ts = ioctl(sock, SIOCGSTAMP, "12345678")
    s,us = struct.unpack("II",ts)
    return s+us/1000000.0




