## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Customization for the Solaris operation system.
"""
from __future__ import with_statement
import sys,os,struct,socket,time,platform
from select import select
import fcntl
from fcntl import ioctl
import scapy
import scapy.utils
import scapy.utils6
from scapy.config import conf
from scapy.supersocket import SuperSocket
import scapy.arch
from scapy.error import warning,Scapy_Exception,log_loading
import scapy.data
import scapy.plist as plist
import scapy.sendrecv
from scapy.utils import *


if "sunos" in sys.platform:
    try:
        import dlpi
        if not hasattr(dlpi, "DL_PROMISC_NOLOOP"):
            dlpi.DL_PROMISC_NOLOOP = 0x10000000
        conf.use_dlpi = 1
    except ImportError,e:
        log_loading.info("Solaris Unable to import dlpi module: %s" % e)
        conf.use_dlpi = 0
else:
    raise Exception("system platform need be solaris")

log_loading.warning("Solaris must indicate a speicific network interface when recieve msg")
log_loading.warning("It means sr()/sniff() need 'iface' parameter.")
log_loading.warning("Otherwise, the interface which has default route will be used.")

X86_64 = ( platform.architecture()[0] == '64bit')


# correct data.py value
scapy.data.ETH_P_ALL = 0
scapy.sendrecv.ETH_P_ALL = 0
from scapy.data import *

def load_ethertypes(filename):
    spaces = re.compile("[ \t]+|\n")
    dct = DADict(_name=filename)
    try:
        f="""
IPv4	 	0800  	ip ip4 		# Internet IP (IPv4)
X25		0805
ARP		0806	ether-arp	#
FR_ARP		0808    		# Frame Relay ARP        [RFC1701]
BPQ		08FF			# G8BPQ AX.25 Ethernet Packet
DEC		6000			# DEC Assigned proto
DNA_DL		6001			# DEC DNA Dump/Load
DNA_RC		6002			# DEC DNA Remote Console
DNA_RT		6003			# DEC DNA Routing
LAT		6004			# DEC LAT
DIAG		6005			# DEC Diagnostics
CUST		6006			# DEC Customer use
SCA		6007			# DEC Systems Comms Arch
TEB		6558             	# Trans Ether Bridging   [RFC1701]
RAW_FR  	6559                   	# Raw Frame Relay        [RFC1701]
AARP		80F3			# Appletalk AARP
ATALK		809B                  	# Appletalk
802_1Q		8100	8021q 1q 802.1q	dot1q # 802.1Q Virtual LAN tagged frame
IPX		8137			# Novell IPX
NetBEUI		8191			# NetBEUI
IPv6		86DD	ip6 		# IP version 6
PPP		880B                    # PPP
ATMMPOA		884C			# MultiProtocol over ATM
PPP_DISC	8863			# PPPoE discovery messages
PPP_SES		8864			# PPPoE session messages
ATMFATE		8884			# Frame-based ATM Transport over Ethernet
LOOP		9000	loopback 	# loop proto
"""
        for l in f.splitlines():
            try:
                shrp = l.find("#")
                if  shrp >= 0:
                    l = l[:shrp]
                l = l.strip()
                if not l:
                    continue
                lt = tuple(re.split(spaces, l))
                if len(lt) < 2 or not lt[0]:
                    continue
                dct[lt[0]] = int(lt[1], 16)
            except Exception,e:
                log_loading.info("Couldn't parse file [%s]: line [%r] (%s)" % (filename,l,e))
    except IOError,msg:
        pass
    return dct

scapy.data.ETHER_TYPES=load_ethertypes("/etc/ethertypes")
scapy.data.MANUFDB = load_manuf("/usr/share/wireshark/manuf")


# From sys/sockio.h and net/if.h
SIOCGIFHWADDR  = 0xc02069b9          # Get hardware address    
SIOCGIFADDR    = 0xc020690d          # get PA address          
SIOCGIFNETMASK = 0xc0206919          # get network PA mask     
#SIOCGIFNAME    = 0x8910          # get iface name          
#SIOCSIFLINK    = 0x8911          # set iface channel       
SIOCGIFCONF    = 0xc008695c          # get iface list          
SIOCGIFFLAGS   = 0xc0206911          # get flags               
SIOCSIFFLAGS   = 0x80206910          # set flags               
SIOCGIFINDEX   = 0xc020695a          # name -> if_index mapping
#SIOCGIFCOUNT   = 0x8938          # get number of devices
SIOCGSTAMP     = 0xc02069b9          # get packet timestamp (as a timeval)

# From net/if.h
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
PACKET_ADD_MEMBERSHIP  = 2
PACKET_DROP_MEMBERSHIP = 3
#PACKET_RECV_OUTPUT     = 3
#PACKET_RX_RING         = 5
PACKET_STATISTICS      = 1
PACKET_MR_MULTICAST    = 1
PACKET_MR_PROMISC      = 2
PACKET_MR_ALLMULTI     = 3

# From sys/socket.h
SOL_PACKET = 0xfffd
# From sys/socket.h
SO_ATTACH_FILTER = 0x40000001
SOL_SOCKET = 0xffff
SO_TIMESTAMP= 0x1013

# From net/route.h
RTF_UP = 0x0001  # Route usable
RTF_REJECT = 0x8


# IPPROTO_GRE and IPPROTO_IPIP is missing on Solaris
if not hasattr(socket, "IPPROTO_GRE"):
    socket.IPPROTO_IPIP = 47

if not hasattr(socket, "IPPROTO_IPIP"):
    socket.IPPROTO_IPIP = 4

LOOPBACK_NAME="lo0"

with os.popen("tcpdump -V 2> /dev/null") as _f:
    if _f.close() >> 8 == 0x7f:
        log_loading.warning("Failed to execute tcpdump. Check it is installed and in the PATH")
        TCPDUMP=0
    else:
        TCPDUMP=1
    del _f


def get_if_raw_hwaddr(iff):
    return struct.unpack("16xh6s8x",get_if(iff,SIOCGIFHWADDR))


def get_if_raw_addr(iff):
    try:
        return get_if(iff, SIOCGIFADDR)[20:24]
    except IOError:
        return "\0\0\0\0"

def get_if_list():
    ret = []
    f=os.popen("dladm show-link -p -o link")
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        ret.append(l)
    f.close()
    return  ret


def get_if_list_l3():
    ret=set()
    f=os.popen("ifconfig -a")
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        if l.find("flags") >= 0: # a new interface
            lspl = l.split()
            netif = lspl[0].split(':')[0]
            ret.add(netif)
    f.close()
    return list(ret)

def get_if_l2_index_name_dict():
    ret = {}
    iflist = get_if_list()
    for ifname in iflist:
        if ifname == LOOPBACK_NAME:
            continue
        ifindex = get_if_l2_index(ifname)
        ret[ifindex]=ifname
    return  ret

def get_if_l2_name_index_dict():
    ret = {}
    iflist = get_if_list()
    for ifname in iflist:
        if ifname == LOOPBACK_NAME:
            continue
        ifindex = get_if_l2_index(ifname)
        ret[ifname]=ifindex
    return  ret

def get_working_if():
    for i in get_if_list_l3():
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
        f = os.popen("%s -i %s -ddd -s 1600 '%s'" % (conf.prog.tcpdump,conf.iface,filter))
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
    # BPF is a 'str' object, its
    # typedef struct {
    #     PyObject_VAR_HEAD
    #     long ob_shash;
    #     int ob_sstate;
    #     char ob_sval[1];
    # } PyStringObject;
    # we need use sys.getsizeof('') to get the relative address of ob_sval
    if scapy.arch.X86_64:
        bpfh = struct.pack("HQ", nb, id(bpf)+sys.getsizeof('')-1)
    else:
        bpfh = struct.pack("HI", nb, id(bpf)+sys.getsizeof('')-1)  
    s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, bpfh)


def set_promisc(s,iff,val=1):
    mreq = struct.pack("IHH8s", get_if_l2_index(iff), PACKET_MR_PROMISC, 0, "")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)

def read_routes():
    f=os.popen("netstat -rvn -f inet") # -f inet
    ok = 0
    mtu_present = False
    prio_present = False
    routes = []
    pending_if = []
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        if l.find("----") >= 0: # a separation line
            continue
        if not ok:
            if l.find("Destination") >= 0:
                ok = 1
                mtu_present = l.find("MTU") >= 0
                prio_present = l.find("Prio") >= 0
            continue
        if not l:
            break
        lspl = l.split()
        if len(lspl) == 9:
            dest,mask,gw,netif,mtu,ref,flg = lspl[:7]
        else: # missing interface
            dest,mask,gw,mtu,ref,flg = lspl[:6]
            netif=None
        if flg.find("Lc") >= 0:
            continue                
        if dest == "default":
            dest = 0L
            netmask = 0L
        else:
            netmask = scapy.utils.atol(mask)
            dest += ".0"*(3-dest.count("."))
            dest = scapy.utils.atol(dest)
        if not "G" in flg:
            gw = '0.0.0.0'
        if netif is not None:
            ifaddr = scapy.arch.get_if_addr(netif)
            routes.append((dest,netmask,gw,netif,ifaddr))
        else:
            pending_if.append((dest,netmask,gw))
    f.close()
    # On Solaris, netstat does not provide output interfaces for some routes
    # We need to parse completely the routing table to route their gw and
    # know their output interface
    for dest,netmask,gw in pending_if:
        gw_l = scapy.utils.atol(gw)
        max_rtmask,gw_if,gw_if_addr, = 0,None,None
        for rtdst,rtmask,_,rtif,rtaddr in routes[:]:
            if gw_l & rtmask == rtdst:
                if rtmask >= max_rtmask:
                    max_rtmask = rtmask
                    gw_if = rtif
                    gw_if_addr = rtaddr
        if gw_if:
            routes.append((dest,netmask,gw,gw_if,gw_if_addr))
        else:
            warning("Did not find output interface to reach gateway %s" % gw)
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
    f=os.popen("ifconfig -a6")
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        if l.find("flags") >= 0: # a new interface
            lspl = l.split()
            netif = lspl[0].split(':')[0]
        if l.find("inet6") >= 0: # a new inet6 address
            lspl = l.split()
            addr = lspl[1].split('/')[0]
            addr = scapy.utils6.in6_ptop(addr)
            scope = scapy.utils6.in6_getscope(addr)
            ret.append((addr, scope, netif)) # (addr, scope, iface)
    f.close()
    return ret

def read_routes6():
    f = os.popen("netstat -rvn -f inet6")
    ok = False
    mtu_present = False
    prio_present = False
    routes = []
    pending_if = []
    lifaddr = in6_getifaddr()
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        if l.find("----") >= 0: # a separation line
            continue
        if not ok:
            if l.find("Destination") >= 0:
                ok = 1
                mtu_present = l.find("MTU") >= 0
                prio_present = l.find("Prio") >= 0
            continue
        # d,destination network
        # nh,next hop
        # fl,flags
        # dev,device name
        # dp, destination prefix length
        lspl = l.split()
        if len(lspl) == 8:
            d,nh,dev,mtu,ref,fl = l.split()[:6]
        else: # missing interface
            d,nh,mtu,ref,fl = l.split()[:5]
            dev = None
        if dev is not None and filter(lambda x: x[2] == dev, lifaddr) == []:
            continue
        if 'L' in fl: # drop MAC addresses
            continue
        
        if 'link' in nh:
            nh = '::'
        
        cset = [] # candidate set (possible source addresses)
        dp = 128
        if d == 'default':
            d = '::'
            dp = 0
        if '/' in d:
            d,dp = d.split("/")
            dp = int(dp)
        if '%' in d:
            d,dev = d.split('%')
        if '%' in nh:
            nh,dev = nh.split('%')
        
        if dev is None:
            pending_if.append((d, dp, nh, cset))
        elif scapy.arch.LOOPBACK_NAME in dev:
            cset = ['::1']
            nh = '::'
        else:
            devaddrs = filter(lambda x: x[2] == dev, lifaddr)
            cset = scapy.utils6.construct_source_candidate_set(d, dp, devaddrs, scapy.arch.LOOPBACK_NAME)
        
        if len(cset) != 0:
            routes.append((d, dp, nh, dev, cset))
    
    f.close()
    # On Solaris, netstat does not provide output interfaces for some routes
    # We need to parse completely the routing table to route their gw and
    # know their output interface
    for d,dp,nh,cset in pending_if:
        max_rtmask,gw_if,gw_if_addr, = 0,None,None
        for rtdst,rtmask,_,rtif,rtcset in routes[:]:
            if in6_isincluded(nh, rtdst, rtmask):
                if rtmask >= max_rtmask:
                    max_rtmask = rtmask
                    gw_if = rtif
                    gw_cset = rtcset
        if gw_if:
            routes.append((d,dp,nh,gw_if,gw_cset))
        else:
            warning("Did not find output interface to reach gateway %s" % nh)
    
    return routes



def get_if(iff,cmd):
    s=socket.socket()
    ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
    s.close()
    return ifreq

def get_if_l2(iff,cmd):
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
    s.close()
    return ifreq

def get_if_index(iff):
    return int(struct.unpack("I",get_if(iff, SIOCGIFINDEX)[16:20])[0])

def get_if_l2_index(iff):
    return int(struct.unpack("I",get_if_l2(iff, SIOCGIFINDEX)[16:20])[0])

if X86_64:
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
    if type(fd) is not int:
        fd = fd.fileno()
    while 1:
        r,w,e = select([fd],[],[],0)
        if r:
            os.read(fd,MTU)
        else:
            break


try:
    import pcap
    conf.use_pcap = 1
    if not hasattr(pcap, "DLT_IPNET"):
        pcap.DLT_IPNET = 226
    if not hasattr(pcap, "DLT_IPNET_HEADER_LEN"):
        pcap.DLT_IPNET_HEADER_LEN = 24
except ImportError,e:
    log_loading.info("Solaris Unable to import pcap module: %s" % e)
    conf.use_pcap = 0

if conf.use_pcap:
    # From net/bpf.h
    #BIOCIMMEDIATE=0x80044270
    BIOCIMMEDIATE=-2147204496
    
    if hasattr(pcap,"pcap"): # python-pypcap
        class _PcapWrapper_pypcap:
            def __init__(self, device, snaplen, promisc, to_ms):
                try:
                    self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1, timeout_ms=to_ms)
                except TypeError:
                    # Older pypcap versions do not support the timeout_ms argument
                    self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1)                    
            def __getattr__(self, attr):
                return getattr(self.pcap, attr)
            def __del__(self):
                # warning("__del__: don't know how to close the file descriptor. Bugs ahead ! Please report this bug.")
                fd = self.pcap.fileno()
                os.close(fd)
                del self.pcap
                pass
            def next(self):
                c = self.pcap.next()
                if c is None:
                    return
                ts, pkt = c
                return ts, str(pkt)
        open_pcap = lambda *args,**kargs: _PcapWrapper_pypcap(*args,**kargs)
    elif hasattr(pcap,"pcapObject"): # python-libpcap
        class _PcapWrapper_libpcap:
            def __init__(self, *args, **kargs):
                self.pcap = pcap.pcapObject()
                self.pcap.open_live(*args, **kargs)
            def setfilter(self, filter):
                self.pcap.setfilter(filter, 0, 0)
            def next(self):
                c = self.pcap.next()
                if c is None:
                    return
                l,pkt,ts = c 
                return ts,pkt
            def __getattr__(self, attr):
                return getattr(self.pcap, attr)
            def __del__(self):
                fd = self.pcap.fileno()
                os.close(fd)
        open_pcap = lambda *args,**kargs: _PcapWrapper_libpcap(*args,**kargs)
    
    class PcapTimeoutElapsed(Scapy_Exception):
        pass
    
    class L2pcapListenSocket(SuperSocket):
        desc = "read packets at layer 2 using libpcap"
        def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
            self.type = type
            self.outs = None
            if iface is None:
                #iface = "any"
                #if iface not in pcap.findalldevs():
                    iface = conf.iface
            self.iface = iface
            if promisc is None:
                promisc = conf.sniff_promisc
            self.promisc = promisc
            self.ins = open_pcap(iface, 1600, self.promisc, 100)
            self.ins.setdirection(pcap.PCAP_D_IN)
            self.ins.setnonblock(1)
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
                    self.ins.setfilter(filter)
        
        def close(self):
            #if hasattr(self, "ins"):
            #    del(self.ins)
            del(self.ins)
        
        def recv(self, x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
            
            pkt = None
            
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            else:
                return None
                
            if ll == pcap.DLT_IPNET:
                ipnet_version,ipnet_protocol = struct.unpack("BB", pkt[0:2])
                pkt=pkt[pcap.DLT_IPNET_HEADER_LEN:]
                if ipnet_protocol == socket.AF_INET:
                    cls = conf.l3types[ETH_P_IP]
                elif ipnet_protocol == socket.AF_INET6:
                    cls = conf.l3types[ETH_P_IPV6]
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt
        
        
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv(MTU)
            self.ins.setnonblock(0)
            return p
        
        def fileno(self):
            fd=-1
            try:
                fd=self.ins.select_fileno()
            except:
                fd=self.ins.fileno()
            return fd;
        
        def send(self, x):
            raise Scapy_Exception("Can't send anything with L2pcapListenSocket")
    
    def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None,
              opened_socket=None, stop_filter=None, *arg, **karg):
        """Sniff packets
    sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets
        
      count: number of packets to capture. 0 means infinity
      store: wether to store sniffed packets or discard them
        prn: function to apply to each packet. If something is returned,
             it is displayed. Ex:
             ex: prn = lambda x: x.summary()
    lfilter: python function applied to each packet to determine
             if further action may be done
             ex: lfilter = lambda x: x.haslayer(Padding)
    offline: pcap file to read packets from, instead of sniffing them
    timeout: stop sniffing after a given time (default: None)
    L2socket: use the provided L2socket
    opened_socket: provide an object ready to use .recv() on
    stop_filter: python function applied to each packet to determine
                 if we have to stop the capture after this packet
                 ex: stop_filter = lambda x: x.haslayer(TCP)
        """
        c = 0
        
        if opened_socket is not None:
            s = opened_socket
        else:
            if offline is None:
                if L2socket is None:
                    L2socket = conf.L2listen
                s = L2socket(type=ETH_P_ALL, *arg, **karg)
            else:
                s = PcapReader(offline)
        
        lst = []
        if timeout is not None:
            stoptime = time.time()+timeout
        remain = None
        try:
            while 1:
                if timeout is not None:
                    remain = stoptime-time.time()
                    if remain <= 0:
                        break
                if scapy.arch.FREEBSD :
                    #inp, out, err = select([s],[],[], 0.005)
                    #if len(inp) == 0 or s in inp:
                    #    p = s.nonblock_recv()
                    #else :
                    #    continue
                    p = s.nonblock_recv()
                else:
                    sel = select([s],[],[],remain)
                    if s in sel[0]:
                        p = s.recv(MTU)
                    else:
                        continue
                if p is None:
                    continue
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print r
                if stop_filter and stop_filter(p):
                    break
                if count > 0 and c >= count:
                    break
        except KeyboardInterrupt:
            pass
        if opened_socket is None:
            s.close()
        return plist.PacketList(lst,"Sniffed")
    
    scapy.sendrecv.sniff = sniff

try:
    import dnet
    # dnet workaround for Solaris
    def linkdev(devlist):
        for netif in devlist:
            if netif == LOOPBACK_NAME:
                continue
            src="/dev/net/"+netif
            dst="/dev/"+netif
            if os.path.exists(src) and not os.path.exists(dst):
                os.symlink(src, dst)
    
    linkdev(get_if_list())
    conf.use_dnet = 1
except ImportError,e:
    log_loading.info("Solaris Unable to import dnet module: %s" % e)
    conf.use_dnet = 0

if conf.use_pcap and conf.use_dnet:
    class L3dnetSocket(SuperSocket):
        desc = "read/write packets at layer 3 using libdnet and libpcap"
        def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
            self.iflist = {}
            self.intf = dnet.intf()
            if iface is None:
                #iface = "any"
                #if iface not in pcap.findalldevs():
                    iface = conf.iface
            self.iface = iface
            self.ins = open_pcap(iface, 1600, 0, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            self.ins.setdirection(pcap.PCAP_D_IN)
            self.ins.setnonblock(1)
            flags = fcntl.fcntl(self.ins.fileno(), fcntl.F_GETFD, 0);
            fcntl.fcntl(self.ins.fileno(),fcntl.F_GETFD, 0)
            fcntl.fcntl(self.ins.fileno(), fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
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
                self.ins.setfilter(filter)
        def send(self, x):
            iff,a,gw  = x.route()
            if iff is None:
                iff = conf.iface
            ifs,cls = self.iflist.get(iff,(None,None))
            if ifs is None:
                iftype = self.intf.get(iff)["type"]
                if iftype == dnet.INTF_TYPE_ETH:
                    try:
                        cls = conf.l2types[1]
                    except KeyError:
                        warning("Unable to find Ethernet class. Using nothing")
                    ifs = dnet.eth(iff)
                else:
                    ifs = dnet.ip()
                self.iflist[iff] = ifs,cls
            if cls is None:
                sx = str(x)
            else:
                sx = str(cls()/x)
            x.sent_time = time.time()
            ifs.send(sx)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
            
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
            if ll == pcap.DLT_IPNET:
                ipnet_version,ipnet_protocol = struct.unpack("BB", pkt[0:2])
                pkt=pkt[pcap.DLT_IPNET_HEADER_LEN:]
                if ipnet_protocol == socket.AF_INET:
                    cls = conf.l3types[ETH_P_IP]
                elif ipnet_protocol == socket.AF_INET6:
                    cls = conf.l3types[ETH_P_IPV6]
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            if ll == pcap.DLT_IPNET:
                return pkt
            else:
                return pkt.payload
        
        def fileno(self):
            fd=-1
            try:
                fd=self.ins.select_fileno()
            except:
                fd=self.ins.fileno()
            return fd;
        
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv()
            self.ins.setnonblock(0)
            return p
        
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            for (outs_iff,outs_tuple) in self.iflist.items():
                outs,outs_cls=outs_tuple
                del(outs)
    
    
    class L2dnetSocket(SuperSocket):
        desc = "read/write packets at layer 2 using libdnet and libpcap"
        def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
            if iface is None:
                iface = conf.iface
            self.iface = iface
            self.ins = open_pcap(iface, 1600, 0, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            self.ins.setdirection(pcap.PCAP_D_IN)
            self.ins.setnonblock(1)
            flags = fcntl.fcntl(self.ins.fileno(), fcntl.F_GETFD, 0);
            fcntl.fcntl(self.ins.fileno(),fcntl.F_GETFD, 0)
            fcntl.fcntl(self.ins.fileno(), fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
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
                self.ins.setfilter(filter)
            self.outs = dnet.eth(iface)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
            
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
            
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt
        
        def fileno(self):
            fd=-1
            try:
                fd=self.ins.select_fileno()
            except:
                fd=self.ins.fileno()
            return fd;
        
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
    
    from scapy.base_classes import Gen, Net, SetGen
    from scapy.sendrecv import debug
    def sndrcv(pks, pkt, timeout = None, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
        if not isinstance(pkt, Gen):
            pkt = SetGen(pkt)
        
        if verbose is None:
            verbose = conf.verb
        debug.recv = plist.PacketList([],"Unanswered")
        debug.sent = plist.PacketList([],"Sent")
        debug.match = plist.SndRcvList([])
        nbrecv=0
        ans = []
        # do it here to fix random fields, so that parent and child have the same
        all_stimuli = tobesent = [p for p in pkt]
        notans = len(tobesent)
        
        hsent={}
        for i in tobesent:
            h = i.hashret()
            if h in hsent:
                hsent[h].append(i)
            else:
                hsent[h] = [i]
        if retry < 0:
            retry = -retry
            autostop=retry
        else:
            autostop=0
        
        
        while retry >= 0:
            found=0
            
            if timeout < 0:
                timeout = None
                
            rdpipe,wrpipe = os.pipe()
            rdpipe=os.fdopen(rdpipe)
            wrpipe=os.fdopen(wrpipe,"w")
            
            pid=1
            try:
                pid = os.fork()
                if pid == 0:
                    try:
                        sys.stdin.close()
                        rdpipe.close()
                        try:
                            i = 0
                            if verbose:
                                print "Begin emission:"
                            for p in tobesent:
                                pks.send(p)
                                i += 1
                                time.sleep(inter)
                            if verbose:
                                print "Finished to send %i packets." % i
                        except SystemExit:
                            pass
                        except KeyboardInterrupt:
                            pass
                        except:
                            log_runtime.exception("--- Error in child %i" % os.getpid())
                            log_runtime.info("--- Error in child %i" % os.getpid())
                    finally:
                        try:
                            os.setpgrp() # Chance process group to avoid ctrl-C
                            sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                            cPickle.dump( (conf.netcache,sent_times), wrpipe )
                            wrpipe.close()
                        except:
                            pass
                elif pid < 0:
                    log_runtime.error("fork error")
                else:
                    wrpipe.close()
                    stoptime = 0
                    remaintime = None
                    inmask = [rdpipe,pks]
                    try:
                        try:
                            while 1:
                                if stoptime:
                                    remaintime = stoptime-time.time()
                                    if remaintime <= 0:
                                        break
                                r = None
                                if scapy.arch.FREEBSD:
                                    r = pks.nonblock_recv()
                                else:
                                    inp, out, err = select(inmask,[],[], remaintime)
                                    if len(inp) == 0:
                                        break
                                    if pks in inp:
                                        r = pks.recv(MTU)
                                    if rdpipe in inp:
                                        if timeout:
                                            stoptime = time.time()+timeout
                                        del(inmask[inmask.index(rdpipe)])
                                if r is None:
                                    continue
                                ok = 0
                                h = r.hashret()
                                if h in hsent:
                                    hlst = hsent[h]
                                    for i in range(len(hlst)):
                                        if r.answers(hlst[i]):
                                            ans.append((hlst[i],r))
                                            if verbose > 1:
                                                os.write(1, "*")
                                            ok = 1                                
                                            if not multi:
                                                del(hlst[i])
                                                notans -= 1;
                                            else:
                                                if not hasattr(hlst[i], '_answered'):
                                                    notans -= 1;
                                                hlst[i]._answered = 1;
                                            break
                                if notans == 0 and not multi:
                                    break
                                if not ok:
                                    if verbose > 1:
                                        os.write(1, ".")
                                    nbrecv += 1
                                    if conf.debug_match:
                                        debug.recv.append(r)
                        except KeyboardInterrupt:
                            if chainCC:
                                raise
                    finally:
                        try:
                            nc,sent_times = cPickle.load(rdpipe)
                        except EOFError:
                            warning("Child died unexpectedly. Packets may have not been sent %i"%os.getpid())
                        else:
                            conf.netcache.update(nc)
                            for p,t in zip(all_stimuli, sent_times):
                                p.sent_time = t
                        os.waitpid(pid,0)
            finally:
                if pid == 0:
                    os._exit(0)
            
            remain = reduce(list.__add__, hsent.values(), [])
            if multi:
                remain = filter(lambda p: not hasattr(p, '_answered'), remain);
                
            if autostop and len(remain) > 0 and len(remain) != len(tobesent):
                retry = autostop
                
            tobesent = remain
            if len(tobesent) == 0:
                break
            retry -= 1
            
        if conf.debug_match:
            debug.sent=plist.PacketList(remain[:],"Sent")
            debug.match=plist.SndRcvList(ans[:])
        
        #clean the ans list to delete the field _answered
        if (multi):
            for s,r in ans:
                if hasattr(s, '_answered'):
                    del(s._answered)
        
        if verbose:
            print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
        return plist.SndRcvList(ans),plist.PacketList(remain,"Unanswered")
    
    scapy.sendrecv.sndrcv = sndrcv


if conf.use_dlpi:
    
    RCV_SIZE_DEFAULT = 4096
    RCV_TIMEOUT = 10000
    class L2DlpiListenSocket(SuperSocket):
        desc = "read packets at layer 2 using libdlpi"
        def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
            self.type = type
            self.outs = None
            self.iface = iface
            if iface is None:
                iface = conf.iface
            if promisc is None:
                promisc = conf.sniff_promisc
            self.promisc = promisc
            self.ins = dlpi.link(iface,dlpi.RAW)
            self.ins.promiscon(dlpi.PROMISC_PHYS|dlpi.DL_PROMISC_NOLOOP)
            self.ins.promiscon(dlpi.PROMISC_SAP|dlpi.DL_PROMISC_NOLOOP)
            self.ins.promiscon(dlpi.PROMISC_MULTI|dlpi.DL_PROMISC_NOLOOP)
            self.ins.bind(dlpi.ANY_SAP)
            self.ins.set_timeout(RCV_TIMEOUT)
            ins_mactype=dlpi.arptype(self.ins.get_mactype())
            if ins_mactype in conf.l2types:
                self.LL = conf.l2types[ins_mactype]
            else:
                self.LL = conf.default_l2
        
        def close(self):
            del(self.ins)
        
        def recv(self, x=MTU):
            src, pkt = self.ins.recv(x)
            if pkt is None:
                return None
            try:
                pkt = self.LL(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = time.time()
            return pkt
        
        def fileno(self):
            return self.ins.get_fd()
        
        def send(self, x):
            raise Scapy_Exception("Can't send anything with L2DlpiListenSocket")
    
    class L3DlpiSocket(SuperSocket):
        desc = "read/write packets at layer 3 using libdlpi"
        def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
            self.iflist = {}
            self.intf = dlpi.listlink()
            if iface is None:
                iface = conf.iface
            self.iface = iface
            self.ins = dlpi.link(iface,dlpi.RAW)
            flags=fcntl.fcntl(self.ins.get_fd(),fcntl.F_GETFD, 0)
            fcntl.fcntl(self.ins.get_fd(), fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
            self.ins.promiscon(dlpi.PROMISC_PHYS|dlpi.DL_PROMISC_NOLOOP)
            self.ins.promiscon(dlpi.PROMISC_SAP|dlpi.DL_PROMISC_NOLOOP)
            self.ins.promiscon(dlpi.PROMISC_MULTI|dlpi.DL_PROMISC_NOLOOP)
            self.ins.bind(dlpi.ANY_SAP)
            self.ins.set_timeout(RCV_TIMEOUT)
            ins_mactype=dlpi.arptype(self.ins.get_mactype())
            if ins_mactype in conf.l2types:
                self.LL = conf.l2types[ins_mactype]
            else:
                self.LL = conf.default_l2
        
        def send(self, x):
            iff,a,gw  = x.route()
            if iff is None:
                iff = conf.iface
            ifs,cls = self.iflist.get(iff,(None,None))
            if ifs is None:
                ifs = dlpi.link(iff,dlpi.RAW)
                ifs.bind(dlpi.ANY_SAP)
                iftype = dlpi.arptype(ifs.get_mactype())
                if iftype in conf.l2types:
                    cls = conf.l2types[iftype]
                else:
                    cls = conf.default_l2
                self.iflist[iff] = ifs,cls
            sx = str(cls()/x)
            x.sent_time = time.time()
            addr = ifs.get_physaddr(dlpi.CURR_PHYS_ADDR)
            ifs.send(addr,sx)
        
        def recv(self,x=MTU):
            cls=self.LL
            src, pkt = self.ins.recv(x)
            if pkt is None:
                return None
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = time.time()
            return pkt.payload
        
        def fileno(self):
            return self.ins.get_fd()
        
        def close(self):
            if hasattr(self, "ins"):
                self.ins.unbind()
                del(self.ins)
            for (outs_iff,outs_tuple) in self.iflist.items():
                outs,outs_cls=outs_tuple
                outs.unbind()
                del(outs)
    
    class L2DlpiSocket(SuperSocket):
        desc = "read/write packets at layer 2 using libdlpi"
        def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
            if iface is None:
                iface = conf.iface
            self.iface = iface
            
            self.ins = dlpi.link(iface,dlpi.RAW)
            self.ins.promiscon(dlpi.PROMISC_PHYS|dlpi.DL_PROMISC_NOLOOP)
            self.ins.promiscon(dlpi.PROMISC_SAP|dlpi.DL_PROMISC_NOLOOP)
            self.ins.promiscon(dlpi.PROMISC_MULTI|dlpi.DL_PROMISC_NOLOOP)
            self.ins.bind(dlpi.ANY_SAP)
            self.ins.set_timeout(RCV_TIMEOUT)
            self.outs = self.ins
            ins_mactype=dlpi.arptype(self.ins.get_mactype())
            if ins_mactype in conf.l2types:
                self.LL = conf.l2types[ins_mactype]
            else:
                self.LL = conf.default_l2
        
        def recv(self,x=MTU):
            src, pkt = self.ins.recv(x)
            if pkt is None:
                return None
            try:
                pkt = self.LL(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = time.time()
            return pkt
        
        def send(self, x):
            sx = str(x)
            x.sent_time = time.time()
            addr = self.outs.get_physaddr(dlpi.CURR_PHYS_ADDR)
            self.outs.send(addr,sx)
        
        def fileno(self):
            return self.ins.get_fd()
        
        def close(self):
            if hasattr(self, "ins"):
                self.ins.unbind()
                del(self.ins)


def analyze_sa_ll(sa_ll):
    if len(sa_ll) == 2:
        # struct sockaddr_ll {
        #     uint16_t        sll_family;
        #     uint16_t        sll_protocol;
        #     int32_t         sll_ifindex;
        #     uint16_t        sll_hatype;
        #     uint8_t         sll_pkttype;
        #     uint8_t         sll_halen;
        #     uint8_t         sll_addr[8];
        # }
        sll_family=sa_ll[0]
        sll_protocol,sll_ifindex,sll_hatype,sll_pkttype,sll_halen,sll_addr = struct.unpack("=HiHBB4s",sa_ll[1])
        # Solaris use sll_hatype to store L3 protocal and sll_protocal is 0, force sll_hatype to ARPHDR_ETHER
        sll_protocol,sll_hatype=sll_hatype,ARPHDR_ETHER
        sa_ll=[if_l2_index_name_dict[sll_ifindex],sll_protocol,sll_pkttype,sll_hatype,sll_addr]
        # warning("L3PacketSocket (interface=%s protocol=%d family=%d)." % (sa_ll[0],sa_ll[1],sa_ll[3]))
    else:
        # sa_ll[0] ifname
        # sa_ll[1] sll_protocol
        # sa_ll[2] sll_pkttype
        # sa_ll[3] sll_hatype
        # sa_ll[4] sll_addr
        # ('enp1s1f1', 2048, 4, 1, '\x00\x14O\x1f\xd7\xd9')
        pass
    return sa_ll

class L3PacketSocket(SuperSocket):
    desc = "read/write packets at layer 3 using Solaris PF_PACKET sockets"
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
        self.type = type
        # Solaris has bug and it desn't need socket.htons(type)
        # try socket.htons(type) firstly
        try :
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        except:
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, type)
        #self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if iface is None:
            iface = conf.iface
        self.ins.bind((iface, type))
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        _flush_fd(self.ins)
        try :
            self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        except:
            self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, type)
        #self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
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
    def recv(self, x=MTU):
        pkt, sa_ll = self.ins.recvfrom(x)
        sa_ll=analyze_sa_ll(sa_ll)
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
            warning("L3PacketSocket Unable to guess type (interface=%s protocol=%#x family=%i). Using %s" % (sa_ll[0],sa_ll[1],sa_ll[3],cls.name))
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
            pkt.time = time.time()
        return pkt
    
    def send(self, x):
        iff,a,gw  = x.route()
        if iff is None:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        # Solaris must bind to a interface when recv, dont's support 'any' interface like Linux
        # So assume recv will use same interface as send
        try:
            self.ins.bind(sdto)
        except socket.error,msg:
            pass
        
        try:
            sn = self.outs.getsockname()
            sn = analyze_sa_ll(sn)
        except socket.error,msg:
            # Solaris doesn't support getsockname, force sa_ll value
            sn = [iff,ETH_P_IP,socket.PACKET_OUTGOING,ARPHDR_ETHER]
        ll = lambda x:x
        if type(x) in conf.l3types:
            sdto = (iff, conf.l3types[type(x)])
        if sn[3] in conf.l2types:
            ll = lambda x:conf.l2types[sn[3]]()/x
        try:
            sx = str(ll(x))
            x.sent_time = time.time()
            self.outs.sendto(sx, sdto)
        except socket.error,msg:
            x.sent_time = time.time()  # bad approximation
            if conf.auto_fragment and msg[0] == 90:
                for p in x.fragment():
                    self.outs.sendto(str(ll(p)), sdto)
            else:
                raise





class L2PacketSocket(SuperSocket):
    desc = "read/write packets at layer 2 using Solaris PF_PACKET sockets"
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
        if iface is None:
            iface = conf.iface
        try :
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        except:
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, type)
        #self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if not nofilter: 
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        self.ins.bind((iface, type))
        _flush_fd(self.ins)
        #self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs = self.ins
        #self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        try:
            sa_ll = self.outs.getsockname()
            sa_ll = analyze_sa_ll(sa_ll)
        except socket.error,msg:
            # Solaris doesn't support getsockname, force sa_ll value
            sa_ll=[iface,ETH_P_IP,socket.PACKET_OUTGOING,ARPHDR_ETHER]
        if sa_ll[3] in conf.l2types:
            self.LL = conf.l2types[sa_ll[3]]
        elif sa_ll[1] in conf.l3types:
            self.LL = conf.l3types[sa_ll[1]]
        else:
            self.LL = conf.default_l2
            warning("L2Socket Unable to guess type (interface=%s protocol=%#x family=%i). Using %s" % (sa_ll[0],sa_ll[1],sa_ll[3],self.LL.name))
    
    def recv(self, x=MTU):
        pkt, sa_ll = self.ins.recvfrom(x)
        sa_ll=analyze_sa_ll(sa_ll)
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
        q.time = time.time() #get_last_packet_timestamp(self.ins)
        return q


class L2PacketListenSocket(SuperSocket):
    desc = "read packets at layer 2 using Solaris PF_PACKET sockets"
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None, nofilter=0):
        self.type = type
        self.outs = None
        try :
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        except:
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, type)
        #self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        if iface is None:
            iface = conf.iface
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
        _flush_fd(self.ins)
        #self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    def close(self):
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)
    
    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        sa_ll=analyze_sa_ll(sa_ll)
        if sa_ll[3] in conf.l2types :
            cls = conf.l2types[sa_ll[3]]
        elif sa_ll[1] in conf.l3types:
            cls = conf.l3types[sa_ll[1]]
        else:
            cls = conf.default_l2
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s" % (sa_ll[0],sa_ll[1],sa_ll[3],cls.name))
        
        try:
            pkt = cls(pkt)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            pkt = conf.raw_layer(pkt)
        pkt.time = time.time()
        return pkt
    
    def send(self, x):
        raise Scapy_Exception("Can't send anything with L2PacketListenSocket")

conf.iface = get_working_if()

try:
    l3socket=L3PacketSocket(iface=conf.iface)
    del l3socket
    if_l2_index_name_dict=get_if_l2_index_name_dict()
    if_l2_name_index_dict=get_if_l2_name_index_dict()
    conf.use_pf_packet=1
except:
    conf.use_pf_packet=0

if conf.use_pf_packet:
    conf.L3socket = L3PacketSocket
    conf.L2socket = L2PacketSocket
    conf.L2listen = L2PacketListenSocket
elif conf.use_pcap and conf.use_dnet:
    FREEBSD = 1
    conf.L3socket=L3dnetSocket
    conf.L2socket=L2dnetSocket
    conf.L2listen = L2pcapListenSocket
elif conf.use_dlpi:
    conf.L3socket=L3DlpiSocket
    conf.L2socket=L2DlpiSocket
    conf.L2listen = L2DlpiListenSocket
else:
    log_loading.error("Solaris Scapy no suitable Socket module to send/recv msg")

