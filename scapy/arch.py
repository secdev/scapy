## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


import sys,os,struct,socket,time
from fcntl import ioctl
from data import *

import config

try:
    import Gnuplot
    GNUPLOT=1
except ImportError:
    log_loading.info("did not find python gnuplot wrapper . Won't be able to plot")
    GNUPLOT=0

try:
    import pyx
    PYX=1
except ImportError:
    log_loading.info("Can't import PyX. Won't be able to use psdump() or pdfdump()")
    PYX=0


LINUX=sys.platform.startswith("linux")
OPENBSD=sys.platform.startswith("openbsd")
FREEBSD=sys.platform.startswith("freebsd")
NETBSD = sys.platform.startswith("netbsd")
DARWIN=sys.platform.startswith("darwin")
BIG_ENDIAN= struct.pack("H",1) == "\x00\x01"
X86_64 = (os.uname()[4] == 'x86_64')
SOLARIS=sys.platform.startswith("sunos")

if LINUX:
    DNET=PCAP=0
else:
    DNET=PCAP=1

if OPENBSD or FREEBSD or NETBSD or DARWIN:
    LOOPBACK_NAME="lo0"
else:
    LOOPBACK_NAME="lo"

    

if PCAP:
    try:
        import pcap
        PCAP = 1
    except ImportError:
        if LINUX:
            log_loading.warning("did not find pcap module. Fallback to linux primitives")
            PCAP = 0
        else:
            if __name__ == "__main__":
                log_loading.error("did not find pcap module")
                raise SystemExit
            else:
                raise

if DNET:
    try:
        import dnet
        DNET = 1
    except ImportError:
        if LINUX:
            log_loading.warning("did not find dnet module. Fallback to linux primitives")
            DNET = 0
        else:
            if __name__ == "__main__":
                log_loading.error("did not find dnet module")
                raise SystemExit
            else:
                raise

if not PCAP:
    f = os.popen("tcpdump -V 2> /dev/null")
    if f.close() >> 8 == 0x7f:
        log_loading.warning("Failed to execute tcpdump. Check it is installed and in the PATH")
        TCPDUMP=0
    else:
        TCPDUMP=1
    del(f)
        
    

try:
    from Crypto.Cipher import ARC4
except ImportError:
    log_loading.info("Can't find Crypto python lib. Won't be able to decrypt WEP")


# Workarround bug 643005 : https://sourceforge.net/tracker/?func=detail&atid=105470&aid=643005&group_id=5470
try:
    socket.inet_aton("255.255.255.255")
except socket.error:
    def inet_aton(x):
        if x == "255.255.255.255":
            return "\xff"*4
        else:
            return socket.inet_aton(x)
else:
    inet_aton = socket.inet_aton

inet_ntoa = socket.inet_ntoa
try:
    inet_ntop = socket.inet_ntop
    inet_pton = socket.inet_pton
except AttributeError:
    log_loading.info("inet_ntop/pton functions not found. Python IPv6 support not present")


if SOLARIS:
    # GRE is missing on Solaris
    socket.IPPROTO_GRE = 47



def str2mac(s):
    return ("%02x:"*6)[:-1] % tuple(map(ord, s)) 


######################
## Interfaces stuff ##
######################


if DNET:
    def get_if_raw_hwaddr(iff):
        if iff[:2] == LOOPBACK_NAME:
            return (772, '\x00'*6)
        try:
            l = dnet.intf().get(iff)
            l = l["link_addr"]
        except:
            raise Scapy_Exception("Error in attempting to get hw address for interface [%s]" % iff)
        return l.type,l.data
    def get_if_raw_addr(ifname):
        i = dnet.intf()
        return i.get(ifname)["addr"].data
else:
    def get_if_raw_hwaddr(iff):
        return struct.unpack("16xh6s8x",get_if(iff,SIOCGIFHWADDR))

    def get_if_raw_addr(iff):
        try:
            return get_if(iff, SIOCGIFADDR)[20:24]
        except IOError:
            return "\0\0\0\0"


if PCAP:
    def get_if_list():
        # remove 'any' interface
        return map(lambda x:x[0],filter(lambda x:x[1] is None,pcap.findalldevs()))
    def get_working_if():
        try:
            return pcap.lookupdev()
        except Exception:
            return LOOPBACK_NAME

    def attach_filter(s, filter):
        warning("attach_filter() should not be called in PCAP mode")
    def set_promisc(s,iff,val=1):
        warning("set_promisc() should not be called in DNET/PCAP mode")
    
else:
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



##################
## Routes stuff ##
##################

if not LINUX:

    def new_read_routes():

        rtlst = []
        def addrt(rt,lst):
            dst,gw = rt
            lst.append(rt)

        r = dnet.route()
        print r.loop(addrt, rtlst)
        return rtlst

    def read_routes():
        if SOLARIS:
            f=os.popen("netstat -rvn") # -f inet
        elif FREEBSD:
            f=os.popen("netstat -rnW") # -W to handle long interface names
        else:
            f=os.popen("netstat -rn") # -f inet
        ok = 0
        mtu_present = False
        routes = []
        for l in f.readlines():
            if not l:
                break
            l = l.strip()
            if l.find("----") >= 0: # a separation line
                continue
            if l.find("Destination") >= 0:
                ok = 1
                if l.find("Mtu") >= 0:
                    mtu_present = True
                continue
            if ok == 0:
                continue
            if not l:
                break
            if SOLARIS:
                dest,mask,gw,netif,mxfrg,rtt,ref,flg = l.split()[:8]
            else:
                if mtu_present:
                    dest,gw,flg,ref,use,mtu,netif = l.split()[:7]
                else:
                    dest,gw,flg,ref,use,netif = l.split()[:6]
            if flg.find("Lc") >= 0:
                continue                
            if dest == "default":
                dest = 0L
                netmask = 0L
            else:
                if SOLARIS:
                    netmask = atol(mask)
                elif "/" in dest:
                    dest,netmask = dest.split("/")
                    netmask = itom(int(netmask))
                else:
                    netmask = itom((dest.count(".") + 1) * 8)
                dest += ".0"*(3-dest.count("."))
                dest = atol(dest)
            if not "G" in flg:
                gw = '0.0.0.0'
            ifaddr = get_if_addr(netif)
            routes.append((dest,netmask,gw,netif,ifaddr))
        f.close()
        return routes

    def read_interfaces():
        i = dnet.intf()
        ifflist = {}
        def addif(iff,lst):
            if not iff.has_key("addr"):
                return
            if not iff.has_key("link_addr"):
                return
            rawip = iff["addr"].data
            ip = inet_ntoa(rawip)
            rawll = iff["link_addr"].data
            ll = str2mac(rawll)
            lst[iff["name"]] = (rawll,ll,rawip,ip)
        i.loop(addif, ifflist)
        return ifflist

            
else:

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
            ifaddr = inet_ntoa(ifreq[20:24])
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
                    ifaddr = inet_ntoa(ifreq[20:24])
                else:
                    warning("Interface %s: unkown address family (%i)"%(iff, addrfamily))
                    continue
            routes.append((socket.htonl(long(dst,16))&0xffffffffL,
                           socket.htonl(long(msk,16))&0xffffffffL,
                           inet_ntoa(struct.pack("I",long(gw,16))),
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

    
def get_if_addr(iff):
    return inet_ntoa(get_if_raw_addr(iff))
    
def get_if_hwaddr(iff):
    addrfamily, mac = get_if_raw_hwaddr(iff)
    if addrfamily in [ARPHDR_ETHER,ARPHDR_LOOPBACK]:
        return str2mac(mac)
    else:
        raise Scapy_Exception("Unsupported address family (%i) for interface [%s]" % (addrfamily,iff))



