## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


import sys,os,struct,socket,time
from fcntl import ioctl
from scapy.error import *
import scapy.config

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

try:
    from Crypto.Cipher import ARC4
except ImportError:
    log_loading.info("Can't find Crypto python lib. Won't be able to decrypt WEP")




def str2mac(s):
    return ("%02x:"*6)[:-1] % tuple(map(ord, s)) 


    
def get_if_addr(iff):
    return socket.inet_ntoa(get_if_raw_addr(iff))
    
def get_if_hwaddr(iff):
    addrfamily, mac = get_if_raw_hwaddr(iff)
    if addrfamily in [ARPHDR_ETHER,ARPHDR_LOOPBACK]:
        return str2mac(mac)
    else:
        raise Scapy_Exception("Unsupported address family (%i) for interface [%s]" % (addrfamily,iff))


LINUX=sys.platform.startswith("linux")
OPENBSD=sys.platform.startswith("openbsd")
FREEBSD=sys.platform.startswith("freebsd")
NETBSD = sys.platform.startswith("netbsd")
DARWIN=sys.platform.startswith("darwin")
SOLARIS=sys.platform.startswith("sunos")

X86_64 = (os.uname()[4] == 'x86_64')


# Next step is to import following architecture specific functions:
# def get_if_raw_hwaddr(iff)
# def get_if_raw_addr(iff):
# def get_if_list():
# def get_working_if():
# def attach_filter(s, filter):
# def set_promisc(s,iff,val=1):
# def read_routes():
# def get_if(iff,cmd):
# def get_if_index(iff):



if LINUX:
    from linux import *
    if scapy.config.conf.use_pcap or scapy.config.conf.use_dnet:
        from pcapdnet import *
elif OPENBSD or FREEBSD or NETBSD or DARWIN:
    from bsd import *
elif SOLARIS:
    from solaris import *
    
if scapy.config.conf.iface is None:
    scapy.config.conf.iface = LOOPBACK_NAME

