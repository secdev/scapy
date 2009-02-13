## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


import sys,os,socket
from scapy.error import *
import scapy.config

try:
    import Gnuplot
    GNUPLOT=1
except ImportError:
    log_loading.info("Can't import python gnuplot wrapper . Won't be able to plot.")
    GNUPLOT=0

try:
    import pyx
    PYX=1
except ImportError:
    log_loading.info("Can't import PyX. Won't be able to use psdump() or pdfdump().")
    PYX=0


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
WINDOWS=sys.platform.startswith("win32")

X86_64 = not WINDOWS and (os.uname()[4] == 'x86_64')


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
elif WINDOWS:
    from windows import *

if scapy.config.conf.iface is None:
    scapy.config.conf.iface = LOOPBACK_NAME


def get_if_raw_addr6(iff):
    """
    Returns the main global unicast address associated with provided 
    interface, in network format. If no global address is found, None 
    is returned. 
    """
    r = filter(lambda x: x[2] == iff and x[1] == IPV6_ADDR_GLOBAL, in6_getifaddr())
    if len(r) == 0:
        return None
    else:
        r = r[0][0] 
    return inet_pton(socket.AF_INET6, r)
