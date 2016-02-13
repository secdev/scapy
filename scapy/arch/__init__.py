## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Operating system specific functionality.
"""


import sys,os,socket
from scapy.error import *
import scapy.config

try:
    from matplotlib import get_backend as matplotlib_get_backend
    import matplotlib.pyplot as plt
    MATPLOTLIB = 1
    if "inline" in matplotlib_get_backend():
        MATPLOTLIB_INLINED = 1
    else:
        MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = {"marker": "+"}
except ImportError:
    plt = None
    MATPLOTLIB = 0
    MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = dict()
    log_loading.info("Can't import matplotlib. Won't be able to plot.")

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
FREEBSD= "freebsd" in sys.platform
NETBSD=sys.platform.startswith("netbsd")
DARWIN=sys.platform.startswith("darwin")
SOLARIS=sys.platform.startswith("sunos")
WINDOWS=sys.platform.startswith("win32")

X86_64 = not WINDOWS and (os.uname()[4] == 'x86_64')
ARM_64 = not WINDOWS and (os.uname()[4] == 'aarch64')


# Next step is to import following architecture specific functions:
# def get_if_raw_hwaddr(iff)
# def get_if_raw_addr(iff):
# def get_if_list():
# def get_working_if():
# def attach_filter(s, filter, iface):
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


def get_if_addr6(iff):
    """
    Returns the main global unicast address associated with provided 
    interface, in human readable form. If no global address is found,
    None is returned. 
    """
    for x in in6_getifaddr():
        if x[2] == iff and x[1] == IPV6_ADDR_GLOBAL:
            return x[0]
        
    return None

def get_if_raw_addr6(iff):
    """
    Returns the main global unicast address associated with provided 
    interface, in network format. If no global address is found, None 
    is returned. 
    """
    ip6= get_if_addr6(iff)
    if ip6 is not None:
        return inet_pton(socket.AF_INET6, ip6)
    
    return None
