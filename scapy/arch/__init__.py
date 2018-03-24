## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Operating system specific functionality.
"""

from __future__ import absolute_import
import socket

from scapy.consts import LINUX, OPENBSD, FREEBSD, NETBSD, DARWIN, \
    SOLARIS, WINDOWS, BSD, IS_64BITS, LOOPBACK_NAME
from scapy.error import *
import scapy.config
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.data import *

def str2mac(s):
    return ("%02x:"*6)[:-1] % tuple(orb(x) for x in s)

if not WINDOWS:
    if not scapy.config.conf.use_pcap and not scapy.config.conf.use_dnet:
        from scapy.arch.bpf.core import get_if_raw_addr

def get_if_addr(iff):
    return inet_ntop(socket.AF_INET, get_if_raw_addr(iff))
    
def get_if_hwaddr(iff):
    addrfamily, mac = get_if_raw_hwaddr(iff)
    if addrfamily in [ARPHDR_ETHER,ARPHDR_LOOPBACK]:
        return str2mac(mac)
    else:
        raise Scapy_Exception("Unsupported address family (%i) for interface [%s]" % (addrfamily,iff))


# Next step is to import following architecture specific functions:
# def get_if_raw_hwaddr(iff)
# def get_if_raw_addr(iff):
# def get_if_list():
# def get_working_if():
# def attach_filter(s, filter, iface):
# def set_promisc(s,iff,val=1):
# def read_routes():
# def read_routes6():
# def get_if(iff,cmd):
# def get_if_index(iff):

if LINUX:
    from scapy.arch.linux import *
    if scapy.config.conf.use_pcap or scapy.config.conf.use_dnet:
        from scapy.arch.pcapdnet import *
elif BSD:
    from scapy.arch.unix import read_routes, read_routes6, in6_getifaddr

    if scapy.config.conf.use_pcap or scapy.config.conf.use_dnet:
        from scapy.arch.pcapdnet import *
    else:
        from scapy.arch.bpf.supersocket import L2bpfListenSocket, L2bpfSocket, L3bpfSocket
        from scapy.arch.bpf.core import *
        scapy.config.conf.use_bpf = True
        scapy.config.conf.L2listen = L2bpfListenSocket
        scapy.config.conf.L2socket = L2bpfSocket
        scapy.config.conf.L3socket = L3bpfSocket
elif SOLARIS:
    from scapy.arch.solaris import *
elif WINDOWS:
    from scapy.arch.windows import *

if scapy.config.conf.iface is None:
    scapy.config.conf.iface = scapy.consts.LOOPBACK_INTERFACE


def get_if_addr6(iff):
    """
    Returns the main global unicast address associated with provided 
    interface, in human readable form. If no global address is found,
    None is returned. 
    """
    return next((x[0] for x in in6_getifaddr()
                 if x[2] == iff and x[1] == IPV6_ADDR_GLOBAL), None)

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
