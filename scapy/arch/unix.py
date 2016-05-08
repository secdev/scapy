## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Common customizations for all Unix-like operating systems other than Linux
"""

import sys,os,struct,socket,time
from fcntl import ioctl
from scapy.error import warning
import scapy.config
import scapy.utils
import scapy.utils6
import scapy.arch
from scapy.config import conf


##################
## Routes stuff ##
##################


def read_routes():
    if scapy.arch.SOLARIS:
        f=os.popen("netstat -rvn") # -f inet
    elif scapy.arch.FREEBSD:
        f=os.popen("netstat -rnW") # -W to handle long interface names
    else:
        f=os.popen("netstat -rn") # -f inet
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
                mtu_present = "Mtu" in l
                prio_present = "Prio" in l
                refs_present = "Refs" in l
            continue
        if not l:
            break
        if scapy.arch.SOLARIS:
            lspl = l.split()
            if len(lspl) == 10:
                dest,mask,gw,netif,mxfrg,rtt,ref,flg = lspl[:8]
            else: # missing interface
                dest,mask,gw,mxfrg,rtt,ref,flg = lspl[:7]
                netif=None
        else:
            rt = l.split()
            dest,gw,flg = rt[:3]
            netif = rt[4 + mtu_present + prio_present + refs_present]
        if flg.find("Lc") >= 0:
            continue
        if dest == "default":
            dest = 0L
            netmask = 0L
        else:
            if scapy.arch.SOLARIS:
                netmask = scapy.utils.atol(mask)
            elif "/" in dest:
                dest,netmask = dest.split("/")
                netmask = scapy.utils.itom(int(netmask))
            else:
                netmask = scapy.utils.itom((dest.count(".") + 1) * 8)
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

def _in6_getifaddr(ifname):
    """
    Returns a list of IPv6 addresses configured on the interface ifname.
    """

    # Get the output of ifconfig
    try:
        f = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError,msg:
        log_interactive.warning("Failed to execute ifconfig.")
        return []

    # Iterate over lines and extract IPv6 addresses
    ret = []
    for line in f:
        if "inet6" in line:
            addr = line.rstrip().split(None, 2)[1] # The second element is the IPv6 address
        else:
            continue
        if '%' in line: # Remove the interface identifier if present
            addr = addr.split("%", 1)[0]

        # Check if it is a valid IPv6 address
        try:
            socket.inet_pton(socket.AF_INET6, addr)
        except:
            continue

        # Get the scope and keep the address
        scope = scapy.utils6.in6_getscope(addr)
        ret.append((addr, scope, ifname))

    return ret

def in6_getifaddr():
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'iface'.

    This is the list of all addresses of all interfaces available on
    the system.
    """

    # List all network interfaces
    if scapy.arch.OPENBSD:
        try:
            f = os.popen("%s" % conf.prog.ifconfig)
        except OSError,msg:
	    log_interactive.warning("Failed to execute ifconfig.")
	    return []

        # Get the list of network interfaces
        splitted_line = []
        for l in f:
            if "flags" in l:
                iface = l.split()[0].rstrip(':')
                splitted_line.append(iface)

    else: # FreeBSD, NetBSD or Darwin
        try:
	    f = os.popen("%s -l" % conf.prog.ifconfig)
        except OSError,msg:
	    log_interactive.warning("Failed to execute ifconfig.")
	    return []

        # Get the list of network interfaces
        splitted_line = f.readline().rstrip().split()

    ret = []
    for i in splitted_line:
	ret += _in6_getifaddr(i)
    return ret

def read_routes6():
    f = os.popen("netstat -rn -f inet6")
    ok = False
    mtu_present = False
    prio_present = False
    routes = []
    lifaddr = in6_getifaddr()
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        if not ok:
            if l.find("Destination") >= 0:
                ok = 1
                mtu_present = l.find("Mtu") >= 0
                prio_present = l.find("Prio") >= 0
            continue
        # gv 12/12/06: under debugging
        if scapy.arch.NETBSD or scapy.arch.OPENBSD:
            lspl = l.split()
            d,nh,fl = lspl[:3]
            dev = lspl[5+mtu_present+prio_present]
        else:       # FREEBSD or DARWIN
            d,nh,fl,dev = l.split()[:4]
        if filter(lambda x: x[2] == dev, lifaddr) == []:
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
        if scapy.arch.LOOPBACK_NAME in dev:
            cset = ['::1']
            nh = '::'
        else:
            devaddrs = filter(lambda x: x[2] == dev, lifaddr)
            cset = scapy.utils6.construct_source_candidate_set(d, dp, devaddrs, scapy.arch.LOOPBACK_NAME)

        if len(cset) != 0:
            routes.append((d, dp, nh, dev, cset))

    f.close()
    return routes






