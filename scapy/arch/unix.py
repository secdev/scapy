## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Common customizations for all Unix-like operating systems other than Linux
"""

import sys,os,struct,socket,time
from fcntl import ioctl
import socket

from scapy.error import warning, log_interactive
import scapy.config
import scapy.utils
from scapy.utils6 import in6_getscope, construct_source_candidate_set
from scapy.utils6 import in6_isvalid, in6_ismlladdr, in6_ismnladdr
import scapy.arch
from scapy.config import conf


##################
## Routes stuff ##
##################

def _guess_iface_name(netif):
    """
    We attempt to guess the name of interfaces that are truncated from the
    output of ifconfig -l.
    If there is only one possible candidate matching the interface name then we
    return it.
    If there are none or more, then we return None.
    """
    with os.popen('%s -l' % conf.prog.ifconfig) as fdesc:
        ifaces = fdesc.readline().strip().split(' ')
    matches = [iface for iface in ifaces if iface.startswith(netif)]
    if len(matches) == 1:
        return matches[0]
    return None


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
            try:
                ifaddr = scapy.arch.get_if_addr(netif)
                routes.append((dest,netmask,gw,netif,ifaddr))
            except OSError as exc:
                if exc.message == 'Device not configured':
                    # This means the interface name is probably truncated by
                    # netstat -nr. We attempt to guess it's name and if not we
                    # ignore it.
                    guessed_netif = _guess_iface_name(netif)
                    if guessed_netif is not None:
                        ifaddr = scapy.arch.get_if_addr(guessed_netif)
                        routes.append((dest, netmask, gw, guessed_netif, ifaddr))
                    else:
                        warning("Could not guess partial interface name: %s" % netif)
                else:
                    raise
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
        scope = in6_getscope(addr)
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
    """Return a list of IPv6 routes than can be used by Scapy."""

    # Call netstat to retrieve IPv6 routes
    fd_netstat = os.popen("netstat -rn -f inet6")

    # List interfaces IPv6 addresses 
    lifaddr = in6_getifaddr()
    if not lifaddr:
        return []

    # Routes header information
    got_header = False
    mtu_present = False
    prio_present = False

    # Parse the routes
    routes = []
    for line in fd_netstat.readlines():

        # Parse the routes header and try to identify extra columns
        if not got_header:
            if "Destination" == line[:11]:
                got_header = True
                mtu_present = "Mtu" in line
                prio_present = "Prio" in line
            continue

        # Parse a route entry according to the operating system
        splitted_line = line.split()
        if scapy.arch.OPENBSD or scapy.arch.NETBSD:
            index = 5 + mtu_present + prio_present
            if len(splitted_line) < index:
                warning("Not enough columns in route entry !")
                continue
            destination, next_hop, flags = splitted_line[:3]
            dev = splitted_line[index]
        else:
            # FREEBSD or DARWIN 
            if len(splitted_line) < 4:
                warning("Not enough columns in route entry !")
                continue
            destination, next_hop, flags, dev = splitted_line[:4]

        # Check flags
        if not "U" in flags:  # usable route
            continue
        if "R" in flags:  # Host or net unrechable
            continue
        if "m" in flags:  # multicast address
            # Note: multicast routing is handled in Route6.route()
            continue

        # Replace link with the default route in next_hop
        if "link" in next_hop:
            next_hop = "::"

        # Default prefix length
        destination_plen = 128

        # Extract network interface from the zone id
        if '%' in destination:
            destination, dev = destination.split('%')
            if '/' in dev:
                # Example: fe80::%lo0/64 ; dev = "lo0/64"
                dev, destination_plen = dev.split('/')
        if '%' in next_hop:
            next_hop, dev = next_hop.split('%')

        # Ensure that the next hop is a valid IPv6 address
        if not in6_isvalid(next_hop):
            # Note: the 'Gateway' column might contain a MAC address
            next_hop = "::"

        # Modify parsed routing entries
        # Note: these rules are OS specific and may evolve over time
        if destination == "default":
            destination, destination_plen = "::", 0
        elif '/' in destination:
            # Example: fe80::/10
            destination, destination_plen = destination.split('/')
        if '/' in dev:
            # Example: ff02::%lo0/32 ; dev = "lo0/32"
            dev, destination_plen = dev.split('/')

        # Check route entries parameters consistency
        if not in6_isvalid(destination):
            warning("Invalid destination IPv6 address in route entry !")
            continue
        try:
            destination_plen = int(destination_plen)
        except:
            warning("Invalid IPv6 prefix length in route entry !")
            continue
        if in6_ismlladdr(destination) or in6_ismnladdr(destination):
            # Note: multicast routing is handled in Route6.route()
            continue

        if scapy.arch.LOOPBACK_NAME in dev:
            # Handle ::1 separately
            cset = ["::1"]
            next_hop = "::"
        else:
            # Get possible IPv6 source addresses
            devaddrs = filter(lambda x: x[2] == dev, lifaddr)
            cset = construct_source_candidate_set(destination, destination_plen, devaddrs, scapy.arch.LOOPBACK_NAME)

        if len(cset):
            routes.append((destination, destination_plen, next_hop, dev, cset))

    fd_netstat.close()
    return routes
