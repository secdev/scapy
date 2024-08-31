# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Common customizations for all Unix-like operating systems other than Linux
"""

import os
import socket
import struct
from fcntl import ioctl

import scapy.config
import scapy.utils
from scapy.config import conf
from scapy.consts import FREEBSD, NETBSD, OPENBSD, SOLARIS
from scapy.error import log_runtime, warning
from scapy.pton_ntop import inet_pton
from scapy.utils6 import in6_getscope, construct_source_candidate_set
from scapy.utils6 import in6_isvalid, in6_ismlladdr, in6_ismnladdr

# Typing imports
from typing import (
    List,
    Optional,
    Tuple,
    Union,
    cast,
)


def get_if(iff, cmd):
    # type: (str, int) -> bytes
    """Ease SIOCGIF* ioctl calls"""

    sck = socket.socket()
    try:
        return ioctl(sck, cmd, struct.pack("16s16x", iff.encode("utf8")))
    finally:
        sck.close()


def get_if_raw_hwaddr(iff,  # type: str
                      siocgifhwaddr=None,  # type: Optional[int]
                      ):
    # type: (...) -> Tuple[int, bytes]
    """Get the raw MAC address of a local interface.

    This function uses SIOCGIFHWADDR calls, therefore only works
    on some distros.

    :param iff: the network interface name as a string
    :returns: the corresponding raw MAC address
    """

    if siocgifhwaddr is None:
        from scapy.arch import SIOCGIFHWADDR
        siocgifhwaddr = SIOCGIFHWADDR
    return cast(
        "Tuple[int, bytes]",
        struct.unpack(
            "16xH6s8x",
            get_if(iff, siocgifhwaddr)
        )
    )


##################
#  Routes stuff  #
##################

def _guess_iface_name(netif):
    # type: (str) -> Optional[str]
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
    # type: () -> List[Tuple[int, int, str, str, str, int]]
    """Return a list of IPv4 routes than can be used by Scapy.

    This function parses netstat.
    """
    if SOLARIS:
        f = os.popen("netstat -rvn -f inet")
    elif FREEBSD:
        f = os.popen("netstat -rnW -f inet")  # -W to show long interface names
    else:
        f = os.popen("netstat -rn -f inet")
    ok = 0
    mtu_present = False
    prio_present = False
    refs_present = False
    use_present = False
    routes = []  # type: List[Tuple[int, int, str, str, str, int]]
    pending_if = []  # type: List[Tuple[int, int, str]]
    for line in f.readlines():
        if not line:
            break
        line = line.strip().lower()
        if line.find("----") >= 0:  # a separation line
            continue
        if not ok:
            if line.find("destination") >= 0:
                ok = 1
                mtu_present = "mtu" in line
                prio_present = "prio" in line
                refs_present = "ref" in line  # There is no s on Solaris
                use_present = "use" in line or "nhop" in line
            continue
        if not line:
            break
        rt = line.split()
        if SOLARIS:
            dest_, netmask_, gw, netif = rt[:4]
            flg = rt[4 + mtu_present + refs_present]
        else:
            dest_, gw, flg = rt[:3]
            locked = OPENBSD and rt[6] == "l"
            offset = mtu_present + prio_present + refs_present + locked
            offset += use_present
            netif = rt[3 + offset]
        if flg.find("lc") >= 0:
            continue
        elif dest_ == "default":
            dest = 0
            netmask = 0
        elif SOLARIS:
            dest = scapy.utils.atol(dest_)
            netmask = scapy.utils.atol(netmask_)
        else:
            if "/" in dest_:
                dest_, netmask_ = dest_.split("/")
                netmask = scapy.utils.itom(int(netmask_))
            else:
                netmask = scapy.utils.itom((dest_.count(".") + 1) * 8)
            dest_ += ".0" * (3 - dest_.count("."))
            dest = scapy.utils.atol(dest_)
        # XXX: TODO: add metrics for unix.py (use -e option on netstat)
        metric = 1
        if "g" not in flg:
            gw = '0.0.0.0'
        if netif is not None:
            from scapy.arch import get_if_addr
            try:
                ifaddr = get_if_addr(netif)
                if ifaddr == "0.0.0.0":
                    # This means the interface name is probably truncated by
                    # netstat -nr. We attempt to guess it's name and if not we
                    # ignore it.
                    guessed_netif = _guess_iface_name(netif)
                    if guessed_netif is not None:
                        ifaddr = get_if_addr(guessed_netif)
                        netif = guessed_netif
                    else:
                        log_runtime.info(
                            "Could not guess partial interface name: %s",
                            netif
                        )
                routes.append((dest, netmask, gw, netif, ifaddr, metric))
            except OSError:
                raise
        else:
            pending_if.append((dest, netmask, gw))
    f.close()

    # On Solaris, netstat does not provide output interfaces for some routes
    # We need to parse completely the routing table to route their gw and
    # know their output interface
    for dest, netmask, gw in pending_if:
        gw_l = scapy.utils.atol(gw)
        max_rtmask, gw_if, gw_if_addr = 0, None, None
        for rtdst, rtmask, _, rtif, rtaddr, _ in routes[:]:
            if gw_l & rtmask == rtdst:
                if rtmask >= max_rtmask:
                    max_rtmask = rtmask
                    gw_if = rtif
                    gw_if_addr = rtaddr
        # XXX: TODO add metrics
        metric = 1
        if gw_if and gw_if_addr:
            routes.append((dest, netmask, gw, gw_if, gw_if_addr, metric))
        else:
            warning("Did not find output interface to reach gateway %s", gw)

    return routes

############
#   IPv6   #
############


def _in6_getifaddr(ifname):
    # type: (str) -> List[Tuple[str, int, str]]
    """
    Returns a list of IPv6 addresses configured on the interface ifname.
    """

    # Get the output of ifconfig
    try:
        f = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError:
        log_runtime.warning("Failed to execute ifconfig.")
        return []

    # Iterate over lines and extract IPv6 addresses
    ret = []
    for line in f:
        if "inet6" in line:
            addr = line.rstrip().split(None, 2)[1]  # The second element is the IPv6 address  # noqa: E501
        else:
            continue
        if '%' in line:  # Remove the interface identifier if present
            addr = addr.split("%", 1)[0]

        # Check if it is a valid IPv6 address
        try:
            inet_pton(socket.AF_INET6, addr)
        except (socket.error, ValueError):
            continue

        # Get the scope and keep the address
        scope = in6_getscope(addr)
        ret.append((addr, scope, ifname))

    f.close()
    return ret


def in6_getifaddr():
    # type: () -> List[Tuple[str, int, str]]
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'iface'.

    This is the list of all addresses of all interfaces available on
    the system.
    """

    # List all network interfaces
    if OPENBSD or SOLARIS:
        if SOLARIS:
            cmd = "%s -a6"
        else:
            cmd = "%s"
        try:
            f = os.popen(cmd % conf.prog.ifconfig)
        except OSError:
            log_runtime.warning("Failed to execute ifconfig.")
            return []

        # Get the list of network interfaces
        splitted_line = []
        for line in f:
            if "flags" in line:
                iface = line.split()[0].rstrip(':')
                splitted_line.append(iface)

    else:  # FreeBSD, NetBSD or Darwin
        try:
            f = os.popen("%s -l" % conf.prog.ifconfig)
        except OSError:
            log_runtime.warning("Failed to execute ifconfig.")
            return []

        # Get the list of network interfaces
        splitted_line = f.readline().rstrip().split()

    ret = []
    for i in splitted_line:
        ret += _in6_getifaddr(i)
    f.close()
    return ret


def read_routes6():
    # type: () -> List[Tuple[str, int, str, str, List[str], int]]
    """Return a list of IPv6 routes than can be used by Scapy.

    This function parses netstat.
    """

    # Call netstat to retrieve IPv6 routes
    fd_netstat = os.popen("netstat -rn -f inet6")

    # List interfaces IPv6 addresses
    lifaddr = in6_getifaddr()
    if not lifaddr:
        fd_netstat.close()
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
        if OPENBSD or NETBSD:
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

        # XXX: TODO: add metrics for unix.py (use -e option on netstat)
        metric = 1

        # Check flags
        if "U" not in flags:  # usable route
            continue
        if "R" in flags:  # Host or net unreachable
            continue
        if "m" in flags:  # multicast address
            # Note: multicast routing is handled in Route6.route()
            continue

        # Replace link with the default route in next_hop
        if "link" in next_hop:
            next_hop = "::"

        # Default prefix length
        destination_plen = 128  # type: Union[int, str]

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
        except Exception:
            warning("Invalid IPv6 prefix length in route entry !")
            continue
        if in6_ismlladdr(destination) or in6_ismnladdr(destination):
            # Note: multicast routing is handled in Route6.route()
            continue

        if conf.loopback_name in dev:
            # Handle ::1 separately
            cset = ["::1"]
            next_hop = "::"
        else:
            # Get possible IPv6 source addresses
            devaddrs = (x for x in lifaddr if x[2] == dev)
            cset = construct_source_candidate_set(destination, destination_plen, devaddrs)  # noqa: E501

        if len(cset):
            routes.append((destination, destination_plen, next_hop, dev, cset, metric))  # noqa: E501

    fd_netstat.close()
    return routes
