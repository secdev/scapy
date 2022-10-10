# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Operating system specific functionality.
"""

import socket
import sys

from scapy.compat import orb
from scapy.config import conf, _set_conf_sockets
from scapy.consts import LINUX, SOLARIS, WINDOWS, BSD
from scapy.data import (
    ARPHDR_ETHER,
    ARPHDR_LOOPBACK,
    ARPHDR_PPP,
    ARPHDR_TUN,
    IPV6_ADDR_GLOBAL
)
from scapy.error import log_loading, Scapy_Exception
from scapy.interfaces import NetworkInterface, network_name
from scapy.pton_ntop import inet_pton, inet_ntop

# Typing imports
from scapy.compat import (
    Optional,
    Union,
)

# Note: the typing of this file is heavily ignored because MyPy doesn't allow
# to import the same function from different files.

# This list only includes imports that are common across all platforms.
__all__ = [  # noqa: F405
    "get_if_addr",
    "get_if_addr6",
    "get_if_hwaddr",
    "get_if_list",
    "get_if_raw_addr",
    "get_if_raw_addr6",
    "get_if_raw_hwaddr",
    "get_working_if",
    "in6_getifaddr",
    "read_routes",
    "read_routes6",
    "SIOCGIFHWADDR",
]

# BACKWARD COMPATIBILITY
from scapy.interfaces import (
    get_if_list,
    get_working_if,
)


# We build the utils functions BEFORE importing the underlying handlers
# because they might be themselves imported within the arch/ folder.

def str2mac(s):
    # Duplicated from scapy/utils.py for import reasons
    # type: (bytes) -> str
    return ("%02x:" * 6)[:-1] % tuple(orb(x) for x in s)


def get_if_addr(iff):
    # type: (str) -> str
    """
    Returns the IPv4 of an interface or "0.0.0.0" if not available
    """
    return inet_ntop(socket.AF_INET, get_if_raw_addr(iff))  # noqa: F405


def get_if_hwaddr(iff):
    # type: (Union[NetworkInterface, str]) -> str
    """
    Returns the MAC (hardware) address of an interface
    """
    from scapy.arch import get_if_raw_hwaddr
    addrfamily, mac = get_if_raw_hwaddr(iff)  # noqa: F405
    if addrfamily in [ARPHDR_ETHER, ARPHDR_LOOPBACK, ARPHDR_PPP, ARPHDR_TUN]:
        return str2mac(mac)
    else:
        raise Scapy_Exception("Unsupported address family (%i) for interface [%s]" % (addrfamily, iff))  # noqa: E501


def get_if_addr6(niff):
    # type: (NetworkInterface) -> Optional[str]
    """
    Returns the main global unicast address associated with provided
    interface, in human readable form. If no global address is found,
    None is returned.
    """
    iff = network_name(niff)
    return next((x[0] for x in in6_getifaddr()
                 if x[2] == iff and x[1] == IPV6_ADDR_GLOBAL), None)


def get_if_raw_addr6(iff):
    # type: (NetworkInterface) -> Optional[bytes]
    """
    Returns the main global unicast address associated with provided
    interface, in network format. If no global address is found, None
    is returned.
    """
    ip6 = get_if_addr6(iff)
    if ip6 is not None:
        return inet_pton(socket.AF_INET6, ip6)

    return None


# Next step is to import following architecture specific functions:
# def attach_filter(s, filter, iface)
# def get_if(iff,cmd)
# def get_if_index(iff)
# def get_if_raw_addr(iff)
# def get_if_raw_hwaddr(iff)
# def in6_getifaddr()
# def read_routes()
# def read_routes6()
# def set_promisc(s,iff,val=1)

if LINUX:
    from scapy.arch.linux import *  # noqa F403
elif BSD:
    from scapy.arch.unix import read_routes, read_routes6, in6_getifaddr  # noqa: E501
    from scapy.arch.bpf.core import *  # noqa F403
    if not conf.use_pcap:
        # Native
        from scapy.arch.bpf.supersocket import *  # noqa F403
        conf.use_bpf = True
    SIOCGIFHWADDR = 0  # mypy compat
elif SOLARIS:
    from scapy.arch.solaris import *  # noqa F403
elif WINDOWS:
    from scapy.arch.windows import *  # noqa F403
    from scapy.arch.windows.native import *  # noqa F403
    SIOCGIFHWADDR = 0  # mypy compat
else:
    log_loading.critical(
        "Scapy currently does not support %s! I/O will NOT work!" % sys.platform
    )
    SIOCGIFHWADDR = 0  # mypy compat

if LINUX or BSD:
    conf.load_layers.append("tuntap")

_set_conf_sockets()  # Apply config
