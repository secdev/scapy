# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Customization for the Solaris operation system.
"""

import socket

from scapy.config import conf
conf.use_pcap = True

# IPPROTO_GRE is missing on Solaris
socket.IPPROTO_GRE = 47

# From sys/sockio.h and net/if.h
SIOCGIFHWADDR = 0xc02069b9  # Get hardware address

from scapy.arch.libpcap import *  # noqa: F401, F403, E402
from scapy.arch.unix import *  # noqa: F401, F403, E402

from scapy.interfaces import NetworkInterface  # noqa: E402


def get_working_if():
    # type: () -> NetworkInterface
    """Return an interface that works"""
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        iface = min(conf.route.routes, key=lambda x: x[1])[3]
    except ValueError:
        # no route
        iface = conf.loopback_name
    return conf.ifaces.dev_from_name(iface)
