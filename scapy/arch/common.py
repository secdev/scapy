# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Functions common to different architectures
"""

import ctypes
import re
import socket

from scapy.config import conf
from scapy.data import MTU, ARPHDR_ETHER, ARPHRD_TO_DLT
from scapy.error import Scapy_Exception, warning
from scapy.interfaces import network_name, resolve_iface, NetworkInterface
from scapy.libs.structures import bpf_program
from scapy.pton_ntop import inet_pton
from scapy.utils import decode_locale_str

# Type imports
import scapy
from typing import (
    List,
    Optional,
    Union,
)

# From if.h
_iff_flags = [
    "UP",
    "BROADCAST",
    "DEBUG",
    "LOOPBACK",
    "POINTTOPOINT",
    "NOTRAILERS",
    "RUNNING",
    "NOARP",
    "PROMISC",
    "ALLMULTI",
    "MASTER",
    "SLAVE",
    "MULTICAST",
    "PORTSEL",
    "AUTOMEDIA",
    "DYNAMIC",
    "LOWER_UP",
    "DORMANT",
    "ECHO"
]


def get_if_raw_addr(iff):
    # type: (Union[NetworkInterface, str]) -> bytes
    """Return the raw IPv4 address of interface"""
    iff = resolve_iface(iff)
    if not iff.ip:
        return b"\x00" * 4
    return inet_pton(socket.AF_INET, iff.ip)


# BPF HANDLERS


def compile_filter(filter_exp,  # type: str
                   iface=None,  # type: Optional[Union[str, 'scapy.interfaces.NetworkInterface']]  # noqa: E501
                   linktype=None,  # type: Optional[int]
                   promisc=False  # type: bool
                   ):
    # type: (...) -> bpf_program
    """Asks libpcap to parse the filter, then build the matching
    BPF bytecode.

    :param iface: if provided, use the interface to compile
    :param linktype: if provided, use the linktype to compile
    """
    try:
        from scapy.libs.winpcapy import (
            PCAP_ERRBUF_SIZE,
            pcap_open_live,
            pcap_compile,
            pcap_compile_nopcap,
            pcap_close
        )
    except OSError:
        raise ImportError(
            "libpcap is not available. Cannot compile filter !"
        )
    from ctypes import create_string_buffer
    bpf = bpf_program()
    bpf_filter = create_string_buffer(filter_exp.encode("utf8"))
    if not linktype:
        # Try to guess linktype to avoid root
        if not iface:
            if not conf.iface:
                raise Scapy_Exception(
                    "Please provide an interface or linktype!"
                )
            iface = conf.iface
        # Try to guess linktype to avoid requiring root
        try:
            arphd = resolve_iface(iface).type
            linktype = ARPHRD_TO_DLT.get(arphd)
        except Exception:
            # Failed to use linktype: use the interface
            pass
        if not linktype and conf.use_bpf:
            linktype = ARPHDR_ETHER
    if linktype is not None:
        ret = pcap_compile_nopcap(
            MTU, linktype, ctypes.byref(bpf), bpf_filter, 1, -1
        )
    elif iface:
        err = create_string_buffer(PCAP_ERRBUF_SIZE)
        iface_b = create_string_buffer(network_name(iface).encode("utf8"))
        pcap = pcap_open_live(
            iface_b, MTU, promisc, 0, err
        )
        error = decode_locale_str(bytearray(err).strip(b"\x00"))
        if error:
            raise OSError(error)
        ret = pcap_compile(
            pcap, ctypes.byref(bpf), bpf_filter, 1, -1
        )
        pcap_close(pcap)
    if ret == -1:
        raise Scapy_Exception(
            "Failed to compile filter expression %s (%s)" % (filter_exp, ret)
        )
    return bpf


#######
# DNS #
#######

def read_nameservers() -> List[str]:
    """Return the nameservers configured by the OS
    """
    try:
        with open('/etc/resolv.conf', 'r') as fd:
            return re.findall(r"nameserver\s+([^\s]+)", fd.read())
    except FileNotFoundError:
        warning("Could not retrieve the OS's nameserver !")
        return []
