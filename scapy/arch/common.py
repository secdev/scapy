# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Functions common to different architectures
"""

import ctypes
import socket
import struct
from scapy.consts import WINDOWS
from scapy.config import conf
from scapy.data import MTU, ARPHDR_ETHER, ARPHRD_TO_DLT
from scapy.error import Scapy_Exception
from scapy.interfaces import network_name, NetworkInterface
from scapy.libs.structures import bpf_program

# Type imports
import scapy
from scapy.compat import (
    Optional,
    Tuple,
    Union,
)

if not WINDOWS:
    from fcntl import ioctl

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
    "NOTRAILERS",
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

# UTILS


def get_if(iff, cmd):
    # type: (Union[NetworkInterface, str], int) -> bytes
    """Ease SIOCGIF* ioctl calls"""

    iff = network_name(iff)
    sck = socket.socket()
    try:
        return ioctl(sck, cmd, struct.pack("16s16x", iff.encode("utf8")))
    finally:
        sck.close()


def get_if_raw_hwaddr(iff,  # type: Union[NetworkInterface, str]
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
        from scapy.arch import SIOCGIFHWADDR  # type: ignore
        siocgifhwaddr = SIOCGIFHWADDR
    return struct.unpack(  # type: ignore
        "16xH6s8x",
        get_if(iff, siocgifhwaddr)
    )


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
            arphd = get_if_raw_hwaddr(iface)[0]
            linktype = ARPHRD_TO_DLT.get(arphd)
        except Exception:
            # Failed to use linktype: use the interface
            pass
        if not linktype and conf.use_bpf:
            linktype = ARPHDR_ETHER
    if linktype is not None:
        ret = pcap_compile_nopcap(
            MTU, linktype, ctypes.byref(bpf), bpf_filter, 0, -1
        )
    elif iface:
        err = create_string_buffer(PCAP_ERRBUF_SIZE)
        iface_b = create_string_buffer(network_name(iface).encode("utf8"))
        pcap = pcap_open_live(
            iface_b, MTU, promisc, 0, err
        )
        error = bytes(bytearray(err)).strip(b"\x00")
        if error:
            raise OSError(error)
        ret = pcap_compile(
            pcap, ctypes.byref(bpf), bpf_filter, 0, -1
        )
        pcap_close(pcap)
    if ret == -1:
        raise Scapy_Exception(
            "Failed to compile filter expression %s (%s)" % (filter_exp, ret)
        )
    return bpf
