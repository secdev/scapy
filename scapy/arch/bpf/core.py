# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - core
"""


import fcntl
import os
import socket
import struct

from scapy.arch.bpf.consts import BIOCSETF, BIOCSETIF
from scapy.arch.common import compile_filter
from scapy.config import conf
from scapy.consts import LINUX
from scapy.error import Scapy_Exception
from scapy.interfaces import (
    InterfaceProvider,
    NetworkInterface,
    _GlobInterfaceType,
)

# re-export
from scapy.arch.bpf.pfroute import (  # noqa F403
    read_routes,
    read_routes6,
    _get_if_list,
)
from scapy.arch.common import get_if_raw_addr, read_nameservers  # noqa: F401

# Typing
from typing import (
    Dict,
    List,
    Tuple,
)

if LINUX:
    raise OSError("BPF conflicts with Linux")

# BPF specific functions


def get_dev_bpf():
    # type: () -> Tuple[int, int]
    """Returns an opened BPF file object"""

    # Get the first available BPF handle
    for bpf in range(256):
        try:
            fd = os.open("/dev/bpf%i" % bpf, os.O_RDWR)
            return (fd, bpf)
        except OSError as ex:
            if ex.errno == 13:  # Permission denied
                raise Scapy_Exception(
                    (
                        "Permission denied: could not open /dev/bpf%i. "
                        "Make sure to be running Scapy as root ! (sudo)"
                    )
                    % bpf
                )
            continue

    raise Scapy_Exception("No /dev/bpf handle is available !")


def attach_filter(fd, bpf_filter, iface):
    # type: (int, str, _GlobInterfaceType) -> None
    """Attach a BPF filter to the BPF file descriptor"""
    bp = compile_filter(bpf_filter, iface)
    # Assign the BPF program to the interface
    ret = fcntl.ioctl(fd, BIOCSETF, bp)
    if ret < 0:
        raise Scapy_Exception("Can't attach the BPF filter !")


def in6_getifaddr():
    # type: () -> List[Tuple[str, int, str]]
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'iface'.

    This is the list of all addresses of all interfaces available on
    the system.
    """
    ifaces = _get_if_list()
    return [
        (ip["address"], ip["scope"], iface["name"])
        for iface in ifaces.values()
        for ip in iface["ips"]
        if ip["af_family"] == socket.AF_INET6
    ]


# Interface provider


class BPFInterfaceProvider(InterfaceProvider):
    name = "BPF"

    def _is_valid(self, dev):
        # type: (NetworkInterface) -> bool
        if not dev.flags & 0x1:  # not IFF_UP
            return False
        # Get a BPF handle
        try:
            fd = get_dev_bpf()[0]
        except Scapy_Exception:
            return True  # Can't check if available (non sudo?)
        if fd is None:
            raise Scapy_Exception("No /dev/bpf are available !")
        # Check if the interface can be used
        try:
            fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", dev.network_name.encode()))
        except IOError:
            return False
        else:
            return True
        finally:
            # Close the file descriptor
            os.close(fd)

    def load(self):
        # type: () -> Dict[str, NetworkInterface]
        data = {}
        for iface in _get_if_list().values():
            if_data = iface.copy()
            if_data.update(
                {
                    "network_name": iface["name"],
                    "description": iface["name"],
                    "ips": [x["address"] for x in iface["ips"]],
                }
            )
            data[iface["name"]] = NetworkInterface(self, if_data)
        return data


conf.ifaces.register_provider(BPFInterfaceProvider)
