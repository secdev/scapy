# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - core
"""

from __future__ import absolute_import

from ctypes import cdll, cast, pointer
from ctypes import c_int, c_ulong, c_uint, c_char_p, Structure, POINTER
from ctypes.util import find_library
import fcntl
import os
import re
import socket
import struct
import subprocess

import scapy
from scapy.arch.bpf.consts import BIOCSETF, SIOCGIFFLAGS, BIOCSETIF
from scapy.arch.common import compile_filter, _iff_flags
from scapy.arch.unix import get_if, in6_getifaddr
from scapy.compat import plain_str
from scapy.config import conf
from scapy.consts import LINUX
from scapy.data import ARPHDR_LOOPBACK, ARPHDR_ETHER
from scapy.error import Scapy_Exception, warning
from scapy.interfaces import InterfaceProvider, IFACES, NetworkInterface, \
    network_name
from scapy.pton_ntop import inet_ntop

if LINUX:
    raise OSError("BPF conflicts with Linux")


# ctypes definitions

LIBC = cdll.LoadLibrary(find_library("c"))

LIBC.ioctl.argtypes = [c_int, c_ulong, ]
LIBC.ioctl.restype = c_int

# The following is implemented as of Python >= 3.3
# under socket.*. Remember to use them when dropping Py2.7

# See https://docs.python.org/3/library/socket.html#socket.if_nameindex


class if_nameindex(Structure):
    _fields_ = [("if_index", c_uint),
                ("if_name", c_char_p)]


_ptr_ifnameindex_table = POINTER(if_nameindex * 255)

LIBC.if_nameindex.argtypes = []
LIBC.if_nameindex.restype = _ptr_ifnameindex_table
LIBC.if_freenameindex.argtypes = [_ptr_ifnameindex_table]
LIBC.if_freenameindex.restype = None

# Addresses manipulation functions


def get_if_raw_addr(ifname):
    """Returns the IPv4 address configured on 'ifname', packed with inet_pton."""  # noqa: E501

    ifname = network_name(ifname)

    # Get ifconfig output
    subproc = subprocess.Popen(
        [conf.prog.ifconfig, ifname],
        close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = subproc.communicate()
    if subproc.returncode:
        warning("Failed to execute ifconfig: (%s)", plain_str(stderr).strip())
        return b"\0\0\0\0"

    # Get IPv4 addresses
    addresses = [
        line.strip() for line in plain_str(stdout).splitlines()
        if "inet " in line
    ]

    if not addresses:
        warning("No IPv4 address found on %s !", ifname)
        return b"\0\0\0\0"

    # Pack the first address
    address = addresses[0].split(' ')[1]
    if '/' in address:  # NetBSD 8.0
        address = address.split("/")[0]
    return socket.inet_pton(socket.AF_INET, address)


def get_if_raw_hwaddr(ifname):
    """Returns the packed MAC address configured on 'ifname'."""

    NULL_MAC_ADDRESS = b'\x00' * 6

    ifname = network_name(ifname)
    # Handle the loopback interface separately
    if ifname == conf.loopback_name:
        return (ARPHDR_LOOPBACK, NULL_MAC_ADDRESS)

    # Get ifconfig output
    subproc = subprocess.Popen(
        [conf.prog.ifconfig, ifname],
        close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = subproc.communicate()
    if subproc.returncode:
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" %
                              plain_str(stderr).strip())

    # Get MAC addresses
    addresses = [
        line.strip() for line in plain_str(stdout).splitlines() if (
            "ether" in line or "lladdr" in line or "address" in line
        )
    ]
    if not addresses:
        raise Scapy_Exception("No MAC address found on %s !" % ifname)

    # Pack and return the MAC address
    mac = addresses[0].split(' ')[1]
    mac = [chr(int(b, 16)) for b in mac.split(':')]

    # Check that the address length is correct
    if len(mac) != 6:
        raise Scapy_Exception("No MAC address found on %s !" % ifname)

    return (ARPHDR_ETHER, ''.join(mac))


# BPF specific functions

def get_dev_bpf():
    """Returns an opened BPF file object"""

    # Get the first available BPF handle
    for bpf in range(256):
        try:
            fd = os.open("/dev/bpf%i" % bpf, os.O_RDWR)
            return (fd, bpf)
        except OSError as ex:
            if ex.errno == 13:  # Permission denied
                raise Scapy_Exception((
                    "Permission denied: could not open /dev/bpf%i. "
                    "Make sure to be running Scapy as root ! (sudo)"
                ) % bpf)
            continue

    raise Scapy_Exception("No /dev/bpf handle is available !")


def attach_filter(fd, bpf_filter, iface):
    """Attach a BPF filter to the BPF file descriptor"""
    bp = compile_filter(bpf_filter, iface)
    # Assign the BPF program to the interface
    ret = LIBC.ioctl(c_int(fd), BIOCSETF, cast(pointer(bp), c_char_p))
    if ret < 0:
        raise Scapy_Exception("Can't attach the BPF filter !")


# Interface manipulation functions

def _get_ifindex_list():
    """
    Returns a list containing (iface, index)
    """
    ptr = LIBC.if_nameindex()
    ifaces = []
    for i in range(255):
        iface = ptr.contents[i]
        if not iface.if_name:
            break
        ifaces.append((plain_str(iface.if_name), iface.if_index))
    LIBC.if_freenameindex(ptr)
    return ifaces


_IFNUM = re.compile(r"([0-9]*)([ab]?)$")


def _get_if_flags(ifname):
    """Internal function to get interface flags"""
    # Get interface flags
    try:
        result = get_if(ifname, SIOCGIFFLAGS)
    except IOError:
        warning("ioctl(SIOCGIFFLAGS) failed on %s !", ifname)
        return None

    # Convert flags
    ifflags = struct.unpack("16xH14x", result)[0]
    return ifflags


class BPFInterfaceProvider(InterfaceProvider):
    name = "BPF"

    def _is_valid(self, dev):
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
            fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x",
                                                   dev.network_name.encode()))
        except IOError:
            return False
        else:
            return True
        finally:
            # Close the file descriptor
            os.close(fd)

    def load(self):
        from scapy.fields import FlagValue
        data = {}
        ips = in6_getifaddr()
        for ifname, index in _get_ifindex_list():
            try:
                ifflags = _get_if_flags(ifname)
                mac = scapy.utils.str2mac(get_if_raw_hwaddr(ifname)[1])
                ip = inet_ntop(socket.AF_INET, get_if_raw_addr(ifname))
            except Scapy_Exception:
                continue
            ifflags = FlagValue(ifflags, _iff_flags)
            if_data = {
                "name": ifname,
                "network_name": ifname,
                "description": ifname,
                "flags": ifflags,
                "index": index,
                "ip": ip,
                "ips": [x[0] for x in ips if x[2] == ifname] + [ip],
                "mac": mac
            }
            data[ifname] = NetworkInterface(self, if_data)
        return data


IFACES.register_provider(BPFInterfaceProvider)
