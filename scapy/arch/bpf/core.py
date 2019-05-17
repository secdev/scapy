# Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - core
"""

from __future__ import absolute_import

from ctypes import cdll, cast, pointer
from ctypes import c_int, c_ulong, c_char_p
from ctypes.util import find_library
import fcntl
import os
import re
import socket
import struct

from scapy.arch.bpf.consts import BIOCSETF, SIOCGIFFLAGS, BIOCSETIF
from scapy.arch.common import get_if, compile_filter
from scapy.config import conf
from scapy.consts import LOOPBACK_NAME
from scapy.data import ARPHDR_LOOPBACK, ARPHDR_ETHER
from scapy.error import Scapy_Exception, warning
from scapy.modules.six.moves import range


# ctypes definitions

LIBC = cdll.LoadLibrary(find_library("libc"))
LIBC.ioctl.argtypes = [c_int, c_ulong, c_char_p]
LIBC.ioctl.restype = c_int


# Addresses manipulation functions

def get_if_raw_addr(ifname):
    """Returns the IPv4 address configured on 'ifname', packed with inet_pton."""  # noqa: E501

    # Get ifconfig output
    try:
        fd = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError as msg:
        warning("Failed to execute ifconfig: (%s)", msg)
        return b"\0\0\0\0"

    # Get IPv4 addresses
    addresses = [l for l in fd if l.find("inet ") >= 0]
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

    # Handle the loopback interface separately
    if ifname == LOOPBACK_NAME:
        return (ARPHDR_LOOPBACK, NULL_MAC_ADDRESS)

    # Get ifconfig output
    try:
        fd = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError as msg:
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" % msg)

    # Get MAC addresses
    addresses = [l for l in fd.readlines() if l.find("ether") >= 0 or
                 l.find("lladdr") >= 0 or
                 l.find("address") >= 0]
    if not addresses:
        raise Scapy_Exception("No MAC address found on %s !" % ifname)

    # Pack and return the MAC address
    mac = addresses[0].split(' ')[1]
    mac = [chr(int(b, 16)) for b in mac.split(':')]
    return (ARPHDR_ETHER, ''.join(mac))


# BPF specific functions

def get_dev_bpf():
    """Returns an opened BPF file object"""

    # Get the first available BPF handle
    for bpf in range(256):
        try:
            fd = os.open("/dev/bpf%i" % bpf, os.O_RDWR)
            return (fd, bpf)
        except OSError:
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

def get_if_list():
    """Returns a list containing all network interfaces."""

    # Get ifconfig output
    try:
        fd = os.popen("%s -a" % conf.prog.ifconfig)
    except OSError as msg:
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" % msg)

    # Get interfaces
    interfaces = [line[:line.find(':')] for line in fd.readlines()
                  if ": flags" in line.lower()]
    return interfaces


_IFNUM = re.compile("([0-9]*)([ab]?)$")


def get_working_ifaces():
    """
    Returns an ordered list of interfaces that could be used with BPF.
    Note: the order mimics pcap_findalldevs() behavior
    """

    # Only root is allowed to perform the following ioctl() call
    if os.getuid() != 0:
        return []

    # Test all network interfaces
    interfaces = []
    for ifname in get_if_list():

        # Unlike pcap_findalldevs(), we do not care of loopback interfaces.
        if ifname == LOOPBACK_NAME:
            continue

        # Get interface flags
        try:
            result = get_if(ifname, SIOCGIFFLAGS)
        except IOError:
            warning("ioctl(SIOCGIFFLAGS) failed on %s !", ifname)
            continue

        # Convert flags
        ifflags = struct.unpack("16xH14x", result)[0]
        if ifflags & 0x1:  # IFF_UP

            # Get a BPF handle
            fd = get_dev_bpf()[0]
            if fd is None:
                raise Scapy_Exception("No /dev/bpf are available !")

            # Check if the interface can be used
            try:
                fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x",
                                                       ifname.encode()))
            except IOError:
                pass
            else:
                ifnum, ifab = _IFNUM.search(ifname).groups()
                interfaces.append((ifname, int(ifnum) if ifnum else -1, ifab))
            finally:
                # Close the file descriptor
                os.close(fd)

    # Sort to mimic pcap_findalldevs() order
    interfaces.sort(key=lambda elt: (elt[1], elt[2], elt[0]))

    return [iface[0] for iface in interfaces]


def get_working_if():
    """Returns the first interface than can be used with BPF"""

    ifaces = get_working_ifaces()
    if not ifaces:
        # A better interface will be selected later using the routing table
        return LOOPBACK_NAME
    return ifaces[0]
