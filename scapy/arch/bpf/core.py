# Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - core
"""

from scapy.config import conf
from scapy.error import Scapy_Exception, warning
from scapy.data import ARPHDR_LOOPBACK, ARPHDR_ETHER
from scapy.arch.common import get_if
from scapy.consts import LOOPBACK_NAME

from scapy.arch.bpf.consts import *

import os
import socket
import fcntl
import struct

from ctypes import cdll, cast, pointer, POINTER, Structure
from ctypes import c_uint, c_uint32, c_int, c_ulong, c_char_p, c_ushort, c_ubyte
from ctypes.util import find_library


# ctypes definitions

LIBC = cdll.LoadLibrary(find_library("libc"))
LIBC.ioctl.argtypes = [c_int, c_ulong, c_char_p]
LIBC.ioctl.restype = c_int


class bpf_insn(Structure):
    """"The BPF instruction data structure"""
    _fields_ = [("code", c_ushort),
                ("jt", c_ubyte),
                ("jf", c_ubyte),
                ("k", c_uint32)]


class bpf_program(Structure):
    """"Structure for BIOCSETF"""
    _fields_ = [("bf_len", c_uint),
                ("bf_insns", POINTER(bpf_insn))]


# Addresses manipulation functions

def get_if_raw_addr(ifname):
    """Returns the IPv4 address configured on 'ifname', packed with inet_pton."""

    # Get ifconfig output
    try:
        fd = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError, msg:
        warning("Failed to execute ifconfig: (%s)" % msg)
        return "\0\0\0\0"

    # Get IPv4 addresses
    addresses = [l for l in fd if l.find("netmask") >= 0]
    if not addresses:
        warning("No IPv4 address found on %s !" % ifname)
        return "\0\0\0\0"

    # Pack the first address
    address = addresses[0].split(' ')[1]
    return socket.inet_pton(socket.AF_INET, address)


def get_if_raw_hwaddr(ifname):
    """Returns the packed MAC address configured on 'ifname'."""

    NULL_MAC_ADDRESS = '\x00'*6

    # Handle the loopback interface separately
    if ifname == LOOPBACK_NAME:
        return (ARPHDR_LOOPBACK, NULL_MAC_ADDRESS)

    # Get ifconfig output
    try:
        fd = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError, msg:
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
    for bpf in range(0, 8):
        try:
            fd = os.open("/dev/bpf%i" % bpf, os.O_RDWR)
            return (fd, bpf)
        except OSError, err:
            continue

    raise Scapy_Exception("No /dev/bpf handle is available !")


def attach_filter(fd, iface, bpf_filter_string):
    """Attach a BPF filter to the BPF file descriptor"""

    # Retrieve the BPF byte code in decimal
    command = "%s -i %s -ddd -s 1600 '%s'" % (conf.prog.tcpdump, iface, bpf_filter_string)
    try:
        f = os.popen(command)
    except OSError, msg:
        raise Scapy_Exception("Failed to execute tcpdump: (%s)" % msg)

    # Convert the byte code to a BPF program structure
    lines = f.readlines()
    if lines == []:
        raise Scapy_Exception("Got an empty BPF filter from tcpdump !")

    # Allocate BPF instructions
    size = int(lines[0])
    bpf_insn_a = bpf_insn * size
    bip = bpf_insn_a()

    # Fill the BPF instruction structures with the byte code
    lines = lines[1:]
    for i in xrange(len(lines)):
        values = [int(v) for v in lines[i].split()]
        bip[i].code = c_ushort(values[0])
        bip[i].jt = c_ubyte(values[1])
        bip[i].jf = c_ubyte(values[2])
        bip[i].k = c_uint(values[3])

    # Create the BPF program and assign it to the interface
    bp = bpf_program(size, bip)
    ret = LIBC.ioctl(c_int(fd), BIOCSETF, cast(pointer(bp), c_char_p))
    if ret < 0:
        raise Scapy_Exception("Can't attach the BPF filter !")


# Interface manipulation functions

def get_if_list():
    """Returns a list containing all network interfaces."""

    # Get ifconfig output
    try:
        fd = os.popen("%s -a" % conf.prog.ifconfig)
    except OSError, msg:
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" % msg)

    # Get interfaces
    interfaces = [line[:line.find(':')] for line in fd.readlines()
                                        if ": flags" in line.lower()]
    return interfaces


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
        except IOError, msg:
            warning("ioctl(SIOCGIFFLAGS) failed on %s !" % ifname)
            continue

        # Convert flags
        ifflags = struct.unpack("16xH14x", result)[0]
        if ifflags & 0x1:  # IFF_UP

            # Get a BPF handle
            fd, _ = get_dev_bpf()
            if fd is None:
                raise Scapy_Exception("No /dev/bpf are available !")

            # Check if the interface can be used
            try:
                fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", ifname))
                interfaces.append((ifname, int(ifname[-1])))
            except IOError, err:
                pass

            # Close the file descriptor
            os.close(fd)

    # Sort to mimic pcap_findalldevs() order
    interfaces.sort(lambda (ifname_left, ifid_left),
                        (ifname_right, ifid_right): ifid_left-ifid_right)
    return interfaces


def get_working_if():
    """Returns the first interface than can be used with BPF"""

    ifaces = get_working_ifaces()
    if not ifaces:
        # A better interface will be selected later using the routing table
        return LOOPBACK_NAME
    return ifaces[0][0]
