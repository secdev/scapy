# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Functions common to different architectures
"""

import ctypes
import os
import socket
import struct
import subprocess
import time
from ctypes import POINTER, Structure
from ctypes import c_uint, c_uint32, c_ushort, c_ubyte
from scapy.consts import WINDOWS
from scapy.config import conf
from scapy.data import MTU
from scapy.error import Scapy_Exception
from scapy.consts import OPENBSD
import scapy.modules.six as six

if not WINDOWS:
    from fcntl import ioctl

# BOOT


def _check_tcpdump():
    """
    Return True if the tcpdump command can be started
    """
    with open(os.devnull, 'wb') as devnull:
        try:
            proc = subprocess.Popen([conf.prog.tcpdump, "--version"],
                                    stdout=devnull, stderr=subprocess.STDOUT)
        except OSError:
            return False

    if OPENBSD:
        # 'tcpdump --version' returns 1 on OpenBSD 6.4
        return proc.wait() == 1
    else:
        return proc.wait() == 0


# This won't be used on Windows
TCPDUMP = WINDOWS or _check_tcpdump()

# UTILS


def get_if(iff, cmd):
    """Ease SIOCGIF* ioctl calls"""

    sck = socket.socket()
    ifreq = ioctl(sck, cmd, struct.pack("16s16x", iff.encode("utf8")))
    sck.close()
    return ifreq


def get_if_raw_hwaddr(iff):
    """Get the raw MAC address of a local interface.

    This function uses SIOCGIFHWADDR calls, therefore only works
    on some distros.

    :param iff: the network interface name as a string
    :returns: the corresponding raw MAC address
    """
    from scapy.arch import SIOCGIFHWADDR
    return struct.unpack("16xh6s8x", get_if(iff, SIOCGIFHWADDR))

# SOCKET UTILS


def _select_nonblock(sockets, remain=None):
    """This function is called during sendrecv() routine to select
    the available sockets.
    """
    # pcap sockets aren't selectable, so we return all of them
    # and ask the selecting functions to use nonblock_recv instead of recv
    def _sleep_nonblock_recv(self):
        res = self.nonblock_recv()
        if res is None:
            time.sleep(conf.recv_poll_rate)
        return res
    # we enforce remain=None: don't wait.
    return sockets, _sleep_nonblock_recv

# BPF HANDLERS


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


def _legacy_bpf_pointer(tcpdump_lines):
    """Get old-format BPF Pointer. Deprecated"""
    X86_64 = os.uname()[4] in ['x86_64', 'aarch64']
    size = int(tcpdump_lines[0])
    bpf = b""
    for l in tcpdump_lines[1:]:
        if six.PY2:
            int_type = long  # noqa: F821
        else:
            int_type = int
        bpf += struct.pack("HBBI", *map(int_type, l.split()))

    # Thanks to http://www.netprojects.de/scapy-with-pypy-solved/ for the pypy trick  # noqa: E501
    if conf.use_pypy:
        str_buffer = ctypes.create_string_buffer(bpf)
        return struct.pack('HL', size, ctypes.addressof(str_buffer))
    else:
        # XXX. Argl! We need to give the kernel a pointer on the BPF,
        # Python object header seems to be 20 bytes. 36 bytes for x86 64bits arch.  # noqa: E501
        if X86_64:
            return struct.pack("HL", size, id(bpf) + 36)
        else:
            return struct.pack("HI", size, id(bpf) + 20)


def get_bpf_pointer(tcpdump_lines):
    """Create a BPF Pointer for TCPDump filter"""
    if conf.use_pypy:
        return _legacy_bpf_pointer(tcpdump_lines)

    # Allocate BPF instructions
    size = int(tcpdump_lines[0])
    bpf_insn_a = bpf_insn * size
    bip = bpf_insn_a()

    # Fill the BPF instruction structures with the byte code
    tcpdump_lines = tcpdump_lines[1:]
    i = 0
    for line in tcpdump_lines:
        values = [int(v) for v in line.split()]
        bip[i].code = c_ushort(values[0])
        bip[i].jt = c_ubyte(values[1])
        bip[i].jf = c_ubyte(values[2])
        bip[i].k = c_uint(values[3])
        i += 1

    # Create the BPF program
    return bpf_program(size, bip)


def compile_filter(bpf_filter, iface=None):
    """Asks Tcpdump to parse the filter, then build the matching
    BPF bytecode using get_bpf_pointer.
    """
    if not TCPDUMP:
        raise Scapy_Exception("tcpdump is not available. Cannot use filter !")
    try:
        process = subprocess.Popen([
            conf.prog.tcpdump,
            "-p",
            "-i", (conf.iface if iface is None else iface),
            "-ddd",
            "-s", str(MTU),
            bpf_filter],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except OSError as ex:
        raise Scapy_Exception("Failed to attach filter: %s" % ex)
    lines, err = process.communicate()
    ret = process.returncode
    if ret:
        raise Scapy_Exception(
            "Failed to attach filter: tcpdump returned: %s" % err
        )
    lines = lines.strip().split(b"\n")
    return get_bpf_pointer(lines)
