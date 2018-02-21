## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Functions common to different architectures
"""

import socket
from fcntl import ioctl
import os, struct, ctypes
from ctypes import POINTER, Structure
from ctypes import c_uint, c_uint32, c_ushort, c_ubyte
from scapy.config import conf
import scapy.modules.six as six

## UTILS

def get_if(iff, cmd):
    """Ease SIOCGIF* ioctl calls"""

    sck = socket.socket()
    ifreq = ioctl(sck, cmd, struct.pack("16s16x", iff.encode("utf8")))
    sck.close()
    return ifreq

## BPF HANDLERS

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
    bpf = ""
    for l in tcpdump_lines[1:]:
        bpf += struct.pack("HBBI",*map(long,l.split()))

    # Thanks to http://www.netprojects.de/scapy-with-pypy-solved/ for the pypy trick
    if conf.use_pypy and six.PY2:
        str_buffer = ctypes.create_string_buffer(bpf)
        return struct.pack('HL', size, ctypes.addressof(str_buffer))
    else:
        # XXX. Argl! We need to give the kernel a pointer on the BPF,
        # Python object header seems to be 20 bytes. 36 bytes for x86 64bits arch.
        if X86_64:
            return struct.pack("HL", size, id(bpf)+36)
        else:
            return struct.pack("HI", size, id(bpf)+20)

def get_bpf_pointer(tcpdump_lines):
    """Create a BPF Pointer for TCPDump filter"""
    if conf.use_pypy and six.PY2:
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
