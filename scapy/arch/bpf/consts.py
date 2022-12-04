# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy BSD native support - constants
"""

import ctypes

from scapy.libs.structures import bpf_program
from scapy.data import MTU

# Type hints
from typing import (
    Any,
    Callable,
)

SIOCGIFFLAGS = 0xc0206911
BPF_BUFFER_LENGTH = MTU

# From sys/ioccom.h

IOCPARM_MASK = 0x1fff
IOC_VOID = 0x20000000
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT

_th = lambda x: x if isinstance(x, int) else ctypes.sizeof(x)  # type: Callable[[Any], int]  # noqa: E501


def _IOC(inout, group, num, len):
    # type: (int, str, int, Any) -> int
    return (inout |
            ((_th(len) & IOCPARM_MASK) << 16) |
            (ord(group) << 8) | (num))


_IO = lambda g, n: _IOC(IOC_VOID, g, n, 0)  # type: Callable[[str, int], int]
_IOR = lambda g, n, t: _IOC(IOC_OUT, g, n, t)  # type: Callable[[str, int, Any], int]
_IOW = lambda g, n, t: _IOC(IOC_IN, g, n, t)  # type: Callable[[str, int, Any], int]
_IOWR = lambda g, n, t: _IOC(IOC_INOUT, g, n, t)  # type: Callable[[str, int, Any], int]

# Length of some structures
_bpf_stat = 8
_ifreq = 32

# From net/bpf.h
BIOCGBLEN = _IOR('B', 102, ctypes.c_uint)
BIOCSBLEN = _IOWR('B', 102, ctypes.c_uint)
BIOCSETF = _IOW('B', 103, bpf_program)
BIOCPROMISC = _IO('B', 105)
BIOCGDLT = _IOR('B', 106, ctypes.c_uint)
BIOCSETIF = _IOW('B', 108, 32)
BIOCGSTATS = _IOR('B', 111, _bpf_stat)
BIOCIMMEDIATE = _IOW('B', 112, ctypes.c_uint)
BIOCSHDRCMPLT = _IOW('B', 117, ctypes.c_uint)
BIOCSDLT = _IOW('B', 120, ctypes.c_uint)
BIOCSTSTAMP = _IOW('B', 132, ctypes.c_uint)

BPF_T_NANOTIME = 0x0001
