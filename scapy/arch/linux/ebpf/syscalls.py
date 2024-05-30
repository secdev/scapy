# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - syscalls
"""

import ctypes
import platform

from scapy.arch.linux.ebpf.consts import SYS_bpf_id, SYS_perf_event_open_id
from scapy.error import warning


# ctypes definition
_syscall = ctypes.CDLL(None, use_errno=True).syscall
_syscall.restype = ctypes.c_int
_syscall.args = ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, \
    ctypes.c_uint  # type: ignore

_perf_event_open = ctypes.CDLL(None, use_errno=True).syscall
_perf_event_open.restype = ctypes.c_int
_perf_event_open.args = ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, \
    ctypes.c_uint, ctypes.c_uint


def bpf(cmd, attr, size):
    # type: (int, ctypes.c_void_p, int) -> int
    """
    Call the bpf syscall independently of the processor
    """
    processor = platform.processor()
    try:
        SYS_bpf = SYS_bpf_id[processor]
    except KeyError:
        warning("Unsupported processor (%s)!", processor)
        return -1

    return _syscall(SYS_bpf, cmd, attr, size)


def perf_event_open(attr, pid, cpu, group_fd, flags):
    # type: (ctypes.c_void_p, int, int, int, int) -> int
    """
    Call the bperf_event_open syscall independently of the processor
    """
    processor = platform.processor()
    try:
        SYS_perf_event_open = SYS_perf_event_open_id[processor]
    except KeyError:
        warning("Unsupported processor (%s)!" % processor)
        return -1
    return _perf_event_open(SYS_perf_event_open,
                            attr, pid, cpu, group_fd, flags)
