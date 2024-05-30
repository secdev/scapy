
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - utilities
"""


import ctypes
import fcntl
import os

from scapy.error import warning

from .consts import BPF_MAP_TYPE_QUEUE, BPF_MAP_CREATE, BPF_PROG_TYPE_KPROBE, \
    BPF_PROG_LOAD, PERF_TYPE_TRACEPOINT, PERF_FLAG_FD_CLOEXEC, \
    PERF_EVENT_IOC_SET_BPF, PERF_EVENT_IOC_ENABLE
from .structures import BpfAttrMapCreate, BpfAttrProgLoad, PerfEventAttr
from .syscalls import bpf, perf_event_open


def set_kprobe(symbol):
    # type: (str) -> int
    """
    Set a kprobe on a symbol and return its ID
    :param symbol: symbol of a Linux kernel function
    """
    kprobe_name = "p_scapy_%s" % symbol
    definition = "p:%s %s" % (kprobe_name, symbol)

    try:
        fd = open("/sys/kernel/debug/tracing/kprobe_events", "w")
        fd.write(definition)
        fd.close()
    except FileNotFoundError:
        warning("Could not open /sys/kernel/debug/tracing/kprobe_events")
        kprobe_id = 0

    try:
        fd = open("/sys/kernel/debug/tracing/events/kprobes/%s/id" % kprobe_name)  # noqa: E501
        kprobe_id = fd.read()
        fd.close()
    except FileNotFoundError:
        warning("Could not retrieve the kprobe ID")
        kprobe_id = 0

    return int(kprobe_id)


def bpf_map_queue_create(value_size, max_entries, map_name):
    # type: (int, int, bytes) -> int
    """
    Create a BPF map of type BPF_MAP_TYPE_QUEUE
    :param value_size: size of the value stored in the queue
    :param max_entries: maximum number of entries in the queue
    :param map_name: name of the eBPF map
    :return: file descriptor of the eBPF map
    """

    bpf_attr_map_create = BpfAttrMapCreate()
    bpf_attr_map_create.map_type = BPF_MAP_TYPE_QUEUE
    bpf_attr_map_create.key_size = 0  # Always 0 for a queue
    bpf_attr_map_create.value_size = value_size
    bpf_attr_map_create.max_entries = max_entries
    bpf_attr_map_create.map_name = map_name

    map_fd = bpf(BPF_MAP_CREATE, ctypes.byref(bpf_attr_map_create),
                 ctypes.sizeof(bpf_attr_map_create))
    if map_fd < 0:
        if ctypes.get_errno() != 0:
            warning("bpf() failed with:", ctypes.get_errno(),
                    os.strerror(ctypes.get_errno()))
    return map_fd


def bpf_prog_raw_load(bpf_prog_raw):
    # type: (bytes) -> int
    """
    Load a raw eBPF program
    :param bpf_prog_raw: raw eBPF program
    """
    insns = ctypes.create_string_buffer(bpf_prog_raw, len(bpf_prog_raw))

    bpf_attr_prog_load = BpfAttrProgLoad()
    bpf_attr_prog_load.prog_type = BPF_PROG_TYPE_KPROBE
    bpf_attr_prog_load.insns = ctypes.cast(ctypes.byref(insns),
                                           ctypes.POINTER(ctypes.c_uint64))
    bpf_attr_prog_load.insn_cnt = int(len(insns) / 8)
    license = ctypes.create_string_buffer(b"GPL")
    bpf_attr_prog_load.license = ctypes.cast(ctypes.byref(license),
                                             ctypes.POINTER(ctypes.c_uint64))
    # Note: a smaller buffer triggers an ENOSPC error
    log_buf = ctypes.create_string_buffer(2**14)
    bpf_attr_prog_load.log_buf = ctypes.cast(ctypes.byref(log_buf),
                                             ctypes.POINTER(ctypes.c_uint64))
    bpf_attr_prog_load.log_size = ctypes.sizeof(log_buf)
    bpf_attr_prog_load.log_level = 1
    bpf_attr_prog_load.prog_name = b"Scapy_kprobe"

    bpf_fd = bpf(BPF_PROG_LOAD, ctypes.byref(bpf_attr_prog_load),
                 ctypes.sizeof(bpf_attr_prog_load))
    if bpf_fd < 0:
        warning("bpf() failed with: ", ctypes.get_errno(),
                os.strerror(ctypes.get_errno()))
        if ctypes.get_errno() in [13, 22]:
            warning("Verifier log:\n", log_buf.value.decode("ascii"))
    return bpf_fd


def bpf_assign_kprobe(kprobe_id, bpf_fd):
    # type: (int, int) -> bool
    """
    Assign a BPF program to a kprobe, and return True if successful
    :param kprobe_id: ID of the kprobe
    :param bpf_fd: file descriptor of the BPF program
    """
    perf_event_attr = PerfEventAttr()
    perf_event_attr.type = PERF_TYPE_TRACEPOINT
    perf_event_attr.sample_period = 1
    perf_event_attr.wakeup_events = 1
    perf_event_attr.config = kprobe_id
    perf_event_attr.size = ctypes.sizeof(perf_event_attr)

    perf_fd = perf_event_open(ctypes.byref(perf_event_attr), -1, 0, -1,
                              PERF_FLAG_FD_CLOEXEC)
    if perf_fd < 0:
        warning("perf_event_open() failed with: ", ctypes.get_errno(),
                os.strerror(ctypes.get_errno()))
        return False

    ret = fcntl.ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, bpf_fd)
    if ret < 0:
        warning("ioctl(PERF_EVENT_IOC_SET_BPF) failed")
        return False

    ret = fcntl.ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0)
    if ret < 0:
        warning("ioctl(PERF_EVENT_IOC_ENABLE) failed")
        return False

    return True
