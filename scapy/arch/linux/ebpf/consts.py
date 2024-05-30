# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - constants
"""

SYS_bpf_id = {}
SYS_bpf_id["x86_64"] = 321
SYS_bpf_id["aarch64"] = 280

SYS_perf_event_open_id = {}
SYS_perf_event_open_id["x86_64"] = 298
SYS_perf_event_open_id["aarch64"] = 241

# from enum bpf_cmd
BPF_MAP_CREATE = 0
BPF_PROG_LOAD = 5
BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21

# from enum bpf_map_type
BPF_PROG_TYPE_KPROBE = 2
BPF_MAP_TYPE_QUEUE = 22

# from enum perf_type_id
PERF_TYPE_TRACEPOINT = 2

# from perf_event.h
PERF_FLAG_FD_CLOEXEC = 1 << 3
PERF_EVENT_IOC_SET_BPF = 0x40042408  # TODO: _IOW('$', 8, __u32)
PERF_EVENT_IOC_ENABLE = 0x2400  # TODO: _IO ('$', 0)
