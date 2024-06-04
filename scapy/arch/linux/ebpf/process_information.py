# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - kprobes
"""

import ctypes

from scapy.error import Scapy_Exception

from scapy.arch.linux.ebpf.utilities import set_kprobe, bpf_map_queue_create, \
    bpf_prog_raw_load, bpf_assign_kprobe
from scapy.arch.linux.ebpf.programs import ProcessInformationStructure, \
    Program_security_sk_classify_flow, ProcessInformationPoller


class KprobeProcessInformation(ProcessInformationPoller):

    def __init__(self):
        # Step 1 - Create the eBPF map queue
        map_fd = bpf_map_queue_create(ctypes.sizeof(ProcessInformationStructure), 256,
                                      b"Scapy_procinfo")
        if map_fd < 0:
            raise Scapy_Exception("! Cannot create the eBPF map")

        # Step 2 - Patch the eBPF program with the eBPF map FD
        bpf_prog_raw = Program_security_sk_classify_flow.update(map_fd)
        if bpf_prog_raw == b"":
            raise Scapy_Exception("! Cannot replace the map FD related instruction")

        # Step 3 - Load the eBPF program
        bpf_fd = bpf_prog_raw_load(bpf_prog_raw)
        if bpf_fd < 0:
            raise Scapy_Exception("! Cannot load the eBPF program")

        # Step 4 - Set a kprobe for security_sk_classify_flow
        kprobe_id = set_kprobe("security_sk_classify_flow")
        if kprobe_id is None:
            raise Scapy_Exception("! Cannot set the kprobe")

        # Step 5 - Assign the eBPF program to the kprobe
        ret = bpf_assign_kprobe(kprobe_id, bpf_fd)
        if not ret:
            raise Scapy_Exception("! Cannot assign the eBPF program to the kprobe")

        # Step 6 - Get data from the eBPF map & Scapy
        ProcessInformationPoller.__init__(self, map_fd)
