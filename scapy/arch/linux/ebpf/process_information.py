# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - kprobes
"""

import ctypes
import os

from scapy.error import Scapy_Exception

from scapy.arch.linux.ebpf.utilities import set_kprobe, bpf_map_queue_create, \
    bpf_prog_raw_load, bpf_assign_kprobe
from scapy.arch.linux.ebpf.programs import ProcessInformationStructure, \
    Program_security_sk_classify_flow, ProcessInformationPoller


class KprobeProcessInformation(ProcessInformationPoller):

    def __init__(self):
        # Step 1 - Create the eBPF map queue
        self.map_fd = bpf_map_queue_create(
            ctypes.sizeof(ProcessInformationStructure), 256, b"Scapy_procinfo")
        if self.map_fd < 0:
            raise Scapy_Exception("! Cannot create the eBPF map")

        # Step 2 - Patch the eBPF program with the eBPF map FD
        bpf_prog_raw = Program_security_sk_classify_flow.update(self.map_fd)
        if bpf_prog_raw == b"":
            raise Scapy_Exception("! Cannot replace the map FD related instruction")

        # Step 3 - Load the eBPF program
        self.bpf_fd = bpf_prog_raw_load(bpf_prog_raw)
        if self.bpf_fd < 0:
            raise Scapy_Exception("! Cannot load the eBPF program")

        # Step 4 - Set a kprobe for security_sk_classify_flow
        kprobe_id = set_kprobe("security_sk_classify_flow")
        if kprobe_id is None:
            raise Scapy_Exception("! Cannot set the kprobe")

        # Step 5 - Assign the eBPF program to the kprobe
        self.perf_fd = bpf_assign_kprobe(kprobe_id, self.bpf_fd)
        if not self.perf_fd:
            raise Scapy_Exception("! Cannot assign the eBPF program to the kprobe")

        # Step 6 - Get data from the eBPF map & Scapy
        ProcessInformationPoller.__init__(self, self.map_fd)

    def __del__(self):
        if self.map_fd:
            os.close(self.map_fd)
        if self.bpf_fd:
            os.close(self.bpf_fd)
        if self.perf_fd:
            os.close(self.perf_fd)
