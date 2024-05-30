# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - programs that retrieve process information
"""

import ctypes
import sys

from scapy.all import sniff
from scapy.arch.linux.ebpf.utilities import set_kprobe, bpf_map_queue_create, \
    bpf_prog_raw_load, bpf_assign_kprobe
from scapy.arch.linux.ebpf.probes import ProcessInformation, \
    Program_security_sk_classify_flow, ProcessInformationPoller

if __name__ == "__main__":
    print("Scapy + eBPF = <3")

    # Step 1 - Create the eBPF map queue
    map_fd = bpf_map_queue_create(ctypes.sizeof(ProcessInformation), 256,
                                  b"Scapy_procinfo")
    if map_fd < 0:
        print("! Cannot create the eBPF map")
        sys.exit()

    # Step 2 - Patch the eBPF program with the eBPF map FD
    bpf_prog_raw = Program_security_sk_classify_flow.update(map_fd)
    if bpf_prog_raw == b"":
        print("! Cannot replace the map FD related instruction")
        sys.exit()

    # Step 3 - Load the eBPF program
    bpf_fd = bpf_prog_raw_load(bpf_prog_raw)
    if bpf_fd < 0:
        print("! Cannot load the eBPF program")
        sys.exit()

    # Step 4 - Set a kprobe for security_sk_classify_flow
    kprobe_id = set_kprobe("security_sk_classify_flow")
    if kprobe_id is None:
        print("! Cannot set the kprobe")
        sys.exit()

    # Step 5 - Assign the eBPF program to the kprobe
    ret = bpf_assign_kprobe(kprobe_id, bpf_fd)
    if not ret:
        print("! Cannot assign the eBPF program to the kprobe")
        sys.exit()

    # Step 6 - Get data from the eBPF map & Scapy
    poller = ProcessInformationPoller(map_fd)
    poller.start()

    def get_process_information(packet):
        poller.lookup(packet)

    packets = sniff(count=10, filter="ip and not port 22",
                    prn=get_process_information)
    poller.stop()
    poller.join()
    for p in packets:
        print(p.comment, p.summary())
