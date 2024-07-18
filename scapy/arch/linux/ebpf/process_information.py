# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - kprobes
"""

import ctypes
import os

from scapy.error import Scapy_Exception, warning

from scapy.arch.linux.ebpf.utilities import set_kprobe, bpf_map_queue_create, \
    bpf_prog_raw_load, bpf_assign_kprobe, bpf_prog_update_map_fd
from scapy.arch.linux.ebpf.programs import ProcessInformationStructure, \
    Program_security_sk_classify_flow, ProcessInformationPoller


class KprobeProcessInformation(ProcessInformationPoller):
    map_fd = bpf_fd = perf_fd = -42

    def __init__(self):
        # type: () -> None
        # Step 1 - Create the eBPF map queue
        self.map_fd = bpf_map_queue_create(
            ctypes.sizeof(ProcessInformationStructure), 256, b"Scapy_procinfo")
        if self.map_fd < 0:
            raise Scapy_Exception("! Cannot create the eBPF map")

        # Step 2 - Patch the eBPF program with the eBPF map FD
        bpf_prog_raw = self.get_program(self.map_fd)
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

    def get_program(self, map_fd):
        # type: (int) -> bytes
        """
        Retrieve the eBPF program as bytes
        """
        return Program_security_sk_classify_flow.update(map_fd)

    def __del__(self):
        # type: () -> None
        if self.map_fd >= 0:
            os.close(self.map_fd)
        if self.bpf_fd >= 0:
            os.close(self.bpf_fd)
        if self.perf_fd >= 0:
            os.close(self.perf_fd)


class KprobeProcessInformationBCC(KprobeProcessInformation):
    """
    Object used to prepare the static eBPF propgram used by Scapy.
    It uses the bcc module and should only be used during development.
    """

    def get_program(self, map_fd):
        # type: (int) -> bytes
        """
        This method is used to prepare the static eBPF program used by Scapy.

        It does the following:
        1. it compiles the C program stored in C/kprobe_security_sk_classify_flow.c
        2. it gets the eBPF bytecode from memory
        3. it finds the instruction that stores the map FD,
           assuming a single lddw instruction in thr whole program
        4. it updates the eBPF program with the map FD from Scapy
        """
        import time

        from bcc import BPF
        from bcc.libbcc import lib

        # Compile the eBPF program
        bpf_handler = BPF(src_file=b"C/kprobe_security_sk_classify_flow.c")

        # Get the eBPF bytecode from memory
        start = lib.bpf_function_start(bpf_handler.module,
                                       b"kprobe_security_sk_classify_flow")
        size = lib.bpf_function_size(bpf_handler.module,
                                     b"kprobe_security_sk_classify_flow")
        bpf_program = ctypes.string_at(start, size)

        # Print the disassembled eBPF program
        dis = bpf_handler.disassemble_func("kprobe_security_sk_classify_flow")
        print(dis)

        # Find the instruction that stores the map FD
        bcc_map_fd = lib.bpf_table_fd(bpf_handler.module, b"flowi_map")
        original_instruction = Program_security_sk_classify_flow.build_instruction(bcc_map_fd)  # noqa: E501
        try:
            index = bpf_program.index(original_instruction)
            map_instruction_count = int(index / 8)
        except ValueError:
            warning("Could not find the original instruction!")
            bpf_program = b""
            map_instruction_count = -1

        # Update the eBPF program with the map FD from Scapy
        new_instruction = Program_security_sk_classify_flow.build_instruction(map_fd)
        bpf_program = bpf_prog_update_map_fd(bpf_program,
                                             original_instruction,
                                             map_instruction_count * 8,
                                             new_instruction)

        # Unload everything created by BCC and wait a bit
        del bpf_handler
        time.sleep(0.1)

        # Print the values that can be used by the static eBPF program
        # see the Program_security_sk_classify_flow object
        print('prog_hex = ""')
        for i in range(0, len(bpf_program), 8):
            data = bpf_program[i:i + 8].hex()
            print(f'prog_hex += "{data}"')
        print(f"map_instruction_count = {map_instruction_count}")
        print(f'original_instruction = bytes.fromhex("{new_instruction.hex()}")')

        return bpf_program
