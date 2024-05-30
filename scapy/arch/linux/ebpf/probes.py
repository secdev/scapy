# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - programs that retrieve process information
"""

import collections
import ctypes
import socket
import struct
import threading
import time

from scapy.layers.inet import IP

from .consts import BPF_MAP_LOOKUP_AND_DELETE_ELEM
from .structures import BpfAttrMapLookup
from .syscalls import bpf
from .utilities import bpf_prog_update_map_fd


class ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
        ("dst", ctypes.c_uint32),
        ("src", ctypes.c_uint32),
        ("proto", ctypes.c_uint8),
    ]


class Program_security_sk_classify_flow(object):
    """
  The following eBPF bytecode was generated with bcc from a C function named
    kprobe_security_sk_classify_flow, then retrieved using:
    bpf_handler = BPF(text=ebpf_program_c)

    start = lib.bpf_function_start(bpf_handler.module,
                                   b"kprobe_security_sk_classify_flow")
    size = lib.bpf_function_size(bpf_handler.module,
                                 b"kprobe_security_sk_classify_flow")
    bpf_prog = ct.string_at(start, size)

  The assembly was retieved with:
    dis = bpf_handler.disassemble_func("kprobe_security_sk_classify_flow")
    0: (79) r6 = *(u64*)(r1 +8)
    1: (b7) r1 = 0
    2: (63) *(u32*)(r10 -8) = r1
    3: (63) *(u32*)(r10 -12) = r1
    4: (63) *(u32*)(r10 -16) = r1
    5: (63) *(u32*)(r10 -20) = r1
    6: (63) *(u32*)(r10 -24) = r1
    7: (63) *(u32*)(r10 -28) = r1
    8: (63) *(u32*)(r10 -32) = r1
    9: (63) *(u32*)(r10 -36) = r1
    10: (63) *(u32*)(r10 -40) = r1
    11: (63) *(u32*)(r10 -44) = r1
    12: (63) *(u32*)(r10 -48) = r1
    13: (63) *(u32*)(r10 -52) = r1
    14: (63) *(u32*)(r10 -56) = r1
    15: (63) *(u32*)(r10 -60) = r1
    16: (63) *(u32*)(r10 -64) = r1
    17: (63) *(u32*)(r10 -68) = r1
    18: (63) *(u32*)(r10 -72) = r1
    19: (63) *(u32*)(r10 -76) = r1
    20: (63) *(u32*)(r10 -4) = r1
    21: (85) call bpf_get_current_pid_tgid#14
    22: (77) r0 >>= 32
    23: (63) *(u32*)(r10 -80) = r0
    24: (bf) r1 = r10
    25: (07) r1 += -76
    26: (b7) r2 = 64
    27: (85) call bpf_get_current_comm#16
    28: (bf) r3 = r6
    29: (07) r3 += 14
    30: (bf) r1 = r10
    31: (07) r1 += -4
    32: (b7) r2 = 1
    33: (85) call bpf_probe_read#4
    34: (bf) r3 = r6
    35: (07) r3 += 44
    36: (bf) r1 = r10
    37: (07) r1 += -12
    38: (b7) r2 = 4
    39: (85) call bpf_probe_read#4
    40: (07) r6 += 40
    41: (bf) r1 = r10
    42: (07) r1 += -8
    43: (b7) r2 = 4
    44: (bf) r3 = r6
    45: (85) call bpf_probe_read#4
    46: (18) r1 = <map at fd #0>
    48:      (64-bit upper word)
    48: (bf) r2 = r10
    49: (07) r2 += -80
    50: (b7) r3 = 0
    51: (85) call bpf_map_push_elem#87
    52: (b7) r0 = 0
    53: (95) exit

    This eBPF program fills a ProcessInformation structure and
    pushes it to an eBPF map queue.
    """

    prog_hex = ""
    prog_hex += "7916080000000000"
    prog_hex += "b701000000000000"
    prog_hex += "631af8ff00000000"
    prog_hex += "631af4ff00000000"
    prog_hex += "631af0ff00000000"
    prog_hex += "631aecff00000000"
    prog_hex += "631ae8ff00000000"
    prog_hex += "631ae4ff00000000"
    prog_hex += "631ae0ff00000000"
    prog_hex += "631adcff00000000"
    prog_hex += "631ad8ff00000000"
    prog_hex += "631ad4ff00000000"
    prog_hex += "631ad0ff00000000"
    prog_hex += "631accff00000000"
    prog_hex += "631ac8ff00000000"
    prog_hex += "631ac4ff00000000"
    prog_hex += "631ac0ff00000000"
    prog_hex += "631abcff00000000"
    prog_hex += "631ab8ff00000000"
    prog_hex += "631ab4ff00000000"
    prog_hex += "631afcff00000000"
    prog_hex += "850000000e000000"
    prog_hex += "7700000020000000"
    prog_hex += "630ab0ff00000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000b4ffffff"
    prog_hex += "b702000040000000"
    prog_hex += "8500000010000000"
    prog_hex += "bf63000000000000"
    prog_hex += "070300000e000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000fcffffff"
    prog_hex += "b702000001000000"
    prog_hex += "8500000004000000"
    prog_hex += "bf63000000000000"
    prog_hex += "070300002c000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000f4ffffff"
    prog_hex += "b702000004000000"
    prog_hex += "8500000004000000"
    prog_hex += "0706000028000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000f8ffffff"
    prog_hex += "b702000004000000"
    prog_hex += "bf63000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "1811000000000000"
    prog_hex += "0000000000000000"
    prog_hex += "bfa2000000000000"
    prog_hex += "07020000b0ffffff"
    prog_hex += "b703000000000000"
    prog_hex += "8500000057000000"
    prog_hex += "b700000000000000"
    prog_hex += "9500000000000000"

    map_instruction_count = 46
    original_instruction = bytes.fromhex("1811000000000000")

    @classmethod
    def update(cls, map_fd):
        new_instruction = bytes.fromhex("18110000")
        new_instruction += map_fd.to_bytes(1, "little")
        new_instruction += bytes.fromhex("0000000000000000000000")

        bpf_prog_raw = bytes.fromhex(cls.prog_hex)
        return bpf_prog_update_map_fd(bpf_prog_raw, cls.original_instruction,
                                      cls.map_instruction_count * 8, new_instruction)


class ProcessInformationPoller(threading.Thread):
    def __init__(self, map_fd):
        self.queue = collections.OrderedDict()

        self.bpf_attr_map_lookup = BpfAttrMapLookup()
        self.bpf_attr_map_lookup.map_fd = map_fd
        self.process_information = ProcessInformation()
        self.bpf_attr_map_lookup.value = ctypes.addressof(self.process_information)

        self.continue_polling = True
        threading.Thread.__init__(self)

    def run(self):
        while self.continue_polling:
            ret = bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                      ctypes.byref(self.bpf_attr_map_lookup),
                      ctypes.sizeof(self.bpf_attr_map_lookup))
            if ret >= 0:
                src = socket.inet_ntoa(struct.pack("I", self.process_information.src))
                dst = socket.inet_ntoa(struct.pack("I", self.process_information.dst))
                value = (self.process_information.pid, self.process_information.name)
                self.queue[f"{dst} {src} {self.process_information.proto}"] = value
                self.queue[f"{src} {dst} {self.process_information.proto}"] = value
            else:
                time.sleep(0.0001)

    def stop(self):
        self.continue_polling = False

    def lookup(self, packet):
        packet_key = f"{packet[IP].src} {packet[IP].dst} {packet[IP].proto}"
        if packet_key in self.queue:
            pid, name = self.queue[packet_key]
            packet.comment = f"{pid} {name}"
