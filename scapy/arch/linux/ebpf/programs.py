# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - eBPF programs that retrieve process information
"""

import collections
import ctypes
import socket
import struct
import threading
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


from .consts import BPF_MAP_LOOKUP_AND_DELETE_ELEM
from .structures import BpfAttrMapLookup
from .syscalls import bpf
from .utilities import bpf_prog_update_map_fd


class ProcessInformationStructure(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
        ("is_ipv6", ctypes.c_uint8),
        ("dst", ctypes.c_uint32 * 4),
        ("src", ctypes.c_uint32 * 4),
        ("proto", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("code", ctypes.c_uint8),
        ("dport", ctypes.c_uint16),
        ("sport", ctypes.c_uint16),
    ]

    def unpack(self):
        """
        Convert internal values
        """

        sport = struct.unpack("!H", struct.pack("H", self.sport))[0]
        dport = struct.unpack("!H", struct.pack("H", self.dport))[0]

        if self.is_ipv6 == 0:
            src = socket.inet_ntoa(struct.pack("I", self.src[0]))
            dst = socket.inet_ntoa(struct.pack("I", self.dst[0]))
        elif self.is_ipv6 == 1:
            src = socket.inet_ntop(socket.AF_INET6,
                                   struct.pack("IIII", *self.src))
            dst = socket.inet_ntop(socket.AF_INET6,
                                   struct.pack("IIII", *self.dst))
        else:
            src = dst = None

        return src, dst, sport, dport

    def keys(self):
        """
        Generate the lookup keys for the ProcessInformationStructure
        """
        if self.proto != socket.IPPROTO_TCP and self.proto != socket.IPPROTO_UDP:
            if self.proto != socket.IPPROTO_ICMP:
                return []

        src, dst, sport, dport = self.unpack()

        if self.proto == socket.IPPROTO_ICMP:
            keys = [f"{dst} {src} {self.proto} {self.type} {self.code}"]
            keys += [f"{src} {dst} {self.proto} {self.type} {self.code}"]
        else:
            keys = [f"{dst} {src} {self.proto} {dport} {sport}"]
            keys += [f"{src} {dst} {self.proto} {sport} {dport}"]

        return keys

    @classmethod
    def key_from_packet(cls, packet):
        """
        Generate a lookup key from a packet
        """
        if IPv6 in packet:
            ip_key = IPv6
            proto = packet[ip_key].nh
        elif IP in packet:
            ip_key = IP
            proto = packet[ip_key].proto
        else:
            return ""

        if TCP in packet or UDP in packet:
            key = f"{packet[ip_key].src} {packet[ip_key].dst} {proto} "
            key += f"{packet[ip_key].sport} {packet[ip_key].dport}"
            return key
        elif ICMP in packet:
            key = f"0.0.0.0 {packet[ip_key].dst} {proto} "
            key += f"{packet[ICMP].type} {packet[ICMP].code}"
            return key

        return ""


class Program_security_sk_classify_flow(object):
    """
    The following eBPF bytecode was generated with bcc
    using the KprobeProcessInformationBCC object

    This eBPF program fills a ProcessInformationStructure and
    pushes it to an eBPF map queue.
    """

    prog_hex = ""
    prog_hex += "7917000000000000"
    prog_hex += "7916080000000000"
    prog_hex += "b708000000000000"
    prog_hex += "638af8ff00000000"
    prog_hex += "638af4ff00000000"
    prog_hex += "638af0ff00000000"
    prog_hex += "638aecff00000000"
    prog_hex += "638ae8ff00000000"
    prog_hex += "638ae4ff00000000"
    prog_hex += "638ae0ff00000000"
    prog_hex += "638adcff00000000"
    prog_hex += "638ad8ff00000000"
    prog_hex += "638ad4ff00000000"
    prog_hex += "638ad0ff00000000"
    prog_hex += "638accff00000000"
    prog_hex += "638ac8ff00000000"
    prog_hex += "638ac4ff00000000"
    prog_hex += "638ac0ff00000000"
    prog_hex += "638abcff00000000"
    prog_hex += "638ab8ff00000000"
    prog_hex += "638ab4ff00000000"
    prog_hex += "638ab0ff00000000"
    prog_hex += "638aacff00000000"
    prog_hex += "638aa8ff00000000"
    prog_hex += "638aa4ff00000000"
    prog_hex += "638aa0ff00000000"
    prog_hex += "638a9cff00000000"
    prog_hex += "638a98ff00000000"
    prog_hex += "638a94ff00000000"
    prog_hex += "638afcff00000000"
    prog_hex += "850000000e000000"
    prog_hex += "7700000020000000"
    prog_hex += "630a90ff00000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "0701000094ffffff"
    prog_hex += "b702000040000000"
    prog_hex += "8500000010000000"
    prog_hex += "bf63000000000000"
    prog_hex += "070300000e000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000f8ffffff"
    prog_hex += "b709000001000000"
    prog_hex += "b702000001000000"
    prog_hex += "8500000004000000"
    prog_hex += "0707000010000000"
    prog_hex += "6b8a8cff00000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "070100008cffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "69a18cff00000000"
    prog_hex += "150101000a000000"
    prog_hex += "b709000000000000"
    prog_hex += "739ad4ff00000000"
    prog_hex += "6b8a8cff00000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "070100008cffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "69a18cff00000000"
    prog_hex += "5501150002000000"
    prog_hex += "bf63000000000000"
    prog_hex += "070300002c000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000d8ffffff"
    prog_hex += "b702000004000000"
    prog_hex += "8500000004000000"
    prog_hex += "bf63000000000000"
    prog_hex += "0703000028000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000e8ffffff"
    prog_hex += "b702000004000000"
    prog_hex += "8500000004000000"
    prog_hex += "bf67000000000000"
    prog_hex += "0707000030000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000f9ffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "0706000031000000"
    prog_hex += "05001d0000000000"
    prog_hex += "b701000000000000"
    prog_hex += "6b1a8cff00000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "070100008cffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "69a18cff00000000"
    prog_hex += "55012a000a000000"
    prog_hex += "bf63000000000000"
    prog_hex += "0703000028000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000d8ffffff"
    prog_hex += "b702000010000000"
    prog_hex += "8500000004000000"
    prog_hex += "bf63000000000000"
    prog_hex += "0703000038000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000e8ffffff"
    prog_hex += "b702000010000000"
    prog_hex += "8500000004000000"
    prog_hex += "bf67000000000000"
    prog_hex += "070700004c000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000f9ffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "070600004d000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000faffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf63000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000fcffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "0707000002000000"
    prog_hex += "bfa1000000000000"
    prog_hex += "07010000feffffff"
    prog_hex += "b702000002000000"
    prog_hex += "bf73000000000000"
    prog_hex += "8500000004000000"
    prog_hex += "1811000004000000"
    prog_hex += "0000000000000000"
    prog_hex += "bfa2000000000000"
    prog_hex += "0702000090ffffff"
    prog_hex += "b703000000000000"
    prog_hex += "8500000057000000"
    prog_hex += "b700000000000000"
    prog_hex += "9500000000000000"

    map_instruction_count = 129
    original_instruction = bytes.fromhex("18110000040000000000000000000000")

    @classmethod
    def build_instruction(cls, map_fd):
        new_instruction = bytes.fromhex("18110000")
        new_instruction += map_fd.to_bytes(1, "little")
        new_instruction += bytes.fromhex("0000000000000000000000")
        return new_instruction

    @classmethod
    def update(cls, map_fd):
        return bpf_prog_update_map_fd(bytes.fromhex(cls.prog_hex),
                                      cls.original_instruction,
                                      cls.map_instruction_count * 8,
                                      cls.build_instruction(map_fd))


class ProcessInformationPoller(threading.Thread):
    def __init__(self, map_fd):
        self.queue = collections.OrderedDict()

        self.bpf_attr_map_lookup = BpfAttrMapLookup()
        self.bpf_attr_map_lookup.map_fd = map_fd
        self.process_information = ProcessInformationStructure()
        self.bpf_attr_map_lookup.value = ctypes.addressof(self.process_information)

        self.continue_polling = True
        threading.Thread.__init__(self)

    def run(self):
        while self.continue_polling:
            ret = bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                      ctypes.byref(self.bpf_attr_map_lookup),
                      ctypes.sizeof(self.bpf_attr_map_lookup))
            if ret >= 0:
                value = (self.process_information.pid,
                         self.process_information.name)
                for key in self.process_information.keys():
                    self.queue[key] = value
            else:
                time.sleep(0.0001)

    def stop(self):
        self.continue_polling = False

    def lookup(self, packet, retries=3):
        if TCP not in packet and UDP not in packet and ICMP not in packet:
            return
        while retries:
            packet_key = ProcessInformationStructure.key_from_packet(packet)
            if packet_key in self.queue:
                pid, name = self.queue.pop(packet_key)
                packet.comment = f"{pid} {name}"
                return
            retries -= 1
            time.sleep(0.00001)
