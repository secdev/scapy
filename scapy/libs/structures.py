# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# This program is published under a GPLv2 license

"""
Commonly used structures shared across Scapy
"""

import ctypes


class bpf_insn(ctypes.Structure):
    """"The BPF instruction data structure"""
    _fields_ = [("code", ctypes.c_ushort),
                ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_int)]


class bpf_program(ctypes.Structure):
    """"Structure for BIOCSETF"""
    _fields_ = [('bf_len', ctypes.c_int),
                ('bf_insns', ctypes.POINTER(bpf_insn))]
