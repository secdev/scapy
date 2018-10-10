# Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - constants
"""

from ctypes import sizeof

from scapy.arch.common import bpf_program
from scapy.data import MTU


SIOCGIFFLAGS = 0xc0206911
BPF_BUFFER_LENGTH = MTU

# From net/bpf.h
BIOCIMMEDIATE = 0x80044270
BIOCGSTATS = 0x4008426f
BIOCPROMISC = 0x20004269
BIOCSETIF = 0x8020426c
BIOCSBLEN = 0xc0044266
BIOCGBLEN = 0x40044266
BIOCSETF = 0x80004267 | ((sizeof(bpf_program) & 0x1fff) << 16)
BIOCSDLT = 0x80044278
BIOCSHDRCMPLT = 0x80044275
BIOCGDLT = 0x4004426a
DLT_IEEE802_11_RADIO = 127
