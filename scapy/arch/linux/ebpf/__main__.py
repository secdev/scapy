# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - programs that retrieve process information
"""

from .demo import sniff

if __name__ == "__main__":
    print("Scapy + eBPF = <3\n")

    packets = sniff(count=10, filter="ip and not port 22",
                    process_information=True)

    for p in packets:
        print(p.comment, p.summary())
