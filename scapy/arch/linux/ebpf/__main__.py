# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - programs that retrieve process information
"""


from scapy.all import sniff

from scapy.arch.linux.ebpf.process_information import KprobeProcessInformation


if __name__ == "__main__":
    print("Scapy + eBPF = <3")

    k = KprobeProcessInformation()
    k.start()

    def get_process_information(packet):
        k.lookup(packet)

    packets = sniff(count=10, filter="ip and not port 22",
                    prn=get_process_information)
    k.stop()
    k.join()
    for p in packets:
        print(p.comment, p.summary())
