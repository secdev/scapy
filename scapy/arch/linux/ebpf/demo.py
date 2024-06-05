# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - demo
"""

from scapy.all import *

from .process_information import KprobeProcessInformation


@conf.commands.register
def sniff(*args, **kwargs):
    # type: (*Any, **Any) -> PacketList

    kprobe = None
    if "process_information" in kwargs:
        del kwargs["process_information"]

        if LINUX:
            try:
                kprobe = KprobeProcessInformation()
                kprobe.start()

                user_prn = lambda p: None
                if "prn" in kwargs:
                    user_prn = kwargs["prn"]

                def _prn(packet):
                    kprobe.lookup(packet)
                    user_prn(packet)

                kwargs["prn"] = _prn
            except Scapy_Exception:
                warning("Could not instanciate KprobeProcessInformation() !")
        else:
            warning("'process_information' is only support on Linux!")

    sniffer = AsyncSniffer()
    sniffer._run(*args, **kwargs)
    if kprobe:
        kprobe.stop()
        kprobe.join()
    return cast(PacketList, sniffer.results)
