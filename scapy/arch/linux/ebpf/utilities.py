
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy eBPF native support - utilities
"""

from scapy.error import warning


def set_kprobe(symbol):
    # type: (str) -> int
    """
    Set a kprobe on a symbol and return its ID
    """
    kprobe_name = "p_scapy_%s" % symbol
    definition = "p:%s %s" % (kprobe_name, symbol)

    try:
        fd = open("/sys/kernel/debug/tracing/kprobe_events", "w")
        fd.write(definition)
        fd.close()
    except FileNotFoundError:
        warning("Could not open /sys/kernel/debug/tracing/kprobe_events")
        kprobe_id = 0

    try:
        fd = open("/sys/kernel/debug/tracing/events/kprobes/%s/id" % kprobe_name)  # noqa: E501
        kprobe_id = fd.read()
        fd.close()
    except FileNotFoundError:
        warning("Could not retrieve the kprobe ID")
        kprobe_id = 0

    return int(kprobe_id)
