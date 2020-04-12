# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Parag Bhide
# This program is published under GPLv2 license

"""
BFD - Bidirectional Forwarding Detection - RFC 5880, 5881
"""

# scapy.contrib.description = BFD
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import BitField, FlagsField, XByteField
from scapy.layers.inet import UDP


class BFD(Packet):
    name = "BFD"
    fields_desc = [
        BitField("version", 1, 3),
        BitField("diag", 0, 5),
        BitField("sta", 3, 2),
        FlagsField("flags", 0x00, 6, ['P', 'F', 'C', 'A', 'D', 'M']),
        XByteField("detect_mult", 0x03),
        XByteField("len", 24),
        BitField("my_discriminator", 0x11111111, 32),
        BitField("your_discriminator", 0x22222222, 32),
        BitField("min_tx_interval", 1000000000, 32),
        BitField("min_rx_interval", 1000000000, 32),
        BitField("echo_rx_interval", 1000000000, 32)]

    def mysummary(self):
        return self.sprintf(
            "BFD (my_disc=%BFD.my_discriminator%,"
            "your_disc=%BFD.my_discriminator%)"
        )


bind_bottom_up(UDP, BFD, dport=3784)
bind_bottom_up(UDP, BFD, sport=3784)
bind_layers(UDP, BFD, sport=3784, dport=3784)
