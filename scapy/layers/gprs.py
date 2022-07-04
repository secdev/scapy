# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
GPRS (General Packet Radio Service) for mobile data communication.
"""

from scapy.fields import StrStopField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP


class GPRS(Packet):
    name = "GPRSdummy"
    fields_desc = [
        StrStopField("dummy", "", b"\x65\x00\x00", 1)
    ]


bind_layers(GPRS, IP,)
