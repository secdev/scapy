# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# Copyright (C) 2019 Brandon Ewing <brandon.ewing@warningg.com>
#               2019 Guillaume Valadon <guillaume.valadon@netatmo.com>

# scapy.contrib.description = Arista Metawatch
# scapy.contrib.status = loads

from scapy.layers.l2 import Ether
from scapy.fields import (
    ByteField,
    ShortField,
    FlagsField,
    SecondsIntField,
    TrailerField,
    UTCTimeField,
)


class MetawatchEther(Ether):
    name = "Ethernet (with MetaWatch trailer)"
    match_subclass = True
    fields_desc = Ether.fields_desc + [
        TrailerField(ByteField("metamako_portid", None)),
        TrailerField(ShortField("metamako_devid", None)),
        TrailerField(FlagsField("metamako_flags", 0x0, 8, "VX______")),
        TrailerField(SecondsIntField("metamako_nanos", 0, use_nano=True)),
        TrailerField(UTCTimeField("metamako_seconds", 0)),
        # TODO: Add TLV support
    ]
