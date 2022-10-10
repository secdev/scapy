# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Slow Protocol
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField
from scapy.layers.l2 import Ether
from scapy.data import ETHER_TYPES


ETHER_TYPES[0x8809] = 'SlowProtocol'
SLOW_SUB_TYPES = {
    'Unused': 0,
    'LACP': 1,
    'Marker Protocol': 2,
    'OAM': 3,
    'OSSP': 10,
}


class SlowProtocol(Packet):
    name = "SlowProtocol"
    fields_desc = [ByteEnumField("subtype", 0, SLOW_SUB_TYPES)]


bind_layers(Ether, SlowProtocol, type=0x8809, dst='01:80:c2:00:00:02')
