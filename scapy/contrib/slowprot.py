# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

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
