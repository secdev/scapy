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

# scapy.contrib.description = EtherIP
# scapy.contrib.status = loads

from scapy.fields import BitField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


class EtherIP(Packet):
    name = "EtherIP / RFC 3378"
    fields_desc = [BitField("version", 3, 4),
                   BitField("reserved", 0, 12)]


bind_layers(IP, EtherIP, frag=0, proto=0x61)
bind_layers(EtherIP, Ether)
