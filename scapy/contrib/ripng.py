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

# scapy.contrib.description = Routing Information Protocol next gen (RIPng)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IP6Field, ShortField
from scapy.layers.inet import UDP


class RIPng(Packet):
    name = "RIPng header"
    fields_desc = [
        ByteEnumField("cmd", 1, {1: "req", 2: "resp"}),
        ByteField("ver", 1),
        ShortField("null", 0)
    ]


class RIPngEntry(Packet):
    name = "RIPng entry"
    fields_desc = [
        IP6Field("prefix_or_nh", "::"),
        ShortField("routetag", 0),
        ByteField("prefixlen", 0),
        ByteEnumField("metric", 1, {16: "Unreach",
                                    255: "next-hop entry"})
    ]


bind_layers(UDP, RIPng, sport=521, dport=521)
bind_layers(RIPng, RIPngEntry)
bind_layers(RIPngEntry, RIPngEntry)
