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

# scapy.contrib.description = MPLS
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, Padding
from scapy.fields import BitField,ByteField
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.compat import orb

class MPLS(Packet):
   name = "MPLS"
   fields_desc =  [ BitField("label", 3, 20),
                    BitField("cos", 0, 3),
                    BitField("s", 1, 1),
                    ByteField("ttl", 0)  ]

   def guess_payload_class(self, payload):
       if len(payload) >= 1:
           if not self.s:
              return MPLS
           ip_version = (orb(payload[0]) >> 4) & 0xF
           if ip_version == 4:
               return IP
           elif ip_version == 6:
               return IPv6
       return Padding

bind_layers(Ether, MPLS, type=0x8847)
bind_layers(GRE, MPLS, proto=0x8847)
bind_layers(MPLS, MPLS, s=0)
