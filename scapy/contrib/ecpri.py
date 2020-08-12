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

# scapy.contrib.description = enhanced Common Public Radio Interface (eCPRI)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, Padding
from scapy.fields import BitField, ByteField, ShortField
from scapy.layers.inet import IP, UDP
from scapy.contrib.bier import BIER
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q
from scapy.compat import orb


ecpritypes = {0: "iq-data",
             1: "bit-sequence",
             2: "realtime-control-data",
             3: "generic-data-transfer",
             4: "remote-memory-access",
             5: "oneway-delay-measurement",
             6: "remote-reset",
             7: "event-indication",
             8: "iwf-startup",
             9: "iwf-operation",
             10: "iwf-mapping",
             11: "iwf-delay-control"}

class ECPRI(Packet):
    name = "eCPRI"
    fields_desc = [BitField("revision", 1, 4),
                   BitField("reserved", 0, 3),
                   BitField("c", 0, 1),
                   ByteEnumField("type", 0, ecpritypes),
                   ShortField("size", None),
                   ConditionalField(ShortField("pcid", 0), lambda pkt:pkt.type == 0),
                   ConditionalField(ShortField("rtcid", 0), lambda pkt:pkt.type == 2),
                   ConditionalField(ShortField("mstid", 0), lambda pkt:pkt.type == 5),
                   ConditionalField(ShortField("seqid", 0), lambda pkt:pkt.type in [0, 2])
                   ]

    def post_build(self, p, pay):
        tmp_len = len(pay) + len(p) - 4
        pay += b"\0" * ((-len(pay)) % 4)  # pad eCPRI payload if needed
        if self.size is None:
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p + pay

    def mysummary(self):
            return self.sprintf("eCPRI %ECPRI.type%")

bind_layers(Ether, ECPRI, type=0xAEFE)
bind_layers(Dot1Q, ECPRI, type=0xAEFE)
