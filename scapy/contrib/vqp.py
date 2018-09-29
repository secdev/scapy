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

# scapy.contrib.description = VLAN Query Protocol
# scapy.contrib.status = loads

import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    FieldLenField, IntEnumField, IntField, IPField, MACField, StrLenField
from scapy.layers.inet import UDP


class VQP(Packet):
    name = "VQP"
    fields_desc = [
        ByteField("const", 1),
        ByteEnumField("type", 1, {
            1: "requestPort", 2: "responseVLAN",
            3: "requestReconfirm", 4: "responseReconfirm"
        }),
        ByteEnumField("errorcodeaction", 0, {
            0: "none", 3: "accessDenied",
            4: "shutdownPort", 5: "wrongDomain"
        }),
        ByteEnumField("unknown", 2, {
            2: "inGoodResponse", 6: "inRequests"
        }),
        IntField("seq", 0),
    ]


class VQPEntry(Packet):
    name = "VQPEntry"
    fields_desc = [
        IntEnumField("datatype", 0, {
            3073: "clientIPAddress", 3074: "portName",
            3075: "VLANName", 3076: "Domain", 3077: "ethernetPacket",
            3078: "ReqMACAddress", 3079: "unknown",
            3080: "ResMACAddress"
        }),
        FieldLenField("len", None),
        ConditionalField(IPField("datatom", "0.0.0.0"),
                         lambda p: p.datatype == 3073),
        ConditionalField(MACField("data", "00:00:00:00:00:00"),
                         lambda p: p.datatype == 3078),
        ConditionalField(MACField("data", "00:00:00:00:00:00"),
                         lambda p: p.datatype == 3080),
        ConditionalField(StrLenField("data", None,
                                     length_from=lambda p: p.len),
                         lambda p: p.datatype not in [3073, 3078, 3080]),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p.data)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p


bind_layers(UDP, VQP, sport=1589)
bind_layers(UDP, VQP, dport=1589)
bind_layers(VQP, VQPEntry,)
bind_layers(VQPEntry, VQPEntry,)
