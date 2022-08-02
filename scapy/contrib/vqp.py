# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = VLAN Query Protocol
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    IPField,
    IntEnumField,
    IntField,
    MACField,
    MultipleTypeField,
    StrLenField,
)
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
        FieldLenField("len", None, length_of="data", fmt="H"),
        MultipleTypeField(
            [
                (IPField("data", "0.0.0.0"),
                    lambda p: p.datatype == 3073),
                (MACField("data", "00:00:00:00:00:00"),
                    lambda p: p.datatype in [3078, 3080]),
            ],
            StrLenField("data", None, length_from=lambda p: p.len)
        )
    ]


bind_bottom_up(UDP, VQP, sport=1589)
bind_bottom_up(UDP, VQP, dport=1589)
bind_layers(UDP, VQP, sport=1589, dport=1589)

bind_layers(VQP, VQPEntry,)
bind_layers(VQPEntry, VQPEntry,)
