# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Lucas Preston <lucas.preston@infinite.io>
# This program is published under a GPLv2 license

# scapy.contrib.description = Portmapper v2
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import IntField, PacketListField
from scapy.contrib.oncrpc import RPC, RPC_Call


class GETPORT_Call(Packet):
    name = 'GETPORT Call'
    fields_desc = [
        IntField('prog', 0),
        IntField('vers', 0),
        IntField('prot', 0),
        IntField('port', 0)
    ]


class GETPORT_Reply(Packet):
    name = 'GETPORT Reply'
    fields_desc = [
        IntField('port', 0)
    ]


bind_layers(RPC, GETPORT_Call, mtype=0)
bind_layers(RPC, GETPORT_Reply, mtype=1)
bind_layers(
    RPC_Call, GETPORT_Call, program=100000, pversion=2, procedure=3
)


class NULL_Call(Packet):
    name = 'PORTMAP NULL Call'
    fields_desc = []


class NULL_Reply(Packet):
    name = 'PORTMAP NULL Reply'
    fields_desc = []


bind_layers(RPC, NULL_Call, mtype=0)
bind_layers(RPC, NULL_Reply, mtype=1)
bind_layers(RPC_Call, NULL_Call, program=100000, pversion=2, procedure=0)


class Map_Entry(Packet):
    name = 'PORTMAP Map Entry'
    fields_desc = [
        IntField('prog', 0),
        IntField('vers', 0),
        IntField('prot', 0),
        IntField('port', 0),
        IntField('value_follows', 0)
    ]

    def extract_padding(self, s):
        return '', s


class DUMP_Call(Packet):
    name = 'PORTMAP DUMP Call'
    fields_desc = []


class DUMP_Reply(Packet):
    name = 'PORTMAP DUMP Reply'
    fields_desc = [
        IntField('value_follows', 0),
        PacketListField('mappings', [], cls=Map_Entry,
                        next_cls_cb=lambda pkt, lst, cur, remain:
                        Map_Entry if pkt.value_follows == 1 and
                        (len(lst) == 0 or cur.value_follows == 1) and
                        len(remain) > 4 else None)
    ]


bind_layers(RPC, DUMP_Call, mtype=0)
bind_layers(RPC, DUMP_Reply, mtype=1)
bind_layers(RPC_Call, DUMP_Call, program=100000, pversion=2, procedure=4)
