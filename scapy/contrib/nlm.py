# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Lucas Preston <lucas.preston@infinite.io>

# scapy.contrib.description = Network Lock Manager (NLM) v4
# scapy.contrib.status = loads

from scapy.contrib.oncrpc import RPC, RPC_Call, Object_Name
from scapy.packet import Packet, bind_layers
from scapy.fields import IntField, StrLenField, LongField, PacketField, \
    IntEnumField
from scapy.contrib.nfs import File_Object

nlm4_stats = {
    0: 'NLM4_GRANTED',
    1: 'NLM4_DENIED',
    2: 'NLM4_DENIED_NOLOCKS',
    3: 'NLM4_BLOCKED',
    4: 'NLM4_DENIED_GRACE_PERIOD',
    5: 'NLM4_DEADLCK',
    6: 'NLM4_ROFS',
    7: 'NLM4_STALE_FH',
    8: 'NLM4_FBIG',
    9: 'NLM4_FAILED'
}


class NLM4_Cookie(Packet):
    name = 'Cookie'
    fields_desc = [
        IntField('length', 0),
        StrLenField('contents', '', length_from=lambda pkt: pkt.length),
        StrLenField('fill', b'', length_from=lambda pkt: (4 - pkt.length) % 4)
    ]

    def set(self, c, length=None, fill=None):
        if length is None:
            length = len(c)
        if fill is None:
            fill = b'\x00' * ((4 - len(c)) % 4)
        self.length = length
        self.contents = c
        self.fill = fill

    def extract_padding(self, s):
        return '', s


class SHARE_Call(Packet):
    name = 'SHARE Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('mode', 0),
        IntField('access', 0),
        IntEnumField('reclaim', 0, {0: 'NO', 1: 'YES'})
    ]


class SHARE_Reply(Packet):
    name = 'SHARE Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats),
        IntField('sequence', 0)
    ]


bind_layers(RPC_Call, SHARE_Call, program=100021, pversion=4, procedure=20)
bind_layers(RPC, SHARE_Call, mtype=0)
bind_layers(RPC, SHARE_Reply, mtype=1)


class UNSHARE_Call(Packet):
    name = 'UNSHARE Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('mode', 0),
        IntField('access', 0),
        IntEnumField('reclaim', 0, {0: 'NO', 1: 'YES'})
    ]


class UNSHARE_Reply(Packet):
    name = 'UNSHARE Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats),
        IntField('sequence', 0)
    ]


bind_layers(
    RPC_Call, UNSHARE_Call, program=100021, pversion=4, procedure=21
)
bind_layers(RPC, UNSHARE_Call, mtype=0)
bind_layers(RPC, UNSHARE_Reply, mtype=1)


class LOCK_Call(Packet):
    name = 'LOCK Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('block', 0, {0: 'NO', 1: 'YES'}),
        IntEnumField('exclusive', 0, {0: 'NO', 1: 'YES'}),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('svid', 0),
        LongField('l_offset', 0),
        LongField('l_len', 0),
        IntField('reclaim', 0),
        IntField('state', 0)
    ]


class LOCK_Reply(Packet):
    name = 'LOCK Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats)
    ]


bind_layers(RPC_Call, LOCK_Call, program=100021, pversion=4, procedure=2)
bind_layers(RPC, LOCK_Call, mtype=0)
bind_layers(RPC, LOCK_Reply, mtype=1)


class UNLOCK_Call(Packet):
    name = 'UNLOCK Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('svid', 0),
        LongField('l_offset', 0),
        LongField('l_len', 0)
    ]


class UNLOCK_Reply(Packet):
    name = 'UNLOCK Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats)
    ]


bind_layers(RPC_Call, UNLOCK_Call, program=100021, pversion=4, procedure=4)
bind_layers(RPC, UNLOCK_Call, mtype=0)
bind_layers(RPC, UNLOCK_Reply, mtype=1)


class GRANTED_MSG_Call(Packet):
    name = 'GRANTED_MSG Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('exclusive', 0, {0: 'NO', 1: 'YES'}),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('svid', 0),
        LongField('l_offset', 0),
        LongField('l_len', 0)
    ]


class GRANTED_MSG_Reply(Packet):
    name = 'GRANTED_MSG Reply'
    fields_desc = []


bind_layers(
    RPC_Call, GRANTED_MSG_Call, program=100021, pversion=4, procedure=10
)
bind_layers(RPC, GRANTED_MSG_Call, mtype=0)
bind_layers(RPC, GRANTED_MSG_Reply, mtype=1)


class GRANTED_RES_Call(Packet):
    name = 'GRANTED_RES Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats)
    ]


class GRANTED_RES_Reply(Packet):
    name = 'GRANTED_RES Reply'
    fields_desc = []


bind_layers(
    RPC_Call, GRANTED_RES_Call, program=100021, pversion=4, procedure=15
)
bind_layers(RPC, GRANTED_RES_Call, mtype=0)
bind_layers(RPC, GRANTED_RES_Reply, mtype=1)


class CANCEL_Call(Packet):
    name = 'CANCEL Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('block', 0, {0: 'NO', 1: 'YES'}),
        IntEnumField('exclusive', 0, {0: 'NO', 1: 'YES'}),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('svid', 0),
        LongField('l_offset', 0),
        LongField('l_len', 0)
    ]


class CANCEL_Reply(Packet):
    name = 'CANCEL Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats)
    ]


bind_layers(RPC_Call, CANCEL_Call, program=100021, pversion=4, procedure=3)
bind_layers(RPC, CANCEL_Call, mtype=0)
bind_layers(RPC, CANCEL_Reply, mtype=1)


class TEST_Call(Packet):
    name = 'TEST Call'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('exclusive', 0, {0: 'NO', 1: 'YES'}),
        PacketField('caller', Object_Name(), Object_Name),
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('owner', Object_Name(), Object_Name),
        IntField('svid', 0),
        LongField('l_offset', 0),
        LongField('l_len', 0)
    ]


class TEST_Reply(Packet):
    name = 'TEST Reply'
    fields_desc = [
        PacketField('cookie', NLM4_Cookie(), NLM4_Cookie),
        IntEnumField('status', 0, nlm4_stats)
    ]


bind_layers(RPC_Call, TEST_Call, program=100021, pversion=4, procedure=1)
bind_layers(RPC, TEST_Call, mtype=0)
bind_layers(RPC, TEST_Reply, mtype=1)
