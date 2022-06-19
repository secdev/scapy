# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Lucas Preston <lucas.preston@infinite.io>

# scapy.contrib.description = NFS Mount v3
# scapy.contrib.status = loads

from scapy.contrib.oncrpc import RPC, RPC_Call
from scapy.packet import Packet, bind_layers
from scapy.fields import IntField, StrLenField, IntEnumField, PacketField, \
    ConditionalField, FieldListField
from scapy.contrib.nfs import File_Object

mountstat3 = {
    0: 'MNT3_OK',
    1: 'MNT3ERR_PERM',
    2: 'MNT3ERR_NOENT',
    5: 'MNT3ERR_IO',
    13: 'MNT3ERR_ACCES',
    20: 'MNT3ERR_NOTDIR',
    22: 'MNT3ERR_INVAL',
    63: 'MNT3ERR_NAMETOOLONG',
    10004: 'MNT3ERR_NOTSUPP',
    10006: 'MNT3ERR_SERVERFAULT'
}


class Path(Packet):
    name = 'Path'
    fields_desc = [
        IntField('length', 0),
        StrLenField('path', '', length_from=lambda pkt: pkt.length),
        StrLenField('fill', '', length_from=lambda pkt: (4 - pkt.length) % 4)
    ]

    def extract_padding(self, s):
        return '', s

    def set(self, path, length=None, fill=None):
        if length is None:
            length = len(path)
        if fill is None:
            fill = b'\x00' * ((4 - len(path)) % 4)
        self.length = length
        self.path = path
        self.fill = fill


class NULL_Call(Packet):
    name = 'MOUNT NULL Call'
    fields_desc = []


class NULL_Reply(Packet):
    name = 'MOUNT NULL Reply'
    fields_desc = []


bind_layers(RPC, NULL_Call, mtype=0)
bind_layers(RPC, NULL_Reply, mtype=1)
bind_layers(RPC_Call, NULL_Call, program=100005, procedure=0, pversion=3)


class MOUNT_Call(Packet):
    name = 'MOUNT Call'
    fields_desc = [
        PacketField('path', Path(), Path)
    ]


class MOUNT_Reply(Packet):
    name = 'MOUNT Reply'
    fields_desc = [
        IntEnumField('status', 0, mountstat3),
        ConditionalField(
            PacketField('filehandle', File_Object(), File_Object),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(IntField('flavors', 0), lambda pkt: pkt.status == 0),
        ConditionalField(
            FieldListField(
                'flavor', None, IntField('', None),
                count_from=lambda pkt: pkt.flavors
            ),
            lambda pkt: pkt.status == 0
        )
    ]

    def get_filehandle(self):
        if self.status == 0:
            return self.filehandle.fh
        return None


bind_layers(RPC, MOUNT_Call, mtype=0)
bind_layers(RPC, MOUNT_Reply, mtype=1)
bind_layers(RPC_Call, MOUNT_Call, program=100005, procedure=1, pversion=3)


class UNMOUNT_Call(Packet):
    name = 'UNMOUNT Call'
    fields_desc = [
        PacketField('path', Path(), Path)
    ]


class UNMOUNT_Reply(Packet):
    name = 'UNMOUNT Reply'
    fields_desc = []


bind_layers(RPC, UNMOUNT_Call, mtype=0)
bind_layers(RPC, UNMOUNT_Reply, mtype=1)
bind_layers(
    RPC_Call, UNMOUNT_Call, program=100005, procedure=3, pversion=3
)
