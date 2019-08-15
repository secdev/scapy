# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Lucas Preston <lucas.preston@infinite.io>
# This program is published under a GPLv2 license

# scapy.contrib.description = ONC-RPC v2
# scapy.contrib.status = loads

from scapy.fields import XIntField, IntField, IntEnumField, StrLenField, \
    FieldListField, ConditionalField, PacketField, XLongField
from scapy.packet import Packet, bind_layers


class object_name(Packet):
    name = 'Object Name'
    fields_desc = [
        IntField('length', 0),
        StrLenField('_name', '', length_from=lambda pkt: pkt.length),
        StrLenField('fill', '', length_from=lambda pkt: (4-pkt.length) % 4)
    ]

    def set(self, name, length=None, fill=None):
        if length is None:
            length = len(name)
        if fill is None:
            fill = '\x00' * ((4-len(name)) % 4)
        self.length = length
        self._name = name
        self.fill = fill

    def extract_padding(self, s):
        return '', s


class RM_Header(Packet):
    name = 'RM Header'
    fields_desc = [
        XIntField('rm', 0)
    ]

    def post_build(self, pkt, pay):
        """Override of post_build to set the rm header == len(payload)"""
        self.rm = 0x80000000 + len(self.payload)
        pkt = self.rm.to_bytes(4, byteorder='big')
        return Packet.post_build(self, pkt, pay)


class RPC(Packet):
    name = 'RPC'
    fields_desc = [
        XIntField('xid', 0),
        IntEnumField('mtype', 0, {0: 'CALL', 1: 'REPLY'}),
    ]


class a_unix(Packet):
    name = 'AUTH Unix'
    fields_desc = [
        XIntField('stamp', 0),
        PacketField('mname', object_name(), object_name),
        IntField('uid', 0),
        IntField('gid', 0),
        IntField('num_auxgids', 0),
        FieldListField(
            'auxgids', [], IntField('', None),
            count_from=lambda pkt: pkt.num_auxgids
        )
    ]

    def extract_padding(self, s):
        return '', s


class RPC_Call(Packet):
    name = 'RPC Call'

    fields_desc = [
        IntField('version', 2),
        IntField('program', 100003),
        IntField('pversion', 3),
        IntField('procedure', 0),
        IntEnumField('aflavor', 1, {0: 'AUTH_NULL', 1: 'AUTH_UNIX'}),
        IntField('alength', 0),
        ConditionalField(
            PacketField('a_unix', a_unix(), a_unix),
            lambda pkt: pkt.aflavor == 1
        ),
        IntEnumField('vflavor', 0, {0: 'AUTH_NULL', 1: 'AUTH_UNIX'}),
        IntField('vlength', 0),
        ConditionalField(
            PacketField('v_unix', a_unix(), a_unix),
            lambda pkt: pkt.vflavor == 1
        )
    ]

    def set_auth(self, **kwargs):
        """Used to easily set the fields in an a_unix packet"""
        if kwargs is None:
            return

        if 'mname' in kwargs:
            self.a_unix.mname.set(kwargs['mname'])
            del kwargs['mname']

        for arg, val in kwargs.items():
            if hasattr(self.a_unix, arg):
                setattr(self.a_unix, arg, val)

        self.alength = 0 if self.aflavor == 0 else len(self.a_unix)
        self.vlength = 0 if self.vflavor == 0 else len(self.v_unix)

    def post_build(self, pkt, pay):
        """Override of post_build to handle length fields"""
        if self.aflavor == 0 and self.vflavor == 0:
            # No work required if there are no auth fields,
            # default will be correct
            return Packet.post_build(self, pkt, pay)
        if self.aflavor != 0:
            pkt = pkt[:20] \
                + len(self.a_unix).to_bytes(4, byteorder='big') \
                + pkt[24:]
            return Packet.post_build(self, pkt, pay)
        if self.vflavor != 0:
            pkt = pkt[:28] \
                + len(self.v_unix).to_bytes(4, byteorder='big') \
                + pkt[32:]
        return Packet.post_build(self, pkt, pay)


class RPC_Reply(Packet):
    name = 'RPC Response'
    fields_desc = [
        IntField('reply_stat', 0),
        IntEnumField('flavor', 0, {0: 'AUTH_NULL', 1: 'AUTH_UNIX'}),
        ConditionalField(
            PacketField('a_unix', a_unix(), a_unix),
            lambda pkt: pkt.flavor == 1
        ),
        IntField('length', 0),
        IntField('accept_stat', 0)
    ]

    def set_auth(self, **kwargs):
        """Used to easily set the fields in an a_unix packet"""
        if kwargs is None:
            return

        if 'mname' in kwargs:
            self.a_unix.mname.set(kwargs['mname'])
            del kwargs['mname']

        for arg, val in kwargs.items():
            if hasattr(self.a_unix, arg):
                setattr(self.a_unix, arg, val)

        self.length = 0 if self.flavor == 0 else len(self.a_unix)


bind_layers(RPC, RPC_Call, mtype=0)
bind_layers(RPC, RPC_Reply, mtype=1)
