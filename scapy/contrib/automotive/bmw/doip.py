#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import struct
import socket
from scapy.packet import Packet, bind_layers
from scapy.fields import LenField, ShortEnumField, XByteField
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.contrib.uds import UDS


"""
BMW specific diagnostic over IP protocol implementation
"""

# #########################DoIP###################################


class DoIP(Packet):
    name = 'DoIP'
    fields_desc = [
        LenField('length', None, fmt='I', adjust=lambda x: x + 2),
        ShortEnumField('type', 1, {0x01: "message",
                                   0x02: "echo"}),
        XByteField('src', 0),
        XByteField('dst', 0),
    ]

    def hashret(self):
        hdr_hash = struct.pack("B", self.src ^ self.dst)
        pay_hash = self.payload.hashret()
        return hdr_hash + pay_hash

    def answers(self, other):
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def extract_padding(self, s):
        return s[:8], s[8:]


bind_layers(TCP, DoIP, sport=6801)
bind_layers(TCP, DoIP, dport=6801)
bind_layers(DoIP, UDS)


# ########################DoIPSocket###################################

class DoIPSocket(StreamSocket):
    def __init__(self, ip='127.0.0.1', port=6801):
        s = socket.socket()
        s.connect((ip, port))
        StreamSocket.__init__(self, s, DoIP)
