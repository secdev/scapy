#! /usr/bin/env python

## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Nils Weiss <nils@we155.de>
## This program is published under a GPLv2 license

"""
ISO13400
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.sendrecv import sndrcv
from scapy.layers.uds import ISO14229


#########################ISO13400###################################

class ISO13400(Packet):
    name = 'ISO13400'
    fields_desc = [
        IntField('length', 0),
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
        return s[:self.length - 2], s[self.length - 2:]


bind_layers(TCP, ISO13400, sport=6801)
bind_layers(TCP, ISO13400, dport=6801)
bind_layers(ISO13400, ISO14229)


#########################DoIPSocket###################################

class DoIPSocket(StreamSocket):
    def __init__(self, ip='192.168.2.1', port=6801):
        s = socket.socket()
        s.connect((ip, port))
        StreamSocket.__init__(self, s, ISO13400)

    def sr(self, *args, **kargs):
        return sndrcv(self, *args, **kargs)

    def sr1(self, *args, **kargs):
        a, b = sndrcv(self, *args, **kargs)
        if len(a) > 0:
            return a[0][1]
        else:
            return None
