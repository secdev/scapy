# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = HSFZ - BMW High-Speed-Fahrzeug-Zugang
# scapy.contrib.status = loads


import struct
import socket
import time

from scapy.compat import Optional, Tuple, Type

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import IntField, ShortEnumField, XByteField
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.contrib.automotive.uds import UDS
from scapy.contrib.isotp import ISOTP
from scapy.error import Scapy_Exception
from scapy.data import MTU


"""
BMW HSFZ (High-Speed-Fahrzeug-Zugang / High-Speed-Car-Access).
BMW specific diagnostic over IP protocol implementation.
The physical interface for this connection is called ENET.
"""

# #########################HSFZ###################################


class HSFZ(Packet):
    name = 'HSFZ'
    fields_desc = [
        IntField('length', None),
        ShortEnumField('type', 1, {0x01: "message",
                                   0x02: "echo"}),
        XByteField('src', 0),
        XByteField('dst', 0),
    ]

    def hashret(self):
        # type: () -> bytes
        hdr_hash = struct.pack("B", self.src ^ self.dst)
        pay_hash = self.payload.hashret()
        return hdr_hash + pay_hash

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return s[:self.length - 2], s[self.length - 2:]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """
        This will set the LenField 'length' to the correct value.
        """
        if self.length is None:
            pkt = struct.pack("!I", len(pay) + 2) + pkt[4:]
        return pkt + pay


bind_bottom_up(TCP, HSFZ, sport=6801)
bind_bottom_up(TCP, HSFZ, dport=6801)
bind_layers(TCP, HSFZ, sport=6801, dport=6801)
bind_layers(HSFZ, UDS)


# ########################HSFZSocket###################################


class HSFZSocket(StreamSocket):
    def __init__(self, ip='127.0.0.1', port=6801):
        # type: (str, int) -> None
        self.ip = ip
        self.port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((self.ip, self.port))
        StreamSocket.__init__(self, s, HSFZ)


class ISOTP_HSFZSocket(HSFZSocket):
    def __init__(self, src, dst, ip='127.0.0.1', port=6801, basecls=ISOTP):
        # type: (int, int, str, int, Type[Packet]) -> None
        super(ISOTP_HSFZSocket, self).__init__(ip, port)
        self.src = src
        self.dst = dst
        self.basecls = HSFZ
        self.outputcls = basecls

    def send(self, x):
        # type: (bytes) -> int
        if not isinstance(x, ISOTP):
            raise Scapy_Exception(
                "Please provide a packet class based on ISOTP")
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        return super(ISOTP_HSFZSocket, self).send(
            HSFZ(src=self.src, dst=self.dst) / x
        )

    def recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        pkt = super(ISOTP_HSFZSocket, self).recv(x)
        if pkt:
            return self.outputcls(bytes(pkt.payload))
        else:
            return pkt
