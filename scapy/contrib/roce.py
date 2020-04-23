# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Haggai Eran <haggai.eran@gmail.com>
# This program is published under a GPLv2 license

# scapy.contrib.description = RoCE v2
# scapy.contrib.status = loads

"""
RoCE: RDMA over Converged Ethernet
"""

from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteEnumField, XShortField, \
    XLongField, BitField, FCSField
from scapy.layers.inet import IP, UDP
from scapy.compat import raw
from scapy.error import warning
from zlib import crc32
import struct

_transports = {
    'RC': 0x00,
    'UC': 0x20,
    'RD': 0x40,
    'UD': 0x60,
}

_ops = {
    'SEND_FIRST': 0x00,
    'SEND_MIDDLE': 0x01,
    'SEND_LAST': 0x02,
    'SEND_LAST_WITH_IMMEDIATE': 0x03,
    'SEND_ONLY': 0x04,
    'SEND_ONLY_WITH_IMMEDIATE': 0x05,
    'RDMA_WRITE_FIRST': 0x06,
    'RDMA_WRITE_MIDDLE': 0x07,
    'RDMA_WRITE_LAST': 0x08,
    'RDMA_WRITE_LAST_WITH_IMMEDIATE': 0x09,
    'RDMA_WRITE_ONLY': 0x0a,
    'RDMA_WRITE_ONLY_WITH_IMMEDIATE': 0x0b,
    'RDMA_READ_REQUEST': 0x0c,
    'RDMA_READ_RESPONSE_FIRST': 0x0d,
    'RDMA_READ_RESPONSE_MIDDLE': 0x0e,
    'RDMA_READ_RESPONSE_LAST': 0x0f,
    'RDMA_READ_RESPONSE_ONLY': 0x10,
    'ACKNOWLEDGE': 0x11,
    'ATOMIC_ACKNOWLEDGE': 0x12,
    'COMPARE_SWAP': 0x13,
    'FETCH_ADD': 0x14,
}


CNP_OPCODE = 0x81


def opcode(transport, op):
    return (_transports[transport] + _ops[op], '{}_{}'.format(transport, op))


_bth_opcodes = dict([
    opcode('RC', 'SEND_FIRST'),
    opcode('RC', 'SEND_MIDDLE'),
    opcode('RC', 'SEND_LAST'),
    opcode('RC', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('RC', 'SEND_ONLY'),
    opcode('RC', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('RC', 'RDMA_WRITE_FIRST'),
    opcode('RC', 'RDMA_WRITE_MIDDLE'),
    opcode('RC', 'RDMA_WRITE_LAST'),
    opcode('RC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('RC', 'RDMA_WRITE_ONLY'),
    opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    opcode('RC', 'RDMA_READ_REQUEST'),
    opcode('RC', 'RDMA_READ_RESPONSE_FIRST'),
    opcode('RC', 'RDMA_READ_RESPONSE_MIDDLE'),
    opcode('RC', 'RDMA_READ_RESPONSE_LAST'),
    opcode('RC', 'RDMA_READ_RESPONSE_ONLY'),
    opcode('RC', 'ACKNOWLEDGE'),
    opcode('RC', 'ATOMIC_ACKNOWLEDGE'),
    opcode('RC', 'COMPARE_SWAP'),
    opcode('RC', 'FETCH_ADD'),

    opcode('UC', 'SEND_FIRST'),
    opcode('UC', 'SEND_MIDDLE'),
    opcode('UC', 'SEND_LAST'),
    opcode('UC', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('UC', 'SEND_ONLY'),
    opcode('UC', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('UC', 'RDMA_WRITE_FIRST'),
    opcode('UC', 'RDMA_WRITE_MIDDLE'),
    opcode('UC', 'RDMA_WRITE_LAST'),
    opcode('UC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('UC', 'RDMA_WRITE_ONLY'),
    opcode('UC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),

    opcode('RD', 'SEND_FIRST'),
    opcode('RD', 'SEND_MIDDLE'),
    opcode('RD', 'SEND_LAST'),
    opcode('RD', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('RD', 'SEND_ONLY'),
    opcode('RD', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('RD', 'RDMA_WRITE_FIRST'),
    opcode('RD', 'RDMA_WRITE_MIDDLE'),
    opcode('RD', 'RDMA_WRITE_LAST'),
    opcode('RD', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('RD', 'RDMA_WRITE_ONLY'),
    opcode('RD', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    opcode('RD', 'RDMA_READ_REQUEST'),
    opcode('RD', 'RDMA_READ_RESPONSE_FIRST'),
    opcode('RD', 'RDMA_READ_RESPONSE_MIDDLE'),
    opcode('RD', 'RDMA_READ_RESPONSE_LAST'),
    opcode('RD', 'RDMA_READ_RESPONSE_ONLY'),
    opcode('RD', 'ACKNOWLEDGE'),
    opcode('RD', 'ATOMIC_ACKNOWLEDGE'),
    opcode('RD', 'COMPARE_SWAP'),
    opcode('RD', 'FETCH_ADD'),

    opcode('UD', 'SEND_ONLY'),
    opcode('UD', 'SEND_ONLY_WITH_IMMEDIATE'),

    (CNP_OPCODE, 'CNP'),
])


class BTH(Packet):
    name = "BTH"
    fields_desc = [
        ByteEnumField("opcode", 0, _bth_opcodes),
        BitField("solicited", 0, 1),
        BitField("migreq", 0, 1),
        BitField("padcount", 0, 2),
        BitField("version", 0, 4),
        XShortField("pkey", 0xffff),
        BitField("fecn", 0, 1),
        BitField("becn", 0, 1),
        BitField("resv6", 0, 6),
        BitField("dqpn", 0, 24),
        BitField("ackreq", 0, 1),
        BitField("resv7", 0, 7),
        BitField("psn", 0, 24),

        FCSField("icrc", None, fmt="!I")]

    @staticmethod
    def pack_icrc(icrc):
        return struct.pack("!I", icrc & 0xffffffff)[::-1]

    def compute_icrc(self, p):
        udp = self.underlayer
        if udp is None or not isinstance(udp, UDP):
            warning("Expecting UDP underlayer to compute checksum. Got %s.",
                    udp and udp.name)
            return self.pack_icrc(0)
        ip = udp.underlayer
        if isinstance(ip, IP):
            # pseudo-LRH / IP / UDP / BTH / payload
            pshdr = Raw(b'\xff' * 8) / ip.copy()
            pshdr.chksum = 0xffff
            pshdr.ttl = 0xff
            pshdr.tos = 0xff
            pshdr[UDP].chksum = 0xffff
            pshdr[BTH].fecn = 1
            pshdr[BTH].becn = 1
            pshdr[BTH].resv6 = 0xff
            bth = pshdr[BTH].self_build()
            payload = raw(pshdr[BTH].payload)
            # add ICRC placeholder just to get the right IP.totlen and
            # UDP.length
            icrc_placeholder = b'\xff\xff\xff\xff'
            pshdr[UDP].payload = Raw(bth + payload + icrc_placeholder)
            icrc = crc32(raw(pshdr)[:-4]) & 0xffffffff
            return self.pack_icrc(icrc)
        else:
            # TODO support IPv6
            warning("The underlayer protocol %s is not supported.",
                    ip and ip.name)
            return self.pack_icrc(0)

    # RoCE packets end with ICRC - a 32-bit CRC of the packet payload and
    # pseudo-header. Add the ICRC header if it is missing and calculate its
    # value.
    def post_build(self, p, pay):
        p += pay
        if self.icrc is None:
            p = p[:-4] + self.compute_icrc(p)
        return p


class CNPPadding(Packet):
    name = "CNPPadding"
    fields_desc = [
        XLongField("reserved1", 0),
        XLongField("reserved2", 0),
    ]


def cnp(dqpn):
    return BTH(opcode=CNP_OPCODE, becn=1, dqpn=dqpn) / CNPPadding()


bind_layers(BTH, CNPPadding, opcode=CNP_OPCODE)

bind_layers(UDP, BTH, dport=4791)
