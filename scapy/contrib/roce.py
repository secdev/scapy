# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Haggai Eran <haggai.eran@gmail.com>

# scapy.contrib.description = RoCE v2
# scapy.contrib.status = loads

"""
RoCE: RDMA over Converged Ethernet
"""

import enum
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    PacketField, XByteField, ShortField, XIntField, XShortField, XLongField, \
    BitField, XBitField, FCSField
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.compat import raw
from scapy.error import warning
from zlib import crc32
import struct

from typing import (
    Callable,
    Optional,
    Tuple,
)

_transports = {
    'RC': 0x00,
    'UC': 0x20,
    'RD': 0x40,
    'UD': 0x60,
}

OP_MASK = 0x1f
TRANSPORT_MASK = 0xe0


def transport(opcode):
    # type: (Optional[int]) -> Optional[int]
    return opcode is not None and opcode & TRANSPORT_MASK


def op(opcode):
    # type: (int) -> int
    return opcode & OP_MASK


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
    'RESYNC': 0x15,
    'SEND_LAST_WITH_INVALIDATE': 0x16,
    'SEND_ONLY_WITH_INVALIDATE': 0x17,
}


CNP_OPCODE = 0x81
UD_SEND_ONLY = _transports['UD'] | _ops['SEND_ONLY']
UD_SEND_ONLY_IMM = _transports['UD'] | _ops['SEND_ONLY_WITH_IMMEDIATE']


class _ETH(enum.Flag):
    '''Enum of RDMA extended transport headers'''

    RDETH = enum.auto()
    DETH = enum.auto()
    RETH = enum.auto()
    AtomicETH = enum.auto()
    AETH = enum.auto()
    AtomicAckETH = enum.auto()
    ImmDt = enum.auto()
    IETH = enum.auto()
    CNPPadding = enum.auto()


def _opcode(transport, op, eth):
    # type: (str, str, _ETH) -> Tuple[int, Tuple[str, _ETH]]
    return (_transports[transport] + _ops[op], (f'{transport}_{op}', eth))


_bth_opcodes = dict([
    _opcode('RC', 'SEND_FIRST', _ETH(0)),
    _opcode('RC', 'SEND_MIDDLE', _ETH(0)),
    _opcode('RC', 'SEND_LAST', _ETH(0)),
    _opcode('RC', 'SEND_LAST_WITH_IMMEDIATE', _ETH.ImmDt),
    _opcode('RC', 'SEND_ONLY', _ETH(0)),
    _opcode('RC', 'SEND_ONLY_WITH_IMMEDIATE', _ETH.ImmDt),
    _opcode('RC', 'RDMA_WRITE_FIRST', _ETH.RETH),
    _opcode('RC', 'RDMA_WRITE_MIDDLE', _ETH(0)),
    _opcode('RC', 'RDMA_WRITE_LAST', _ETH(0)),
    _opcode('RC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE', _ETH.ImmDt),
    _opcode('RC', 'RDMA_WRITE_ONLY', _ETH.RETH),
    _opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE', _ETH.RETH | _ETH.ImmDt),
    _opcode('RC', 'RDMA_READ_REQUEST', _ETH.RETH),
    _opcode('RC', 'RDMA_READ_RESPONSE_FIRST', _ETH.AETH),
    _opcode('RC', 'RDMA_READ_RESPONSE_MIDDLE', _ETH(0)),
    _opcode('RC', 'RDMA_READ_RESPONSE_LAST', _ETH.AETH),
    _opcode('RC', 'RDMA_READ_RESPONSE_ONLY', _ETH.AETH),
    _opcode('RC', 'ACKNOWLEDGE', _ETH.AETH),
    _opcode('RC', 'ATOMIC_ACKNOWLEDGE', _ETH.AETH | _ETH.AtomicAckETH),
    _opcode('RC', 'COMPARE_SWAP', _ETH.AtomicETH),
    _opcode('RC', 'FETCH_ADD', _ETH.AtomicETH),
    _opcode('RC', 'SEND_LAST_WITH_INVALIDATE', _ETH.IETH),
    _opcode('RC', 'SEND_ONLY_WITH_INVALIDATE', _ETH.IETH),

    _opcode('UC', 'SEND_FIRST', _ETH(0)),
    _opcode('UC', 'SEND_MIDDLE', _ETH(0)),
    _opcode('UC', 'SEND_LAST', _ETH(0)),
    _opcode('UC', 'SEND_LAST_WITH_IMMEDIATE', _ETH.ImmDt),
    _opcode('UC', 'SEND_ONLY', _ETH(0)),
    _opcode('UC', 'SEND_ONLY_WITH_IMMEDIATE', _ETH.ImmDt),
    _opcode('UC', 'RDMA_WRITE_FIRST', _ETH.RETH),
    _opcode('UC', 'RDMA_WRITE_MIDDLE', _ETH(0)),
    _opcode('UC', 'RDMA_WRITE_LAST', _ETH(0)),
    _opcode('UC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE', _ETH.ImmDt),
    _opcode('UC', 'RDMA_WRITE_ONLY', _ETH.RETH),
    _opcode('UC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE', _ETH.RETH | _ETH.ImmDt),

    _opcode('RD', 'SEND_FIRST', _ETH.RDETH | _ETH.DETH),
    _opcode('RD', 'SEND_MIDDLE', _ETH.RDETH | _ETH.DETH),
    _opcode('RD', 'SEND_LAST', _ETH.RDETH | _ETH.DETH),
    _opcode('RD', 'SEND_LAST_WITH_IMMEDIATE', _ETH.RDETH | _ETH.DETH | _ETH.ImmDt),
    _opcode('RD', 'SEND_ONLY', _ETH.RDETH | _ETH.DETH),
    _opcode('RD', 'SEND_ONLY_WITH_IMMEDIATE', _ETH.RDETH | _ETH.DETH | _ETH.ImmDt),
    _opcode('RD', 'RDMA_WRITE_FIRST', _ETH.RDETH | _ETH.DETH | _ETH.RETH),
    _opcode('RD', 'RDMA_WRITE_MIDDLE', _ETH.RDETH | _ETH.DETH),
    _opcode('RD', 'RDMA_WRITE_LAST', _ETH.RDETH | _ETH.DETH),
    _opcode('RD', 'RDMA_WRITE_LAST_WITH_IMMEDIATE',
            _ETH.RDETH | _ETH.DETH | _ETH.ImmDt),
    _opcode('RD', 'RDMA_WRITE_ONLY', _ETH.RDETH | _ETH.DETH | _ETH.RETH),
    _opcode('RD', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE',
            _ETH.RDETH | _ETH.DETH | _ETH.RETH | _ETH.ImmDt),
    _opcode('RD', 'RDMA_READ_REQUEST', _ETH.RDETH | _ETH.DETH | _ETH.RETH),
    _opcode('RD', 'RDMA_READ_RESPONSE_FIRST', _ETH.RDETH | _ETH.AETH),
    _opcode('RD', 'RDMA_READ_RESPONSE_MIDDLE', _ETH.RDETH),
    _opcode('RD', 'RDMA_READ_RESPONSE_LAST', _ETH.RDETH | _ETH.AETH),
    _opcode('RD', 'RDMA_READ_RESPONSE_ONLY', _ETH.RDETH | _ETH.AETH),
    _opcode('RD', 'ACKNOWLEDGE', _ETH.RDETH | _ETH.AETH),
    _opcode('RD', 'ATOMIC_ACKNOWLEDGE', _ETH.RDETH | _ETH.AETH | _ETH.AtomicAckETH),
    _opcode('RD', 'COMPARE_SWAP', _ETH.RDETH | _ETH.DETH | _ETH.AtomicETH),
    _opcode('RD', 'FETCH_ADD', _ETH.RDETH | _ETH.DETH | _ETH.AtomicETH),
    _opcode('RD', 'RESYNC', _ETH.RDETH | _ETH.DETH),

    _opcode('UD', 'SEND_ONLY', _ETH.DETH),
    _opcode('UD', 'SEND_ONLY_WITH_IMMEDIATE', _ETH.DETH | _ETH.ImmDt),

    (CNP_OPCODE, ('CNP', _ETH.CNPPadding)),
])


_bth_opcode_to_str = {op: s for op, (s, _) in _bth_opcodes.items()}


class BTHSubHeader(Packet):
    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return b'', s


class DETH(BTHSubHeader):
    name = "Datagram Extended Transport Header"
    fields_desc = [
        XIntField("qkey", 0),
        XByteField("reserved", 0),
        XBitField("sqp", 0, 24)
    ]


class RETH(BTHSubHeader):
    name = "RDMA Extended Transport Header"
    fields_desc = [
        XLongField("va", 0),
        XIntField("rkey", 0),
        XIntField("len", 0),
    ]


class AtomicETH(BTHSubHeader):
    name = "Atomic Extended Transport Header"
    fields_desc = [
        XLongField("va", 0),
        XIntField("rkey", 0),
        XLongField("swapdt", 0),
        XLongField("cmpdt", 0),
    ]


class AETH(BTHSubHeader):
    name = "ACK Extended Transport Header"
    fields_desc = [
        XByteField("syndrome", 0),
        XBitField("msn", 0, 24),
    ]


class AtomicAckETH(BTHSubHeader):
    name = "Atomic ACK Extended Transport Header"
    fields_desc = [
        XLongField("origremdt", 0),
    ]


class ImmDt(BTHSubHeader):
    name = "Immediate Data Extended Transport Header"
    fields_desc = [
        XIntField("imm", 0)
    ]


class IETH(BTHSubHeader):
    name = "Invalidate Extended Transport Header"
    fields_desc = [
        XIntField("rkey", 0)
    ]


class CNPPadding(BTHSubHeader):
    name = "Congestion Notification Packet padding"
    fields_desc = [
        XLongField("reserved1", 0),
        XLongField("reserved2", 0),
    ]


def _has_sub_header(eth):
    # type: (_ETH) -> Callable[[Packet], bool]
    return lambda pkt: pkt.opcode is not None and eth in _bth_opcodes[pkt.opcode][1]


class BTH(Packet):
    name = "Base Transport Header"
    fields_desc = [
        ByteEnumField("opcode", None, _bth_opcode_to_str),
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

        ConditionalField(PacketField("deth", None, DETH),
                         _has_sub_header(_ETH.DETH)),
        ConditionalField(PacketField("reth", None, RETH),
                         _has_sub_header(_ETH.RETH)),
        ConditionalField(PacketField("atomiceth", None, AtomicETH),
                         _has_sub_header(_ETH.AtomicETH)),
        ConditionalField(PacketField("aeth", None, AETH),
                         _has_sub_header(_ETH.AETH)),
        ConditionalField(PacketField("atomicacketh", None, AtomicAckETH),
                         _has_sub_header(_ETH.AtomicAckETH)),
        ConditionalField(PacketField("immdt", None, ImmDt),
                         _has_sub_header(_ETH.ImmDt)),
        ConditionalField(PacketField("ieth", None, IETH),
                         _has_sub_header(_ETH.IETH)),
        ConditionalField(PacketField("cnppadding", None, CNPPadding),
                         _has_sub_header(_ETH.CNPPadding)),

        FCSField("icrc", None, fmt="!I")]

    @staticmethod
    def pack_icrc(icrc):
        # type: (int) -> bytes
        return struct.pack("!I", icrc & 0xffffffff)[::-1]

    def compute_icrc(self, p):
        # type: (bytes) -> bytes
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
        elif isinstance(ip, IPv6):
            # pseudo-LRH / IPv6 / UDP / BTH / payload
            pshdr = Raw(b'\xff' * 8) / ip.copy()
            pshdr.hlim = 0xff
            pshdr.fl = 0xfffff
            pshdr.tc = 0xff
            pshdr[UDP].chksum = 0xffff
            pshdr[BTH].fecn = 1
            pshdr[BTH].becn = 1
            pshdr[BTH].resv6 = 0xff
            bth = pshdr[BTH].self_build()
            payload = raw(pshdr[BTH].payload)
            # add ICRC placeholder just to get the right IPv6.plen and
            # UDP.length
            icrc_placeholder = b'\xff\xff\xff\xff'
            pshdr[UDP].payload = Raw(bth + payload + icrc_placeholder)
            icrc = crc32(raw(pshdr)[:-4]) & 0xffffffff
            return self.pack_icrc(icrc)
        else:
            warning("The underlayer protocol %s is not supported.",
                    ip and ip.name)
            return self.pack_icrc(0)

    # RoCE packets end with ICRC - a 32-bit CRC of the packet payload and
    # pseudo-header. Add the ICRC header if it is missing and calculate its
    # value.
    def post_build(self, p, pay):
        # type: (bytes, bytes) -> bytes
        p += pay
        if self.icrc is None:
            p = p[:-4] + self.compute_icrc(p)
        return p


def cnp(dqpn):
    # type: (int) -> BTH
    return BTH(opcode=CNP_OPCODE, becn=1, dqpn=dqpn, cnppadding=CNPPadding())


class GRH(Packet):
    name = "GRH"
    fields_desc = [
        BitField("ipver", 6, 4),
        BitField("tclass", 0, 8),
        BitField("flowlabel", 6, 20),
        ShortField("paylen", 0),
        ByteField("nexthdr", 0),
        ByteField("hoplmt", 0),
        XBitField("sgid", 0, 128),
        XBitField("dgid", 0, 128),
    ]


bind_layers(Ether, GRH, type=0x8915)
bind_layers(GRH, BTH)
bind_layers(UDP, BTH, dport=4791)
