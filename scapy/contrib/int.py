# scapy.contrib.description = Inband Network Telemetry Protocol (INT)
# scapy.contrib.status = loads

'''
Inband Network Telemetry Protocol (INT)

References:
https://staging.p4.org/p4-spec/docs/INT_v2_1.pdf
https://staging.p4.org/p4-spec/docs/telemetry_report_v2_0.pdf
https://github.com/p4lang/p4-applications

Example Packet Format:
INT-MX mode:
INToGre = Ether/IP/GRE/INTShimGre/INTMetaMx/Raw
INToTCP = Ether/IP/TCP/INTShimTcpUdp/INTMetaMx/Raw
INToUDP = Ether/IP/UDP/INTShimTcpUdp/INTMetaMx/Raw
INToVXLAN = Ether/IP/UDP/VXLAN/INTShimVxlan/INTMetaMx/Raw
INToGENEVE = Ether/IP/UDP/GENEVE/GeneveOptINT/INTMetaMx/Raw

INT-MD mode:
INToGre = Ether/IP/GRE/INTShimGre/INTMetaMd/INTMetaHop/Raw
INToTCP = Ether/IP/TCP/INTShimTcpUdp/INTMetaMd/INTMetaHop/Raw
INToUDP = Ether/IP/UDP/INTShimTcpUdp/INTMetaMd/INTMetaHop/Raw
INToVXLAN = Ether/IP/UDP/VXLAN/INTShimVxlan/INTMetaMd/INTMetaHop/Raw
INToGENEVE = Ether/IP/UDP/GENEVE/GeneveOptINT/INTMetaMd/INTMetaHop/Raw
'''

import struct
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, BitEnumField, FlagsField, ByteField, \
    ShortField, IntField, LongField, FieldLenField, ConditionalField, \
    MultipleTypeField, PacketField, PacketListField
from scapy.layers.l2 import GRE
from scapy.layers.inet import TCP, UDP
from scapy.layers.vxlan import VXLAN

INT_PRI_MASK = 0x80
INT_L4_DPORT = 0x4568
INT_GRE_PROTOCOL = 0x4569
INT_VXLAN_PROTOCOL = 0x82
INT_GENEVE_CLASSID = 0x0103

_INT_TYPE = {
    1: 'INT-MD',
    2: 'INT-DST',
    3: 'INT-MX',
}

_INT_GRE = {
    0: 'Original packet with GRE',
    1: 'Original packet without GRE',
}

_INT_GPE = {
    0: 'Original packet used VXLAN GPE encapsulation',
    1: 'Original packet used VXLAN encapsulation',
}

_INT_INSTR_BITMAP = [
    'checksum',
    'reserved14',
    'reserved13',
    'reserved12',
    'reserved11',
    'reserved10',
    'reserved9',
    'buf_info',
    'tx_info',
    'l2_intf',
    'egr_ts',
    'igr_ts',
    'que_info',
    'latency',
    'l1_intf',
    'node_id',
]


class INTMetaHop(Packet):
    name = 'INTMetaHop'
    fields_desc = [
        ConditionalField(
            IntField('node_id', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 0))
        ),
        ConditionalField(
            ShortField('igr_l1_intf', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 1))
        ),
        ConditionalField(
            ShortField('egr_l1_intf', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 1))
        ),
        ConditionalField(
            IntField('latency', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 2))
        ),
        ConditionalField(
            BitField('que_id', 0, 8),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 3))
        ),
        ConditionalField(
            BitField('que_occupy', 0, 24),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 3))
        ),
        ConditionalField(
            LongField('igr_ts', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 4))
        ),
        ConditionalField(
            LongField('egr_ts', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 5))
        ),
        ConditionalField(
            IntField('igr_l2_intf', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 6))
        ),
        ConditionalField(
            IntField('egr_l2_intf', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 6))
        ),
        ConditionalField(
            IntField('egr_tx_info', 0),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 7))
        ),
        ConditionalField(
            BitField('buf_id', 0, 8),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 8))
        ),
        ConditionalField(
            BitField('buf_occupy', 0, 24),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 8))
        ),
        ConditionalField(
            IntField('reserved9', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 9))
        ),
        ConditionalField(
            IntField('reserved10', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 10))
        ),
        ConditionalField(
            IntField('reserved11', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 11))
        ),
        ConditionalField(
            IntField('reserved12', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 12))
        ),
        ConditionalField(
            IntField('reserved13', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 13))
        ),
        ConditionalField(
            IntField('reserved14', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 14))
        ),
        ConditionalField(
            IntField('checksum', 0xffffffff),
            lambda pkt:pkt.parent.instr_bitmap & (0x1 << (15 - 15))
        ),
    ]

    def extract_padding(self, s):
        return "", s


class INTMetaMx(Packet):
    name = 'INTMetaMx'
    fields_desc = [
        BitField('version', 0, 4),
        BitField('discard', 0, 1),
        BitField('reserved1', 0, 27),
        FlagsField('instr_bitmap', 0xfe00, 16, _INT_INSTR_BITMAP),
        ShortField('ds_id', 0),
        ShortField('ds_instr', 0),
        ShortField('ds_flags', 0),
    ]

    def extract_padding(self, s):
        return "", s


class INTMetaMd(Packet):
    name = 'INTMetaMd'
    fields_desc = [
        BitField('version', 0, 4),
        BitField('discard', 0, 1),
        BitField('exceed_mht', 0, 1),
        BitField('exceed_mtu', 0, 1),
        BitField('reserved0', 0, 12),
        BitField('hop_len', 0, 5),
        BitField('hop_left', 0, 8),
        FlagsField('instr_bitmap', 0xfe00, 16, _INT_INSTR_BITMAP),
        ShortField('ds_id', 0),
        ShortField('ds_instr', 0),
        ShortField('ds_flags', 0),
        PacketListField('meta_hops', [], INTMetaHop,
                        length_from=lambda pkt: pkt.parent.length * 4 - 12),
    ]

    def post_build(self, pkt, pay):
        if self.meta_hops is not None:
            tmp_len = len(self.meta_hops[0]) // 4
            old_value = struct.unpack("B", pkt[2:3])[0]
            new_value = (old_value & 0b11100000) | (tmp_len & 0b00011111)
            pkt = pkt[:2] + struct.pack("B", new_value) + pkt[3:]
        return pkt + pay

    def extract_padding(self, s):
        return "", s


class INTShimTcpUdp(Packet):
    name = 'INTShimTcpUdp'
    fields_desc = [
        BitEnumField('type', 1, 4, _INT_TYPE),
        BitField('npt', 0, 2),
        BitField('reserved1', 0, 2),
        FieldLenField('length', None,
                      length_of="metadata",
                      adjust=lambda pkt, x: x // 4, fmt="B"),
        ConditionalField(ByteField('reserved3', 0), lambda pkt: pkt.npt == 0),
        ConditionalField(BitField('dscp', 0, 6), lambda pkt: pkt.npt == 0),
        ConditionalField(BitField('reserved4', 0, 2), lambda pkt: pkt.npt == 0),
        ConditionalField(ShortField('l4_dport', 0), lambda pkt: pkt.npt == 1),
        ConditionalField(ByteField('ip_proto', 0), lambda pkt: pkt.npt == 2),
        ConditionalField(ByteField('reserved5', 0), lambda pkt: pkt.npt == 2),
        MultipleTypeField([
            (PacketField('metadata', None, INTMetaMd), lambda pkt: pkt.type == 1),
            (PacketField('metadata', None, INTMetaMx), lambda pkt: pkt.type == 3), ],
            PacketField('metadata', None, INTMetaMd)
        ),
    ]


class INTShimGre(Packet):
    name = 'INTShimGre'
    fields_desc = [
        BitEnumField('type', 1, 4, _INT_TYPE),
        BitEnumField('gre', 0, 1, _INT_GRE),
        BitField('reserved0', 0, 3),
        FieldLenField('length', None,
                      length_of="metadata",
                      adjust=lambda pkt, x: x // 4, fmt="B"),
        ShortField('gre_proto', 0),
        MultipleTypeField([
            (PacketField('metadata', None, INTMetaMd), lambda pkt: pkt.type == 1),
            (PacketField('metadata', None, INTMetaMx), lambda pkt: pkt.type == 3), ],
            PacketField('metadata', None, INTMetaMd)
        ),
    ]


class INTShimVxlan(Packet):
    name = 'INTShimVxlan'
    fields_desc = [
        BitEnumField('type', 1, 4, _INT_TYPE),
        BitField('reserved2', 0, 4),
        FieldLenField('length', None,
                      length_of="metadata",
                      adjust=lambda pkt, x: x // 4, fmt="B"),
        BitEnumField('gpe', 0, 1, _INT_GPE),
        BitField('reserved6', 0, 7),
        ByteField('vxlan_proto', 0),
        MultipleTypeField([
            (PacketField('metadata', None, INTMetaMd), lambda pkt: pkt.type == 1),
            (PacketField('metadata', None, INTMetaMx), lambda pkt: pkt.type == 3), ],
            PacketField('metadata', None, INTMetaMd)
        ),
    ]


bind_layers(UDP, INTShimTcpUdp, dport=INT_L4_DPORT)
bind_layers(TCP, INTShimTcpUdp, dport=INT_L4_DPORT)
bind_layers(GRE, INTShimGre, proto=INT_GRE_PROTOCOL)
bind_layers(VXLAN, INTShimVxlan, NextProtocol=INT_VXLAN_PROTOCOL)
