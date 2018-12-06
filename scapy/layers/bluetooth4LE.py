# This file is for use with Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Airbus DS CyberSecurity
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
# This program is published under a GPLv2 license

"""Bluetooth 4LE layer"""

import struct

from scapy.compat import orb, chb
from scapy.config import conf
from scapy.data import DLT_BLUETOOTH_LE_LL, DLT_BLUETOOTH_LE_LL_WITH_PHDR
from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    Field, FlagsField, LEIntField, LEShortEnumField, LEShortField, MACField, \
    PacketListField, X3BytesField, XBitField, XByteField, XIntField, \
    XShortField, XLEIntField, XLEShortField
from scapy.layers.dot11 import _dbmField
from scapy.layers.ppi import PPI, addPPIType

from scapy.layers.bluetooth import EIR_Hdr, L2CAP_Hdr

from scapy.modules.six.moves import range
from scapy.utils import mac2str, str2mac

####################
# Transport Layers #
####################


class BTLE_PPI(Packet):
    name = "BTLE PPI header"
    fields_desc = [
        LEShortField("pfh_type", 30006),
        LEShortField("pfh_datalen", 24),
        ByteField("btle_version", 0),
        LEShortField("btle_channel", None),
        ByteField("btle_clkn_high", None),
        LEIntField("btle_clk_100ns", None),
        Field("rssi_max", None, fmt="b"),
        Field("rssi_min", None, fmt="b"),
        Field("rssi_avg", None, fmt="b"),
        ByteField("rssi_count", None)
    ]


class BTLE_RF(Packet):
    name = "BTLE RF info header"
    fields_desc = [
        ByteField("rf_channel", 0),
        _dbmField("signal", -256),
        _dbmField("noise", -256),
        ByteField("access_address_offenses", 0),
        XLEIntField("reference_access_address", 0),
        FlagsField("flags", 0, -16, [
            "dewhitened", "sig_power_valid", "noise_power_valid",
            "decrypted", "reference_access_address_valid",
            "access_address_offenses_valid", "channel_aliased",
            "res1", "res2", "res3", "crc_checked", "crc_valid",
            "mic_checked", "mic_valid", "res4", "res5"
        ])
    ]


##########
# Fields #
##########

class BDAddrField(MACField):
    def __init__(self, name, default, resolve=False):
        MACField.__init__(self, name, default)
        if resolve:
            conf.resolve.add(self)

    def i2m(self, pkt, x):
        if x is None:
            return b"\0\0\0\0\0\0"
        return mac2str(':'.join(x.split(':')[::-1]))

    def m2i(self, pkt, x):
        return str2mac(x[::-1])


class BTLEChanMapField(XByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[:5]

    def getfield(self, pkt, s):
        return s[5:], self.m2i(pkt, struct.unpack(self.fmt, s[:5] + b"\x00\x00\x00")[0])  # noqa: E501


##########
# Layers #
##########

class BTLE(Packet):
    name = "BT4LE"
    fields_desc = [
        XLEIntField("access_addr", 0x8E89BED6),
        X3BytesField("crc", None)
    ]

    @staticmethod
    def compute_crc(pdu, init=0x555555):
        def swapbits(a):
            v = 0
            if a & 0x80 != 0:
                v |= 0x01
            if a & 0x40 != 0:
                v |= 0x02
            if a & 0x20 != 0:
                v |= 0x04
            if a & 0x10 != 0:
                v |= 0x08
            if a & 0x08 != 0:
                v |= 0x10
            if a & 0x04 != 0:
                v |= 0x20
            if a & 0x02 != 0:
                v |= 0x40
            if a & 0x01 != 0:
                v |= 0x80
            return v

        state = swapbits(init & 0xff) + (swapbits((init >> 8) & 0xff) << 8) + (swapbits((init >> 16) & 0xff) << 16)  # noqa: E501
        lfsr_mask = 0x5a6000
        for i in (orb(x) for x in pdu):
            for j in range(8):
                next_bit = (state ^ i) & 1
                i >>= 1
                state >>= 1
                if next_bit:
                    state |= 1 << 23
                    state ^= lfsr_mask
        return struct.pack("<L", state)[:-1]

    def post_build(self, p, pay):
        # Switch payload and CRC
        crc = p[-3:]
        p = p[:-3] + pay
        p += crc if self.crc is not None else self.compute_crc(p[4:])
        return p

    def post_dissect(self, s):
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def pre_dissect(self, s):
        # move crc
        return s[:4] + s[-3:] + s[4:-3]

    def hashret(self):
        return struct.pack("!L", self.access_addr)


class BTLE_ADV(Packet):
    name = "BTLE advertising header"
    fields_desc = [
        BitEnumField("RxAdd", 0, 1, {0: "public", 1: "random"}),
        BitEnumField("TxAdd", 0, 1, {0: "public", 1: "random"}),
        BitField("RFU", 0, 2),  # Unused
        BitEnumField("PDU_type", 0, 4, {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",  # noqa: E501
                                        4: "SCAN_RSP", 5: "CONNECT_REQ", 6: "ADV_SCAN_IND"}),  # noqa: E501
        BitField("unused", 0, 2),  # Unused
        XBitField("Length", None, 6),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.Length is None:
            if len(pay) > 2:
                l_pay = len(pay)
            else:
                l_pay = 0
            p = p[:1] + chb(l_pay & 0x3f) + p[2:]
        if not isinstance(self.underlayer, BTLE):
            self.add_underlayer(BTLE)
        return p


class BTLE_DATA(Packet):
    name = "BTLE data header"
    fields_desc = [
        BitField("RFU", 0, 3),  # Unused
        BitField("MD", 0, 1),
        BitField("SN", 0, 1),
        BitField("NESN", 0, 1),
        BitEnumField("LLID", 0, 2, {1: "continue", 2: "start", 3: "control"}),
        ByteField("len", None),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            p = p[:-1] + chb(len(pay))
        return p + pay


class BTLE_ADV_IND(Packet):
    name = "BTLE ADV_IND"
    fields_desc = [
        BDAddrField("AdvA", None),
        PacketListField("data", None, EIR_Hdr)
    ]


class BTLE_ADV_DIRECT_IND(Packet):
    name = "BTLE ADV_DIRECT_IND"
    fields_desc = [
        BDAddrField("AdvA", None),
        BDAddrField("InitA", None)
    ]


class BTLE_ADV_NONCONN_IND(BTLE_ADV_IND):
    name = "BTLE ADV_NONCONN_IND"


class BTLE_ADV_SCAN_IND(BTLE_ADV_IND):
    name = "BTLE ADV_SCAN_IND"


class BTLE_SCAN_REQ(Packet):
    name = "BTLE scan request"
    fields_desc = [
        BDAddrField("ScanA", None),
        BDAddrField("AdvA", None)
    ]

    def answers(self, other):
        return BTLE_SCAN_RSP in other and self.AdvA == other.AdvA


class BTLE_SCAN_RSP(Packet):
    name = "BTLE scan response"
    fields_desc = [
        BDAddrField("AdvA", None),
        PacketListField("data", None, EIR_Hdr)
    ]

    def answers(self, other):
        return BTLE_SCAN_REQ in other and self.AdvA == other.AdvA


class BTLE_CONNECT_REQ(Packet):
    name = "BTLE connect request"
    fields_desc = [
        BDAddrField("InitA", None),
        BDAddrField("AdvA", None),
        # LLDATA
        XIntField("AA", 0x00),
        X3BytesField("crc_init", 0x0),
        XByteField("win_size", 0x0),
        XLEShortField("win_offset", 0x0),
        XLEShortField("interval", 0x0),
        XLEShortField("latency", 0x0),
        XLEShortField("timeout", 0x0),
        BTLEChanMapField("chM", 0),
        BitField("SCA", 0, 3),
        BitField("hop", 0, 5),
    ]


BTLE_Versions = {
    7: '4.1'
}
BTLE_Corp_IDs = {
    0xf: 'Broadcom Corporation'
}


class CtrlPDU(Packet):
    name = "CtrlPDU"
    fields_desc = [
        XByteField("optcode", 0),
        ByteEnumField("version", 0, BTLE_Versions),
        LEShortEnumField("Company", 0, BTLE_Corp_IDs),
        XShortField("subversion", 0)
    ]


bind_layers(BTLE, BTLE_ADV, access_addr=0x8E89BED6)
bind_layers(BTLE, BTLE_DATA)
bind_layers(BTLE_ADV, BTLE_ADV_IND, PDU_type=0)
bind_layers(BTLE_ADV, BTLE_ADV_DIRECT_IND, PDU_type=1)
bind_layers(BTLE_ADV, BTLE_ADV_NONCONN_IND, PDU_type=2)
bind_layers(BTLE_ADV, BTLE_SCAN_REQ, PDU_type=3)
bind_layers(BTLE_ADV, BTLE_SCAN_RSP, PDU_type=4)
bind_layers(BTLE_ADV, BTLE_CONNECT_REQ, PDU_type=5)
bind_layers(BTLE_ADV, BTLE_ADV_SCAN_IND, PDU_type=6)

bind_layers(BTLE_DATA, L2CAP_Hdr, LLID=2)  # BTLE_DATA / L2CAP_Hdr / ATT_Hdr
# LLID=1 -> Continue
bind_layers(BTLE_DATA, CtrlPDU, LLID=3)

conf.l2types.register(DLT_BLUETOOTH_LE_LL, BTLE)
conf.l2types.register(DLT_BLUETOOTH_LE_LL_WITH_PHDR, BTLE_RF)

bind_layers(BTLE_RF, BTLE)

bind_layers(PPI, BTLE, dlt=147)
addPPIType(30006, BTLE_PPI)
