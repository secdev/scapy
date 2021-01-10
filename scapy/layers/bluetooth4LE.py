# This file is for use with Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Airbus DS CyberSecurity
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
# This program is published under a GPLv2 license

"""Bluetooth 4LE layer"""

import struct

from scapy.compat import orb, chb
from scapy.config import conf
from scapy.data import DLT_BLUETOOTH_LE_LL, DLT_BLUETOOTH_LE_LL_WITH_PHDR, \
    PPI_BTLE
from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    Field, FlagsField, LEIntField, LEShortEnumField, LEShortField, \
    MACField, PacketListField, SignedByteField, X3BytesField, XBitField, \
    XByteField, XIntField, XShortField, XLEIntField, XLELongField, \
    XLEShortField
from scapy.contrib.ethercat import LEBitEnumField, LEBitField

from scapy.layers.bluetooth import EIR_Hdr, L2CAP_Hdr
from scapy.layers.ppi import PPI_Element, PPI_Hdr

from scapy.modules.six.moves import range
from scapy.utils import mac2str, str2mac

####################
# Transport Layers #
####################


class BTLE_PPI(PPI_Element):
    """Cooked BTLE PPI header

    See ``ppi_btle_t`` in
    https://github.com/greatscottgadgets/libbtbb/blob/master/lib/src/pcap.c
    """
    name = "BTLE PPI header"
    fields_desc = [
        ByteField("btle_version", 0),
        # btle_channel is a frequency in MHz. Named for consistency with
        # other users.
        LEShortField("btle_channel", None),
        ByteField("btle_clkn_high", None),
        LEIntField("btle_clk_100ns", None),
        SignedByteField("rssi_max", None),
        SignedByteField("rssi_min", None),
        SignedByteField("rssi_avg", None),
        ByteField("rssi_count", None)
    ]


class BTLE_RF(Packet):
    """Cooked BTLE link-layer pseudoheader.

    https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.html
    """
    name = "BTLE RF info header"

    _TYPES = {
        0: "ADV_OR_DATA_UNKNOWN_DIR",
        1: "AUX_ADV",
        2: "DATA_M_TO_S",
        3: "DATA_S_TO_M",
        4: "CONN_ISO_M_TO_S",
        5: "CONN_ISO_S_TO_M",
        6: "BROADCAST_ISO",
        7: "RFU",
    }

    _PHY = {
        0: "1M",
        1: "2M",
        2: "Coded",
        3: "RFU",
    }

    fields_desc = [
        ByteField("rf_channel", 0),
        SignedByteField("signal", -128),
        SignedByteField("noise", -128),
        ByteField("access_address_offenses", 0),
        XLEIntField("reference_access_address", 0),
        LEBitField("dewhitened", 0, 1),
        LEBitField("sig_power_valid", 0, 1),
        LEBitField("noise_power_valid", 0, 1),
        LEBitField("decrypted", 0, 1),
        LEBitField("reference_access_address_valid", 0, 1),
        LEBitField("access_address_offenses_valid", 0, 1),
        LEBitField("channel_aliased", 0, 1),
        LEBitEnumField("type", 0, 3, _TYPES),
        LEBitField("crc_checked", 0, 1),
        LEBitField("crc_valid", 0, 1),
        LEBitField("mic_checked", 0, 1),
        LEBitField("mic_valid", 0, 1),
        LEBitEnumField("phy", 0, 2, _PHY),
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


class BTLEFeatureField(FlagsField):
    def __init__(self, name, default):
        super(BTLEFeatureField, self).__init__(
            name, default, -64,
            ['le_encryption',
             'conn_par_req_proc',
             'ext_reject_ind',
             'slave_init_feat_exch',
             'le_ping',
             'le_data_len_ext',
             'll_privacy',
             'ext_scan_filter',
             'le_2m_phy',
             'tx_mod_idx',
             'rx_mod_idx',
             'le_coded_phy',
             'le_ext_adv',
             'le_periodic_adv',
             'ch_sel_alg',
             'le_pwr_class']
        )


class BTLEPhysField(FlagsField):
    def __init__(self, name, default):
        super(BTLEPhysField, self).__init__(
            name, default, -8,
            ['phy_1m', 'phy_2m', 'phy_coded']
        )


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
    6: '4.0',
    7: '4.1',
    8: '4.2',
    9: '5.0',
    10: '5.1',
    11: '5.2',
}


BTLE_Corp_IDs = {
    0xf: 'Broadcom Corporation',
    0x59: 'Nordic Semiconductor ASA'
}


BTLE_BTLE_CTRL_opcode = {
    0x00: 'LL_CONNECTION_UPDATE_REQ',
    0x01: 'LL_CHANNEL_MAP_REQ',
    0x02: 'LL_TERMINATE_IND',
    0x03: 'LL_ENC_REQ',
    0x04: 'LL_ENC_RSP',
    0x05: 'LL_START_ENC_REQ',
    0x06: 'LL_START_ENC_RSP',
    0x07: 'LL_UNKNOWN_RSP',
    0x08: 'LL_FEATURE_REQ',
    0x09: 'LL_FEATURE_RSP',
    0x0A: 'LL_PAUSE_ENC_REQ',
    0x0B: 'LL_PAUSE_ENC_RSP',
    0x0C: 'LL_VERSION_IND',
    0x0D: 'LL_REJECT_IND',
    0x0E: 'LL_SLAVE_FEATURE_REQ',
    0x0F: 'LL_CONNECTION_PARAM_REQ',
    0x10: 'LL_CONNECTION_PARAM_RSP',
    0x14: 'LL_LENGTH_REQ',
    0x15: 'LL_LENGTH_RSP',
    0x16: 'LL_PHY_REQ',
    0x17: 'LL_PHY_RSP',
    0x18: 'LL_PHY_UPDATE_IND',
}


class BTLE_EMPTY_PDU(Packet):
    name = "Empty data PDU"


class BTLE_CTRL(Packet):
    name = "BTLE_CTRL"
    fields_desc = [
        ByteEnumField("opcode", 0, BTLE_BTLE_CTRL_opcode)
    ]


class LL_CONNECTION_UPDATE_IND(Packet):
    name = 'LL_CONNECTION_UPDATE_IND'
    fields_desc = [
        XByteField("win_size", 0),
        XLEShortField("win_offset", 0),
        XLEShortField("interval", 6),
        XLEShortField("latency", 0),
        XLEShortField("timeout", 50),
        XLEShortField("instant", 6),
    ]


class LL_CHANNEL_MAP_IND(Packet):
    name = 'LL_CHANNEL_MAP_IND'
    fields_desc = [
        BTLEChanMapField("chM", 0xFFFFFFFFFE),
        XLEShortField("instant", 0),
    ]


class LL_TERMINATE_IND(Packet):
    name = 'LL_TERMINATE_IND'
    fields_desc = [
        XByteField("code", 0x0),
    ]


class LL_ENC_REQ(Packet):
    name = 'LL_ENC_REQ'
    fields_desc = [
        XLELongField("rand", 0),
        XLEShortField("ediv", 0),
        XLELongField("skdm", 0),
        XLEIntField("ivm", 0),
    ]


class LL_ENC_RSP(Packet):
    name = 'LL_ENC_RSP'
    fields_desc = [
        XLELongField("skds", 0),
        XLEIntField("ivs", 0),
    ]


class LL_START_ENC_REQ(Packet):
    name = 'LL_START_ENC_REQ'
    fields_desc = []


class LL_START_ENC_RSP(Packet):
    name = 'LL_START_ENC_RSP'


class LL_UNKNOWN_RSP(Packet):
    name = 'LL_UNKNOWN_RSP'
    fields_desc = [
        XByteField("code", 0x0),
    ]


class LL_FEATURE_REQ(Packet):
    name = "LL_FEATURE_REQ"
    fields_desc = [
        BTLEFeatureField("feature_set", 0)
    ]


class LL_FEATURE_RSP(Packet):
    name = "LL_FEATURE_RSP"
    fields_desc = [
        BTLEFeatureField("feature_set", 0)
    ]


class LL_PAUSE_ENC_REQ(Packet):
    name = "LL_PAUSE_ENC_REQ"


class LL_PAUSE_ENC_RSP(Packet):
    name = "LL_PAUSE_ENC_RSP"


class LL_VERSION_IND(Packet):
    name = "LL_VERSION_IND"
    fields_desc = [
        ByteEnumField("version", 8, BTLE_Versions),
        LEShortEnumField("company", 0, BTLE_Corp_IDs),
        XShortField("subversion", 0)
    ]


class LL_REJECT_IND(Packet):
    name = "LL_REJECT_IND"
    fields_desc = [
        XByteField("code", 0x0),
    ]


class LL_SLAVE_FEATURE_REQ(Packet):
    name = "LL_SLAVE_FEATURE_REQ"
    fields_desc = [
        BTLEFeatureField("feature_set", 0)
    ]


class LL_CONNECTION_PARAM_REQ(Packet):
    name = "LL_CONNECTION_PARAM_REQ"
    fields_desc = [
        XShortField("interval_min", 0x6),
        XShortField("interval_max", 0x6),
        XShortField("latency", 0x0),
        XShortField("timeout", 0x0),
        XByteField("preferred_periodicity", 0x0),
        XShortField("reference_conn_evt_count", 0x0),
        XShortField("offset0", 0x0),
        XShortField("offset1", 0x0),
        XShortField("offset2", 0x0),
        XShortField("offset3", 0x0),
        XShortField("offset4", 0x0),
        XShortField("offset5", 0x0),
    ]


class LL_CONNECTION_PARAM_RSP(Packet):
    name = "LL_CONNECTION_PARAM_RSP"
    fields_desc = [
        XShortField("interval_min", 0x6),
        XShortField("interval_max", 0x6),
        XShortField("latency", 0x0),
        XShortField("timeout", 0x0),
        XByteField("preferred_periodicity", 0x0),
        XShortField("reference_conn_evt_count", 0x0),
        XShortField("offset0", 0x0),
        XShortField("offset1", 0x0),
        XShortField("offset2", 0x0),
        XShortField("offset3", 0x0),
        XShortField("offset4", 0x0),
        XShortField("offset5", 0x0),
    ]


class LL_REJECT_EXT_IND(Packet):
    name = "LL_REJECT_EXT_IND"
    fields_desc = [
        XByteField("reject_opcode", 0x0),
        XByteField("error_code", 0x0),
    ]


class LL_PING_REQ(Packet):
    name = "LL_PING_REQ"


class LL_PING_RSP(Packet):
    name = "LL_PING_RSP"


class LL_LENGTH_REQ(Packet):
    name = ' LL_LENGTH_REQ'
    fields_desc = [
        XLEShortField("max_rx_bytes", 251),
        XLEShortField("max_rx_time", 2120),
        XLEShortField("max_tx_bytes", 251),
        XLEShortField("max_tx_time", 2120),
    ]


class LL_LENGTH_RSP(Packet):
    name = ' LL_LENGTH_RSP'
    fields_desc = [
        XLEShortField("max_rx_bytes", 251),
        XLEShortField("max_rx_time", 2120),
        XLEShortField("max_tx_bytes", 251),
        XLEShortField("max_tx_time", 2120),
    ]


class LL_PHY_REQ(Packet):
    name = "LL_PHY_REQ"
    fields_desc = [
        BTLEPhysField('tx_phys', 0),
        BTLEPhysField('rx_phys', 0),
    ]


class LL_PHY_RSP(Packet):
    name = "LL_PHY_RSP"
    fields_desc = [
        BTLEPhysField('tx_phys', 0),
        BTLEPhysField('rx_phys', 0),
    ]


class LL_PHY_UPDATE_IND(Packet):
    name = "LL_PHY_UPDATE_IND"
    fields_desc = [
        BTLEPhysField('tx_phy', 0),
        BTLEPhysField('rx_phy', 0),
        XShortField("instant", 0x0),
    ]


class LL_MIN_USED_CHANNELS_IND(Packet):
    name = "LL_MIN_USED_CHANNELS_IND"
    fields_desc = [
        BTLEPhysField('phys', 0),
        ByteField("min_used_channels", 2),
    ]


# Advertisement (37-39) channel PDUs
bind_layers(BTLE, BTLE_ADV, access_addr=0x8E89BED6)
bind_layers(BTLE, BTLE_DATA)
bind_layers(BTLE_ADV, BTLE_ADV_IND, PDU_type=0)
bind_layers(BTLE_ADV, BTLE_ADV_DIRECT_IND, PDU_type=1)
bind_layers(BTLE_ADV, BTLE_ADV_NONCONN_IND, PDU_type=2)
bind_layers(BTLE_ADV, BTLE_SCAN_REQ, PDU_type=3)
bind_layers(BTLE_ADV, BTLE_SCAN_RSP, PDU_type=4)
bind_layers(BTLE_ADV, BTLE_CONNECT_REQ, PDU_type=5)
bind_layers(BTLE_ADV, BTLE_ADV_SCAN_IND, PDU_type=6)

# Data channel (0-36) PDUs
# LLID=1 -> Continue
bind_layers(BTLE_DATA, L2CAP_Hdr, LLID=2)
bind_layers(BTLE_DATA, BTLE_CTRL, LLID=3)
bind_layers(BTLE_DATA, BTLE_EMPTY_PDU, {'len': 0, 'LLID': 1})
bind_layers(BTLE_CTRL, LL_CONNECTION_UPDATE_IND, opcode=0x00)
bind_layers(BTLE_CTRL, LL_CHANNEL_MAP_IND, opcode=0x01)
bind_layers(BTLE_CTRL, LL_TERMINATE_IND, opcode=0x02)
bind_layers(BTLE_CTRL, LL_ENC_REQ, opcode=0x03)
bind_layers(BTLE_CTRL, LL_ENC_RSP, opcode=0x04)
bind_layers(BTLE_CTRL, LL_START_ENC_REQ, opcode=0x05)
bind_layers(BTLE_CTRL, LL_START_ENC_RSP, opcode=0x06)
bind_layers(BTLE_CTRL, LL_UNKNOWN_RSP, opcode=0x07)
bind_layers(BTLE_CTRL, LL_FEATURE_REQ, opcode=0x08)
bind_layers(BTLE_CTRL, LL_FEATURE_RSP, opcode=0x09)
bind_layers(BTLE_CTRL, LL_PAUSE_ENC_REQ, opcode=0x0A)
bind_layers(BTLE_CTRL, LL_PAUSE_ENC_RSP, opcode=0x0B)
bind_layers(BTLE_CTRL, LL_VERSION_IND, opcode=0x0C)
bind_layers(BTLE_CTRL, LL_REJECT_IND, opcode=0x0D)
bind_layers(BTLE_CTRL, LL_SLAVE_FEATURE_REQ, opcode=0x0E)
bind_layers(BTLE_CTRL, LL_CONNECTION_PARAM_REQ, opcode=0x0F)
bind_layers(BTLE_CTRL, LL_CONNECTION_PARAM_RSP, opcode=0x10)
bind_layers(BTLE_CTRL, LL_REJECT_EXT_IND, opcode=0x11)
bind_layers(BTLE_CTRL, LL_PING_REQ, opcode=0x12)
bind_layers(BTLE_CTRL, LL_PING_RSP, opcode=0x13)
bind_layers(BTLE_CTRL, LL_LENGTH_REQ, opcode=0x14)
bind_layers(BTLE_CTRL, LL_LENGTH_RSP, opcode=0x15)
bind_layers(BTLE_CTRL, LL_PHY_REQ, opcode=0x16)
bind_layers(BTLE_CTRL, LL_PHY_RSP, opcode=0x17)
bind_layers(BTLE_CTRL, LL_PHY_UPDATE_IND, opcode=0x18)
bind_layers(BTLE_CTRL, LL_MIN_USED_CHANNELS_IND, opcode=0x19)


conf.l2types.register(DLT_BLUETOOTH_LE_LL, BTLE)
conf.l2types.register(DLT_BLUETOOTH_LE_LL_WITH_PHDR, BTLE_RF)

bind_layers(BTLE_RF, BTLE)

bind_layers(PPI_Hdr, BTLE_PPI, pfh_type=PPI_BTLE)
