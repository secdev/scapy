# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Wireless LAN according to IEEE 802.11.

This file contains bindings for 802.11 layers and some usual linklayers:
  - PRISM
  - RadioTap
"""

from __future__ import print_function
import re
import struct
from zlib import crc32

from scapy.config import conf, crypto_validator
from scapy.data import ETHER_ANY, DLT_IEEE802_11, DLT_PRISM_HEADER, \
    DLT_IEEE802_11_RADIO
from scapy.compat import raw, plain_str, orb, chb
from scapy.packet import Packet, bind_layers, bind_top_down, NoPayload
from scapy.fields import (
    BitEnumField,
    BitField,
    BitMultiEnumField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    FCSField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IntField,
    LEFieldLenField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    LESignedIntField,
    MultipleTypeField,
    OUIField,
    PacketField,
    PacketListField,
    ReversePadField,
    ScalingField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    XByteField,
    XStrFixedLenField,
)
from scapy.ansmachine import AnsweringMachine
from scapy.plist import PacketList
from scapy.layers.l2 import Ether, LLC, MACField
from scapy.layers.inet import IP, TCP
from scapy.error import warning, log_loading
from scapy.sendrecv import sniff, sendp


if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
else:
    default_backend = Ciphers = algorithms = None
    log_loading.info("Can't import python-cryptography v1.7+. Disabled WEP decryption/encryption. (Dot11)")  # noqa: E501


#########
# Prism #
#########

# http://www.martin.cc/linux/prism

class PrismHeader(Packet):
    """ iwpriv wlan0 monitor 3 """
    name = "Prism header"
    fields_desc = [LEIntField("msgcode", 68),
                   LEIntField("len", 144),
                   StrFixedLenField("dev", "", 16),
                   LEIntField("hosttime_did", 0),
                   LEShortField("hosttime_status", 0),
                   LEShortField("hosttime_len", 0),
                   LEIntField("hosttime", 0),
                   LEIntField("mactime_did", 0),
                   LEShortField("mactime_status", 0),
                   LEShortField("mactime_len", 0),
                   LEIntField("mactime", 0),
                   LEIntField("channel_did", 0),
                   LEShortField("channel_status", 0),
                   LEShortField("channel_len", 0),
                   LEIntField("channel", 0),
                   LEIntField("rssi_did", 0),
                   LEShortField("rssi_status", 0),
                   LEShortField("rssi_len", 0),
                   LEIntField("rssi", 0),
                   LEIntField("sq_did", 0),
                   LEShortField("sq_status", 0),
                   LEShortField("sq_len", 0),
                   LEIntField("sq", 0),
                   LEIntField("signal_did", 0),
                   LEShortField("signal_status", 0),
                   LEShortField("signal_len", 0),
                   LESignedIntField("signal", 0),
                   LEIntField("noise_did", 0),
                   LEShortField("noise_status", 0),
                   LEShortField("noise_len", 0),
                   LEIntField("noise", 0),
                   LEIntField("rate_did", 0),
                   LEShortField("rate_status", 0),
                   LEShortField("rate_len", 0),
                   LEIntField("rate", 0),
                   LEIntField("istx_did", 0),
                   LEShortField("istx_status", 0),
                   LEShortField("istx_len", 0),
                   LEIntField("istx", 0),
                   LEIntField("frmlen_did", 0),
                   LEShortField("frmlen_status", 0),
                   LEShortField("frmlen_len", 0),
                   LEIntField("frmlen", 0),
                   ]

    def answers(self, other):
        if isinstance(other, PrismHeader):
            return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)

############
# RadioTap #
############

# https://www.radiotap.org/

# Note: Radiotap alignment is crazy. See the doc:
# https://www.radiotap.org/#alignment-in-radiotap

# RadioTap constants


_rt_present = ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',
               'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation',
               'dB_TX_Attenuation', 'dBm_TX_Power', 'Antenna',
               'dB_AntSignal', 'dB_AntNoise', 'RXFlags', 'TXFlags',
               'b17', 'b18', 'ChannelPlus', 'MCS', 'A_MPDU',
               'VHT', 'timestamp', 'HE', 'HE_MU', 'HE_MU_other_user',
               'zero_length_psdu', 'L_SIG', 'TLV',
               'RadiotapNS', 'VendorNS', 'Ext']

# Note: Inconsistencies with wireshark
# Wireshark ignores the suggested fields, whereas we implement some of them
# (some are well-used even though not accepted)
# However, flags that conflicts with Wireshark are not and MUST NOT be
# implemented -> b17, b18

_rt_flags = ['CFP', 'ShortPreamble', 'wep', 'fragment', 'FCS', 'pad',
             'badFCS', 'ShortGI']

_rt_channelflags = ['res1', 'res2', 'res3', 'res4', 'Turbo', 'CCK',
                    'OFDM', '2GHz', '5GHz', 'Passive', 'Dynamic_CCK_OFDM',
                    'GFSK', 'GSM', 'StaticTurbo', '10MHz', '5MHz']

_rt_rxflags = ["res1", "BAD_PLCP", "res2"]

_rt_txflags = ["TX_FAIL", "CTS", "RTS", "NOACK", "NOSEQ", "ORDER"]

_rt_channelflags2 = ['res1', 'res2', 'res3', 'res4', 'Turbo', 'CCK',
                     'OFDM', '2GHz', '5GHz', 'Passive', 'Dynamic_CCK_OFDM',
                     'GFSK', 'GSM', 'StaticTurbo', '10MHz', '5MHz',
                     '20MHz', '40MHz_ext_channel_above',
                     '40MHz_ext_channel_below',
                     'res5', 'res6', 'res7', 'res8', 'res9']

_rt_knownmcs = ['MCS_bandwidth', 'MCS_index', 'guard_interval', 'HT_format',
                'FEC_type', 'STBC_streams', 'Ness', 'Ness_MSB']

_rt_bandwidth = {0: "20MHz", 1: "40MHz", 2: "ht40Mhz-", 3: "ht40MHz+"}

_rt_a_mpdu_flags = ['Report0Subframe', 'Is0Subframe', 'KnownLastSubframe',
                    'LastSubframe', 'CRCerror', 'EOFsubframe', 'KnownEOF',
                    'res1', 'res2', 'res3', 'res4', 'res5', 'res6', 'res7',
                    'res8']

_rt_vhtbandwidth = {
    0: "20MHz", 1: "40MHz", 2: "40MHz", 3: "40MHz", 4: "80MHz", 5: "80MHz",
    6: "80MHz", 7: "80MHz", 8: "80MHz", 9: "80MHz", 10: "80MHz", 11: "160MHz",
    12: "160MHz", 13: "160MHz", 14: "160MHz", 15: "160MHz", 16: "160MHz",
    17: "160MHz", 18: "160MHz", 19: "160MHz", 20: "160MHz", 21: "160MHz",
    22: "160MHz", 23: "160MHz", 24: "160MHz", 25: "160MHz"
}

_rt_knownvht = ['STBC', 'TXOP_PS_NOT_ALLOWED', 'GuardInterval', 'SGINsysmDis',
                'LDPCextraOFDM', 'Beamformed', 'Bandwidth', 'GroupID',
                'PartialAID',
                'res1', 'res2', 'res3', 'res4', 'res5', 'res6', 'res7']

_rt_presentvht = ['STBC', 'TXOP_PS_NOT_ALLOWED', 'GuardInterval',
                  'SGINsysmDis', 'LDPCextraOFDM', 'Beamformed',
                  'res1', 'res2']

_rt_hemuother_per_user_known = {
    'user field position',
    'STA-ID',
    'NSTS',
    'Tx Beamforming',
    'Spatial Configuration',
    'MCS',
    'DCM',
    'Coding',
}


# Radiotap utils

# Note: extended presence masks are dissected pretty dumbly by
# Wireshark.

def _next_radiotap_extpm(pkt, lst, cur, s):
    """Generates the next RadioTapExtendedPresenceMask"""
    if cur is None or (cur.present and cur.present.Ext):
        st = len(lst) + (cur is not None)
        return lambda *args: RadioTapExtendedPresenceMask(*args, index=st)
    return None


class RadioTapExtendedPresenceMask(Packet):
    """RadioTapExtendedPresenceMask should be instantiated by passing an
    `index=` kwarg, stating which place the item has in the list.

    Passing index will update the b[x] fields accordingly to the index.
      e.g.
       >>> a = RadioTapExtendedPresenceMask(present="b0+b12+b29+Ext")
       >>> b = RadioTapExtendedPresenceMask(index=1, present="b33+b45+b59+b62")
       >>> pkt = RadioTap(present="Ext", Ext=[a, b])
    """
    name = "RadioTap Extended presence mask"
    fields_desc = [FlagsField('present', None, -32,
                              ["b%s" % i for i in range(0, 31)] + ["Ext"])]

    def __init__(self, _pkt=None, index=0, **kwargs):
        self._restart_indentation(index)
        Packet.__init__(self, _pkt, **kwargs)

    def _restart_indentation(self, index):
        st = index * 32
        self.fields_desc[0].names = ["b%s" % (i + st) for i in range(0, 31)] + ["Ext"]  # noqa: E501

    def guess_payload_class(self, pay):
        return conf.padding_layer


# This is still unimplemented in Wireshark
# https://www.radiotap.org/fields/TLV.html
class RadioTapTLV(Packet):
    fields_desc = [
        LEShortEnumField("type", 0, _rt_present),
        LEShortField("length", None),
        ConditionalField(
            OUIField("oui", 0),
            lambda pkt: pkt.type == 30  # VendorNS
        ),
        ConditionalField(
            ByteField("subtype", 0),
            lambda pkt: pkt.type == 30
        ),
        ConditionalField(
            LEShortField("presence_type", 0),
            lambda pkt: pkt.type == 30
        ),
        ConditionalField(
            LEShortField("reserved", 0),
            lambda pkt: pkt.type == 30
        ),
        StrLenField("data", b"",
                    length_from=lambda pkt: pkt.length),
        StrLenField("pad", None, length_from=lambda pkt: -pkt.length % 4)
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            pkt = pkt[:2] + struct.pack("<H", len(self.data)) + pkt[4:]
        if self.pad is None:
            pkt += b"\x00" * (-len(self.data) % 4)
        return pkt + pay

    def extract_padding(self, s):
        return "", s


# RADIOTAP

class RadioTap(Packet):
    name = "RadioTap"
    deprecated_fields = {
        "Channel": ("ChannelFrequency", "2.4.3"),
        "ChannelFlags2": ("ChannelPlusFlags", "2.4.3"),
        "ChannelNumber": ("ChannelPlusNumber", "2.4.3"),
    }
    fields_desc = [
        ByteField('version', 0),
        ByteField('pad', 0),
        LEShortField('len', None),
        FlagsField('present', None, -32, _rt_present),  # noqa: E501
        # Extended presence mask
        ConditionalField(PacketListField("Ext", [], next_cls_cb=_next_radiotap_extpm), lambda pkt: pkt.present and pkt.present.Ext),  # noqa: E501
        # RadioTap fields - each starts with a ReversePadField
        # to handle padding

        # TSFT
        ConditionalField(
            ReversePadField(
                LELongField("mac_timestamp", 0),
                8
            ),
            lambda pkt: pkt.present and pkt.present.TSFT),
        # Flags
        ConditionalField(
            FlagsField("Flags", None, -8, _rt_flags),
            lambda pkt: pkt.present and pkt.present.Flags),
        # Rate
        ConditionalField(
            ScalingField("Rate", 0, scaling=0.5,
                         unit="Mbps", fmt="B"),
            lambda pkt: pkt.present and pkt.present.Rate),
        # Channel
        ConditionalField(
            ReversePadField(
                LEShortField("ChannelFrequency", 0),
                2
            ),
            lambda pkt: pkt.present and pkt.present.Channel),
        ConditionalField(
            FlagsField("ChannelFlags", None, -16, _rt_channelflags),
            lambda pkt: pkt.present and pkt.present.Channel),
        # dBm_AntSignal
        ConditionalField(
            ScalingField("dBm_AntSignal", 0,
                         unit="dBm", fmt="b"),
            lambda pkt: pkt.present and pkt.present.dBm_AntSignal),
        # dBm_AntNoise
        ConditionalField(
            ScalingField("dBm_AntNoise", 0,
                         unit="dBm", fmt="b"),
            lambda pkt: pkt.present and pkt.present.dBm_AntNoise),
        # Lock_Quality
        ConditionalField(
            ReversePadField(
                LEShortField("Lock_Quality", 0),
                2
            ),
            lambda pkt: pkt.present and pkt.present.Lock_Quality),
        # Antenna
        ConditionalField(
            ByteField("Antenna", 0),
            lambda pkt: pkt.present and pkt.present.Antenna),
        # RX Flags
        ConditionalField(
            ReversePadField(
                FlagsField("RXFlags", None, -16, _rt_rxflags),
                2
            ),
            lambda pkt: pkt.present and pkt.present.RXFlags),
        # TX Flags
        ConditionalField(
            ReversePadField(
                FlagsField("TXFlags", None, -16, _rt_txflags),
                2
            ),
            lambda pkt: pkt.present and pkt.present.TXFlags),
        # ChannelPlus
        ConditionalField(
            ReversePadField(
                FlagsField("ChannelPlusFlags", None, -32, _rt_channelflags2),
                4
            ),
            lambda pkt: pkt.present and pkt.present.ChannelPlus),
        ConditionalField(
            LEShortField("ChannelPlusFrequency", 0),
            lambda pkt: pkt.present and pkt.present.ChannelPlus),
        ConditionalField(
            ByteField("ChannelPlusNumber", 0),
            lambda pkt: pkt.present and pkt.present.ChannelPlus),
        # MCS
        ConditionalField(
            ReversePadField(
                FlagsField("knownMCS", None, -8, _rt_knownmcs),
                4
            ),
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            BitField("Ness_LSB", 0, 1),
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            BitField("STBC_streams", 0, 2),
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            BitEnumField("FEC_type", 0, 1, {0: "BCC", 1: "LDPC"}),
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            BitEnumField("HT_format", 0, 1, {0: "mixed", 1: "greenfield"}),
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            BitEnumField("guard_interval", 0, 1, {0: "Long_GI", 1: "Short_GI"}),  # noqa: E501
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            BitEnumField("MCS_bandwidth", 0, 2, _rt_bandwidth),
            lambda pkt: pkt.present and pkt.present.MCS),
        ConditionalField(
            ByteField("MCS_index", 0),
            lambda pkt: pkt.present and pkt.present.MCS),
        # A_MPDU
        ConditionalField(
            ReversePadField(
                LEIntField("A_MPDU_ref", 0),
                4
            ),
            lambda pkt: pkt.present and pkt.present.A_MPDU),
        ConditionalField(
            FlagsField("A_MPDU_flags", None, -32, _rt_a_mpdu_flags),
            lambda pkt: pkt.present and pkt.present.A_MPDU),
        # VHT
        ConditionalField(
            ReversePadField(
                FlagsField("KnownVHT", None, -16, _rt_knownvht),
                2
            ),
            lambda pkt: pkt.present and pkt.present.VHT),
        ConditionalField(
            FlagsField("PresentVHT", None, -8, _rt_presentvht),
            lambda pkt: pkt.present and pkt.present.VHT),
        ConditionalField(
            ByteEnumField("VHT_bandwidth", 0, _rt_vhtbandwidth),
            lambda pkt: pkt.present and pkt.present.VHT),
        ConditionalField(
            StrFixedLenField("mcs_nss", 0, length=5),
            lambda pkt: pkt.present and pkt.present.VHT),
        ConditionalField(
            ByteField("GroupID", 0),
            lambda pkt: pkt.present and pkt.present.VHT),
        ConditionalField(
            ShortField("PartialAID", 0),
            lambda pkt: pkt.present and pkt.present.VHT),
        # timestamp
        ConditionalField(
            ReversePadField(
                LELongField("timestamp", 0),
                8
            ),
            lambda pkt: pkt.present and pkt.present.timestamp),
        ConditionalField(
            LEShortField("ts_accuracy", 0),
            lambda pkt: pkt.present and pkt.present.timestamp),
        ConditionalField(
            ByteField("ts_position", 0),
            lambda pkt: pkt.present and pkt.present.timestamp),
        ConditionalField(
            ByteField("ts_flags", 0),
            lambda pkt: pkt.present and pkt.present.timestamp),
        # HE - XXX not complete
        ConditionalField(
            ReversePadField(
                ShortField("he_data1", 0),
                2
            ),
            lambda pkt: pkt.present and pkt.present.HE),
        ConditionalField(
            ShortField("he_data2", 0),
            lambda pkt: pkt.present and pkt.present.HE),
        ConditionalField(
            ShortField("he_data3", 0),
            lambda pkt: pkt.present and pkt.present.HE),
        ConditionalField(
            ShortField("he_data4", 0),
            lambda pkt: pkt.present and pkt.present.HE),
        ConditionalField(
            ShortField("he_data5", 0),
            lambda pkt: pkt.present and pkt.present.HE),
        ConditionalField(
            ShortField("he_data6", 0),
            lambda pkt: pkt.present and pkt.present.HE),
        # HE_MU
        ConditionalField(
            ReversePadField(
                LEShortField("hemu_flags1", 0),
                2
            ),
            lambda pkt: pkt.present and pkt.present.HE_MU),
        ConditionalField(
            LEShortField("hemu_flags2", 0),
            lambda pkt: pkt.present and pkt.present.HE_MU),
        ConditionalField(
            FieldListField("RU_channel1", [], ByteField,
                           count_from=lambda x: 4),
            lambda pkt: pkt.present and pkt.present.HE_MU),
        ConditionalField(
            FieldListField("RU_channel2", [], ByteField,
                           count_from=lambda x: 4),
            lambda pkt: pkt.present and pkt.present.HE_MU),
        # HE_MU_other_user
        ConditionalField(
            ReversePadField(
                LEShortField("hemuou_per_user_1", 0x7fff),
                2
            ),
            lambda pkt: pkt.present and pkt.present.HE_MU_other_user),
        ConditionalField(
            LEShortField("hemuou_per_user_2", 0x003f),
            lambda pkt: pkt.present and pkt.present.HE_MU_other_user),
        ConditionalField(
            ByteField("hemuou_per_user_position", 0),
            lambda pkt: pkt.present and pkt.present.HE_MU_other_user),
        ConditionalField(
            FlagsField("hemuou_per_user_known", 0, -16,
                       _rt_hemuother_per_user_known),
            lambda pkt: pkt.present and pkt.present.HE_MU_other_user),
        # L_SIG
        ConditionalField(
            ReversePadField(
                FlagsField("lsig_data1", 0, -16, ["rate", "length"]),
                2
            ),
            lambda pkt: pkt.present and pkt.present.L_SIG),
        ConditionalField(
            BitField("lsig_length", 0, 12),
            lambda pkt: pkt.present and pkt.present.L_SIG),
        ConditionalField(
            BitField("lsig_rate", 0, 4),
            lambda pkt: pkt.present and pkt.present.L_SIG),
        # TLV fields
        ConditionalField(
            ReversePadField(
                PacketListField("tlvs", [], RadioTapTLV),
                4
            ),
            lambda pkt: pkt.present and pkt.present.TLV,
        ),
        # Remaining
        StrLenField('notdecoded', "", length_from=lambda pkt: 0)
    ]

    def guess_payload_class(self, payload):
        if self.present and self.present.Flags and self.Flags.FCS:
            return Dot11FCS
        return Dot11

    def post_dissect(self, s):
        length = max(self.len - len(self.original) + len(s), 0)
        self.notdecoded = s[:length]
        return s[length:]

    def post_build(self, p, pay):
        if self.len is None:
            p = p[:2] + struct.pack("!H", len(p))[::-1] + p[4:]
        return p + pay


##########
# 802.11 #
##########

# Note:
# 802.11-2016 includes the spec for
# 802.11abdghijekrywnpzvus,ae,aa,ad,ac,af

# 802.11-2016 9.2

# 802.11-2016 9.2.4.1.3
_dot11_subtypes = {
    0: {  # Management
        0: "Association Request",
        1: "Association Response",
        2: "Reassociation Request",
        3: "Reassociation Response",
        4: "Probe Request",
        5: "Probe Response",
        6: "Timing Advertisement",
        8: "Beacon",
        9: "ATIM",
        10: "Disassociation",
        11: "Authentication",
        12: "Deauthentification",
        13: "Action",
        14: "Action No Ack",
    },
    1: {  # Control
        4: "Beamforming Report Poll",
        5: "VHT NDP Announcement",
        6: "Control Frame Extension",
        7: "Control Wrapper",
        8: "Block Ack Request",
        9: "Block Ack",
        10: "PS-Poll",
        11: "RTS",
        12: "CTS",
        13: "Ack",
        14: "CF-End",
        15: "CF-End+CF-Ack",
    },
    2: {  # Data
        0: "Data",
        1: "Data+CF-Ack",
        2: "Data+CF-Poll",
        3: "Data+CF-Ack+CF-Poll",
        4: "Null (no data)",
        5: "CF-Ack (no data)",
        6: "CF-Poll (no data)",
        7: "CF-Ack+CF-Poll (no data)",
        8: "QoS Data",
        9: "QoS Data+CF-Ack",
        10: "QoS Data+CF-Poll",
        11: "QoS Data+CF-Ack+CF-Poll",
        12: "QoS Null (no data)",
        14: "QoS CF-Poll (no data)",
        15: "QoS CF-Ack+CF-Poll (no data)"
    },
    3: {  # Extension
        0: "DMG Beacon"
    }
}

_dot11_cfe = {
    2: "Poll",
    3: "SPR",
    4: "Grant",
    5: "DMG CTS",
    6: "DMG DTS",
    7: "Grant Ack",
    8: "SSW",
    9: "SSW-Feedback",
    10: "SSW-Ack",
}


_dot11_addr_meaning = [
    [  # Management: 802.11-2016 9.3.3.2
        "RA=DA", "TA=SA", "BSSID/STA", None,
    ],
    [  # Control
        "RA", "TA", None, None
    ],
    [  # Data: 802.11-2016 9.3.2.1: Table 9-26
        [["RA=DA", "RA=DA"], ["RA=BSSID", "RA"]],
        [["TA=SA", "TA=BSSID"], ["TA=SA", "TA"]],
        [["BSSID", "SA"], ["DA", "DA"]],
        [[None, None], ["SA", "BSSID"]],
    ],
    [  # Extension
        "BSSID", None, None, None
    ],
]


class _Dot11MacField(MACField):
    """
    A MACField that displays the address type depending on the
    802.11 flags
    """
    __slots__ = ["index"]

    def __init__(self, name, default, index):
        self.index = index
        super(_Dot11MacField, self).__init__(name, default)

    def i2repr(self, pkt, val):
        s = super(_Dot11MacField, self).i2repr(pkt, val)
        meaning = pkt.address_meaning(self.index)
        if meaning:
            return "%s (%s)" % (s, meaning)
        return s


# 802.11-2016 9.2.4.1.1
class Dot11(Packet):
    name = "802.11"
    fields_desc = [
        BitMultiEnumField("subtype", 0, 4, _dot11_subtypes,
                          lambda pkt: pkt.type),
        BitEnumField("type", 0, 2, ["Management", "Control", "Data",
                                    "Extension"]),
        BitField("proto", 0, 2),
        ConditionalField(
            BitEnumField("cfe", 0, 4, _dot11_cfe),
            lambda pkt: (pkt.type, pkt.subtype) == (1, 6)
        ),
        MultipleTypeField(
            [
                (
                    FlagsField("FCfield", 0, 4,
                               ["pw-mgt", "MD", "protected", "order"]),
                    lambda pkt: (pkt.type, pkt.subtype) == (1, 6)
                )
            ],
            FlagsField("FCfield", 0, 8,
                       ["to-DS", "from-DS", "MF", "retry",
                        "pw-mgt", "MD", "protected", "order"])
        ),
        ShortField("ID", 0),
        _Dot11MacField("addr1", ETHER_ANY, 1),
        ConditionalField(
            _Dot11MacField("addr2", ETHER_ANY, 2),
            lambda pkt: (pkt.type != 1 or
                         pkt.subtype in [0x8, 0x9, 0xa, 0xb, 0xe, 0xf]),
        ),
        ConditionalField(
            _Dot11MacField("addr3", ETHER_ANY, 3),
            lambda pkt: pkt.type in [0, 2],
        ),
        ConditionalField(LEShortField("SC", 0), lambda pkt: pkt.type != 1),
        ConditionalField(
            _Dot11MacField("addr4", ETHER_ANY, 4),
            lambda pkt: (pkt.type == 2 and
                         pkt.FCfield & 3 == 3),  # from-DS+to-DS
        )
    ]

    def mysummary(self):
        # Supports both Dot11 and Dot11FCS
        return self.sprintf("802.11 %%%s.type%% %%%s.subtype%% %%%s.addr2%% > %%%s.addr1%%" % ((self.__class__.__name__,) * 4))  # noqa: E501

    def guess_payload_class(self, payload):
        if self.type == 0x02 and (
                0x08 <= self.subtype <= 0xF and self.subtype != 0xD):
            return Dot11QoS
        elif self.FCfield.protected:
            # When a frame is handled by encryption, the Protected Frame bit
            # (previously called WEP bit) is set to 1, and the Frame Body
            # begins with the appropriate cryptographic header.
            return Dot11Encrypted
        else:
            return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot11):
            if self.type == 0:  # management
                if self.addr1.lower() != other.addr2.lower():  # check resp DA w/ req SA  # noqa: E501
                    return 0
                if (other.subtype, self.subtype) in [(0, 1), (2, 3), (4, 5)]:
                    return 1
                if self.subtype == other.subtype == 11:  # auth
                    return self.payload.answers(other.payload)
            elif self.type == 1:  # control
                return 0
            elif self.type == 2:  # data
                return self.payload.answers(other.payload)
            elif self.type == 3:  # reserved
                return 0
        return 0

    def address_meaning(self, index):
        """
        Return the meaning of the address[index] considering the context
        """
        if index not in [1, 2, 3, 4]:
            raise ValueError("Wrong index: should be [1, 2, 3, 4]")
        index = index - 1
        if self.type == 0:  # Management
            return _dot11_addr_meaning[0][index]
        elif self.type == 1:  # Control
            return _dot11_addr_meaning[1][index]
        elif self.type == 2:  # Data
            meaning = _dot11_addr_meaning[2][index][
                self.FCfield.to_DS
            ][self.FCfield.from_DS]
            if meaning and index in [2, 3]:  # Address 3-4
                if isinstance(self.payload, Dot11QoS):
                    # MSDU and Short A-MSDU
                    if self.payload.A_MSDU_Present:
                        meaning = "BSSID"
            return meaning
        elif self.type == 3:  # Extension
            return _dot11_addr_meaning[3][index]
        return None

    def unwep(self, key=None, warn=1):
        if self.FCfield & 0x40 == 0:
            if warn:
                warning("No WEP to remove")
            return
        if isinstance(self.payload.payload, NoPayload):
            if key or conf.wepkey:
                self.payload.decrypt(key)
            if isinstance(self.payload.payload, NoPayload):
                if warn:
                    warning("Dot11 can't be decrypted. Check conf.wepkey.")
                return
        self.FCfield &= ~0x40
        self.payload = self.payload.payload


class Dot11FCS(Dot11):
    name = "802.11-FCS"
    match_subclass = True
    fields_desc = Dot11.fields_desc + [FCSField("fcs", None, fmt="<I")]

    def compute_fcs(self, s):
        return struct.pack("!I", crc32(s) & 0xffffffff)[::-1]

    def post_build(self, p, pay):
        p += pay
        if self.fcs is None:
            p = p[:-4] + self.compute_fcs(p[:-4])
        return p


class Dot11QoS(Packet):
    name = "802.11 QoS"
    fields_desc = [BitField("A_MSDU_Present", 0, 1),
                   BitField("Ack_Policy", 0, 2),
                   BitField("EOSP", 0, 1),
                   BitField("TID", 0, 4),
                   ByteField("TXOP", 0)]

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, Dot11):
            if self.underlayer.FCfield.protected:
                return Dot11Encrypted
        return Packet.guess_payload_class(self, payload)


capability_list = ["res8", "res9", "short-slot", "res11",
                   "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]

reason_code = {0: "reserved", 1: "unspec", 2: "auth-expired",
               3: "deauth-ST-leaving",
               4: "inactivity", 5: "AP-full", 6: "class2-from-nonauth",
               7: "class3-from-nonass", 8: "disas-ST-leaving",
               9: "ST-not-auth"}

status_code = {0: "success", 1: "failure", 10: "cannot-support-all-cap",
               11: "inexist-asso", 12: "asso-denied", 13: "algo-unsupported",
               14: "bad-seq-num", 15: "challenge-failure",
               16: "timeout", 17: "AP-full", 18: "rate-unsupported"}


class _Dot11EltUtils(Packet):
    """
    Contains utils for classes that have Dot11Elt as payloads
    """
    def network_stats(self):
        """Return a dictionary containing a summary of the Dot11
        elements fields
        """
        summary = {}
        crypto = set()
        p = self.payload
        while isinstance(p, Dot11Elt):
            # Avoid overriding already-set SSID values because it is not part
            # of the standard and it protects from parsing bugs,
            # see https://github.com/secdev/scapy/issues/2683
            if p.ID == 0 and "ssid" not in summary:
                summary["ssid"] = plain_str(p.info)
            elif p.ID == 3:
                summary["channel"] = ord(p.info)
            elif isinstance(p, Dot11EltCountry):
                summary["country"] = plain_str(p.country_string[:2])
                country_descriptor_types = {
                    b"I": "Indoor",
                    b"O": "Outdoor",
                    b"X": "Non-country",
                    b"\xff": "Ignored"
                }
                summary["country_desc_type"] = country_descriptor_types.get(
                    p.country_string[-1:]
                )
            elif isinstance(p, Dot11EltRates):
                rates = [(x & 0x7f) / 2. for x in p.rates]
                if "rates" in summary:
                    summary["rates"].extend(rates)
                else:
                    summary["rates"] = rates
            elif isinstance(p, Dot11EltRSN):
                wpa_version = "WPA2"
                # WPA3-only:
                # - AP shall at least enable AKM suite selector 00-0F-AC:8
                # - AP shall not enable AKM suite selector 00-0F-AC:2 and
                #   00-0F-AC:6
                # - AP shall set MFPC and MFPR to 1
                # - AP shall not enable WEP and TKIP
                # WPA3-transition:
                # - AP shall at least enable AKM suite selector 00-0F-AC:2
                #   and 00-0F-AC:8
                # - AP shall set MFPC to 1 and MFPR to 0
                if any(x.suite == 8 for x in p.akm_suites) and \
                        all(x.suite not in [2, 6] for x in p.akm_suites) and \
                        p.mfp_capable and p.mfp_required and \
                        all(x.cipher not in [1, 2, 5]
                            for x in p.pairwise_cipher_suites):
                    # WPA3 only mode
                    wpa_version = "WPA3"
                elif any(x.suite == 8 for x in p.akm_suites) and \
                        any(x.suite == 2 for x in p.akm_suites) and \
                        p.mfp_capable and not p.mfp_required:
                    # WPA3 transition mode
                    wpa_version = "WPA3-transition"
                # Append suite
                if p.akm_suites:
                    auth = p.akm_suites[0].sprintf("%suite%")
                    crypto.add(wpa_version + "/%s" % auth)
                else:
                    crypto.add(wpa_version)
            elif p.ID == 221:
                if isinstance(p, Dot11EltMicrosoftWPA):
                    if p.akm_suites:
                        auth = p.akm_suites[0].sprintf("%suite%")
                        crypto.add("WPA/%s" % auth)
                    else:
                        crypto.add("WPA")
            p = p.payload
        if not crypto and hasattr(self, "cap"):
            if self.cap.privacy:
                crypto.add("WEP")
            else:
                crypto.add("OPN")
        if crypto:
            summary["crypto"] = crypto
        return summary


#############
# 802.11 IE #
#############

# 802.11-2016 - 9.4.2

_dot11_info_elts_ids = {
    0: "SSID",
    1: "Supported Rates",
    2: "FHset",
    3: "DSSS Set",
    4: "CF Set",
    5: "TIM",
    6: "IBSS Set",
    7: "Country",
    10: "Request",
    11: "BSS Load",
    12: "EDCA Set",
    13: "TSPEC",
    14: "TCLAS",
    15: "Schedule",
    16: "Challenge text",
    32: "Power Constraint",
    33: "Power Capability",
    36: "Supported Channels",
    42: "ERP",
    45: "HT Capabilities",
    46: "QoS Capability",
    48: "RSN",
    50: "Extended Supported Rates",
    52: "Neighbor Report",
    61: "HT Operation",
    107: "Interworking",
    127: "Extendend Capabilities",
    191: "VHT Capabilities",
    221: "Vendor Specific"
}

# Backward compatibility
_dot11_elt_deprecated_names = {
    "Rates": 1,
    "DSset": 3,
    "CFset": 4,
    "IBSSset": 6,
    "challenge": 16,
    "PowerCapability": 33,
    "Channels": 36,
    "ERPinfo": 42,
    "HTinfo": 45,
    "RSNinfo": 48,
    "ESRates": 50,
    "ExtendendCapatibilities": 127,
    "VHTCapabilities": 191,
    "Vendor": 221,
}

_dot11_info_elts_ids_rev = {v: k for k, v in _dot11_info_elts_ids.items()}
_dot11_info_elts_ids_rev.update(_dot11_elt_deprecated_names)
_dot11_id_enum = (
    lambda x: _dot11_info_elts_ids.get(x, x),
    lambda x: _dot11_info_elts_ids_rev.get(x, x)
)


class Dot11Elt(Packet):
    """
    A Generic 802.11 Element
    """
    __slots__ = ["info"]
    name = "802.11 Information Element"
    fields_desc = [ByteEnumField("ID", 0, _dot11_id_enum),
                   FieldLenField("len", None, "info", "B"),
                   StrLenField("info", "", length_from=lambda x: x.len,
                               max_length=255)]
    show_indent = 0

    def __setattr__(self, attr, val):
        if attr == "info":
            # Will be caught by __slots__: we need an extra call
            try:
                self.setfieldval(attr, val)
            except AttributeError:
                pass
        super(Dot11Elt, self).__setattr__(attr, val)

    def mysummary(self):
        if self.ID == 0:
            ssid = plain_str(self.info)
            return "SSID='%s'" % ssid, [Dot11]
        else:
            return ""

    registered_ies = {}

    @classmethod
    def register_variant(cls, id=None):
        id = id or cls.ID.default
        if id not in cls.registered_ies:
            cls.registered_ies[id] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            _id = ord(_pkt[:1])
            idcls = cls.registered_ies.get(_id, cls)
            if idcls.dispatch_hook != cls.dispatch_hook:
                # Vendor has its own dispatch_hook
                return idcls.dispatch_hook(_pkt=_pkt, *args, **kargs)
            cls = idcls
        return cls

    def pre_dissect(self, s):
        # Backward compatibility: add info to all elements
        # This allows to introduce new Dot11Elt classes without breaking
        # previous code
        if len(s) >= 3:
            length = orb(s[1])
            if length > 0 and length <= 255:
                self.info = s[2:2 + length]
        return s

    def post_build(self, p, pay):
        if self.len is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay


class Dot11EltDSSSet(Dot11Elt):
    name = "802.11 DSSS Parameter Set"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 3, _dot11_id_enum),
        ByteField("len", 1),
        ByteField("channel", 0),
    ]


class Dot11EltERP(Dot11Elt):
    name = "802.11 ERP"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 42, _dot11_id_enum),
        ByteField("len", 1),
        BitField("NonERP_Present", 0, 1),
        BitField("Use_Protection", 0, 1),
        BitField("Barker_Preamble_Mode", 0, 1),
        BitField("res", 0, 5),
    ]


class RSNCipherSuite(Packet):
    name = "Cipher suite"
    fields_desc = [
        OUIField("oui", 0x000fac),
        ByteEnumField("cipher", 0x04, {
            0x00: "Use group cipher suite",
            0x01: "WEP-40",
            0x02: "TKIP",
            0x03: "OCB",
            0x04: "CCMP-128",
            0x05: "WEP-104",
            0x06: "BIP-CMAC-128",
            0x07: "Group addressed traffic not allowed",
            0x08: "GCMP-128",
            0x09: "GCMP-256",
            0x0A: "CCMP-256",
            0x0B: "BIP-GMAC-128",
            0x0C: "BIP-GMAC-256",
            0x0D: "BIP-CMAC-256"
        })
    ]

    def extract_padding(self, s):
        return "", s


class AKMSuite(Packet):
    name = "AKM suite"
    fields_desc = [
        OUIField("oui", 0x000fac),
        ByteEnumField("suite", 0x01, {
            0x00: "Reserved",
            0x01: "802.1X",
            0x02: "PSK",
            0x03: "FT-802.1X",
            0x04: "FT-PSK",
            0x05: "WPA-SHA256",
            0x06: "PSK-SHA256",
            0x07: "TDLS",
            0x08: "SAE",
            0x09: "FT-SAE",
            0x0A: "AP-PEER-KEY",
            0x0B: "WPA-SHA256-SUITE-B",
            0x0C: "WPA-SHA384-SUITE-B",
            0x0D: "FT-802.1X-SHA384",
            0x0E: "FILS-SHA256",
            0x0F: "FILS-SHA384",
            0x10: "FT-FILS-SHA256",
            0x11: "FT-FILS-SHA384",
            0x12: "OWE"
        })
    ]

    def extract_padding(self, s):
        return "", s


class PMKIDListPacket(Packet):
    name = "PMKIDs"
    fields_desc = [
        LEFieldLenField("nb_pmkids", None, count_of="pmkid_list"),
        FieldListField(
            "pmkid_list",
            None,
            XStrFixedLenField("", "", length=16),
            count_from=lambda pkt: pkt.nb_pmkids
        )
    ]

    def extract_padding(self, s):
        return "", s


class Dot11EltRSN(Dot11Elt):
    name = "802.11 RSN information"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 48, _dot11_id_enum),
        ByteField("len", None),
        LEShortField("version", 1),
        PacketField("group_cipher_suite", RSNCipherSuite(), RSNCipherSuite),
        LEFieldLenField(
            "nb_pairwise_cipher_suites",
            None,
            count_of="pairwise_cipher_suites"
        ),
        PacketListField(
            "pairwise_cipher_suites",
            [RSNCipherSuite()],
            RSNCipherSuite,
            count_from=lambda p: p.nb_pairwise_cipher_suites
        ),
        LEFieldLenField(
            "nb_akm_suites",
            None,
            count_of="akm_suites"
        ),
        PacketListField(
            "akm_suites",
            [AKMSuite()],
            AKMSuite,
            count_from=lambda p: p.nb_akm_suites
        ),
        BitField("mfp_capable", 1, 1),
        BitField("mfp_required", 1, 1),
        BitField("gtksa_replay_counter", 0, 2),
        BitField("ptksa_replay_counter", 0, 2),
        BitField("no_pairwise", 0, 1),
        BitField("pre_auth", 0, 1),
        BitField("reserved", 0, 8),
        # Theorically we could use mfp_capable/mfp_required to know if those
        # fields are present, but some implementations poorly implement it.
        # In practice, do as wireshark: guess using offset.
        ConditionalField(
            PacketField("pmkids", PMKIDListPacket(), PMKIDListPacket),
            lambda pkt: (
                True if pkt.len is None else
                pkt.len - (
                    12 +
                    (pkt.nb_pairwise_cipher_suites or 0) * 4 +
                    (pkt.nb_akm_suites or 0) * 4
                ) >= 2
            )
        ),
        ConditionalField(
            PacketField("group_management_cipher_suite",
                        RSNCipherSuite(cipher=0x6), RSNCipherSuite),
            lambda pkt: (
                True if pkt.len is None else
                pkt.len - (
                    12 +
                    (pkt.nb_pairwise_cipher_suites or 0) * 4 +
                    (pkt.nb_akm_suites or 0) * 4 +
                    (pkt.pmkids and pkt.pmkids.nb_pmkids or 0) * 16
                ) >= 2
            )
        )
    ]


class Dot11EltCountryConstraintTriplet(Packet):
    name = "802.11 Country Constraint Triplet"
    fields_desc = [
        ByteField("first_channel_number", 1),
        ByteField("num_channels", 24),
        ByteField("mtp", 0)
    ]

    def extract_padding(self, s):
        return b"", s


class Dot11EltCountry(Dot11Elt):
    name = "802.11 Country"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 7, _dot11_id_enum),
        ByteField("len", None),
        StrFixedLenField("country_string", b"\0\0\0", length=3),
        PacketListField(
            "descriptors",
            [],
            Dot11EltCountryConstraintTriplet,
            length_from=lambda pkt: (
                pkt.len - 3 - (pkt.len % 3)
            )
        ),
        ConditionalField(
            ByteField("pad", 0),
            lambda pkt: (len(pkt.descriptors) + 1) % 2
        )
    ]


class _RateField(ByteField):
    def i2repr(self, pkt, val):
        if val is None:
            return ""
        s = str((val & 0x7f) / 2.)
        if val & 0x80:
            s += "(B)"
        return s + " Mbps"


class Dot11EltRates(Dot11Elt):
    name = "802.11 Rates"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 1, _dot11_id_enum),
        ByteField("len", None),
        FieldListField(
            "rates",
            [0x82],
            _RateField("", 0),
            length_from=lambda p: p.len
        )
    ]


Dot11EltRates.register_variant(50)  # Extended rates


class Dot11EltHTCapabilities(Dot11Elt):
    name = "802.11 HT Capabilities"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 45, _dot11_id_enum),
        ByteField("len", None),
        # HT Capabilities Info: 2B
        BitField("L_SIG_TXOP_Protection", 0, 1, tot_size=-2),
        BitField("Forty_Mhz_Intolerant", 0, 1),
        BitField("PSMP", 0, 1),
        BitField("DSSS_CCK", 0, 1),
        BitEnumField("Max_A_MSDU", 0, 1, {0: "3839 o", 1: "7935 o"}),
        BitField("Delayed_BlockAck", 0, 1),
        BitField("Rx_STBC", 0, 2),
        BitField("Tx_STBC", 0, 1),
        BitField("Short_GI_40Mhz", 0, 1),
        BitField("Short_GI_20Mhz", 0, 1),
        BitField("Green_Field", 0, 1),
        BitEnumField("SM_Power_Save", 0, 2,
                     {0: "static SM", 1: "dynamic SM", 3: "disabled"}),
        BitEnumField("Supported_Channel_Width", 0, 1,
                     {0: "20Mhz", 1: "20Mhz+40Mhz"}),
        BitField("LDPC_Coding_Capability", 0, 1, end_tot_size=-2),
        # A-MPDU Parameters: 1B
        BitField("res1", 0, 3, tot_size=-1),
        BitField("Min_MPDCU_Start_Spacing", 8, 3),
        BitField("Max_A_MPDU_Length_Exponent", 3, 2, end_tot_size=-1),
        # Supported MCS set: 16B
        BitField("res2", 0, 27, tot_size=-16),
        BitField("TX_Unequal_Modulation", 0, 1),
        BitField("TX_Max_Spatial_Streams", 0, 2),
        BitField("TX_RX_MCS_Set_Not_Equal", 0, 1),
        BitField("TX_MCS_Set_Defined", 0, 1),
        BitField("res3", 0, 6),
        BitField("RX_Highest_Supported_Data_Rate", 0, 10),
        BitField("res4", 0, 3),
        BitField("RX_MSC_Bitmask", 0, 77, end_tot_size=-16),
        # HT Extended capabilities: 2B
        BitField("res5", 0, 4, tot_size=-2),
        BitField("RD_Responder", 0, 1),
        BitField("HTC_HT_Support", 0, 1),
        BitField("MCS_Feedback", 0, 2),
        BitField("res6", 0, 5),
        BitField("PCO_Transition_Time", 0, 2),
        BitField("PCO", 0, 1, end_tot_size=-2),
        # TX Beamforming Capabilities TxBF: 4B
        BitField("res7", 0, 3, tot_size=-4),
        BitField("Channel_Estimation_Capability", 0, 2),
        BitField("CSI_max_n_Rows_Beamformer_Supported", 0, 2),
        BitField("Compressed_Steering_n_Beamformer_Antennas_Supported", 0, 2),
        BitField("Noncompressed_Steering_n_Beamformer_Antennas_Supported",
                 0, 2),
        BitField("CSI_n_Beamformer_Antennas_Supported", 0, 2),
        BitField("Minimal_Grouping", 0, 2),
        BitField("Explicit_Compressed_Beamforming_Feedback", 0, 2),
        BitField("Explicit_Noncompressed_Beamforming_Feedback", 0, 2),
        BitField("Explicit_Transmit_Beamforming_CSI_Feedback", 0, 2),
        BitField("Explicit_Compressed_Steering", 0, 1),
        BitField("Explicit_Noncompressed_Steering", 0, 1),
        BitField("Explicit_CSI_Transmit_Beamforming", 0, 1),
        BitField("Calibration", 0, 2),
        BitField("Implicit_Trasmit_Beamforming", 0, 1),
        BitField("Transmit_NDP", 0, 1),
        BitField("Receive_NDP", 0, 1),
        BitField("Transmit_Staggered_Sounding", 0, 1),
        BitField("Receive_Staggered_Sounding", 0, 1),
        BitField("Implicit_Transmit_Beamforming_Receiving", 0, 1,
                 end_tot_size=-4),
        # ASEL Capabilities: 1B
        FlagsField("ASEL", 0, 8, [
            "res",
            "Transmit_Sounding_PPDUs",
            "Receive_ASEL",
            "Antenna_Indices_Feedback",
            "Explicit_CSI_Feedback",
            "Explicit_CSI_Feedback_Based_Transmit_ASEL",
            "Antenna_Selection",
        ])
    ]


class Dot11EltVendorSpecific(Dot11Elt):
    name = "802.11 Vendor Specific"
    match_subclass = True
    fields_desc = [
        ByteEnumField("ID", 221, _dot11_id_enum),
        ByteField("len", None),
        OUIField("oui", 0x000000),
        StrLenField("info", "", length_from=lambda x: x.len - 3)
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            oui = struct.unpack("!I", b"\x00" + _pkt[2:5])[0]
            if oui == 0x0050f2:  # Microsoft
                type_ = orb(_pkt[5])
                if type_ == 0x01:
                    # MS WPA IE
                    return Dot11EltMicrosoftWPA
                elif type_ == 0x02:
                    # MS WME IE TODO
                    # return Dot11EltMicrosoftWME
                    pass
                elif type_ == 0x04:
                    # MS WPS IE TODO
                    # return Dot11EltWPS
                    pass
                return Dot11EltVendorSpecific
        return cls


class Dot11EltMicrosoftWPA(Dot11EltVendorSpecific):
    name = "802.11 Microsoft WPA"
    match_subclass = True
    ID = 221
    oui = 0x0050f2
    # It appears many WPA implementations ignore the fact
    # that this IE should only have a single cipher and auth suite
    fields_desc = Dot11EltVendorSpecific.fields_desc[:3] + [
        XByteField("type", 0x01)
    ] + Dot11EltRSN.fields_desc[2:8]


######################
# 802.11 Frame types #
######################

# 802.11-2016 9.3

class Dot11Beacon(_Dot11EltUtils):
    name = "802.11 Beacon"
    fields_desc = [LELongField("timestamp", 0),
                   LEShortField("beacon_interval", 0x0064),
                   FlagsField("cap", 0, 16, capability_list)]


class Dot11ATIM(Packet):
    name = "802.11 ATIM"


class Dot11Disas(Packet):
    name = "802.11 Disassociation"
    fields_desc = [LEShortEnumField("reason", 1, reason_code)]


class Dot11AssoReq(_Dot11EltUtils):
    name = "802.11 Association Request"
    fields_desc = [FlagsField("cap", 0, 16, capability_list),
                   LEShortField("listen_interval", 0x00c8)]


class Dot11AssoResp(_Dot11EltUtils):
    name = "802.11 Association Response"
    fields_desc = [FlagsField("cap", 0, 16, capability_list),
                   LEShortField("status", 0),
                   LEShortField("AID", 0)]


class Dot11ReassoReq(_Dot11EltUtils):
    name = "802.11 Reassociation Request"
    fields_desc = [FlagsField("cap", 0, 16, capability_list),
                   LEShortField("listen_interval", 0x00c8),
                   MACField("current_AP", ETHER_ANY)]


class Dot11ReassoResp(Dot11AssoResp):
    name = "802.11 Reassociation Response"


class Dot11ProbeReq(_Dot11EltUtils):
    name = "802.11 Probe Request"


class Dot11ProbeResp(_Dot11EltUtils):
    name = "802.11 Probe Response"
    fields_desc = [LELongField("timestamp", 0),
                   LEShortField("beacon_interval", 0x0064),
                   FlagsField("cap", 0, 16, capability_list)]


class Dot11Auth(_Dot11EltUtils):
    name = "802.11 Authentication"
    fields_desc = [LEShortEnumField("algo", 0, ["open", "sharedkey"]),
                   LEShortField("seqnum", 0),
                   LEShortEnumField("status", 0, status_code)]

    def answers(self, other):
        if self.seqnum == other.seqnum + 1:
            return 1
        return 0


class Dot11Deauth(Packet):
    name = "802.11 Deauthentication"
    fields_desc = [LEShortEnumField("reason", 1, reason_code)]


class Dot11Ack(Packet):
    name = "802.11 Ack packet"


###################
# 802.11 Security #
###################

# 802.11-2016 12

class Dot11Encrypted(Packet):
    name = "802.11 Encrypted (unknown algorithm)"
    fields_desc = [StrField("data", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # Extracted from
        # https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ieee80211.c  # noqa: E501
        KEY_EXTIV = 0x20
        EXTIV_LEN = 8
        if _pkt and len(_pkt) >= 3:
            if (orb(_pkt[3]) & KEY_EXTIV) and (len(_pkt) >= EXTIV_LEN):
                if orb(_pkt[1]) == ((orb(_pkt[0]) | 0x20) & 0x7f):  # IS_TKIP
                    return Dot11TKIP
                elif orb(_pkt[2]) == 0:  # IS_CCMP
                    return Dot11CCMP
                else:
                    # Unknown encryption algorithm
                    return Dot11Encrypted
            else:
                return Dot11WEP
        return conf.raw_layer


# 802.11-2016 12.3.2

class Dot11WEP(Dot11Encrypted):
    name = "802.11 WEP packet"
    fields_desc = [StrFixedLenField("iv", b"\0\0\0", 3),
                   ByteField("keyid", 0),
                   StrField("wepdata", None, remain=4),
                   IntField("icv", None)]

    def decrypt(self, key=None):
        if key is None:
            key = conf.wepkey
        if key and conf.crypto_valid:
            d = Cipher(
                algorithms.ARC4(self.iv + key.encode("utf8")),
                None,
                default_backend(),
            ).decryptor()
            self.add_payload(LLC(d.update(self.wepdata) + d.finalize()))

    def post_dissect(self, s):
        self.decrypt()

    def build_payload(self):
        if self.wepdata is None:
            return Packet.build_payload(self)
        return b""

    @crypto_validator
    def encrypt(self, p, pay, key=None):
        if key is None:
            key = conf.wepkey
        if key:
            if self.icv is None:
                pay += struct.pack("<I", crc32(pay) & 0xffffffff)
                icv = b""
            else:
                icv = p[4:8]
            e = Cipher(
                algorithms.ARC4(self.iv + key.encode("utf8")),
                None,
                default_backend(),
            ).encryptor()
            return p[:4] + e.update(pay) + e.finalize() + icv
        else:
            warning("No WEP key set (conf.wepkey).. strange results expected..")  # noqa: E501
            return b""

    def post_build(self, p, pay):
        if self.wepdata is None:
            p = self.encrypt(p, raw(pay))
        return p

# we can't dissect ICV / MIC here: they are encrypted

# 802.11-2016 12.5.2.2


class Dot11TKIP(Dot11Encrypted):
    name = "802.11 TKIP packet"
    fields_desc = [
        # iv - 4 bytes
        ByteField("TSC1", 0),
        ByteField("WEPSeed", 0),
        ByteField("TSC0", 0),
        BitField("key_id", 0, 2),  #
        BitField("ext_iv", 0, 1),  # => LE = reversed order
        BitField("res", 0, 5),     #
        # ext_iv - 4 bytes
        ConditionalField(ByteField("TSC2", 0), lambda pkt: pkt.ext_iv),
        ConditionalField(ByteField("TSC3", 0), lambda pkt: pkt.ext_iv),
        ConditionalField(ByteField("TSC4", 0), lambda pkt: pkt.ext_iv),
        ConditionalField(ByteField("TSC5", 0), lambda pkt: pkt.ext_iv),
        # data
        StrField("data", None),
    ]

# 802.11-2016 12.5.3.2


class Dot11CCMP(Dot11Encrypted):
    name = "802.11 CCMP packet"
    fields_desc = [
        # iv - 8 bytes
        ByteField("PN0", 0),
        ByteField("PN1", 0),
        ByteField("res0", 0),
        BitField("key_id", 0, 2),  #
        BitField("ext_iv", 0, 1),  # => LE = reversed order
        BitField("res1", 0, 5),    #
        ByteField("PN2", 0),
        ByteField("PN3", 0),
        ByteField("PN4", 0),
        ByteField("PN5", 0),
        # data
        StrField("data", None),
    ]


############
# Bindings #
############


bind_top_down(RadioTap, Dot11FCS, present=2, Flags=16)
bind_top_down(Dot11, Dot11QoS, type=2, subtype=0xc)

bind_layers(PrismHeader, Dot11,)
bind_layers(Dot11, LLC, type=2)
bind_layers(Dot11QoS, LLC,)
bind_layers(Dot11, Dot11AssoReq, subtype=0, type=0)
bind_layers(Dot11, Dot11AssoResp, subtype=1, type=0)
bind_layers(Dot11, Dot11ReassoReq, subtype=2, type=0)
bind_layers(Dot11, Dot11ReassoResp, subtype=3, type=0)
bind_layers(Dot11, Dot11ProbeReq, subtype=4, type=0)
bind_layers(Dot11, Dot11ProbeResp, subtype=5, type=0)
bind_layers(Dot11, Dot11Beacon, subtype=8, type=0)
bind_layers(Dot11, Dot11ATIM, subtype=9, type=0)
bind_layers(Dot11, Dot11Disas, subtype=10, type=0)
bind_layers(Dot11, Dot11Auth, subtype=11, type=0)
bind_layers(Dot11, Dot11Deauth, subtype=12, type=0)
bind_layers(Dot11, Dot11Ack, subtype=13, type=1)
bind_layers(Dot11Beacon, Dot11Elt,)
bind_layers(Dot11AssoReq, Dot11Elt,)
bind_layers(Dot11AssoResp, Dot11Elt,)
bind_layers(Dot11ReassoReq, Dot11Elt,)
bind_layers(Dot11ReassoResp, Dot11Elt,)
bind_layers(Dot11ProbeReq, Dot11Elt,)
bind_layers(Dot11ProbeResp, Dot11Elt,)
bind_layers(Dot11Auth, Dot11Elt,)
bind_layers(Dot11Elt, Dot11Elt,)
bind_layers(Dot11TKIP, conf.raw_layer)
bind_layers(Dot11CCMP, conf.raw_layer)


conf.l2types.register(DLT_IEEE802_11, Dot11)
conf.l2types.register_num2layer(801, Dot11)
conf.l2types.register(DLT_PRISM_HEADER, PrismHeader)
conf.l2types.register_num2layer(802, PrismHeader)
conf.l2types.register(DLT_IEEE802_11_RADIO, RadioTap)
conf.l2types.register_num2layer(803, RadioTap)

####################
# Other WiFi utils #
####################


class WiFi_am(AnsweringMachine):
    """Before using this, initialize "iffrom" and "ifto" interfaces:
iwconfig iffrom mode monitor
iwpriv orig_ifto hostapd 1
ifconfig ifto up
note: if ifto=wlan0ap then orig_ifto=wlan0
note: ifto and iffrom must be set on the same channel
ex:
ifconfig eth1 up
iwconfig eth1 mode monitor
iwconfig eth1 channel 11
iwpriv wlan0 hostapd 1
ifconfig wlan0ap up
iwconfig wlan0 channel 11
iwconfig wlan0 essid dontexist
iwconfig wlan0 mode managed
"""
    function_name = "airpwn"
    filter = None

    def parse_options(self, iffrom=conf.iface, ifto=conf.iface, replace="",
                      pattern="", ignorepattern=""):
        self.iffrom = iffrom
        self.ifto = ifto
        self.ptrn = re.compile(pattern.encode())
        self.iptrn = re.compile(ignorepattern.encode())
        self.replace = replace

    def is_request(self, pkt):
        if not isinstance(pkt, Dot11):
            return 0
        if not pkt.FCfield & 1:
            return 0
        if not pkt.haslayer(TCP):
            return 0
        tcp = pkt.getlayer(TCP)
        pay = raw(tcp.payload)
        if not self.ptrn.match(pay):
            return 0
        if self.iptrn.match(pay) is True:
            return 0
        return True

    def make_reply(self, p):
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = raw(tcp.payload)
        del(p.payload.payload.payload)
        p.FCfield = "from-DS"
        p.addr1, p.addr2 = p.addr2, p.addr1
        p /= IP(src=ip.dst, dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq + len(pay),
                 flags="PA")
        q = p.copy()
        p /= self.replace
        q.ID += 1
        q.getlayer(TCP).flags = "RA"
        q.getlayer(TCP).seq += len(self.replace)
        return [p, q]

    def print_reply(self, query, *reply):
        p = reply[0][0]
        print(p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%"))

    def send_reply(self, reply):
        sendp(reply, iface=self.ifto, **self.optsend)

    def sniff(self):
        sniff(iface=self.iffrom, **self.optsniff)


conf.stats_dot11_protocols += [Dot11WEP, Dot11Beacon, ]


class Dot11PacketList(PacketList):
    def __init__(self, res=None, name="Dot11List", stats=None):
        if stats is None:
            stats = conf.stats_dot11_protocols

        PacketList.__init__(self, res, name, stats)

    def toEthernet(self):
        data = [x[Dot11] for x in self.res if Dot11 in x and x.type == 2]
        r2 = []
        for p in data:
            q = p.copy()
            q.unwep()
            r2.append(Ether() / q.payload.payload.payload)  # Dot11/LLC/SNAP/IP
        return PacketList(r2, name="Ether from %s" % self.listname)
