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
"""

from __future__ import print_function
import math
import re
import struct
from zlib import crc32

from scapy.config import conf, crypto_validator
from scapy.data import ETHER_ANY, DLT_IEEE802_11, DLT_PRISM_HEADER, \
    DLT_IEEE802_11_RADIO
from scapy.compat import raw, plain_str, orb, chb
from scapy.packet import Packet, bind_layers, bind_top_down, NoPayload
from scapy.fields import ByteField, LEShortField, BitField, LEShortEnumField, \
    ByteEnumField, X3BytesField, FlagsField, LELongField, StrField, \
    StrLenField, IntField, XByteField, LEIntField, StrFixedLenField, \
    LESignedIntField, ReversePadField, ConditionalField, PacketListField, \
    ShortField, BitEnumField, FieldLenField, LEFieldLenField, \
    FieldListField, XStrFixedLenField, PacketField, FCSField, \
    ScalingField
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


# Layers


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


# RadioTap

class _RadiotapReversePadField(ReversePadField):
    def __init__(self, fld):
        # Quote from https://www.radiotap.org/:
        # ""Radiotap requires that all fields in the radiotap header are aligned to natural boundaries.  # noqa: E501
        # For radiotap, that means all 8-, 16-, 32-, and 64-bit fields must begin on 8-, 16-, 32-, and 64-bit boundaries, respectively.""  # noqa: E501
        if isinstance(fld, BitField):
            _align = int(math.ceil(fld.i2len(None, None)))
        else:
            _align = struct.calcsize(fld.fmt)
        ReversePadField.__init__(
            self,
            fld,
            _align,
            padwith=b"\x00"
        )


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

# RadioTap constants


_rt_present = ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',
               'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation',
               'dB_TX_Attenuation', 'dBm_TX_Power', 'Antenna',
               'dB_AntSignal', 'dB_AntNoise', 'RXFlags', 'TXFlags',
               'b17', 'b18', 'ChannelPlus', 'MCS', 'A_MPDU',
               'VHT', 'timestamp', 'HE', 'HE_MU', 'HE_MU_other_user',
               'zero_length_psdu', 'L_SIG', 'b28',
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

_rt_txflags = ["TX_FAIL", "CTS", "RTS", "NOACK", "NOSEQ"]

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


class RadioTap(Packet):
    name = "RadioTap dummy"
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
        # RadioTap fields - each starts with a _RadiotapReversePadField
        # to handle padding

        # TSFT
        ConditionalField(
            _RadiotapReversePadField(
                LELongField("mac_timestamp", 0)
            ),
            lambda pkt: pkt.present and pkt.present.TSFT),
        # Flags
        ConditionalField(
            _RadiotapReversePadField(
                FlagsField("Flags", None, -8, _rt_flags)
            ),
            lambda pkt: pkt.present and pkt.present.Flags),
        # Rate
        ConditionalField(
            _RadiotapReversePadField(
                ByteField("Rate", 0)
             ),
            lambda pkt: pkt.present and pkt.present.Rate),
        # Channel
        ConditionalField(
            _RadiotapReversePadField(
                LEShortField("ChannelFrequency", 0)
             ),
            lambda pkt: pkt.present and pkt.present.Channel),
        ConditionalField(
            FlagsField("ChannelFlags", None, -16, _rt_channelflags),
            lambda pkt: pkt.present and pkt.present.Channel),
        # dBm_AntSignal
        ConditionalField(
            _RadiotapReversePadField(
                ScalingField("dBm_AntSignal", 0,
                             offset=-256, unit="dBm",
                             fmt="B")
             ),
            lambda pkt: pkt.present and pkt.present.dBm_AntSignal),
        # dBm_AntNoise
        ConditionalField(
            _RadiotapReversePadField(
                ScalingField("dBm_AntNoise", 0,
                             offset=-256, unit="dBm",
                             fmt="B")
             ),
            lambda pkt: pkt.present and pkt.present.dBm_AntNoise),
        # Lock_Quality
        ConditionalField(
            _RadiotapReversePadField(
                LEShortField("Lock_Quality", 0),
             ),
            lambda pkt: pkt.present and pkt.present.Lock_Quality),
        # Antenna
        ConditionalField(
            _RadiotapReversePadField(
                ByteField("Antenna", 0)
             ),
            lambda pkt: pkt.present and pkt.present.Antenna),
        # RX Flags
        ConditionalField(
            _RadiotapReversePadField(
                FlagsField("RXFlags", None, -16, _rt_rxflags)
             ),
             lambda pkt: pkt.present and pkt.present.RXFlags),
        # TX Flags
        ConditionalField(
            _RadiotapReversePadField(
                FlagsField("TXFlags", None, -16, _rt_txflags)
             ),
             lambda pkt: pkt.present and pkt.present.TXFlags),
        # ChannelPlus
        ConditionalField(
            _RadiotapReversePadField(
                FlagsField("ChannelPlusFlags", None, -32, _rt_channelflags2)
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
            _RadiotapReversePadField(
                FlagsField("knownMCS", None, -8, _rt_knownmcs)
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
            _RadiotapReversePadField(
                LEIntField("A_MPDU_ref", 0)
             ),
            lambda pkt: pkt.present and pkt.present.A_MPDU),
        ConditionalField(
            FlagsField("A_MPDU_flags", None, -32, _rt_a_mpdu_flags),
            lambda pkt: pkt.present and pkt.present.A_MPDU),
        # VHT
        ConditionalField(
            _RadiotapReversePadField(
                FlagsField("KnownVHT", None, -16, _rt_knownvht)
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
            _RadiotapReversePadField(
                LELongField("timestamp", 0)
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
            _RadiotapReversePadField(
                ShortField("he_data1", 0)
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
            _RadiotapReversePadField(
                LEShortField("hemu_flags1", 0)
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
            _RadiotapReversePadField(
                LEShortField("hemuou_per_user_1", 0x7fff)
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
            _RadiotapReversePadField(
                FlagsField("lsig_data1", 0, -16, ["rate", "length"])
            ),
            lambda pkt: pkt.present and pkt.present.L_SIG),
        ConditionalField(
            BitField("lsig_length", 0, 12),
            lambda pkt: pkt.present and pkt.present.L_SIG),
        ConditionalField(
            BitField("lsig_rate", 0, 4),
            lambda pkt: pkt.present and pkt.present.L_SIG),
        # Remaining
        StrLenField('notdecoded', "",
                    length_from=lambda pkt: 0)
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


class Dot11(Packet):
    name = "802.11"
    fields_desc = [
        BitField("subtype", 0, 4),
        BitEnumField("type", 0, 2, ["Management", "Control", "Data",
                                    "Reserved"]),
        BitField("proto", 0, 2),
        FlagsField("FCfield", 0, 8, ["to-DS", "from-DS", "MF", "retry",
                                     "pw-mgt", "MD", "protected", "order"]),
        ShortField("ID", 0),
        MACField("addr1", ETHER_ANY),
        ConditionalField(
            MACField("addr2", ETHER_ANY),
            lambda pkt: (pkt.type != 1 or
                         pkt.subtype in [0x8, 0x9, 0xa, 0xb, 0xe, 0xf]),
        ),
        ConditionalField(
            MACField("addr3", ETHER_ANY),
            lambda pkt: pkt.type in [0, 2],
        ),
        ConditionalField(LEShortField("SC", 0), lambda pkt: pkt.type != 1),
        ConditionalField(
            MACField("addr4", ETHER_ANY),
            lambda pkt: (pkt.type == 2 and
                         pkt.FCfield & 3 == 3),  # from-DS+to-DS
        )
    ]

    def mysummary(self):
        # Supports both Dot11 and Dot11FCS
        return self.sprintf("802.11 %%%s.type%% %%%s.subtype%% %%%s.addr2%% > %%%s.addr1%%" % ((self.__class__.__name__,) * 4))  # noqa: E501

    def guess_payload_class(self, payload):
        if self.type == 0x02 and (0x08 <= self.subtype <= 0xF and self.subtype != 0xD):  # noqa: E501
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
            p = p[:-4] + self.compute_fcs(p)
        return p


class Dot11QoS(Packet):
    name = "802.11 QoS"
    fields_desc = [BitField("Reserved", None, 1),
                   BitField("Ack_Policy", None, 2),
                   BitField("EOSP", None, 1),
                   BitField("TID", None, 4),
                   ByteField("TXOP", None)]

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


class _Dot11NetStats(Packet):
    fields_desc = [LELongField("timestamp", 0),
                   LEShortField("beacon_interval", 0x0064),
                   FlagsField("cap", 0, 16, capability_list)]

    def network_stats(self):
        """Return a dictionary containing a summary of the Dot11
        elements fields
        """
        summary = {}
        crypto = set()
        akmsuite_types = {
            0x00: "Reserved",
            0x01: "802.1X",
            0x02: "PSK"
        }
        p = self.payload
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
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
                summary["rates"] = p.rates
            elif isinstance(p, Dot11EltRSN):
                if p.akm_suites:
                    auth = akmsuite_types.get(p.akm_suites[0].suite)
                    crypto.add("WPA2/%s" % auth)
                else:
                    crypto.add("WPA2")
            elif p.ID == 221:
                if isinstance(p, Dot11EltMicrosoftWPA) or \
                        p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    if p.akm_suites:
                        auth = akmsuite_types.get(p.akm_suites[0].suite)
                        crypto.add("WPA/%s" % auth)
                    else:
                        crypto.add("WPA")
            p = p.payload
        if not crypto:
            if self.cap.privacy:
                crypto.add("WEP")
            else:
                crypto.add("OPN")
        summary["crypto"] = crypto
        return summary


class Dot11Beacon(_Dot11NetStats):
    name = "802.11 Beacon"


_dot11_info_elts_ids = {
    0: "SSID",
    1: "Rates",
    2: "FHset",
    3: "DSset",
    4: "CFset",
    5: "TIM",
    6: "IBSSset",
    7: "Country",
    10: "Request",
    16: "challenge",
    33: "PowerCapability",
    36: "Channels",
    42: "ERPinfo",
    45: "HTCapabilities",
    46: "QoSCapability",
    47: "ERPinfo",
    48: "RSNinfo",
    50: "ESRates",
    52: "PowerConstraint",
    61: "HTinfo",
    68: "reserved",
    107: "Interworking",
    127: "ExtendendCapatibilities",
    191: "VHTCapabilities",
    221: "vendor"
}


class Dot11Elt(Packet):
    __slots__ = ["info"]
    name = "802.11 Information Element"
    fields_desc = [ByteEnumField("ID", 0, _dot11_info_elts_ids),
                   FieldLenField("len", None, "info", "B"),
                   StrLenField("info", "", length_from=lambda x: x.len,
                               max_length=255)]
    show_indent = 0

    def mysummary(self):
        if self.ID == 0:
            ssid = repr(self.info)
            if ssid[:2] in ['b"', "b'"]:
                ssid = ssid[1:]
            return "SSID=%s" % ssid, [Dot11]
        else:
            return ""

    registered_ies = {}

    @classmethod
    def register_variant(cls):
        cls.registered_ies[cls.ID.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            _id = orb(_pkt[0])
            if _id == 221:
                oui_a = orb(_pkt[2])
                oui_b = orb(_pkt[3])
                oui_c = orb(_pkt[4])
                if oui_a == 0x00 and oui_b == 0x50 and oui_c == 0xf2:
                    # MS OUI
                    type_ = orb(_pkt[5])
                    if type_ == 0x01:
                        # MS WPA IE
                        return Dot11EltMicrosoftWPA
                    else:
                        return Dot11EltVendorSpecific
                else:
                    return Dot11EltVendorSpecific
            else:
                return cls.registered_ies.get(_id, cls)
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


class RSNCipherSuite(Packet):
    name = "Cipher suite"
    fields_desc = [
        X3BytesField("oui", 0x000fac),
        ByteEnumField("cipher", 0x04, {
            0x00: "Use group cipher suite",
            0x01: "WEP-40",
            0x02: "TKIP",
            0x03: "Reserved",
            0x04: "CCMP",
            0x05: "WEP-104"
        })
    ]

    def extract_padding(self, s):
        return "", s


class AKMSuite(Packet):
    name = "AKM suite"
    fields_desc = [
        X3BytesField("oui", 0x000fac),
        ByteEnumField("suite", 0x01, {
            0x00: "Reserved",
            0x01: "IEEE 802.1X / PMKSA caching",
            0x02: "PSK"
        })
    ]

    def extract_padding(self, s):
        return "", s


class PMKIDListPacket(Packet):
    name = "PMKIDs"
    fields_desc = [
        LEFieldLenField("nb_pmkids", 0, count_of="pmk_id_list"),
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
        ByteField("ID", 48),
        ByteField("len", None),
        LEShortField("version", 1),
        PacketField("group_cipher_suite", RSNCipherSuite(), RSNCipherSuite),
        LEFieldLenField(
            "nb_pairwise_cipher_suites",
            1,
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
            1,
            count_of="akm_suites"
        ),
        PacketListField(
            "akm_suites",
            [AKMSuite()],
            AKMSuite,
            count_from=lambda p: p.nb_akm_suites
        ),
        BitField("mfp_capable", 0, 1),
        BitField("mfp_required", 0, 1),
        BitField("gtksa_replay_counter", 0, 2),
        BitField("ptksa_replay_counter", 0, 2),
        BitField("no_pairwise", 0, 1),
        BitField("pre_auth", 0, 1),
        BitField("reserved", 0, 8),
        ConditionalField(
            PacketField("pmkids", None, PMKIDListPacket),
            lambda pkt: (
                0 if pkt.len is None else
                pkt.len - (12 + (pkt.nb_pairwise_cipher_suites * 4) +
                                (pkt.nb_akm_suites * 4)) >= 18)
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
        ByteField("ID", 7),
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


class Dot11EltMicrosoftWPA(Dot11Elt):
    name = "802.11 Microsoft WPA"
    match_subclass = True
    fields_desc = [
        ByteField("ID", 221),
        ByteField("len", None),
        X3BytesField("oui", 0x0050f2),
        XByteField("type", 0x01),
        LEShortField("version", 1),
        PacketField("group_cipher_suite", RSNCipherSuite(), RSNCipherSuite),
        LEFieldLenField(
            "nb_pairwise_cipher_suites",
            1,
            count_of="pairwise_cipher_suites"
        ),
        PacketListField(
            "pairwise_cipher_suites",
            RSNCipherSuite(),
            RSNCipherSuite,
            count_from=lambda p: p.nb_pairwise_cipher_suites
        ),
        LEFieldLenField(
            "nb_akm_suites",
            1,
            count_of="akm_suites"
        ),
        PacketListField(
            "akm_suites",
            AKMSuite(),
            AKMSuite,
            count_from=lambda p: p.nb_akm_suites
        )
    ]


class Dot11EltRates(Dot11Elt):
    name = "802.11 Rates"
    match_subclass = True
    fields_desc = [
        ByteField("ID", 1),
        ByteField("len", None),
        FieldListField(
            "rates",
            [],
            XByteField("", 0),
            count_from=lambda p: p.len
        )
    ]


class Dot11EltVendorSpecific(Dot11Elt):
    name = "802.11 Vendor Specific"
    match_subclass = True
    fields_desc = [
        ByteField("ID", 221),
        ByteField("len", None),
        X3BytesField("oui", 0x000000),
        StrLenField("info", "", length_from=lambda x: x.len - 3)
    ]


class Dot11ATIM(Packet):
    name = "802.11 ATIM"


class Dot11Disas(Packet):
    name = "802.11 Disassociation"
    fields_desc = [LEShortEnumField("reason", 1, reason_code)]


class Dot11AssoReq(Packet):
    name = "802.11 Association Request"
    fields_desc = [FlagsField("cap", 0, 16, capability_list),
                   LEShortField("listen_interval", 0x00c8)]


class Dot11AssoResp(Packet):
    name = "802.11 Association Response"
    fields_desc = [FlagsField("cap", 0, 16, capability_list),
                   LEShortField("status", 0),
                   LEShortField("AID", 0)]


class Dot11ReassoReq(Packet):
    name = "802.11 Reassociation Request"
    fields_desc = [FlagsField("cap", 0, 16, capability_list),
                   LEShortField("listen_interval", 0x00c8),
                   MACField("current_AP", ETHER_ANY)]


class Dot11ReassoResp(Dot11AssoResp):
    name = "802.11 Reassociation Response"


class Dot11ProbeReq(Packet):
    name = "802.11 Probe Request"


class Dot11ProbeResp(_Dot11NetStats):
    name = "802.11 Probe Response"


class Dot11Auth(Packet):
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

# Dot11TKIP & Dot11CCMP

# we can't dissect ICV / MIC here: they are encrypted


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


class Dot11CCMP(Dot11Encrypted):
    name = "802.11 TKIP packet"
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


class Dot11Ack(Packet):
    name = "802.11 Ack packet"


bind_top_down(RadioTap, Dot11FCS, present=2, Flags=16)

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
