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
from scapy.packet import Packet, bind_layers, NoPayload
from scapy.fields import ByteField, LEShortField, BitField, LEShortEnumField, \
    ByteEnumField, X3BytesField, FlagsField, LELongField, StrField, \
    StrLenField, IntField, XByteField, LEIntField, StrFixedLenField, \
    LESignedIntField, ReversePadField, ConditionalField, PacketListField, \
    ShortField, BitEnumField, XLEIntField, FieldLenField, LEFieldLenField, \
    FieldListField, XStrFixedLenField, PacketField
from scapy.ansmachine import AnsweringMachine
from scapy.plist import PacketList
from scapy.layers.l2 import Ether, LLC, MACField
from scapy.layers.inet import IP, TCP
from scapy.error import warning, log_loading
from scapy.sendrecv import sniff, sendp
from scapy.utils import issubtype


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


class _RadiotapReversePadField(ReversePadField):
    def __init__(self, fld):
        self._fld = fld
        self._padwith = b"\x00"
        # Quote from https://www.radiotap.org/:
        # ""Radiotap requires that all fields in the radiotap header are aligned to natural boundaries.  # noqa: E501
        # For radiotap, that means all 8-, 16-, 32-, and 64-bit fields must begin on 8-, 16-, 32-, and 64-bit boundaries, respectively.""  # noqa: E501
        if isinstance(self._fld, BitField):
            self._align = int(math.ceil(self.i2len(None, None)))
        else:
            self._align = struct.calcsize(self._fld.fmt)


class _dbmField(ByteField):
    def i2m(self, pkt, x):
        return super(ByteField, self).i2m(pkt, x + 256)

    def m2i(self, pkt, x):
        return super(ByteField, self).m2i(pkt, x) - 256

    def i2repr(self, pkt, x):
        return "%sdBm" % x


_vht_bandwidth = {0: "20MHz", 1: "40MHz", 2: "40MHz", 3: "40MHz", 4: "80MHz", 5: "80MHz",  # noqa: E501
                  6: "80MHz", 7: "80MHz", 8: "80MHz", 9: "80MHz", 10: "80MHz", 11: "160MHz",  # noqa: E501
                  12: "160MHz", 13: "160MHz", 14: "160MHz", 15: "160MHz", 16: "160MHz", 17: "160MHz",  # noqa: E501
                  18: "160MHz", 19: "160MHz", 20: "160MHz", 21: "160MHz", 22: "160MHz", 23: "160MHz",  # noqa: E501
                  24: "160MHz", 25: "160MHz"}


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


class RadioTap(Packet):
    name = "RadioTap dummy"
    fields_desc = [ByteField('version', 0),
                   ByteField('pad', 0),
                   LEShortField('len', None),
                   FlagsField('present', None, -32, ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',  # noqa: E501
                                                     'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation', 'dB_TX_Attenuation',  # noqa: E501
                                                     'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',  # noqa: E501
                                                     'RXFlags', 'b16', 'b17', 'b18', 'ChannelPlus', 'MCS', 'A_MPDU',  # noqa: E501
                                                     'VHT', 'timestamp', 'b24', 'b25', 'b26', 'b27', 'b28', 'b29',  # noqa: E501
                                                     'RadiotapNS', 'VendorNS', 'Ext']),  # noqa: E501
                   # Extended presence mask
                   ConditionalField(PacketListField("Ext", [], next_cls_cb=_next_radiotap_extpm), lambda pkt: pkt.present and pkt.present.Ext),  # noqa: E501
                   # Default fields
                   ConditionalField(_RadiotapReversePadField(BitField("mac_timestamp", 0, -64)), lambda pkt: pkt.present and pkt.present.TSFT),  # noqa: E501
                   ConditionalField(
                       _RadiotapReversePadField(
                           FlagsField("Flags", None, -8, ['CFP', 'ShortPreamble', 'wep', 'fragment',  # noqa: E501
                                                          'FCS', 'pad', 'badFCS', 'ShortGI'])  # noqa: E501
                       ),
                       lambda pkt: pkt.present and pkt.present.Flags),
                   ConditionalField(_RadiotapReversePadField(ByteField("Rate", 0)), lambda pkt: pkt.present and pkt.present.Rate),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(LEShortField("Channel", 0)), lambda pkt: pkt.present and pkt.present.Channel),  # noqa: E501
                   ConditionalField(
                       _RadiotapReversePadField(
                           FlagsField("ChannelFlags", None, -16, ['res1', 'res2', 'res3', 'res4', 'Turbo', 'CCK',  # noqa: E501
                                                                  'OFDM', '2GHz', '5GHz', 'Passive', 'Dynamic_CCK_OFDM',  # noqa: E501
                                                                  'GFSK', 'GSM', 'StaticTurbo', '10MHz', '5MHz'])  # noqa: E501
                       ),
                       lambda pkt: pkt.present and pkt.present.Channel),
                   ConditionalField(_RadiotapReversePadField(_dbmField("dBm_AntSignal", -256)), lambda pkt: pkt.present and pkt.present.dBm_AntSignal),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(_dbmField("dBm_AntNoise", -256)), lambda pkt: pkt.present and pkt.present.dBm_AntNoise),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(ByteField("Antenna", 0)), lambda pkt: pkt.present and pkt.present.Antenna),  # noqa: E501
                   # ChannelPlus
                   ConditionalField(
                       _RadiotapReversePadField(
                           FlagsField("ChannelFlags2", None, -32, ['res1', 'res2', 'res3', 'res4', 'Turbo', 'CCK',  # noqa: E501
                                                                   'OFDM', '2GHz', '5GHz', 'Passive', 'Dynamic_CCK_OFDM',  # noqa: E501
                                                                   'GFSK', 'GSM', 'StaticTurbo', '10MHz', '5MHz',  # noqa: E501
                                                                   '20MHz', '40MHz_ext_channel_above', '40MHz_ext_channel_below',  # noqa: E501
                                                                   'res5', 'res6', 'res7', 'res8', 'res9'])  # noqa: E501
                       ),
                       lambda pkt: pkt.present and pkt.present.ChannelPlus),
                   ConditionalField(_RadiotapReversePadField(LEShortField("ChannelFrequency", 0)), lambda pkt: pkt.present and pkt.present.ChannelPlus),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(ByteField("ChannelNumber", 0)), lambda pkt: pkt.present and pkt.present.ChannelPlus),  # noqa: E501
                   # MCS
                   ConditionalField(
                       _RadiotapReversePadField(FlagsField("knownMCS", None, -8, ['bandwidth', 'MCS_index', 'guard_interval', 'HT_format',  # noqa: E501
                                                                                  'FEC_type', 'STBC_streams', 'Ness', 'Ness_MSB'])),  # noqa: E501
                       lambda pkt: pkt.present and pkt.present.MCS),
                   ConditionalField(BitEnumField("bandwidth", 0, 2, {0: "20MHz", 1: "40MHz", 2: "ht40Mhz-", 3: "ht40MHz+"}),  # noqa: E501
                                    lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   ConditionalField(BitEnumField("guard_interval", 0, 1, {0: "Long_GI", 1: "Short_GI"}), lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   ConditionalField(BitEnumField("HT_format", 0, 1, {0: "mixed", 1: "greenfield"}), lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   ConditionalField(BitEnumField("FEC_type", 0, 1, {0: "BCC", 1: "LDPC"}), lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   ConditionalField(BitField("STBC_streams", 0, 2), lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   ConditionalField(BitField("Ness_LSB", 0, 1), lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   ConditionalField(ByteField("MCS_index", 0), lambda pkt: pkt.present and pkt.present.MCS),  # noqa: E501
                   # A_MPDU
                   ConditionalField(_RadiotapReversePadField(LEIntField("A_MPDU_ref", 0)), lambda pkt: pkt.present and pkt.present.A_MPDU),  # noqa: E501
                   ConditionalField(
                       _RadiotapReversePadField(
                           FlagsField("A_MPDU_flags", None, -32, ['Report0Subframe', 'Is0Subframe', 'KnownLastSubframe',  # noqa: E501
                                                                  'LastSubframe', 'CRCerror', 'EOFsubframe', 'KnownEOF',  # noqa: E501
                                                                  'res1', 'res2', 'res3', 'res4', 'res5', 'res6', 'res7', 'res8'])  # noqa: E501
                       ),
                       lambda pkt: pkt.present and pkt.present.A_MPDU),
                   # VHT
                   ConditionalField(
                       _RadiotapReversePadField(
                           FlagsField("KnownVHT", None, -16, ['STBC', 'TXOP_PS_NOT_ALLOWED', 'GuardInterval', 'SGINsysmDis',  # noqa: E501
                                                              'LDPCextraOFDM', 'Beamformed', 'Bandwidth', 'GroupID', 'PartialAID',  # noqa: E501
                                                              'res1', 'res2', 'res3', 'res4', 'res5', 'res6', 'res7'])  # noqa: E501
                       ),
                       lambda pkt: pkt.present and pkt.present.VHT),
                   ConditionalField(
                       _RadiotapReversePadField(
                           FlagsField("PresentVHT", None, -8, ['STBC', 'TXOP_PS_NOT_ALLOWED', 'GuardInterval', 'SGINsysmDis',  # noqa: E501
                                                               'LDPCextraOFDM', 'Beamformed', 'res1', 'res2'])  # noqa: E501
                       ),
                       lambda pkt: pkt.present and pkt.present.VHT),
                   ConditionalField(_RadiotapReversePadField(ByteEnumField("bandwidth", 0, _vht_bandwidth)), lambda pkt: pkt.present and pkt.present.VHT),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(StrFixedLenField("mcs_nss", 0, length=5)), lambda pkt: pkt.present and pkt.present.VHT),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(ByteField("GroupID", 0)), lambda pkt: pkt.present and pkt.present.VHT),  # noqa: E501
                   ConditionalField(_RadiotapReversePadField(ShortField("PartialAID", 0)), lambda pkt: pkt.present and pkt.present.VHT),  # noqa: E501
                   StrLenField('notdecoded', "", length_from=lambda pkt: pkt.len - pkt._tmp_dissect_pos)]  # noqa: E501

    def guess_payload_class(self, payload):
        if self.present and self.present.Flags and self.Flags.FCS:
            return Dot11FCS
        return Dot11

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
                                     "pw-mgt", "MD", "wep", "order"]),
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
        elif self.FCfield & 0x40:
            return Dot11WEP
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
    fields_desc = Dot11.fields_desc + [XLEIntField("fcs", None)]  # Automatically moved to the end of the packet  # noqa: E501

    def compute_fcs(self, s):
        return struct.pack("!I", crc32(s) & 0xffffffff)[::-1]

    def post_build(self, p, pay):
        # Switch payload and frame check sequence
        return p[:-4] + pay + (p[-4:] if self.fcs is not None else self.compute_fcs(p[:-4] + pay))  # noqa: E501

    def post_dissect(self, s):
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def pre_dissect(self, s):
        # Get the frame check sequence
        sty = orb(s[0])
        ty = orb(s[1]) >> 2
        fc = struct.unpack("!H", s[2:4])[0]
        length = 12 + 6 * ((ty != 1 or sty in [0x8, 0x9, 0xa, 0xb, 0xe, 0xf]) + (ty in [0, 2]) + (ty == 2 and fc & 3 == 3))  # noqa: E501
        return s[:length] + s[-4:] + s[length:-4]


class Dot11QoS(Packet):
    name = "802.11 QoS"
    fields_desc = [BitField("Reserved", None, 1),
                   BitField("Ack_Policy", None, 2),
                   BitField("EOSP", None, 1),
                   BitField("TID", None, 4),
                   ByteField("TXOP", None)]

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, Dot11):
            if self.underlayer.FCfield & 0x40:
                return Dot11WEP
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


class Dot11Beacon(Packet):
    name = "802.11 Beacon"
    fields_desc = [LELongField("timestamp", 0),
                   LEShortField("beacon_interval", 0x0064),
                   FlagsField("cap", 0, 16, capability_list)]

    def network_stats(self):
        """Return a dictionary containing a summary of the Dot11
        elements fields
        """
        summary = {}
        crypto = set()
        p = self.payload
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                summary["ssid"] = plain_str(p.info)
            elif p.ID == 3:
                summary["channel"] = ord(p.info)
            elif isinstance(p, Dot11EltRates):
                summary["rates"] = p.rates
            elif isinstance(p, Dot11EltRSN):
                crypto.add("WPA2")
            elif p.ID == 221:
                if isinstance(p, Dot11EltMicrosoftWPA) or \
                        p.info.startswith('\x00P\xf2\x01\x01\x00'):
                    crypto.add("WPA")
            p = p.payload
        if not crypto:
            if self.cap.privacy:
                crypto.add("WEP")
            else:
                crypto.add("OPN")
        summary["crypto"] = crypto
        return summary


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
    107: "Interworking",
    127: "ExtendendCapatibilities",
    191: "VHTCapabilities",
    221: "vendor",
    68: "reserved"
}


class Dot11Elt(Packet):
    name = "802.11 Information Element"
    fields_desc = [ByteEnumField("ID", 0, _dot11_info_elts_ids),
                   FieldLenField("len", None, "info", "B"),
                   StrLenField("info", "", length_from=lambda x: x.len,
                               max_length=255)]

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

    def haslayer(self, cls):
        if cls == "Dot11Elt":
            if isinstance(self, Dot11Elt):
                return True
        elif issubtype(cls, Dot11Elt):
            if isinstance(self, cls):
                return True
        return super(Dot11Elt, self).haslayer(cls)

    def getlayer(self, cls, nb=1, _track=None, _subclass=True, **flt):
        return super(Dot11Elt, self).getlayer(cls, nb=nb, _track=_track,
                                              _subclass=True, **flt)

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
    name = "RSN information"
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
        BitField("pre_auth", 0, 1),
        BitField("no_pairwise", 0, 1),
        BitField("ptksa_replay_counter", 0, 2),
        BitField("gtksa_replay_counter", 0, 2),
        BitField("mfp_required", 0, 1),
        BitField("mfp_capable", 0, 1),
        BitField("reserved", 0, 8),
        ConditionalField(
            PacketField("pmkids", None, PMKIDListPacket),
            lambda pkt: (
                0 if pkt.len is None else
                pkt.len - (12 + (pkt.nb_pairwise_cipher_suites * 4) +
                                (pkt.nb_akm_suites * 4)) >= 18)
        )
    ]


class Dot11EltMicrosoftWPA(Dot11Elt):
    name = "Microsoft WPA"
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
    name = "Rates"
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
    name = "Vendor Specific"
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


class Dot11ProbeResp(Packet):
    name = "802.11 Probe Response"
    fields_desc = [LELongField("timestamp", 0),
                   LEShortField("beacon_interval", 0x0064),
                   FlagsField("cap", 0, 16, capability_list)]


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


class Dot11WEP(Packet):
    name = "802.11 WEP packet"
    fields_desc = [StrFixedLenField("iv", b"\0\0\0", 3),
                   ByteField("keyid", 0),
                   StrField("wepdata", None, remain=4),
                   IntField("icv", None)]

    @crypto_validator
    def decrypt(self, key=None):
        if key is None:
            key = conf.wepkey
        if key:
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


class Dot11Ack(Packet):
    name = "802.11 Ack packet"


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
