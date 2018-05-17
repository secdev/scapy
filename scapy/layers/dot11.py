# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Wireless LAN according to IEEE 802.11.
"""

from __future__ import print_function
import re
import struct
from zlib import crc32

from scapy.config import conf, crypto_validator
from scapy.data import *
from scapy.compat import *
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.plist import PacketList
from scapy.layers.l2 import *
from scapy.layers.inet import IP, TCP
from scapy.error import warning


if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
else:
    default_backend = Ciphers = algorithms = None
    log_loading.info("Can't import python-cryptography v1.7+. Disabled WEP decryption/encryption. (Dot11)")


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


class RadioTap(Packet):
    name = "RadioTap dummy"
    fields_desc = [ByteField('version', 0),
                   ByteField('pad', 0),
                   FieldLenField('len', None, 'notdecoded', '<H', adjust=lambda pkt, x:x + 8),
                   FlagsField('present', None, -32, ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',
                                                     'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation', 'dB_TX_Attenuation',
                                                     'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',
                                                     'b14', 'b15', 'b16', 'b17', 'b18', 'b19', 'b20', 'b21', 'b22', 'b23',
                                                     'b24', 'b25', 'b26', 'b27', 'b28', 'b29', 'b30', 'Ext']),
                   StrLenField('notdecoded', "", length_from=lambda pkt:pkt.len - 8)]


class PPI(Packet):
    name = "Per-Packet Information header (partial)"
    fields_desc = [ByteField("version", 0),
                   ByteField("flags", 0),
                   FieldLenField("len", None, fmt="<H", length_of="notdecoded", adjust=lambda pkt, x:x + 8),
                   LEIntField("dlt", 0),
                   StrLenField("notdecoded", "", length_from=lambda pkt:pkt.len - 8)
                   ]


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
        ),
    ]

    def mysummary(self):
        return self.sprintf("802.11 %Dot11.type% %Dot11.subtype% %Dot11.addr2% > %Dot11.addr1%")

    def guess_payload_class(self, payload):
        if self.type == 0x02 and (0x08 <= self.subtype <= 0xF and self.subtype != 0xD):
            return Dot11QoS
        elif self.FCfield & 0x40:
            return Dot11WEP
        else:
            return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot11):
            if self.type == 0:  # management
                if self.addr1.lower() != other.addr2.lower():  # check resp DA w/ req SA
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


class Dot11Elt(Packet):
    name = "802.11 Information Element"
    fields_desc = [ByteEnumField("ID", 0, {0: "SSID", 1: "Rates", 2: "FHset", 3: "DSset", 4: "CFset", 5: "TIM", 6: "IBSSset", 16: "challenge",
                                           42: "ERPinfo", 46: "QoS Capability", 47: "ERPinfo", 48: "RSNinfo", 50: "ESRates", 221: "vendor", 68: "reserved"}),
                   FieldLenField("len", None, "info", "B"),
                   StrLenField("info", "", length_from=lambda x: x.len)]

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
        FieldLenField("len", 0, "info", "B"),
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
            lambda pkt: pkt.len - (12 + (pkt.nb_pairwise_cipher_suites * 4) +
                                   (pkt.nb_akm_suites * 4)) >= 18
        )
    ]


class Dot11EltMicrosoftWPA(Dot11Elt):
    name = "Microsoft WPA"
    fields_desc = [
        ByteField("ID", 221),
        FieldLenField("len", 0, "info", "B"),
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


class Dot11EltVendorSpecific(Dot11Elt):
    name = "Vendor Specific"
    fields_desc = [
        ByteField("ID", 221),
        FieldLenField("len", 0, "info", "B"),
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
            warning("No WEP key set (conf.wepkey).. strange results expected..")
            return b""

    def post_build(self, p, pay):
        if self.wepdata is None:
            p = self.encrypt(p, raw(pay))
        return p


class Dot11Ack(Packet):
    name = "802.11 Ack packet"


bind_layers(PrismHeader, Dot11,)
bind_layers(RadioTap, Dot11,)
bind_layers(PPI, Dot11, dlt=105)
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
conf.l2types.register(DLT_PPI, PPI)


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
