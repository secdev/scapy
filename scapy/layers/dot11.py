## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Wireless LAN according to IEEE 802.11.
"""

import re,struct
from zlib import crc32

from scapy.config import conf, crypto_validator
from scapy.data import *
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
    log_loading.info("Can't import python-cryptography v1.7+. Disabled WEP decryption/encryption.")


### Fields

class Dot11AddrMACField(MACField):
    def is_applicable(self, pkt):
        return 1
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return MACField.addfield(self, pkt, s, val)
        else:
            return s        
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return MACField.getfield(self, pkt, s)
        else:
            return s,None

class Dot11Addr2MACField(Dot11AddrMACField):
    # Block-Ack, RTS, PS-Poll, CF-End, CF-End+CF-Ack
    subtypes = {0x9, 0xb, 0xa, 0xe, 0xf}
    def is_applicable(self, pkt):
        return pkt.type != 1 or pkt.subtype in self.subtypes

class Dot11Addr3MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type in [0,2]:
            return 1
        return 0

class Dot11Addr4MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 2:
            if pkt.FCfield & 0x3 == 0x3: # To-DS and From-DS are set
                return 1
        return 0
    

### Layers


class PrismHeader(Packet):
    """ iwpriv wlan0 monitor 3 """
    name = "Prism header"
    fields_desc = [ LEIntField("msgcode",68),
                    LEIntField("len",144),
                    StrFixedLenField("dev","",16),
                    LEIntField("hosttime_did",0),
                  LEShortField("hosttime_status",0),
                  LEShortField("hosttime_len",0),
                    LEIntField("hosttime",0),
                    LEIntField("mactime_did",0),
                  LEShortField("mactime_status",0),
                  LEShortField("mactime_len",0),
                    LEIntField("mactime",0),
                    LEIntField("channel_did",0),
                  LEShortField("channel_status",0),
                  LEShortField("channel_len",0),
                    LEIntField("channel",0),
                    LEIntField("rssi_did",0),
                  LEShortField("rssi_status",0),
                  LEShortField("rssi_len",0),
                    LEIntField("rssi",0),
                    LEIntField("sq_did",0),
                  LEShortField("sq_status",0),
                  LEShortField("sq_len",0),
                    LEIntField("sq",0),
                    LEIntField("signal_did",0),
                  LEShortField("signal_status",0),
                  LEShortField("signal_len",0),
              LESignedIntField("signal",0),
                    LEIntField("noise_did",0),
                  LEShortField("noise_status",0),
                  LEShortField("noise_len",0),
                    LEIntField("noise",0),
                    LEIntField("rate_did",0),
                  LEShortField("rate_status",0),
                  LEShortField("rate_len",0),
                    LEIntField("rate",0),
                    LEIntField("istx_did",0),
                  LEShortField("istx_status",0),
                  LEShortField("istx_len",0),
                    LEIntField("istx",0),
                    LEIntField("frmlen_did",0),
                  LEShortField("frmlen_status",0),
                  LEShortField("frmlen_len",0),
                    LEIntField("frmlen",0),
                    ]
    def answers(self, other):
        if isinstance(other, PrismHeader):
            return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)

class RadioTap(Packet):
    name = "RadioTap dummy"
    fields_desc = [ ByteField('version', 0),
                    ByteField('pad', 0),
                    FieldLenField('len', None, 'notdecoded', '<H', adjust=lambda pkt,x:x+8),
                    FlagsField('present', None, -32, ['TSFT','Flags','Rate','Channel','FHSS','dBm_AntSignal',
                                                     'dBm_AntNoise','Lock_Quality','TX_Attenuation','dB_TX_Attenuation',
                                                      'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',
                                                     'b14', 'b15','b16','b17','b18','b19','b20','b21','b22','b23',
                                                     'b24','b25','b26','b27','b28','b29','b30','Ext']),
                    StrLenField('notdecoded', "", length_from= lambda pkt:pkt.len-8) ]

class PPI(Packet):
    name = "Per-Packet Information header (partial)"
    fields_desc = [ ByteField("version", 0),
                    ByteField("flags", 0),
                    FieldLenField("len", None, fmt="<H", length_of="fields", adjust=lambda pkt,x:x+8),
                    LEIntField("dlt", 0),
                    StrLenField("notdecoded", "", length_from = lambda pkt:pkt.len-8)
                    ]



class Dot11SCField(LEShortField):
    def is_applicable(self, pkt):
        return pkt.type != 1 # control frame
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return LEShortField.addfield(self, pkt, s, val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return LEShortField.getfield(self, pkt, s)
        else:
            return s,None

class Dot11(Packet):
    name = "802.11"
    fields_desc = [
                    BitField("subtype", 0, 4),
                    BitEnumField("type", 0, 2, ["Management", "Control", "Data", "Reserved"]),
                    BitField("proto", 0, 2),
                    FlagsField("FCfield", 0, 8, ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]),
                    ShortField("ID",0),
                    MACField("addr1", ETHER_ANY),
                    Dot11Addr2MACField("addr2", ETHER_ANY),
                    Dot11Addr3MACField("addr3", ETHER_ANY),
                    Dot11SCField("SC", 0),
                    Dot11Addr4MACField("addr4", ETHER_ANY) 
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
        if isinstance(other,Dot11):
            if self.type == 0: # management
                if self.addr1.lower() != other.addr2.lower(): # check resp DA w/ req SA
                    return 0
                if (other.subtype,self.subtype) in [(0,1),(2,3),(4,5)]:
                    return 1
                if self.subtype == other.subtype == 11: # auth
                    return self.payload.answers(other.payload)
            elif self.type == 1: # control
                return 0
            elif self.type == 2: # data
                return self.payload.answers(other.payload)
            elif self.type == 3: # reserved
                return 0
        return 0
    def unwep(self, key=None, warn=1):
        if self.FCfield & 0x40 == 0:
            if warn:
                warning("No WEP to remove")
            return
        if  isinstance(self.payload.payload, NoPayload):
            if key or conf.wepkey:
                self.payload.decrypt(key)
            if isinstance(self.payload.payload, NoPayload):
                if warn:
                    warning("Dot11 can't be decrypted. Check conf.wepkey.")
                return
        self.FCfield &= ~0x40
        self.payload=self.payload.payload


class Dot11QoS(Packet):
    name = "802.11 QoS"
    fields_desc = [ BitField("TID",None,4),
                    BitField("EOSP",None,1),
                    BitField("Ack Policy",None,2),
                    BitField("Reserved",None,1),
                    ByteField("TXOP",None) ]
    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, Dot11):
            if self.underlayer.FCfield & 0x40:
                return Dot11WEP
        return Packet.guess_payload_class(self, payload)


capability_list = [ "res8", "res9", "short-slot", "res11",
                    "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]

reason_code = {0:"reserved",1:"unspec", 2:"auth-expired",
               3:"deauth-ST-leaving",
               4:"inactivity", 5:"AP-full", 6:"class2-from-nonauth",
               7:"class3-from-nonass", 8:"disas-ST-leaving",
               9:"ST-not-auth"}

status_code = {0:"success", 1:"failure", 10:"cannot-support-all-cap",
               11:"inexist-asso", 12:"asso-denied", 13:"algo-unsupported",
               14:"bad-seq-num", 15:"challenge-failure",
               16:"timeout", 17:"AP-full",18:"rate-unsupported" }

class Dot11Beacon(Packet):
    name = "802.11 Beacon"
    fields_desc = [ LELongField("timestamp", 0),
                    LEShortField("beacon_interval", 0x0064),
                    FlagsField("cap", 0, 16, capability_list) ]
    

class Dot11Elt(Packet):
    name = "802.11 Information Element"
    fields_desc = [ ByteEnumField("ID", 0, {0:"SSID", 1:"Rates", 2: "FHset", 3:"DSset", 4:"CFset", 5:"TIM", 6:"IBSSset", 16:"challenge",
                                            42:"ERPinfo", 46:"QoS Capability", 47:"ERPinfo", 48:"RSNinfo", 50:"ESRates",221:"vendor",68:"reserved"}),
                    FieldLenField("len", None, "info", "B"),
                    StrLenField("info", "", length_from=lambda x:x.len) ]
    def mysummary(self):
        if self.ID == 0:
            return "SSID=%s"%repr(self.info),[Dot11]
        else:
            return ""

class Dot11ATIM(Packet):
    name = "802.11 ATIM"

class Dot11Disas(Packet):
    name = "802.11 Disassociation"
    fields_desc = [ LEShortEnumField("reason", 1, reason_code) ]

class Dot11AssoReq(Packet):
    name = "802.11 Association Request"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    LEShortField("listen_interval", 0x00c8) ]


class Dot11AssoResp(Packet):
    name = "802.11 Association Response"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    LEShortField("status", 0),
                    LEShortField("AID", 0) ]

class Dot11ReassoReq(Packet):
    name = "802.11 Reassociation Request"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    LEShortField("listen_interval", 0x00c8),
                    MACField("current_AP", ETHER_ANY) ]


class Dot11ReassoResp(Dot11AssoResp):
    name = "802.11 Reassociation Response"

class Dot11ProbeReq(Packet):
    name = "802.11 Probe Request"
    
class Dot11ProbeResp(Packet):
    name = "802.11 Probe Response"
    fields_desc = [ LELongField("timestamp", 0),
                    LEShortField("beacon_interval", 0x0064),
                    FlagsField("cap", 0, 16, capability_list) ]
    
class Dot11Auth(Packet):
    name = "802.11 Authentication"
    fields_desc = [ LEShortEnumField("algo", 0, ["open", "sharedkey"]),
                    LEShortField("seqnum", 0),
                    LEShortEnumField("status", 0, status_code) ]
    def answers(self, other):
        if self.seqnum == other.seqnum+1:
            return 1
        return 0

class Dot11Deauth(Packet):
    name = "802.11 Deauthentication"
    fields_desc = [ LEShortEnumField("reason", 1, reason_code) ]



class Dot11WEP(Packet):
    name = "802.11 WEP packet"
    fields_desc = [ StrFixedLenField("iv", "\0\0\0", 3),
                    ByteField("keyid", 0),
                    StrField("wepdata",None,remain=4),
                    IntField("icv",None) ]

    @crypto_validator
    def decrypt(self, key=None):
        if key is None:
            key = conf.wepkey
        if key:
            d = Cipher(
                algorithms.ARC4(self.iv + key),
                None,
                default_backend(),
            ).decryptor()
            self.add_payload(LLC(d.update(self.wepdata) + d.finalize()))

    def post_dissect(self, s):
        self.decrypt()

    def build_payload(self):
        if self.wepdata is None:
            return Packet.build_payload(self)
        return ""

    @crypto_validator
    def encrypt(self, p, pay, key=None):
        if key is None:
            key = conf.wepkey
        if key:
            if self.icv is None:
                pay += struct.pack("<I", crc32(pay))
                icv = ""
            else:
                icv = p[4:8]
            e = Cipher(
                algorithms.ARC4(self.iv + key),
                None,
                default_backend(),
            ).encryptor()
            return p[:4] + e.update(pay) + e.finalize() + icv
        else:
            warning("No WEP key set (conf.wepkey).. strange results expected..")
            return None

    def post_build(self, p, pay):
        if self.wepdata is None:
            p = self.encrypt(p, pay)
        return p


bind_layers( PrismHeader,   Dot11,         )
bind_layers( RadioTap,      Dot11,         )
bind_layers( PPI,           Dot11,         dlt=105)
bind_layers( Dot11,         LLC,           type=2)
bind_layers( Dot11QoS,      LLC,           )
bind_layers( Dot11,         Dot11AssoReq,    subtype=0, type=0)
bind_layers( Dot11,         Dot11AssoResp,   subtype=1, type=0)
bind_layers( Dot11,         Dot11ReassoReq,  subtype=2, type=0)
bind_layers( Dot11,         Dot11ReassoResp, subtype=3, type=0)
bind_layers( Dot11,         Dot11ProbeReq,   subtype=4, type=0)
bind_layers( Dot11,         Dot11ProbeResp,  subtype=5, type=0)
bind_layers( Dot11,         Dot11Beacon,     subtype=8, type=0)
bind_layers( Dot11,         Dot11ATIM,       subtype=9, type=0)
bind_layers( Dot11,         Dot11Disas,      subtype=10, type=0)
bind_layers( Dot11,         Dot11Auth,       subtype=11, type=0)
bind_layers( Dot11,         Dot11Deauth,     subtype=12, type=0)
bind_layers( Dot11Beacon,     Dot11Elt,    )
bind_layers( Dot11AssoReq,    Dot11Elt,    )
bind_layers( Dot11AssoResp,   Dot11Elt,    )
bind_layers( Dot11ReassoReq,  Dot11Elt,    )
bind_layers( Dot11ReassoResp, Dot11Elt,    )
bind_layers( Dot11ProbeReq,   Dot11Elt,    )
bind_layers( Dot11ProbeResp,  Dot11Elt,    )
bind_layers( Dot11Auth,       Dot11Elt,    )
bind_layers( Dot11Elt,        Dot11Elt,    )


conf.l2types.register(105, Dot11)
conf.l2types.register_num2layer(801, Dot11)
conf.l2types.register(119, PrismHeader)
conf.l2types.register_num2layer(802, PrismHeader)
conf.l2types.register(127, RadioTap)
conf.l2types.register(0xc0, PPI)
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
    
    def parse_options(self, iffrom, ifto, replace, pattern="", ignorepattern=""):
        self.iffrom = iffrom
        self.ifto = ifto
        ptrn = re.compile(pattern)
        iptrn = re.compile(ignorepattern)
        
    def is_request(self, pkt):
        if not isinstance(pkt,Dot11):
            return 0
        if not pkt.FCfield & 1:
            return 0
        if not pkt.haslayer(TCP):
            return 0
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        pay = str(tcp.payload)
        if not self.ptrn.match(pay):
            return 0
        if self.iptrn.match(pay):
            return 0

    def make_reply(self, p):
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
        del(p.payload.payload.payload)
        p.FCfield="from-DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= self.replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(self.replace)
        return [p,q]
    
    def print_reply(self):
        print self.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    def send_reply(self, reply):
        sendp(reply, iface=self.ifto, **self.optsend)

    def sniff(self):
        sniff(iface=self.iffrom, **self.optsniff)


def airpwn(iffrom, ifto, replace, pattern="", ignorepattern=""):
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
    
    ptrn = re.compile(pattern)
    iptrn = re.compile(ignorepattern)
    def do_airpwn(p, ifto=ifto, replace=replace, ptrn=ptrn, iptrn=iptrn):
        if not isinstance(p,Dot11):
            return
        if not p.FCfield & 1:
            return
        if not p.haslayer(TCP):
            return
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
        if not ptrn.match(pay):
            return
        if iptrn.match(pay):
            return
        del(p.payload.payload.payload)
        p.FCfield="from-DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        q = p.copy()
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(replace)
        
        sendp([p,q], iface=ifto, verbose=0)
        print p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    sniff(iface=iffrom,prn=do_airpwn)

            
        
conf.stats_dot11_protocols += [Dot11WEP, Dot11Beacon, ]


        


class Dot11PacketList(PacketList):
    def __init__(self, res=None, name="Dot11List", stats=None):
        if stats is None:
            stats = conf.stats_dot11_protocols

        PacketList.__init__(self, res, name, stats)
    def toEthernet(self):
        data = map(lambda x:x.getlayer(Dot11), filter(lambda x : x.haslayer(Dot11) and x.type == 2, self.res))
        r2 = []
        for p in data:
            q = p.copy()
            q.unwep()
            r2.append(Ether()/q.payload.payload.payload) #Dot11/LLC/SNAP/IP
        return PacketList(r2,name="Ether from %s"%self.listname)
        
        
