## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
##               Vincent Mauge   <vmauge.nospam@nospam.gmail.com>
## This program is published under a GPLv2 license

"""
RADIUS (Remote Authentication Dial In User Service)
"""

import struct
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import *

class RadiusAttribute(Packet): 
    name = "Radius Attribute"
    fields_desc = [
        ByteEnumField("type",1,{ 1:"User-Name",
                                 2:"User-Password",
                                 3:"CHAP-Password",
                                 4:"NAS-IP-Address",
                                 5:"NAS-Port",
                                 6:"Service-Type",
                                 7:"Framed-Protocol",
                                 8:"Framed-IP-Address",
                                 9:"Framed-IP-Netmask",
                                 10:"Framed-Routing",
                                 11:"Filter-Id",
                                 12:"Framed-MTU",
                                 13:"Framed-Compression",
                                 14:"Login-IP-Host",
                                 15:"Login-Service",
                                 16:"Login-TCP-Port",
                                 17:"(unassigned)",
                                 18:"Reply-Message",
                                 19:"Callback-Number",
                                 20:"Callback-Id",
                                 21:"(unassigned)",
                                 22:"Framed-Route",
                                 23:"Framed-IPX-Network",
                                 24:"State",
                                 25:"Class",
                                 26:"Vendor-Specific",
                                 27:"Session-Timeout",
                                 28:"Idle-Timeout",
                                 29:"Termination-Action",
                                 30:"Called-Station-Id",
                                 31:"Calling-Station-Id",
                                 32:"NAS-Identifier",
                                 33:"Proxy-State",
                                 34:"Login-LAT-Service",
                                 35:"Login-LAT-Node",
                                 36:"Login-LAT-Group",
                                 37:"Framed-AppleTalk-Link",
                                 38:"Framed-AppleTalk-Network",
                                 39:"Framed-AppleTalk-Zone",
                                 40:"Acct-Status-Type",
                                 41:"Acct-Delay-Time",
                                 42:"Acct-Input-Octets",
                                 43:"Acct-Output-Octets",
                                 44:"Acct-Session-Id",
                                 45:"Acct-Authentic",
                                 46:"Acct-Session-Time",
                                 47:"Acct-Input-Packets",
                                 48:"Acct-Output-Packets",
                                 49:"Acct-Terminate-Cause",
                                 50:"Acct-Multi-Session-Id",
                                 51:"Acct-Link-Count",
                                 60:"CHAP-Challenge",
                                 61:"NAS-Port-Type",
                                 62:"Port-Limit",
                                 63:"Login-LAT-Port",
                                 70:"ARAP-Password",
                                 75:"Password-Retry",
                                 79:"EAP-Message",
                                 80:"Message-Authenticator",
                                 94:"Originating-Line-Info",
                                 101:"Error-Cause"
                                 }),
        FieldLenField("len", None, "value", "B", adjust=lambda pkt,x:len(pkt.value)+2),
        StrLenField("value", "" , length_from=lambda pkt:pkt.len-2),]

    def post_build(self, p, pay):
        l = self.len
        if l is None:
            l = len(p)
            p = p[:1]+struct.pack("!B", l)+p[2:]
        return p
        
    def extract_padding(self, pay):
        return "",pay


class Radius(Packet):
    name = "Radius"
    fields_desc = [ ByteEnumField("code", 1, {1: "Access-Request",
                                              2: "Access-Accept",
                                              3: "Access-Reject",
                                              4: "Accounting-Request",
                                              5: "Accounting-Accept",
                                              6: "Accounting-Status",
                                              7: "Password-Request",
                                              8: "Password-Ack",
                                              9: "Password-Reject",
                                              10: "Accounting-Message",
                                              11: "Access-Challenge",
                                              12: "Status-Server",
                                              13: "Status-Client",
                                              21: "Resource-Free-Request",
                                              22: "Resource-Free-Response",
                                              23: "Resource-Query-Request",
                                              24: "Resource-Query-Response",
                                              25: "Alternate-Resource-Reclaim-Request",
                                              26: "NAS-Reboot-Request",
                                              27: "NAS-Reboot-Response",
                                              29: "Next-Passcode",
                                              30: "New-Pin",
                                              31: "Terminate-Session",
                                              32: "Password-Expired",
                                              33: "Event-Request",
                                              34: "Event-Response",
                                              40: "Disconnect-Request",
                                              41: "Disconnect-ACK",
                                              42: "Disconnect-NAK",
                                              43: "CoA-Request",
                                              44: "CoA-ACK",
                                              45: "CoA-NAK",
                                              50: "IP-Address-Allocate",
                                              51: "IP-Address-Release",
                                              253: "Experimental-use",
                                              254: "Reserved",
                                              255: "Reserved"} ),
                    ByteField("id", 0),
                    FieldLenField("len", None, "attributes", "H" , adjust=lambda pkt,x:len(pkt.attributes)+20),
                    StrFixedLenField("authenticator","",16),
                    PacketListField("attributes", [], RadiusAttribute, length_from=lambda pkt:pkt.len-20) ]

    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:2]+struct.pack("!H",l)+p[4:]
        return p


bind_layers(UDP, Radius, sport=1812)
bind_layers(UDP, Radius, dport=1812)
bind_layers(UDP, Radius, sport=1813)
bind_layers(UDP, Radius, dport=1813)
