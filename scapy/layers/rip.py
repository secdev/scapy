## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP

class RIP(Packet):
    name = "RIP header"
    fields_desc = [
        ByteEnumField("cmd",1,{1:"req",2:"resp",3:"traceOn",4:"traceOff",5:"sun",
                               6:"trigReq",7:"trigResp",8:"trigAck",9:"updateReq",
                               10:"updateResp",11:"updateAck"}),
        ByteField("version",1),
        ShortField("null",0),
        ]

class RIPEntry(Packet):
    name = "RIP entry"
    fields_desc = [
        ShortEnumField("AF",2,{2:"IP"}),
        ShortField("RouteTag",0),
        IPField("addr","0.0.0.0"),
        IPField("mask","0.0.0.0"),
        IPField("nextHop","0.0.0.0"),
        IntEnumField("metric",1,{16:"Unreach"}),
        ]
        


bind_layers( UDP,           RIP,           sport=520)
bind_layers( UDP,           RIP,           dport=520)
bind_layers( RIP,           RIPEntry,      )
bind_layers( RIPEntry,      RIPEntry,      )
