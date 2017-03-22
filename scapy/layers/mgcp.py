## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
MGCP (Media Gateway Control Protocol)

[RFC 2805]
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP

class MGCP(Packet):
    name = "MGCP"
    longname = "Media Gateway Control Protocol"
    fields_desc = [ StrStopField("verb","AUEP"," ", -1),
                    StrFixedLenField("sep1"," ",1),
                    StrStopField("transaction_id","1234567"," ", -1),
                    StrFixedLenField("sep2"," ",1),
                    StrStopField("endpoint","dummy@dummy.net"," ", -1),
                    StrFixedLenField("sep3"," ",1),
                    StrStopField("version","MGCP 1.0 NCS 1.0",b"\x0a", -1),
                    StrFixedLenField("sep4",b"\x0a",1),
                    ]
                    
    
#class MGCP(Packet):
#    name = "MGCP"
#    longname = "Media Gateway Control Protocol"
#    fields_desc = [ ByteEnumField("type",0, ["request","response","others"]),
#                    ByteField("code0",0),
#                    ByteField("code1",0),
#                    ByteField("code2",0),
#                    ByteField("code3",0),
#                    ByteField("code4",0),
#                    IntField("trasid",0),
#                    IntField("req_time",0),
#                    ByteField("is_duplicate",0),
#                    ByteField("req_available",0) ]
#
bind_layers( UDP,           MGCP,          dport=2727)
bind_layers( UDP,           MGCP,          sport=2727)
