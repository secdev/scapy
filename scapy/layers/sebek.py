## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP


### SEBEK


class SebekHead(Packet):
    name = "Sebek header"
    fields_desc = [ XIntField("magic", 0xd0d0d0),
                    ShortField("version", 1),
                    ShortEnumField("type", 0, {"read":0, "write":1,
                                             "socket":2, "open":3}),
                    IntField("counter", 0),
                    IntField("time_sec", 0),
                    IntField("time_usec", 0) ]
    def mysummary(self):
        return self.sprintf("Sebek Header v%SebekHead.version% %SebekHead.type%")

# we need this because Sebek headers differ between v1 and v3, and
# between v3 type socket and v3 others

class SebekV1(Packet):
    name = "Sebek v1"
    fields_desc = [ IntField("pid", 0),
                    IntField("uid", 0),
                    IntField("fd", 0),
                    StrFixedLenField("command", "", 12),
                    FieldLenField("data_length", None, "data",fmt="I"),
                    StrLenField("data", "", length_from=lambda x:x.data_length) ]
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v1 %SebekHead.type% (%SebekV1.command%)")
        else:
            return self.sprintf("Sebek v1 (%SebekV1.command%)")

class SebekV3(Packet):
    name = "Sebek v3"
    fields_desc = [ IntField("parent_pid", 0),
                    IntField("pid", 0),
                    IntField("uid", 0),
                    IntField("fd", 0),
                    IntField("inode", 0),
                    StrFixedLenField("command", "", 12),
                    FieldLenField("data_length", None, "data",fmt="I"),
                    StrLenField("data", "", length_from=lambda x:x.data_length) ]
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV3.command%)")
        else:
            return self.sprintf("Sebek v3 (%SebekV3.command%)")

class SebekV2(SebekV3):
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV2.command%)")
        else:
            return self.sprintf("Sebek v2 (%SebekV2.command%)")

class SebekV3Sock(Packet):
    name = "Sebek v2 socket"
    fields_desc = [ IntField("parent_pid", 0),
                    IntField("pid", 0),
                    IntField("uid", 0),
                    IntField("fd", 0),
                    IntField("inode", 0),
                    StrFixedLenField("command", "", 12),
                    IntField("data_length", 15),
                    IPField("dip", "127.0.0.1"),
                    ShortField("dport", 0),
                    IPField("sip", "127.0.0.1"),
                    ShortField("sport", 0),
                    ShortEnumField("call", 0, { "bind":2,
                                                "connect":3, "listen":4,
                                               "accept":5, "sendmsg":16,
                                               "recvmsg":17, "sendto":11,
                                               "recvfrom":12}),
                    ByteEnumField("proto", 0, IP_PROTOS) ]
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV3Sock.command%)")
        else:
            return self.sprintf("Sebek v3 socket (%SebekV3Sock.command%)")

class SebekV2Sock(SebekV3Sock):
    def mysummary(self):
        if isinstance(self.underlayer, SebekHead):
            return self.underlayer.sprintf("Sebek v%SebekHead.version% %SebekHead.type% (%SebekV2Sock.command%)")
        else:
            return self.sprintf("Sebek v2 socket (%SebekV2Sock.command%)")

bind_layers( UDP,           SebekHead,     sport=1101)
bind_layers( UDP,           SebekHead,     dport=1101)
bind_layers( UDP,           SebekHead,     dport=1101, sport=1101)
bind_layers( SebekHead,     SebekV1,       version=1)
bind_layers( SebekHead,     SebekV2Sock,   version=2, type=2)
bind_layers( SebekHead,     SebekV2,       version=2)
bind_layers( SebekHead,     SebekV3Sock,   version=3, type=2)
bind_layers( SebekHead,     SebekV3,       version=3)
