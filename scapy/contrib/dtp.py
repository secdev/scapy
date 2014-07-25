#!/usr/bin/env python

# scapy.contrib.description = DTP
# scapy.contrib.status = loads

"""
    DTP Scapy Extension
    ~~~~~~~~~~~~~~~~~~~

    :version: 2008-12-22
    :author: Jochen Bartl <lobo@c3a.de>

    :Thanks:

    - TLV code derived from the CDP implementation of scapy. (Thanks to Nicolas Bareil and Arnaud Ebalard)
        http://trac.secdev.org/scapy/ticket/18
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import SNAP,Dot3,LLC
from scapy.sendrecv import sendp

class DtpGenericTlv(Packet):
    name = "DTP Generic TLV"
    fields_desc = [ XShortField("type", 0x0001),
            FieldLenField("length", None, length_of=lambda pkt:pkt.value + 4),
            StrLenField("value", "", length_from=lambda pkt:pkt.length - 4)
            ]

    def guess_payload_class(self, p):
        return conf.padding_layer

class RepeatedTlvListField(PacketListField):
    def __init__(self, name, default, cls):
        PacketField.__init__(self, name, default, cls)

    def getfield(self, pkt, s):
        lst = []
        remain = s
        while len(remain) > 0:
            p = self.m2i(pkt,remain)
            if conf.padding_layer in p:
                pad = p[conf.padding_layer]
                remain = pad.load
                del(pad.underlayer.payload)
            else:
                remain = ""
            lst.append(p)
        return remain,lst

    def addfield(self, pkt, s, val):
        return s+reduce(str.__add__, map(str, val),"")

_DTP_TLV_CLS = {
                    0x0001 : "DTPDomain",
                    0x0002 : "DTPStatus",
                    0x0003 : "DTPType",
                    0x0004 : "DTPNeighbor"
                   }

class DTPDomain(DtpGenericTlv):
    name = "DTP Domain"
    fields_desc = [ ShortField("type", 1),
            FieldLenField("length", None, "domain", adjust=lambda pkt,x:x + 4),
            StrLenField("domain", "\x00", length_from=lambda pkt:pkt.length - 4)
            ]

class DTPStatus(DtpGenericTlv):
    name = "DTP Status"
    fields_desc = [ ShortField("type", 2),
            FieldLenField("length", None, "status", adjust=lambda pkt,x:x + 4),
            StrLenField("status", "\x03", length_from=lambda pkt:pkt.length - 4)
            ]

class DTPType(DtpGenericTlv):
    name = "DTP Type"
    fields_desc = [ ShortField("type", 3),
            FieldLenField("length", None, "dtptype", adjust=lambda pkt,x:x + 4),
            StrLenField("dtptype", "\xa5", length_from=lambda pkt:pkt.length - 4)
            ]

class DTPNeighbor(DtpGenericTlv):
    name = "DTP Neighbor"
    fields_desc = [ ShortField("type", 4),
            #FieldLenField("length", None, "neighbor", adjust=lambda pkt,x:x + 4),
            ShortField("len", 10),
            MACField("neighbor", None)
            ]

def _DTPGuessPayloadClass(p, **kargs):
    cls = conf.raw_layer
    if len(p) >= 2:
        t = struct.unpack("!H", p[:2])[0]
        clsname = _DTP_TLV_CLS.get(t, "DtpGenericTlv")
        cls = globals()[clsname]
	return cls(p, **kargs)

class DTP(Packet):
    name = "DTP"
    fields_desc = [ ByteField("ver", 1),
                    RepeatedTlvListField("tlvlist", [], _DTPGuessPayloadClass)
                ]

bind_layers(SNAP, DTP, code=0x2004, OUI=0xc)


def negotiate_trunk(iface=conf.iface, mymac=str(RandMAC())):
    print "Trying to negotiate a trunk on interface %s" % iface
    p = Dot3(src=mymac, dst="01:00:0c:cc:cc:cc")/LLC()/SNAP()/DTP(tlvlist=[DTPDomain(),DTPStatus(),DTPType(),DTPNeighbor(neighbor=mymac)])
    sendp(p)

if __name__ == "__main__":
    from scapy.main import interact
    interact(mydict=globals(), mybanner="DTP")
