#!/usr/bin/env python

# This file is part of Scapy
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

# scapy.contrib.description = DTP
# scapy.contrib.status = loads

"""
    DTP Scapy Extension
    ~~~~~~~~~~~~~~~~~~~

    :version: 2008-12-22
    :author: Jochen Bartl <lobo@c3a.de>

    :Thanks:

    - TLV code derived from the CDP implementation of scapy. (Thanks to Nicolas Bareil and Arnaud Ebalard)
"""

from __future__ import absolute_import
from __future__ import print_function
from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import SNAP, Dot3, LLC
from scapy.sendrecv import sendp

class DtpGenericTlv(Packet):
    name = "DTP Generic TLV"
    fields_desc = [ XShortField("type", 0x0001),
            FieldLenField("length", None, length_of=lambda pkt:pkt.value + 4),
            StrLenField("value", "", length_from=lambda pkt:pkt.length - 4)
            ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            cls = _DTP_TLV_CLS.get(t, "DtpGenericTlv")
        return cls

    def guess_payload_class(self, p):
        return conf.padding_layer

class DTPDomain(DtpGenericTlv):
    name = "DTP Domain"
    fields_desc = [ ShortField("type", 1),
            FieldLenField("length", None, "domain", adjust=lambda pkt,x:x + 4),
            StrLenField("domain", b"\x00", length_from=lambda pkt:pkt.length - 4)
            ]

class DTPStatus(DtpGenericTlv):
    name = "DTP Status"
    fields_desc = [ ShortField("type", 2),
            FieldLenField("length", None, "status", adjust=lambda pkt,x:x + 4),
            StrLenField("status", b"\x03", length_from=lambda pkt:pkt.length - 4)
            ]

class DTPType(DtpGenericTlv):
    name = "DTP Type"
    fields_desc = [ ShortField("type", 3),
            FieldLenField("length", None, "dtptype", adjust=lambda pkt,x:x + 4),
            StrLenField("dtptype", b"\xa5", length_from=lambda pkt:pkt.length - 4)
            ]

class DTPNeighbor(DtpGenericTlv):
    name = "DTP Neighbor"
    fields_desc = [ ShortField("type", 4),
            #FieldLenField("length", None, "neighbor", adjust=lambda pkt,x:x + 4),
            ShortField("len", 10),
            MACField("neighbor", None)
            ]

_DTP_TLV_CLS = {
    0x0001: DTPDomain,
    0x0002: DTPStatus,
    0x0003: DTPType,
    0x0004: DTPNeighbor
   }

class DTP(Packet):
    name = "DTP"
    fields_desc = [ByteField("ver", 1),
                   PacketListField("tlvlist", [], DtpGenericTlv)]

bind_layers(SNAP, DTP, code=0x2004, OUI=0xc)

def negotiate_trunk(iface=conf.iface, mymac=str(RandMAC())):
    print("Trying to negotiate a trunk on interface %s" % iface)
    p = Dot3(src=mymac, dst="01:00:0c:cc:cc:cc")/LLC()/SNAP()/DTP(tlvlist=[DTPDomain(),DTPStatus(),DTPType(),DTPNeighbor(neighbor=mymac)])
    sendp(p)
