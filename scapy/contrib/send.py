#! /usr/bin/env python

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

## Copyright (C) 2009 Adline Stephane <adline.stephane@gmail.com>
##

# Partial support of RFC3971
# scapy.contrib.description = SEND (ICMPv6)
# scapy.contrib.status = loads

from __future__ import absolute_import
import socket

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet6 import icmp6typescls, _ICMPv6NDGuessPayload, Net6

send_icmp6typescls = { 11: "ICMPv6NDOptCGA",
                       12: "ICMPv6NDOptRsaSig",
                       13: "ICMPv6NDOptTmstp",
                       14: "ICMPv6NDOptNonce"
                     }
icmp6typescls.update(send_icmp6typescls)

class HashField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")
    def h2i(self, pkt, x):
        if isinstance(x, str):
            try:
                x = in6_ptop(x)
            except socket.error:
                x = Net6(x)
        elif isinstance(x, list):
            x = [Net6(e) for e in x]
        return x
    def i2m(self, pkt, x):
        return inet_pton(socket.AF_INET6, x)
    def m2i(self, pkt, x):
        return inet_ntop(socket.AF_INET6, x)
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)    # No specific information to return

class ICMPv6NDOptNonce(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptNonce"
    fields_desc = [ ByteField("type",14),
                    FieldLenField("len",None,length_of="data",fmt="B", adjust = lambda pkt,x: (x)/8),
                    StrLenField("nonce","", length_from = lambda pkt: pkt.len*8-2) ]

class ICMPv6NDOptTmstp(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptTmstp"
    fields_desc = [ ByteField("type",13),
                    ByteField("len",2),
                    BitField("reserved",0, 48),
                    LongField("timestamp", None) ]

class ICMPv6NDOptRsaSig(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptRsaSig"
    fields_desc = [ ByteField("type",12),
                    FieldLenField("len",None,length_of="data",fmt="B", adjust = lambda pkt,x: (x)/8),
                    ShortField("reserved",0),
                    HashField("key_hash",None),
                    StrLenField("signature_pad", "", length_from = lambda pkt: pkt.len*8-20) ]

class ICMPv6NDOptCGA(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptCGA"
    fields_desc = [ ByteField("type",11),
                    FieldLenField("len",None,length_of="data",fmt="B", adjust = lambda pkt,x: (x)/8),
                    ByteField("padlength",0),
                    ByteField("reserved",0),
                    StrLenField("CGA_PARAMS", "", length_from = lambda pkt: pkt.len*8 - pkt.padlength - 4),
                    StrLenField("padding", None, length_from = lambda pkt: pkt.padlength) ]

if __name__ == "__main__":
    from scapy.all import *
    interact(mydict=globals(), mybanner="SEND add-on")
