#! /usr/bin/env python

## Copyright (C) 2009 Adline Stephane <adline.stephane@gmail.com>
##
## This program is published under a GPLv2 license

# Partial support of RFC3971
# scapy.contrib.description = SEND
# scapy.contrib.status = loads

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
        if type(x) is str:
            try:
                x = in6_ptop(x)
            except socket.error:
                x = Net6(x)
        elif type(x) is list:
            x = map(Net6, x)
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
