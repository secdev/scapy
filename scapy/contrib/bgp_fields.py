#! /usr/bin/env python 
# -*- coding: utf-8 -*-
"""BGP-4 disector: fields for implementing MPBGP extensions"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet6 import IP6Field
from scapy.layers.inet import TCP
from scapy.error import log_runtime

#
# Fields
#

class PacketArrayField(PacketListField):
    """Quick hack to chop BGPPackets in a TCP PDU into an array of BGP packets
Based on the fact that the BGP-4 header has a fixed field format
@param name: name of the array
@param default: default value
@param cls: class of the elements in the array
@param spkt_len(s): inspect the byte array s and return the length of the first packet in it.
"""
    def __init__(self, name, default,cls,spkt_len=None):
        assert spkt_len is not None
        PacketListField.__init__(self, name, default, cls)
        self.spkt_len = spkt_len
    def getfield(self, pkt, s):
        lst = []
        ret = ""
        remain = s
        l = self.spkt_len(s)
        remain,ret = s[:l],s[l:]
        while remain:
            try:
                p = self.m2i(pkt,remain)
            except Exception:
                raise
            else:
                lst.append(p)
            try:
                l = self.spkt_len(ret)
                # log_runtime.info ("Next one will be %d bytes long" % l)
                remain,ret = ret[:l],ret[l:]
            except:
                remain=""
        return ret,lst

#
# -------------------------------------
#
class BGPIPField(Field):
    """Represents how bgp dose an ip prefix in (length, prefix)"""
    def mask2iplen(self,mask):
	"""turn the mask into the length in bytes of the ip field"""
	return (mask + 7) // 8
    def h2i(self, pkt, h):
	"""human x.x.x.x/y to internal"""
	ip,mask = re.split( '/', h)
	return  int(mask), ip
    def i2h( self, pkt, i):
	mask, ip = i
	return ip + '/' + str( mask )
    def i2repr( self, pkt, i):
	"""make it look nice"""
	return self.i2h(pkt,i)
    def i2len(self, pkt, i):
	"""rely on integer division"""
	mask, ip = i
	return self.mask2iplen(mask) + 1
    def i2m(self, pkt, i):
	"""internal (ip as bytes, mask as int) to machine"""
	mask, ip = i
	ip = inet_aton( ip )
	return struct.pack(">B",mask) + ip[:self.mask2iplen(mask)] 
    def addfield(self, pkt, s, val):
	return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
	l = self.mask2iplen( struct.unpack(">B",s[0])[0] ) + 1
	return s[l:], self.m2i(pkt,s[:l])
    def m2i(self,pkt,m):
	mask = struct.unpack(">B",m[0])[0]
	ip = "".join( [ m[i + 1] if i < self.mask2iplen(mask) else '\x00' for i in range(4)] )
	return (mask,inet_ntoa(ip))
#
# -------------------------
#
class CommunityField(Field):
    """BGP Community field"""
    well_known = {
        "NO_EXPORT" : (0xFFFF, 0xFF01),
        "NO_ADVERTISE" : (0xFFFF, 0xFF02),
        "NO_EXPORT_SUBCONFED": (0xFFFF, 0xFF03),
    }
    def h2i(self, pkt, h):
	"""human to internal (hi,lo)"""
        h = h.upper()
        if h in self.well_known.keys():
            return self.well_known[h]
        m = re.match("(\d+):(\d+)",h)
	return  int(m.group(1)), int(m.group(2))
    def i2h( self, pkt, i):
        for r in self.well_known:
            if i == self.well_known[r]:
                return r
	return "%d:%d" % i
    def i2repr( self, pkt, i):
	"""make it look nice"""
	return self.i2h(pkt,i)
    def i2len(self, pkt, i):
	return 4
    def i2m(self, pkt, i):
	"""internal to machine"""
	return struct.pack("!HH",i[0],i[1])
    def addfield(self, pkt, s, val):
	return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
	return s[4:], self.m2i(pkt,s[:4])
    def m2i(self,pkt,m):
	return struct.unpack("!HH",m)
