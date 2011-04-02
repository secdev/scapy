#! /usr/bin/env python 

# http://trac.secdev.org/scapy/ticket/162

# scapy.contrib.description = BGP
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP


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

class BGPHeader(Packet):
	"""The first part of any BGP packet"""
	name = "BGP header"
	fields_desc = [
	XBitField("marker",0xffffffffffffffffffffffffffffffff, 0x80 ),
	ShortField("len", None),
	ByteEnumField("type", 4, {0:"none", 1:"open",2:"update",3:"notification",4:"keep_alive"}),
	]
	def post_build(self, p, pay):
		if self.len is None and pay:
			l = len(p) + len(pay)
			p = p[:16]+struct.pack("!H", l)+p[18:]
		return p+pay

class BGPOptionalParameter(Packet):
	"""Format of optional Parameter for BGP Open"""
	name = "BGP Optional Parameters"
	fields_desc = [
	ByteField("type", 2),
	ByteField("len", None),
	StrLenField("value", "",  length_from = lambda x: x.len),
	]
	def post_build(self,p,pay):
		if self.len is None:
			l = len(p) - 2 # 2 is length without value
			p = p[:1]+struct.pack("!B", l)+p[2:]
		return p+pay
	def extract_padding(self, p):
		"""any thing after this packet is extracted is padding"""
		return "",p

class BGPOpen(Packet):
	""" Opens a new BGP session"""
	name = "BGP Open Header"
	fields_desc = [
	ByteField("version", 4),
	ShortField("AS", 0),
	ShortField("hold_time", 0),
	IPField("bgp_id","0.0.0.0"),
	ByteField("opt_parm_len", None),
	PacketListField("opt_parm",[], BGPOptionalParameter, length_from=lambda p:p.opt_parm_len),
	]
	def post_build(self, p, pay):
		if self.opt_parm_len is None:
			l = len(p) - 10 # 10 is regular length with no additional options
			p = p[:9] + struct.pack("!B",l)  +p[10:]
		return p+pay

class BGPAuthenticationData(Packet):
    name = "BGP Authentication Data"
    fields_desc = [
    ByteField("AuthenticationCode", 0),
    ByteField("FormMeaning", 0),
    FieldLenField("Algorithm", 0),
    ]

class BGPPathAttribute(Packet):
	"the attribute of total path"
	name = "BGP Attribute fields"
	fields_desc = [
	FlagsField("flags", 0x40, 8, ["NA0","NA1","NA2","NA3","Extended-Length","Partial","Transitive","Optional"]), #Extened leght may not work
	ByteEnumField("type", 1, {1:"ORIGIN", 2:"AS_PATH", 3:"NEXT_HOP", 4:"MULTI_EXIT_DISC", 5:"LOCAL_PREF", 6:"ATOMIC_AGGREGATE", 7:"AGGREGATOR"}),
	ByteField("attr_len", None),
	StrLenField("value", "", length_from = lambda p: p.attr_len),
	]
	def post_build(self, p, pay):
		if self.attr_len is None:
			l = len(p) - 3 # 3 is regular length with no additional options
			p = p[:2] + struct.pack("!B",l)  +p[3:]
		return p+pay
	def extract_padding(self, p):
		"""any thing after this packet is extracted is padding"""
		return "",p

class BGPUpdate(Packet):
	"""Update the routes WithdrawnRoutes = UnfeasiableRoutes"""
	name = "BGP Update fields"
	fields_desc = [
	ShortField("withdrawn_len", None),
	FieldListField("withdrawn",[], BGPIPField("","0.0.0.0/0"), length_from=lambda p:p.withdrawn_len),
	ShortField("tp_len", None),
	PacketListField("total_path", [], BGPPathAttribute, length_from = lambda p: p.tp_len),
	FieldListField("nlri",[], BGPIPField("","0.0.0.0/0"), length_from=lambda p:p.underlayer.len - 23 - p.tp_len - p.withdrawn_len), # len should be BGPHeader.len
	]
	def post_build(self,p,pay):
		wl = self.withdrawn_len
		subpacklen = lambda p: len ( str( p ))
		subfieldlen = lambda p: BGPIPField("", "0.0.0.0/0").i2len(self,  p )
		if wl is None:
			wl = sum ( map ( subfieldlen , self.withdrawn))
			p = p[:0]+struct.pack("!H", wl)+p[2:]
		if self.tp_len is None:
			l = sum ( map ( subpacklen , self.total_path))
			p = p[:2+wl]+struct.pack("!H", l)+p[4+wl:]
		return p+pay

class BGPNotification(Packet):
    name = "BGP Notification fields"
    fields_desc = [
    ByteEnumField("ErrorCode",0,{1:"Message Header Error",2:"OPEN Message Error",3:"UPDATE Messsage Error",4:"Hold Timer Expired",5:"Finite State Machine",6:"Cease"}),
    ByteEnumField("ErrorSubCode",0,{1:"MessageHeader",2:"OPENMessage",3:"UPDATEMessage"}),
    LongField("Data", 0),
    ]

class BGPErrorSubcodes(Packet):
    name = "BGP Error Subcodes"
    Fields_desc = [
    ByteEnumField("MessageHeader",0,{1:"Connection Not Synchronized",2:"Bad Message Length",3:"Bad Messsage Type"}),
    ByteEnumField("OPENMessage",0,{1:"Unsupported Version Number",2:"Bad Peer AS",3:"Bad BGP Identifier",4:"Unsupported Optional Parameter",5:"Authentication Failure",6:"Unacceptable Hold Time"}),
    ByteEnumField("UPDATEMessage",0,{1:"Malformed Attribute List",2:"Unrecognized Well-Known Attribute",3:"Missing Well-Known Attribute",4:"Attribute Flags Error",5:"Attribute Length Error",6:"Invalid ORIGIN Attribute",7:"AS Routing Loop",8:"Invalid NEXT_HOP Attribute",9:"Optional Attribute Error",10:"Invalid Network Field",11:"Malformed AS_PATH"}),
    ]

bind_layers( TCP,             BGPHeader,   dport=179)
bind_layers( TCP,             BGPHeader,   sport=179)
bind_layers( BGPHeader,       BGPOpen,     type=1)
bind_layers( BGPHeader,       BGPUpdate,   type=2)
bind_layers( BGPHeader,       BGPHeader,   type=4)


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="BGP addon .05")

