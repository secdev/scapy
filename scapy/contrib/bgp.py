#! /usr/bin/env python

# http://trac.secdev.org/scapy/ticket/162

# scapy.contrib.description = BGP
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP
from scapy.contrib.bgp_fields import *

def classDispatcher(s,classDict,defClass,index_from=None):
    """ A generic class dispatcher:
    s:          packet
    classDict:  a dictionary of index:packetClass
    defClass:   a default packet class when index is not found
    index_from: normally a lambda s: to calculate the index for the classDict

    return Raw(s) if index_from throws an Exception"""
    try:
        index = index_from(s)
        # print "in classDispatcher: index=%d keys=%s" % (index,repr(classDict.keys()))
        cls = classDict[index] if index in classDict.keys() else defClass
    except:
        cls = Raw
    # print repr(cls)
    return cls(s)

class BGPHeader(Packet):
    """The first part of any BGP packet"""
    name = "BGP header"
    fields_desc = [
	XBitField("marker",0xffffffffffffffffffffffffffffffff, 0x80 ),
	ShortField("len", None),
	ByteEnumField("type", 4, {0:"none", 1:"open",2:"update",3:"notification",4:"keep_alive"}),
    ]
    def post_build(self, p, pay):
	if self.len is None:
            l = len(p)
            if pay is not None:
	        l += len(pay)
	    p = p[:16]+struct.pack("!H", l)+p[18:]
	return p+pay

class BGPOptionalParameter(PadPacket):
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


flagNames = ["NA0","NA1","NA2","NA3",
             "Extended-Length","Partial","Transitive","Optional"]

class BGPAttribute(PadPacket):
    """the attribute of total path"""
    name = "BGP Attribute fields"
    fields_desc = [
        FlagsField("flags", 0x40, 8, flagNames),
        # ByteEnumField("type", 1, {1:"ORIGIN",
        #                           2:"AS_PATH",
        #                           3:"NEXT_HOP",
        #                           4:"MULTI_EXIT_DISC",
        #                           5:"LOCAL_PREF",
        #                           6:"ATOMIC_AGGREGATE",
        #                           7:"AGGREGATOR",
        #                           8:"COMMUNITIES"}),
        ByteField("type",1),
        ConditionalField(ByteField("attr_len", None),
                         cond = lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond = lambda p: p.flags & 0x10 == 0x10),
        StrLenField("value", "",
                    length_from = lambda p: p.ext_len if p.attr_len is None else p.attr_len)
    ]
    def post_build(self, p, pay):
        """Handling the length/extended length field and flag"""
	if self.attr_len is None and self.ext_len is None:
            if self.flags & 0x10 == 0x10:
	        l = len(p) - 4 # 4 is the length when extended-length is set
	        p = p[:2] + struct.pack("!H",self.flags | 0x10, l) + p[4:]
            else:
                l = len(p) - 3 # 3 is regular length with no additional options
	        p = p[:2] + struct.pack("!B",l)  +p[3:]
        elif self.attr_len is not None:
            self.flags = self.flags & 0xEF
        elif self.ext_len is not None:
            self.flags = self.flags | 0x10
	return p+pay
#
# Attributes with fixed length are derived from PadPacket
# While attributes with variable length are derived from BGPAttribute
# To fill attr_len or ext_len correctly
#
class BGPOrigin(PadPacket):
    """The origin attribute for BGP-4"""
    name = "BGPOrigin"
    fields_desc = [
        FlagsField("flags", 0x40, 8, flagNames),
        ByteField("type" , 1),
        ByteField("attr_len", 1),
        ByteEnumField("origin", 1 , { 0  : "IGP",
                                      1  : "EGP",
                                      2  : "INCOMPLETE" }),
    ]
 

class BGPASSegment(PadPacket):
    """AS SEGMENT"""
    name="BGPASSegment"
    fields_desc = [
	ByteEnumField("segment_type",2,{1:"AS_SET",
                                        2:"AS_SEQUENCE",
                                        # RFC 5065
                                        3:"AS_CONFED_SEQUENCE",
                                        4:"AS_CONFED_SET"}),
        FieldLenField("segment_len",None,fmt="B",count_of = "segment"),
        #
        # TODO the way of defining conf.bgp.use4as to switch between AS4Field and AS2Field here
        #
        FieldListField("segment", [], AS4Field("","AS0"),
                       count_from = lambda p: p.segment_len),
    ]
    
class BGPASPath(BGPAttribute):
    """The AS_PATH attribute"""
    name="BGPASPath"
    fields_desc = [
	FlagsField("flags", 0x40, 8, flagNames),
        ByteField("type", 2),
        ConditionalField(ByteField("attr_len", None),
                         cond = lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond = lambda p: p.flags & 0x10 == 0x10),
        PacketListField("as_path", [], BGPASSegment,
                        length_from = lambda p: p.ext_len if p.attr_len is None else p.attr_len)
    ]
    
class BGPNextHop(PadPacket):
    """The origin attribute for BGP-4"""
    name = "BGPNextHop"
    fields_desc = [
        FlagsField("flags", 0x40, 8, flagNames),
        ByteField("type", 3),
        ByteField("attr_len", 4),
	IPField("next_hop",0),
    ]

class BGPMultiExitDiscriminator(PadPacket):
    """The multi-exit discriminator attribute for BGP-4"""
    name = "BGPMultiExitDiscriminator"
    fields_desc = [
        FlagsField("flags", 0x00, 8, flagNames), # Non-transitive
        ByteField("type", 4),
        ByteField("attr_len", 4),
	IntField("med",0),
    ]

class BGPLocalPreference(PadPacket):
    """The local preference attribute for BGP-4"""
    name = "BGPLocalPreference"
    fields_desc = [
        FlagsField("flags", 0x40, 8, flagNames),
        ByteField("type", 5),
        ByteField("attr_len", 4),
	IntField("local_pref",0),
    ]

class BGPAtomicAggregate(PadPacket):
    """The local preference attribute for BGP-4"""
    name = "BGPAtomicAggregate"
    fields_desc = [
        FlagsField("flags", 0x40, 8, flagNames),
        ByteField("type", 6),
        ByteField("attr_len", 3),
    ]

class BGPAggregator(PadPacket):
    """The local preference attribute for BGP-4"""
    name = "BGPAggregator"
    fields_desc = [
        FlagsField("flags", 0x40, 8, flagNames),
        ByteField("type", 7),
        ByteField("attr_len", 4),
        IPField("aggregator","0.0.0.0")
    ]

class BGPCommunities(BGPAttribute):
    """BGP Communities - RFC 1997"""
    name = "BGPCommunity"
    fields_desc = [
        FlagsField("flags", 0xC0, 8, flagNames), # optional transitive
        ByteField("type", 8),
        ConditionalField(ByteField("attr_len", None),
                         cond = lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond = lambda p: p.flags & 0x10 == 0x10),
        FieldListField("communities",[],CommunityField("","0:0"),
                       length_from = lambda p: p.ext_len if p.attr_len is None else p.attr_len)
    ]

class BGPOriginatorId(PadPacket):
    """The Originator ID (RFC4456) attribute for BGP-4"""
    name = "BGPOriginatorID"
    fields_desc = [
        FlagsField("flags", 0x80, 8, flagNames), # Optional,Non-transitive
        ByteField("type", 9),
        ByteField("attr_len", 4),
	IPField("originator_id","0.0.0.0"),
    ]

class BGPClusterList(BGPAttribute):
    """The cluster list (RFC4456) attribute for BGP-4"""
    name = "BGPClusterList"
    fields_desc = [
        FlagsField("flags", 0x80, 8, flagNames), # Optional,Non-transitive
        ByteField("type", 10),
        ConditionalField(ByteField("attr_len", None),
                         cond = lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond = lambda p: p.flags & 0x10 == 0x10),
	FieldListField("cluster_id",[],IPField("","0.0.0.0"),
                       length_from = lambda p: p.ext_len if p.attr_len is None else p.attr_len)
    ]

class MPNLRIReach(PadPacket):
    """Generalised Multi-Protocol BGP reach information"""
    name="MPNLRIReach"
    fields_desc = [
        ShortField("AFI",0),
        ByteField("SAFI",0),
        FieldLenField("nha_len",None,fmt="B",length_of="nha"),
        FieldListField("nha",[],ByteField("",0),
                       length_from=lambda p: p.nha_len),
        ByteField("reserved",0),
        FieldListField("nlri",[],ByteField("",0))	
    ]

MPDict = {
    (2,1): MPNLRIReach
}

def MPDispatcher(s):
    print len(s)
    print "".join(["\\x%02x" % ord (c) for c in s[:3]])
    return classDispatcher(s,
                           MPDict,
                           MPNLRIReach,
                           index_from = lambda s: struct.unpack("!HB",s[:3]))

class BGPMPReach(BGPAttribute):
    """The cluster list (RFC4456) attribute for BGP-4"""
    name = "BGPClusterList"
    fields_desc = [
        FlagsField("flags", 0x80, 8, flagNames), # Optional,Non-transitive
        ByteField("type", 10),
        ConditionalField(ByteField("attr_len", None),
                         cond = lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond = lambda p: p.flags & 0x10 == 0x10),
        PacketField("mp_nlri", None, MPDispatcher)
    ]

AttributeDict = {
    1: BGPOrigin,
    2: BGPASPath,
    3: BGPNextHop,
    4: BGPMultiExitDiscriminator,
    5: BGPLocalPreference,
    6: BGPAtomicAggregate,
    7: BGPAggregator,
    8: BGPCommunities, 
    9: BGPOriginatorId,
    10: BGPClusterList,
    14: BGPMPReach,
    # 15: BPGMPUnreach,
    # 16: BGPExtendedCommunities
}

def Attribute_Dispatcher(s):
    return classDispatcher(s,
                           AttributeDict,
                           BGPAttribute,
                           index_from = lambda s: ord(s[1]))

class BGPUpdate(PadPacket):
    """Update the routes WithdrawnRoutes = UnfeasiableRoutes"""
    name = "BGP Update fields"
    fields_desc = [
	ShortField("withdrawn_len", None),
	FieldListField("withdrawn",[], BGPIPField("","0.0.0.0/0"),
                       length_from=lambda p:p.withdrawn_len),
	ShortField("tp_len", None),
	PacketListField("total_path", [], Attribute_Dispatcher,
                        length_from=lambda p:p.tp_len),
	FieldListField("nlri",[], BGPIPField("","0.0.0.0/0")),
                       #length_from=lambda p:p.underlayer.len - 23 - p.tp_len - p.withdrawn_len), # len should be BGPHeader.len
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

class BGPTraffic(Packet):
    """BGP Packets"""
    # name="BGPTraffic"
    fields_desc = [
        PacketArrayField("packets", [],BGPHeader,
                         spkt_len = lambda s: struct.unpack(">H",s[16:18])[0])
    ]

bind_layers( TCP,             BGPTraffic,  dport=179)
bind_layers( TCP,             BGPTraffic,  sport=179)
bind_layers( BGPHeader,       BGPOpen,     type=1)
bind_layers( BGPHeader,       BGPUpdate,   type=2)
bind_layers( BGPHeader,       BGPHeader,   type=4)


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="BGP addon .10")

