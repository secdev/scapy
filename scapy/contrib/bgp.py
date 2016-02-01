#! /usr/bin/env python
"""BGP-4 protocol with mulit-protocol support"""
# scapy.contrib.description = BGP
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP
from scapy.contrib.bgp_fields import *

def _class_dispatcher(s, class_dict, def_class, index_from=None):
    """ A generic class dispatcher:
    s:           packet
    class_dict:  a dictionary of index:packetClass
    def_class:   a default packet class when index is not found
    index_from:  normally a lambda s: to calculate the index for the class_dict

    return Raw(s) if index_from throws an Exception expect when conf.debug_dissector==1"""
    try:
        index = index_from(s)
        cls = class_dict[index] if index in class_dict else def_class
    except:
        if conf.debug_dissector == 1:
            raise
        cls = Raw
    return cls(s)

AFI_NAMES = {1: "IPv4", 2:"IPv6"}
SAFI_NAMES = {1: "Unicast", 2: "Multicast", 128: "MPLS Labeled-VPN"}

class BGPHeader(Packet):
    """The first part of any BGP packet"""
    name = "BGP header"
    fields_desc = [
        XBitField("marker", 0xffffffffffffffffffffffffffffffff, 0x80),
        ShortField("len", None),
        ByteEnumField("type", 4, {0:"none", 1:"open", 2:"update", 3:"notification", 4:"keep_alive"}),
    ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p)
            if pay is not None:
                l += len(pay)
                p = p[:16]+struct.pack("!H", l)+p[18:]
        return p+pay

#
# -------------------  BGP Open message and capability negotiation
#
class BGPOptionalParameter(PadPacket):
    """Format of optional Parameter for BGP Open"""
    name = "BGP Optional Parameters"
    fields_desc = [
        ByteField("type", 2),
        FieldLenField("len", None, fmt="B", length_of="Value"),
        StrLenField("value", "", length_from=lambda x: x.len),
    ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 2 # 2 is length without value
            p = p[:1]+struct.pack("!B", l)+p[2:]
        return p+pay

class Capability(BGPOptionalParameter):
    """Default capability implementation"""
    name = "MultiProtocol address family support"
    fields_desc = [
        ByteField("type", 2),
        ByteField("len", None),
        ByteField("capa_type", 1),
        FieldLenField("capa_len", None, fmt="B", length_of="capa_value"),
        StrLenField("value", "", length_from=lambda x: x.capa_len),
    ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 2      # length of the packet after 'len'
            p = p[:1]+struct.pack("!B", l)+p[2:]
        if self.capa_len is None:
            cl = len(p) - 4     # length of the packet after 'capa_len'
            p = p[:3]+chr(cl)+p[4:]
        return p+pay

class CapabilityAFI(Capability):
    """Declare AFI support"""
    name = "AFI"
    fields_desc = [
        ByteField("type", 2),
        ByteField("len", None),
        ByteField("capa_type", 1),
        ByteField("capa_len", None),
        ShortEnumField("afi", 0, AFI_NAMES),
        ByteField("reserved", 0),
        ByteEnumField("safi", 0, SAFI_NAMES)
    ]

class CapabilityRR(BGPOptionalParameter):
    """Declare route refresh support"""
    name = "MultiProtocol route refresh"
    fields_desc = [
        ByteField("type", 2),
        ByteField("len", None),
        ByteField("capa_type", 2),
        ByteField("capa_len", 0),
    ]

class GracefulAFI(Packet):
    """Declare graceful restart per AFI info"""
    field_desc = [
        ShortEnumField("AFI", 0, AFI_NAMES),
        ByteEnumField("SAFI", 0, SAFI_NAMES),
        FlagsField(
            "af_flags", 0, 8,
            [
                "AFF1", "AFF2", "AFF3", "AFF4",
                "AFF5", "AFF6", "AFF7", "forward"
            ]
        )
    ]
class CapabilityGraceful(Capability):
    """Declare graceful restart"""
    name = "MultiProtocol Graceful restart"
    fields_desc = [
        ByteField("type", 2),
        ByteField("len", None),
        ByteField("capa_type", 64),
        ByteField("capa_len", None),
        FlagsField("restart_flags", 0, 4, ["RR1", "RR2", "RR3", "restart"]),
        BitField("restart_time", 0, 12),
        PacketListField(
            "afi", [], GracefulAFI,
            length_from=lambda p: p.capa_len-2
        )
    ]

class CapabilityAS4(Capability):
    """Declare 4-byte AS support"""
    name = "MultiProtocol 4-byte ASN"
    fields_desc = [
        ByteField("type", 2),
        ByteField("len", None),
        ByteField("capa_type", 65),
        ByteField("capa_len", None),
        AS4Field("asn", "AS0")
    ]

_optparam_dict = {
    (2, 1) :  CapabilityAFI,
    (2, 2) :  CapabilityRR,
    (2, 64) : CapabilityGraceful,
    (2, 65) : CapabilityAS4,
}

def optparam_dispatcher(s):
    """dispatcher"""
    return _class_dispatcher(
        s,
        _optparam_dict,
        BGPOptionalParameter,
        index_from=lambda s: (ord(s[0]), ord(s[2]))
    )

class BGPOpen(Packet):
    """ Opens a new BGP session"""
    name = "BGP Open Header"
    fields_desc = [
        ByteField("version", 4),
        ShortField("AS", 0),
        ShortField("hold_time", 0),
        IPField("bgp_id", "0.0.0.0"),
        ByteField("opt_parm_len", None),
        PacketListField(
            "opt_parm", [], optparam_dispatcher,
            length_from=lambda p: p.opt_parm_len
        ),
    ]
    def post_build(self, p, pay):
        if self.opt_parm_len is None:
            l = len(p) - 10 # 10 is regular length with no additional options
            p = p[:9] + struct.pack("!B", l)  +p[10:]
        return p+pay
#
# -----------------------------------------------------
#
class BGPAuthenticationData(Packet):
    """BGP authentication negotiation"""
    name = "BGP Authentication Data"
    fields_desc = [
        ByteField("AuthenticationCode", 0),
        ByteField("FormMeaning", 0),
        FieldLenField("Algorithm", 0),
    ]

#
# ------------------  BGP Attributes
#
BGP_HEADER_FLAGS = [
    "NA0", "NA1", "NA2", "NA3",
    "Extended-Length", "Partial", "Transitive", "Optional"
]

class BGPAttribute(PadPacket):
    """the attribute of total path"""
    name = "BGP Attribute fields"
    fields_desc = [
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 1),
        ConditionalField(
            ByteField("attr_len", None),
            cond=lambda p: p.flags & 0x10 == 0),
        ConditionalField(
            ShortField("ext_len", None),
            cond=lambda p: p.flags & 0x10 == 0x10),
        StrLenField(
            "value", "",
            length_from=lambda p: p.attr_length())
    ]
    def attr_length(self):
        """Handle the calculation of the attribute length"""
        if self.attr_len is not None:
            return self.attr_len
        else:
            return self.ext_len
    def post_build(self, p, pay):
        """Handling the length/extended length field and flag"""
        if self.attr_len is None and self.ext_len is None:
            if self.flags & 0x10 == 0x10:
                l = len(p) - 4 # 4 is the length when extended-length is set
                p = p[:2] + struct.pack("!H", self.flags | 0x10, l) + p[4:]
            else:
                l = len(p) - 3 # 3 is regular length with no additional options
                p = p[:2] + struct.pack("!B", l)  +p[3:]
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
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 1),
        ByteField("attr_len", 1),
        ByteEnumField("origin", 1, {0  : "IGP",
                                    1  : "EGP",
                                    2  : "INCOMPLETE"}),
    ]

class BGPASSegment(PadPacket):
    """AS SEGMENT"""
    name = "BGPASSegment"
    fields_desc = [
        ByteEnumField("segment_type", 2, {1:"AS_SET",
                                          2:"AS_SEQUENCE",
                                          # RFC 5065
                                          3:"AS_CONFED_SEQUENCE",
                                          4:"AS_CONFED_SET"}),
        FieldLenField("segment_len", None, fmt="B", count_of="segment"),
        #
        # TODO the way of defining conf.bgp.use4as to switch between AS4Field and AS2Field here
        #
        FieldListField(
            "segment", [], AS4Field("", "AS0"),
            count_from=lambda p: p.segment_len
        ),
    ]

class BGPASPath(BGPAttribute):
    """The AS_PATH attribute"""
    name = "BGPASPath"
    fields_desc = [
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 2),
        ConditionalField(
            ByteField("attr_len", None),
            cond=lambda p: p.flags & 0x10 == 0),
        ConditionalField(
            ShortField("ext_len", None),
            cond=lambda p: p.flags & 0x10 == 0x10),
        PacketListField(
            "as_path", [], BGPASSegment,
            length_from=lambda p: p.attr_length())
    ]

class BGPNextHop(PadPacket):
    """The origin attribute for BGP-4"""
    name = "BGPNextHop"
    fields_desc = [
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 3),
        ByteField("attr_len", 4),
        IPField("next_hop", 0),
    ]

class BGPMultiExitDiscriminator(PadPacket):
    """The multi-exit discriminator attribute for BGP-4"""
    name = "BGPMultiExitDiscriminator"
    fields_desc = [
        FlagsField("flags", 0x00, 8, BGP_HEADER_FLAGS), # Non-transitive
        ByteField("type", 4),
        ByteField("attr_len", 4),
        IntField("med", 0),
    ]

class BGPLocalPreference(PadPacket):
    """The local preference attribute for BGP-4"""
    name = "BGPLocalPreference"
    fields_desc = [
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 5),
        ByteField("attr_len", 4),
        IntField("local_pref", 0),
    ]

class BGPAtomicAggregate(PadPacket):
    """The local preference attribute for BGP-4"""
    name = "BGPAtomicAggregate"
    fields_desc = [
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 6),
        ByteField("attr_len", 3),
    ]

class BGPAggregator(PadPacket):
    """The local preference attribute for BGP-4"""
    name = "BGPAggregator"
    fields_desc = [
        FlagsField("flags", 0x40, 8, BGP_HEADER_FLAGS),
        ByteField("type", 7),
        ByteField("attr_len", 4),
        IPField("aggregator", "0.0.0.0")
    ]

class BGPCommunities(BGPAttribute):
    """BGP Communities - RFC 1997"""
    name = "BGPCommunity"
    fields_desc = [
        FlagsField("flags", 0xC0, 8, BGP_HEADER_FLAGS), # optional transitive
        ByteField("type", 8),
        ConditionalField(ByteField("attr_len", None),
                         cond=lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond=lambda p: p.flags & 0x10 == 0x10),
        FieldListField("communities", [], CommunityField("", "0:0"),
                       length_from=lambda p: p.attr_length())
    ]

class BGPOriginatorId(PadPacket):
    """The Originator ID (RFC4456) attribute for BGP-4"""
    name = "BGPOriginatorID"
    fields_desc = [
        FlagsField("flags", 0x80, 8, BGP_HEADER_FLAGS), # Optional, Non-transitive
        ByteField("type", 9),
        ByteField("attr_len", 4),
        IPField("originator_id", "0.0.0.0"),
    ]

class BGPClusterList(BGPAttribute):
    """The cluster list (RFC4456) attribute for BGP-4"""
    name = "BGPClusterList"
    fields_desc = [
        FlagsField("flags", 0x80, 8, BGP_HEADER_FLAGS), # Optional, Non-transitive
        ByteField("type", 10),
        ConditionalField(ByteField("attr_len", None),
                         cond=lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond=lambda p: p.flags & 0x10 == 0x10),
        FieldListField("cluster_id", [], IPField("", "0.0.0.0"),
                       length_from=lambda p: p.attr_length())
    ]

class MPNLRIReach(PadPacket):
    """Generalised Multi-Protocol BGP reach information"""
    name = "MPNLRIReach"
    fields_desc = [
        ShortEnumField("AFI", 0, AFI_NAMES),
        ByteEnumField("SAFI", 0, SAFI_NAMES),
        FieldLenField("nha_len", None, fmt="B",
                      length_of="nha"),
        FieldListField("nha", [], ByteField("", 0),
                       length_from=lambda p: p.nha_len),
        ByteField("reserved", 0),
        FieldListField("nlri", [], ByteField("", 0))
    ]

class MPIPv6Reach(PadPacket):
    """Generalised Multi-Protocol BGP reach information"""
    name = "MPIPv6Reach"
    fields_desc = [
        ShortEnumField("AFI", 2, AFI_NAMES),
        ByteEnumField("SAFI", 1, SAFI_NAMES),
        FieldLenField("nha_len", None, fmt="B", length_of="nha"),
        FieldListField("nha", [], IP6Field("", "::"),
                       length_from=lambda p: p.nha_len),
        ByteField("reserved", 0),
        FieldListField("nlri", [], BGPIPv6Field("", "::/0"))
    ]

_mp_dict = {
    (2, 1): MPIPv6Reach
}

def mp_dispatcher(s):
    """dispatcher"""
    return _class_dispatcher(
        s,
        _mp_dict,
        MPNLRIReach,
        index_from=lambda s: struct.unpack("!HB", s[:3])
    )

class BGPMPReach(BGPAttribute):
    """The cluster list (RFC4456) attribute for BGP-4"""
    name = "BGPMPReach"
    fields_desc = [
        FlagsField("flags", 0x80, 8, BGP_HEADER_FLAGS), # Optional, Non-transitive
        ByteField("type", 14),
        ConditionalField(ByteField("attr_len", None),
                         cond=lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond=lambda p: p.flags & 0x10 == 0x10),
        PacketField("mp_reach", None, mp_dispatcher)
    ]
    #
    # -----------------------------
    #
class MPNLRIUnreach(PadPacket):
    """Generalised Multi-Protocol BGP reach information"""
    name = "MPNLRIUnreach"
    fields_desc = [
        ShortEnumField("AFI", 0, AFI_NAMES),
        ByteEnumField("SAFI", 0, SAFI_NAMES),
        FieldListField("nlri", [], ByteField("", 0))
    ]

class MPIPv6Unreach(PadPacket):
    """Generalised Multi-Protocol BGP reach information"""
    name = "MPIPv6Unreach"
    fields_desc = [
        ShortEnumField("AFI", 2, AFI_NAMES),
        ByteEnumField("SAFI", 1, SAFI_NAMES),
        FieldListField("nlri", [], BGPIPv6Field("", "::/0"))
    ]

_mpu_dict = {
    (2, 1): MPIPv6Unreach
}

def mpu_dispatcher(s):
    """Dispatcher"""
    return _class_dispatcher(
        s,
        _mpu_dict,
        MPNLRIUnreach,
        index_from=lambda s: struct.unpack("!HB", s[:3])
    )

class BGPMPUnreach(BGPAttribute):
    """The cluster list (RFC4456) attribute for BGP-4"""
    name = "BGPMPUnreach"
    fields_desc = [
        FlagsField("flags", 0x80, 8, BGP_HEADER_FLAGS), # Optional, Non-transitive
        ByteField("type", 15),
        ConditionalField(ByteField("attr_len", None),
                         cond=lambda p: p.flags & 0x10 == 0),
        ConditionalField(ShortField("ext_len", None),
                         cond=lambda p: p.flags & 0x10 == 0x10),
        PacketField("mp_unreach", None, mpu_dispatcher)
    ]


_attribute_dict = {
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
    15: BGPMPUnreach,
    # 16: BGPExtendedCommunities,
}

def attribute_dispatcher(s):
    """Dispatcher"""
    return _class_dispatcher(
        s,
        _attribute_dict,
        BGPAttribute,
        index_from=lambda s: ord(s[1])
    )

class BGPUpdate(PadPacket):
    """Update the routes WithdrawnRoutes = UnfeasiableRoutes"""
    name = "BGP Update fields"
    fields_desc = [
        ShortField("withdrawn_len", None),
        FieldListField("withdrawn", [], BGPIPField("", "0.0.0.0/0"),
                       length_from=lambda p: p.withdrawn_len),
        ShortField("tp_len", None),
        PacketListField("total_path", [], attribute_dispatcher,
                        length_from=lambda p: p.tp_len),
        FieldListField("nlri", [], BGPIPField("", "0.0.0.0/0")),
        #length_from=lambda p: p.underlayer.len - 23 - p.tp_len - p.withdrawn_len),
    ]
    def post_build(self, p, pay):
        wl = self.withdrawn_len
        subpacklen = lambda p: len(str(p))
        subfieldlen = lambda p: BGPIPField("", "0.0.0.0/0").i2len(self, p)
        if wl is None:
            wl = sum(map(subfieldlen, self.withdrawn))
            p = p[:0]+struct.pack("!H", wl)+p[2:]
        if self.tp_len is None:
            l = sum(map(subpacklen, self.total_path))
            p = p[:2+wl]+struct.pack("!H", l)+p[4+wl:]
        return p+pay

#
# -------------------- Notifications -------
#
class HeaderNotification(PadPacket):
    """Header Error Notification"""
    name = "Header Notification"
    fields_desc = [
        ByteField("ErrorCode", 1),
        ByteEnumField("SubErrorCode", 0, {
            1 : "Connection Not Synchronized",
            2 : "Bad Message Length",
            3 : "Bad Message Type",
        })]

class OpenNotification(PadPacket):
    """Open Error Notification"""
    name = "Open Error Notification"
    fields_desc = [
        ByteField("ErrorCode", 2),
        ByteEnumField("SubErrorCode", 0, {
            1 : "Unsupported Version Number",
            2 : "Bad Peer AS",
            3 : "Bad BGP Identifier",
            4 : "Unsupported Optional Parameter",
            5 : "[Deprecated]",
            6 : "Unacceptable Hold Time",
            7 : "Unsupported Capability",
        })]

class UpdateNotification(PadPacket):
    """Update Notification"""
    name = "Update Notification"
    fields_desc = [
        ByteField("ErrorCode", 3),
        ByteEnumField("SubErrorCode", 0, {
            1 : "Malformed Attribute List",
            2 : "Unrecognized Well-known Attribute",
            3 : "Missing Well-known Attribute",
            4 : "Attribute Flags Error",
            5 : "Attribute Length Error",
            6 : "Invalid ORIGIN Attribute",
            7 : "[Deprecated]",
            8 : "Invalid NEXT_HOP Attribute",
            9 : "Optional Attribute Error",
            10 : "Invalid Network Field",
            11 : "Malformed AS_PATH",
        })]

class FSMNotification(PadPacket):
    """FSM Notification"""
    name = "FSM Notification"
    fields_desc = [
        ByteField("ErrorCode", 5),
        ByteEnumField("SubErrorCode", 0, {
            1 : "Receive Unexpected Message in OpenSent State",
            2 : "Receive Unexpected Message in OpenConfirm State",
            3 : "Receive Unexpected Message in Established State",
        })]

class CeaseNotification(PadPacket):
    """Cease Notification"""
    name = "Cease Notification"
    fields_desc = [
        ByteField("ErrorCode", 6),
        ByteEnumField("SubErrorCode", 0, {
            1 : "Maximum Number of Prefixes Reached",
            2 : "Administrative Shutdown",
            3 : "Peer De-configured",
            4 : "Administrative Reset",
            5 : "Connection Rejected",
            6 : "Other Configuration Change",
            7 : "Connection Collision Resolution",
            8 : "Out of Resources",
        })]

class RRNotification(PadPacket):
    """RFC 7313"""
    name = "RR Notification"
    fields_desc = [
        ByteField("ErrorCode", 6),
        ByteEnumField("SubErrorCode", 0, {
            1 : "Invalid Message Length",
        })
    ]

class DefaultNotification(PadPacket):
    """Unhandled BGP-4 notifications"""
    fields_desc = [
        ByteEnumField("ErrorCode", 0, {
            1:"Message Header Error",
            2:"OPEN Message Error",
            3:"UPDATE Messsage Error",
            4:"Hold Timer Expired",
            5:"Finite State Machine Error",
            6:"Cease",
            7:"Route Refresh ERROR"}),
        ByteField("SubErrorCode", 0)
    ]

_notification_dict = {
    1: HeaderNotification,
    2: OpenNotification,
    3: UpdateNotification,
    5: FSMNotification,
    6: CeaseNotification,
    7: RRNotification,
}

def notification_dispatcher(s):
    """Dispatcher"""
    return _class_dispatcher(
        s,
        _notification_dict,
        DefaultNotification,
        index_from=lambda s: ord(s[0])
    )

class BGPNotification(Packet):
    """BGP Notification fields"""
    name = "BGP Notification fields"
    fields_desc = [
        PacketField("Notification", None, notification_dispatcher),
        FieldListField("Data", [], ByteField("", None)),
    ]
    #
    #
    # ---- BGPTraffic
    #
class BGPTraffic(Packet):
    """BGP Packets"""
    # name = "BGPTraffic"
    fields_desc = [
        PacketArrayField(
            "packets", [], BGPHeader,
            spkt_len=lambda s: struct.unpack(">H", s[16:18])[0]
        )
    ]

bind_layers(TCP, BGPTraffic, dport=179)
bind_layers(TCP, BGPTraffic, sport=179)
bind_layers(BGPHeader, BGPOpen, type=1)
bind_layers(BGPHeader, BGPUpdate, type=2)
bind_layers(BGPHeader, BGPNotification, type=3)

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="BGP addon .20")

