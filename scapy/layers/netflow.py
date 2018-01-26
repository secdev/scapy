## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
## Netflow V5 appended by spaceB0x and Guillaume Valadon
## Netflow V9 appended ny Gabriel Potter

"""
Cisco NetFlow protocol v1, v5 and v9

HowTo debug NetflowV9 packets:
- get a list of packets containing NetflowV9 packets
- call netflowv9_defragment(plist) to defragment the list
Caution: this API might be updated
"""


from scapy.fields import *
from scapy.packet import *
from scapy.data import IP_PROTOS
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field
import scapy.modules.six as six

class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]

bind_layers( UDP, NetflowHeader, dport=2055 )

###########################################
### Netflow Version 1
###########################################


class NetflowHeaderV1(Packet):
    name = "Netflow Header v1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    UTCTimeField("unixSecs", 0),
                    UTCTimeField("unixNanoSeconds", 0, use_nano=True) ]


class NetflowRecordV1(Packet):
    name = "Netflow Record v1"
    fields_desc = [ IPField("ipsrc", "0.0.0.0"),
                    IPField("ipdst", "0.0.0.0"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("inputIfIndex", 0),
                    ShortField("outpuIfIndex", 0),
                    IntField("dpkts", 0),
                    IntField("dbytes", 0),
                    IntField("starttime", 0),
                    IntField("endtime", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ShortField("padding", 0),
                    ByteField("proto", 0),
                    ByteField("tos", 0),
                    IntField("padding1", 0),
                    IntField("padding2", 0) ]


bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1 )
bind_layers( NetflowRecordV1, NetflowRecordV1 )


#########################################
### Netflow Version 5
#########################################


class NetflowHeaderV5(Packet):
    name = "Netflow Header v5"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    UTCTimeField("unixSecs", 0),
                    UTCTimeField("unixNanoSeconds", 0, use_nano=True),
                    IntField("flowSequence",0),
                    ByteField("engineType", 0),
                    ByteField("engineID", 0),
                    ShortField("samplingInterval", 0) ]


class NetflowRecordV5(Packet):
    name = "Netflow Record v5"
    fields_desc = [ IPField("src", "127.0.0.1"),
                    IPField("dst", "127.0.0.1"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("input", 0),
                    ShortField("output", 0),
                    IntField("dpkts", 1),
                    IntField("dOctets", 60),
                    IntField("first", 0),
                    IntField("last", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ByteField("pad1", 0),
                    FlagsField("tcpFlags", 0x2, 8, "FSRPAUEC"),
                    ByteEnumField("prot", IP_PROTOS["tcp"], IP_PROTOS),
                    ByteField("tos",0),
                    ShortField("src_as", 0),
                    ShortField("dst_as", 0),
                    ByteField("src_mask", 0),
                    ByteField("dst_mask", 0),
                    ShortField("pad2", 0)]


bind_layers( NetflowHeader,   NetflowHeaderV5, version=5)
bind_layers( NetflowHeaderV5, NetflowRecordV5 )
bind_layers( NetflowRecordV5, NetflowRecordV5 )

#########################################
### Netflow Version 9
#########################################

# https://www.ietf.org/rfc/rfc3954.txt

NetflowV9TemplateFieldTypes = {
        1: "IN_BYTES",
        2: "IN_PKTS",
        3: "FLOWS",
        4: "PROTOCOL",
        5: "TOS",
        6: "TCP_FLAGS",
        7: "L4_SRC_PORT",
        8: "IPV4_SRC_ADDR",
        9: "SRC_MASK",
        10: "INPUT_SNMP",
        11: "L4_DST_PORT",
        12: "IPV4_DST_ADDR",
        13: "DST_MASK",
        14: "OUTPUT_SNMP",
        15: "IPV4_NEXT_HOP",
        16: "SRC_AS",
        17: "DST_AS",
        18: "BGP_IPV4_NEXT_HOP",
        19: "MUL_DST_PKTS",
        20: "MUL_DST_BYTES",
        21: "LAST_SWITCHED",
        22: "FIRST_SWITCHED",
        23: "OUT_BYTES",
        24: "OUT_PKTS",
        27: "IPV6_SRC_ADDR",
        28: "IPV6_DST_ADDR",
        29: "IPV6_SRC_MASK",
        30: "IPV6_DST_MASK",
        31: "IPV6_FLOW_LABEL",
        32: "ICMP_TYPE",
        33: "MUL_IGMP_TYPE",
        34: "SAMPLING_INTERVAL",
        35: "SAMPLING_ALGORITHM",
        36: "FLOW_ACTIVE_TIMEOUT",
        37: "FLOW_INACTIVE_TIMEOUT",
        38: "ENGINE_TYPE",
        39: "ENGINE_ID",
        40: "TOTAL_BYTES_EXP",
        41: "TOTAL_PKTS_EXP",
        42: "TOTAL_FLOWS_EXP",
        46: "MPLS_TOP_LABEL_TYPE",
        47: "MPLS_TOP_LABEL_IP_ADDR",
        48: "FLOW_SAMPLER_ID",
        49: "FLOW_SAMPLER_MODE",
        50: "FLOW_SAMPLER_RANDOM_INTERVAL",
        55: "DST_TOS",
        56: "SRC_MAC",
        57: "DST_MAC",
        58: "SRC_VLAN",
        59: "DST_VLAN",
        60: "IP_PROTOCOL_VERSION",
        61: "DIRECTION",
        62: "IPV6_NEXT_HOP",
        63: "BGP_IPV6_NEXT_HOP",
        64: "IPV6_OPTION_HEADERS",
        70: "MPLS_LABEL_1",
        71: "MPLS_LABEL_2",
        72: "MPLS_LABEL_3",
        73: "MPLS_LABEL_4",
        74: "MPLS_LABEL_5",
        75: "MPLS_LABEL_6",
        76: "MPLS_LABEL_7",
        77: "MPLS_LABEL_8",
        78: "MPLS_LABEL_9",
        79: "MPLS_LABEL_10",
    }

ScopeFieldTypes = {
    1: "System",
    2: "Interface",
    3: "Line card",
    4: "Cache",
    5: "Template",
    }

NetflowV9TemplateFieldDefaultLengths = {
        1: 4,
        2: 4,
        3: 4,
        4: 1,
        5: 1,
        6: 1,
        7: 2,
        8: 4,
        9: 1,
        10: 2,
        11: 2,
        12: 4,
        13: 1,
        14: 2,
        15: 4,
        16: 2,
        17: 2,
        18: 4,
        19: 4,
        20: 4,
        21: 4,
        22: 4,
        23: 4,
        24: 4,
        27: 16,
        28: 16,
        29: 1,
        30: 1,
        31: 3,
        32: 2,
        33: 1,
        34: 4,
        35: 1,
        36: 2,
        37: 2,
        38: 1,
        39: 1,
        40: 4,
        41: 4,
        42: 4,
        46: 1,
        47: 4,
        48: 1,
        49: 1,
        50: 4,
        55: 1,
        56: 6,
        57: 6,
        58: 2,
        59: 2,
        60: 1,
        61: 1,
        62: 16,
        63: 16,
        64: 4,
        70: 3,
        71: 3,
        72: 3,
        73: 3,
        74: 3,
        75: 3,
        76: 3,
        77: 3,
        78: 3,
        79: 3,
    }

# NetflowV9 Ready-made fields

class ShortOrInt(IntField):
    def getfield(self, pkt, x):
        if len(x) == 2:
            Field.__init__(self, self.name, self.default, fmt="!H")
        return Field.getfield(self, pkt, x)

NetflowV9TemplateFieldDecoders = {  # Only contains fields that have a fixed length
        4: (ByteEnumField, [IP_PROTOS]),  # PROTOCOL
        5: XByteField,  # TOS
        6: ByteField,  # TCP_FLAGS
        7: ShortField,  # L4_SRC_PORT
        8: IPField,  # IPV4_SRC_ADDR
        9: ByteField,  # SRC_MASK
        11: ShortField,  # L4_DST_PORT
        12: IPField,  # IPV4_DST_PORT
        13: ByteField,  # DST_MASK
        15: IPField,  # IPv4_NEXT_HOP
        16: ShortOrInt,  # SRC_AS
        17: ShortOrInt,  # DST_AS
        18: IPField,  # BGP_IPv4_NEXT_HOP
        21: (SecondsIntField, [True]),  # LAST_SWITCHED
        22: (SecondsIntField, [True]),  # FIRST_SWITCHED
        27: IP6Field,  # IPV6_SRC_ADDR
        28: IP6Field,  # IPV6_DST_ADDR
        29: ByteField,  # IPV6_SRC_MASK
        30: ByteField,  # IPV6_DST_MASK
        31: ThreeBytesField,  # IPV6_FLOW_LABEL
        32: XShortField,  # ICMP_TYPE
        33: ByteField,  # MUL_IGMP_TYPE
        34: LongField,  # SAMPLING_INTERVAL
        35: XByteField,  # SAMPLING_ALGORITHM
        36: ShortField,  # FLOW_ACTIVE_TIMEOUT
        37: ShortField,  # FLOW_ACTIVE_TIMEOUT
        38: ByteField,  # ENGINE_TYPE
        39: ByteField,  # ENGINE_ID
        46: (ByteEnumField, [{ 0x00: "UNKNOWN", 0x01: "TE-MIDPT", 0x02: "ATOM", 0x03: "VPN", 0x04: "BGP", 0x05: "LDP" }]),  # MPLS_TOP_LABEL_TYPE
        47: IPField,  # MPLS_TOP_LABEL_IP_ADDR
        48: ByteField,  # FLOW_SAMPLER_ID
        49: ByteField,  # FLOW_SAMPLER_MODE
        50: LongField,  # FLOW_SAMPLER_RANDOM_INTERVAL
        55: XByteField,  # DST_TOS
        56: MACField,  # SRC_MAC
        57: MACField,  # DST_MAC
        58: ShortField,  # SRC_VLAN
        59: ShortField,  # DST_VLAN
        60: ByteField,  # IP_PROTOCOL_VERSION
        61: (ByteEnumField, [{ 0x00: "Ingress flow", 0x01: "Egress flow" }]),  # DIRECTION
        62: IP6Field,  # IPV6_NEXT_HOP
        63: IP6Field,  # BGP_IPV6_NEXT_HOP
    }

class NetflowHeaderV9(Packet):
    name = "Netflow Header V9"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    UTCTimeField("unixSecs", 0),
                    IntField("packageSequence",0),
                    IntField("SourceID", 0) ]

class NetflowTemplateFieldV9(Packet):
    name = "Netflow Flowset Template Field V9"
    fields_desc = [ ShortEnumField("fieldType", None, NetflowV9TemplateFieldTypes),
                    ShortField("fieldLength", 0) ]
    def __init__(self, *args, **kwargs):
        Packet.__init__(self, *args, **kwargs)
        if self.fieldType != None and not self.fieldLength and self.fieldType in NetflowV9TemplateFieldDefaultLengths:
            self.fieldLength = NetflowV9TemplateFieldDefaultLengths[self.fieldType]

    def default_payload_class(self, p):
        return conf.padding_layer

class NetflowTemplateV9(Packet):
    name = "Netflow Flowset Template V9"
    fields_desc = [ ShortField("templateID", 255),
                    FieldLenField("fieldCount", None, count_of="template_fields"),
                    PacketListField("template_fields", [], NetflowTemplateFieldV9,
                                    count_from = lambda pkt: pkt.fieldCount) ]

    def default_payload_class(self, p):
        return conf.padding_layer

class NetflowFlowsetV9(Packet):
    name = "Netflow FlowSet V9"
    fields_desc = [ ShortField("flowSetID", 0),
                    FieldLenField("length", None, length_of="templates", adjust=lambda pkt,x:x+4),
                    PacketListField("templates", [], NetflowTemplateV9,
                                    length_from = lambda pkt: pkt.length-4) ]

class _CustomStrFixedLenField(StrFixedLenField):
    def i2repr(self, pkt, v):
        return repr(v)

def _GenNetflowRecordV9(cls, lengths_list):
    _fields_desc = []
    for j,k in lengths_list:
        _f_data = NetflowV9TemplateFieldDecoders.get(k, None)
        _f_type, _f_args = (_f_data) if isinstance(_f_data, tuple) else (_f_data, [])
        if _f_type:
            _fields_desc.append(_f_type(NetflowV9TemplateFieldTypes.get(k, "unknown_data"), 0, *_f_args))
        else:
            _fields_desc.append(_CustomStrFixedLenField(NetflowV9TemplateFieldTypes.get(k, "unknown_data"), b"", length=j))
    class NetflowRecordV9I(cls):
        fields_desc = _fields_desc
    return NetflowRecordV9I

class NetflowRecordV9(Packet):
    name = "Netflow DataFlowset Record V9"
    fields_desc = [ StrField("fieldValue", "") ]

    def default_payload_class(self, p):
        return conf.padding_layer

class NetflowDataflowsetV9(Packet):
    name = "Netflow DataFlowSet V9"
    fields_desc = [ ShortField("templateID", 255),
                    FieldLenField("length", None, length_of="records", adjust = lambda pkt,x:x+4),
                    PadField(PacketListField("records", [], NetflowRecordV9,
                                    length_from = lambda pkt: pkt.length-4),
                             4, padwith=b"\x00") ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            if _pkt[:2] == b"\x00\x01":
                return NetflowOptionsFlowsetV9
            if _pkt[:2] == b"\x00\x00":
                return NetflowFlowsetV9
        return cls

def netflowv9_defragment(plist):
    """Process all NetflowV9 Packets to match IDs of the DataFlowsets with the Headers.
    plist: the list of mixed NetflowV9 packets."""
    # We need the whole packet to be dissected to access field def in NetflowFlowsetV9 or NetflowOptionsFlowsetV9
    packet_list = [pkt for pkt in plist if (NetflowFlowsetV9 in pkt or NetflowOptionsFlowsetV9 in pkt)]
    # Iterate through initial list
    for pkt in (x for x in plist if NetflowDataflowsetV9 in x):
        root = pkt.firstlayer()
        # Get all linked NetflowFlowsetV9
        for p in packet_list:
            if NetflowFlowsetV9 in p: ## STEP 1 - NetflowFlowsetV9
                current = p[NetflowFlowsetV9]
                for ntv9 in current.templates:
                    current_ftl = root.getlayer(NetflowDataflowsetV9, templateID=ntv9.templateID)
                    if current_ftl:
                        # Matched
                        try:
                            assert(len(current_ftl.records) > 0)
                            # All data is stored in one record, awaiting to be splitted
                            data = current_ftl.records[0].fieldValue
                            # If fieldValue is available, the record has not been defragmented: pop it
                            current_ftl.records.pop(0)
                        except (AssertionError, AttributeError):
                            continue
                        res = []
                        # Now, according to the NetflowFlowsetV9 data, re-dissect NetflowDataflowsetV9
                        lengths_list = []
                        for template in ntv9.template_fields:
                            lengths_list.append((template.fieldLength, template.fieldType))
                        if lengths_list:
                            tot_len = sum(x for x,y in lengths_list)
                            cls = _GenNetflowRecordV9(NetflowRecordV9, lengths_list)
                            while len(data) >= tot_len:
                                res.append(cls(data[:tot_len]))
                                data = data[tot_len:]
                        # Inject dissected data
                        current_ftl.records = res
                        current_ftl.do_dissect_payload(data)
                        break
            if NetflowOptionsFlowsetV9 in p: ## STEP 2 - NetflowOptionsFlowsetV9
                current = p[NetflowOptionsFlowsetV9]
                current_ftl = root.getlayer(NetflowDataflowsetV9, templateID=current.templateID)
                if current_ftl:
                    # Matched
                    try:
                        assert(len(current_ftl.records) > 0)
                        # All data is stored in one record, awaiting to be splitted
                        data = current_ftl.records.pop(0).fieldValue
                    except (AssertionError, AttributeError):
                        continue
                    res = []
                    # Now, according to the NetflowOptionsFlowsetV9 data, re-dissect NetflowDataflowsetV9
                    ## A - Decode scopes
                    lengths_list = []
                    for scope in current.scopes:
                        lengths_list.append((scope.scopeFieldlength, scope.scopeFieldType))
                    if lengths_list:
                        tot_len = sum(x for x,y in lengths_list)
                        cls = _GenNetflowRecordV9(NetflowOptionsRecordScopeV9, lengths_list)
                        while len(data) >= tot_len:
                            res.append(cls(data[:tot_len]))
                            data = data[tot_len:]
                    ## B - Decode options
                    lengths_list = []
                    for option in current.options:
                        lengths_list.append((option.optionFieldlength, option.optionFieldType))
                    if lengths_list:
                        tot_len = sum(x for x,y in lengths_list)
                        cls = _GenNetflowRecordV9(NetflowOptionsRecordOptionV9, lengths_list)
                        while len(data) >= tot_len:
                            res.append(cls(data[:tot_len]))
                            data = data[tot_len:]
                    if data:
                        res.append(Raw(data))
                    # Inject dissected data
                    current_ftl.records = res
                    current_ftl.name = "Netflow DataFlowSet V9 - OPTIONS"
                    break
    return plist

class NetflowOptionsRecordScopeV9(NetflowRecordV9):
    name = "Netflow Options Template Record V9 - Scope"

class NetflowOptionsRecordOptionV9(NetflowRecordV9):
    name = "Netflow Options Template Record V9 - Option"

class NetflowOptionsFlowsetOptionV9(Packet):
    name = "Netflow Options Template FlowSet V9 - Option"
    fields_desc = [ ShortEnumField("optionFieldType", None, NetflowV9TemplateFieldTypes),
                    ShortField("optionFieldlength", 0) ]

    def default_payload_class(self, p):
        return conf.padding_layer

class NetflowOptionsFlowsetScopeV9(Packet):
    name = "Netflow Options Template FlowSet V9 - Scope"
    fields_desc = [ ShortEnumField("scopeFieldType", None, ScopeFieldTypes),
                    ShortField("scopeFieldlength", 0) ]

    def default_payload_class(self, p):
        return conf.padding_layer

class NetflowOptionsFlowsetV9(Packet):
    name = "Netflow Options Template FlowSet V9"
    fields_desc = [ ShortField("flowSetID", 1),
                    LenField("length", None),
                    ShortField("templateID", 255),
                    FieldLenField("option_scope_length", None, length_of="scopes"),
                    FieldLenField("option_field_length", None, length_of="options"),
                    PacketListField("scopes", [], NetflowOptionsFlowsetScopeV9,
                                    length_from = lambda pkt: pkt.option_scope_length),
                    PadField(PacketListField("options", [], NetflowOptionsFlowsetOptionV9,
                                    length_from = lambda pkt: pkt.option_field_length),
                             4, padwith=b"\x00") ]

bind_layers( NetflowHeader, NetflowHeaderV9, version=9 )
bind_layers( NetflowHeaderV9, NetflowDataflowsetV9 )
bind_layers( NetflowDataflowsetV9, NetflowDataflowsetV9 )
