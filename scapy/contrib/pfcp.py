# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Travelping GmbH <info@travelping.com>

"""
3GPP TS 29.244
"""

# scapy.contrib.description = 3GPP Packet Forwarding Control Protocol
# scapy.contrib.status = loads

import struct

from scapy.compat import chb, orb
from scapy.error import warning
from scapy.fields import Field, BitEnumField, BitField, ByteEnumField, \
    ShortEnumField, ByteField, IntField, LongField, \
    ConditionalField, FieldLenField, BitFieldLenField, FieldListField, \
    IPField, MACField, PacketListField, ShortField, \
    StrLenField, StrField, XBitField, XByteField, XIntField, XLongField, \
    ThreeBytesField, SignedLongField, SignedIntField, MultipleTypeField
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field
from scapy.data import IANA_ENTERPRISE_NUMBERS
from scapy.packet import bind_layers, bind_bottom_up, \
    Packet, Raw
from scapy.volatile import RandNum, RandBin

PFCPmessageType = {
    1: "heartbeat_request",
    2: "heartbeat_response",
    3: "pfd_management_request",
    4: "pfd_management_response",
    5: "association_setup_request",
    6: "association_setup_response",
    7: "association_update_request",
    8: "association_update_response",
    9: "association_release_request",
    10: "association_release_response",
    11: "version_not_supported_response",
    12: "node_report_request",
    13: "node_report_response",
    14: "session_set_deletion_request",
    15: "session_set_deletion_response",
    50: "session_establishment_request",
    51: "session_establishment_response",
    52: "session_modification_request",
    53: "session_modification_response",
    54: "session_deletion_request",
    55: "session_deletion_response",
    56: "session_report_request",
    57: "session_report_response",
}

IEType = {
    0: "Reserved",
    1: "Create PDR",
    2: "PDI",
    3: "Create FAR",
    4: "Forwarding Parameters",
    5: "Duplicating Parameters",
    6: "Create URR",
    7: "Create QER",
    8: "Created PDR",
    9: "Update PDR",
    10: "Update FAR",
    11: "Update Forwarding Parameters",
    12: "Update BAR (PFCP Session Report Response)",
    13: "Update URR",
    14: "Update QER",
    15: "Remove PDR",
    16: "Remove FAR",
    17: "Remove URR",
    18: "Remove QER",
    19: "Cause",
    20: "Source Interface",
    21: "F-TEID",
    22: "Network Instance",
    23: "SDF Filter",
    24: "Application ID",
    25: "Gate Status",
    26: "MBR",
    27: "GBR",
    28: "QER Correlation ID",
    29: "Precedence",
    30: "Transport Level Marking",
    31: "Volume Threshold",
    32: "Time Threshold",
    33: "Monitoring Time",
    34: "Subsequent Volume Threshold",
    35: "Subsequent Time Threshold",
    36: "Inactivity Detection Time",
    37: "Reporting Triggers",
    38: "Redirect Information",
    39: "Report Type",
    40: "Offending IE",
    41: "Forwarding Policy",
    42: "Destination Interface",
    43: "UP Function Features",
    44: "Apply Action",
    45: "Downlink Data Service Information",
    46: "Downlink Data Notification Delay",
    47: "DL Buffering Duration",
    48: "DL Buffering Suggested Packet Count",
    49: "PFCPSMReq-Flags",
    50: "PFCPSRRsp-Flags",
    51: "Load Control Information",
    52: "Sequence Number",
    53: "Metric",
    54: "Overload Control Information",
    55: "Timer",
    56: "PDR ID",
    57: "F-SEID",
    58: "Application ID's PFDs",
    59: "PFD context",
    60: "Node ID",
    61: "PFD contents",
    62: "Measurement Method",
    63: "Usage Report Trigger",
    64: "Measurement Period",
    65: "FQ-CSID",
    66: "Volume Measurement",
    67: "Duration Measurement",
    68: "Application Detection Information",
    69: "Time of First Packet",
    70: "Time of Last Packet",
    71: "Quota Holding Time",
    72: "Dropped DL Traffic Threshold",
    73: "Volume Quota",
    74: "Time Quota",
    75: "Start Time",
    76: "End Time",
    77: "Query URR",
    78: "Usage Report (Session Modification Response)",
    79: "Usage Report (Session Deletion Response)",
    80: "Usage Report (Session Report Request)",
    81: "URR ID",
    82: "Linked URR ID",
    83: "Downlink Data Report",
    84: "Outer Header Creation",
    85: "Create BAR",
    86: "Update BAR (Session Modification Request)",
    87: "Remove BAR",
    88: "BAR ID",
    89: "CP Function Features",
    90: "Usage Information",
    91: "Application Instance ID",
    92: "Flow Information",
    93: "UE IP Address",
    94: "Packet Rate",
    95: "Outer Header Removal",
    96: "Recovery Time Stamp",
    97: "DL Flow Level Marking",
    98: "Header Enrichment",
    99: "Error Indication Report",
    100: "Measurement Information",
    101: "Node Report Type",
    102: "User Plane Path Failure Report",
    103: "Remote GTP-U Peer",
    104: "UR-SEQN",
    105: "Update Duplicating Parameters",
    106: "Activate Predefined Rules",
    107: "Deactivate Predefined Rules",
    108: "FAR ID",
    109: "QER ID",
    110: "OCI Flags",
    111: "PFCP Association Release Request",
    112: "Graceful Release Period",
    113: "PDN Type",
    114: "Failed Rule ID",
    115: "Time Quota Mechanism",
    116: "User Plane IP Resource Information",
    117: "User Plane Inactivity Timer",
    118: "Aggregated URRs",
    119: "Multiplier",
    120: "Aggregated URR ID",
    121: "Subsequent Volume Quota",
    122: "Subsequent Time Quota",
    123: "RQI",
    124: "QFI",
    125: "Query URR Reference",
    126: "Additional Usage Reports Information",
    127: "Create Traffic Endpoint",
    128: "Created Traffic Endpoint",
    129: "Update Traffic Endpoint",
    130: "Remove Traffic Endpoint",
    131: "Traffic Endpoint ID",
    132: "Ethernet Packet Filter",
    133: "MAC Address",
    134: "C-TAG",
    135: "S-TAG",
    136: "Ethertype",
    137: "Proxying",
    138: "Ethernet Filter ID",
    139: "Ethernet Filter Properties",
    140: "Suggested Buffering Packets Count",
    141: "User ID",
    142: "Ethernet PDU Session Information",
    143: "Ethernet Traffic Information",
    144: "MAC Addresses Detected",
    145: "MAC Addresses Removed",
    146: "Ethernet Inactivity Timer",
    147: "Additional Monitoring Time",
    148: "Event Quota",
    149: "Event Threshold",
    150: "Subsequent Event Quota",
    151: "Subsequent Event Threshold",
    152: "Trace Information",
    153: "Framed-Route",
    154: "Framed-Routing",
    155: "Framed-IPv6-Route",
    156: "Event Time Stamp",
    157: "Averaging Window",
    158: "Paging Policy Indicator",
    159: "APN/DNN",
    160: "3GPP Interface Type",
}

CauseValues = {
    0: "Reserved",
    1: "Request accepted",
    64: "Request rejected",
    65: "Session context not found",
    66: "Mandatory IE missing",
    67: "Conditional IE missing",
    68: "Invalid length",
    69: "Mandatory IE incorrect",
    70: "Invalid Forwarding Policy",
    71: "Invalid F-TEID allocation option",
    72: "No established Sx Association",
    73: "Rule creation/modification Failure",
    74: "PFCP entity in congestion",
    75: "No resources available",
    76: "Service not supported",
    77: "System failure",
}

SourceInterface = {
    0: "Access",
    1: "Core",
    2: "SGi-LAN/N6-LAN",
    3: "CP-function",
}

DestinationInterface = {
    0: "Access",
    1: "Core",
    2: "SGi-LAN/N6-LAN",
    3: "CP-function",
    4: "LI function",
}

RedirectAddressType = {
    0: "IPv4 address",
    1: "IPv6 address",
    2: "URL",
    3: "SIP URI",
}

GateStatus = {
    0: "OPEN",
    1: "CLOSED",
    2: "CLOSED_RESERVED_2",
    3: "CLOSED_RESERVED_3",
}

TimerUnit = {
    0: '2 seconds',
    1: '1 minute',
    2: '10 minutes',
    3: '1 hour',
    4: '10 hours',
    7: 'infinite',
}

OuterHeaderRemovalDescription = {
    0: "GTP-U/UDP/IPv4",
    1: "GTP-U/UDP/IPv6",
    2: "UDP/IPv4",
    3: "UDP/IPv6",
    4: "IPv4",
    5: "IPv6",
    6: "GTP-U/UDP/IP",
    7: "VLAN S-TAG",
    8: "S-TAG and C-TAG",
}

NodeIdType = {
    0: "IPv4",
    1: "IPv6",
    2: "FQDN",
}

FqCSIDNodeIdType = {
    0: "IPv4",
    1: "IPv6",
    2: "MCCMNCId",
}

FlowDirection = {
    0: "Unspecified",
    1: "Downlink",  # traffic to the UE
    2: "Uplink",    # traffic from the UE
    3: "Bidirectional",
    4: "Unspecified4",
    5: "Unspecified5",
    6: "Unspecified6",
    7: "Unspecified7",
}

TimeUnit = {
    0: "minute",
    1: "6 minutes",
    2: "hour",
    3: "day",
    4: "week",
    5: "min5",  # same as 0 (minute)
    6: "min6",  # same as 0 (minute)
    7: "min7",  # same as 0 (minute)
}

HeaderType = {
    0: "HTTP",
}

PDNType = {
    0: "IPv4",
    1: "IPv6",
    2: "IPv4v6",
    3: "Non-IP",
    4: "Ethernet",
}

RuleIDType = {
    0: "PDR",
    1: "FAR",
    2: "QER",
    3: "URR",
    4: "BAR",
    # TODO: other values should be interpreted as '1' if received
}

BaseTimeInterval = {
    0: "CTP",
    1: "DTP",
}

InterfaceType = {
    0: "S1-U",
    1: "S5 /S8-U",
    2: "S4-U",
    3: "S11-U",
    4: "S12-U",
    5: "Gn/Gp-U",
    6: "S2a-U",
    7: "S2b-U",
    8: "eNodeB GTP-U interface for DL data forwarding",
    9: "eNodeB GTP-U interface for UL data forwarding",
    10: "SGW/UPF GTP-U interface for DL data forwarding",
    11: "N3 3GPP Access",
    12: "N3 Trusted Non-3GPP Access",
    13: "N3 Untrusted Non-3GPP Access",
    14: "N3 for data forwarding",
    15: "N9",
}


class PFCPLengthMixin(object):
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            tmp_len = len(p) - 4
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p


class PFCP(PFCPLengthMixin, Packet):
    # 3GPP TS 29.244 V15.6.0 (2019-07)
    # without the version
    name = "PFCP (v1) Header"
    fields_desc = [
        BitField("version", 1, 3),
        XBitField("spare_b2", 0, 1),
        XBitField("spare_b3", 0, 1),
        XBitField("spare_b4", 0, 1),
        BitField("MP", 0, 1),
        BitField("S", 1, 1),
        ByteEnumField("message_type", None, PFCPmessageType),
        ShortField("length", None),
        ConditionalField(XLongField("seid", 0),
                         lambda pkt:pkt.S == 1),
        ThreeBytesField("seq", 0),
        ConditionalField(BitField("priority", 0, 4),
                         lambda pkt:pkt.MP == 1),
        ConditionalField(BitField("spare_p", 0, 4),
                         lambda pkt:pkt.MP == 1),
        ConditionalField(ByteField("spare_oct", 0),
                         lambda pkt:pkt.MP == 0),
    ]

    def hashret(self):
        return struct.pack("B", self.version) + struct.pack("I", self.seq) + \
            self.payload.hashret()

    def answers(self, other):
        return (isinstance(other, PFCP) and
                self.version == other.version and
                self.seq == other.seq and
                self.payload.answers(other.payload))


class APNStrLenField(StrLenField):
    # Inspired by DNSStrField
    def m2i(self, pkt, s):
        ret_s = b""
        tmp_s = s
        while tmp_s:
            tmp_len = orb(tmp_s[0]) + 1
            if tmp_len > len(tmp_s):
                warning("APN prematured end of character-string (size=%i, remaining bytes=%i)" % (tmp_len, len(tmp_s)))  # noqa: E501
            ret_s += tmp_s[1:tmp_len]
            tmp_s = tmp_s[tmp_len:]
            if len(tmp_s):
                ret_s += b"."
        s = ret_s
        return s

    def i2m(self, pkt, s):
        s = b"".join(chb(len(x)) + x for x in s.split(b"."))
        return s


class ExtraDataField(StrField):
    def __init__(self, name, default=b""):
        StrField.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        # + 4 accounts for the ietype and length fields
        p = len(pkt.original) - len(s)
        length = pkt.length + 4 - p
        return s[length:], self.m2i(pkt, s[:length])

    def randval(self):
        return RandBin(RandNum(0, 2))


class Int40Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "BI")

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        return s + struct.pack("!BI", val >> 32, val & 0xffffffff)

    def getfield(self, pkt, s):
        hi, lo = struct.unpack("!BI", s[:5])
        return s[5:], self.m2i(pkt, (hi << 32) + lo)

    def randval(self):
        return RandNum(0, 2**40 - 1)


def IE_Dispatcher(s):
    """Choose the correct Information Element class."""

    # Get the IE type
    ietype = (orb(s[0]) * 256) + orb(s[1])
    if ietype & 0x8000:
        return IE_EnterpriseSpecific(s)

    cls = ietypecls.get(ietype, Raw)
    if cls is Raw:
        cls = IE_NotImplemented

    return cls(s)


class IE_Base(PFCPLengthMixin, Packet):
    default_length = None

    def __init__(self, *args, **kwargs):
        self.fields_desc[0].default = self.ie_type
        self.fields_desc[1].default = self.default_length
        super(IE_Base, self).__init__(*args, **kwargs)

    def extract_padding(self, pkt):
        return "", pkt

    fields_desc = [
        ShortEnumField("ietype", 0, IEType),
        ShortField("length", None)
    ]


class IE_Compound(IE_Base):
    fields_desc = IE_Base.fields_desc + [
        PacketListField("IE_list", None, IE_Dispatcher,
                        length_from=lambda pkt: pkt.length)
    ]


class IE_CreatePDR(IE_Compound):
    name = "IE Create PDR"
    ie_type = 1


class IE_PDI(IE_Compound):
    name = "IE PDI"
    ie_type = 2


class IE_CreateFAR(IE_Compound):
    name = "IE Create FAR"
    ie_type = 3


class IE_ForwardingParameters(IE_Compound):
    name = "IE Forwarding Parameters"
    ie_type = 4


class IE_DuplicatingParameters(IE_Compound):
    name = "IE Duplicating Parameters"
    ie_type = 5


class IE_CreateURR(IE_Compound):
    name = "IE Create URR"
    ie_type = 6


class IE_CreateQER(IE_Compound):
    name = "IE Create QER"
    ie_type = 7


class IE_CreatedPDR(IE_Compound):
    name = "IE Created PDR"
    ie_type = 8


class IE_UpdatePDR(IE_Compound):
    name = "IE Update PDR"
    ie_type = 9


class IE_UpdateFAR(IE_Compound):
    name = "IE Update FAR"
    ie_type = 10


class IE_UpdateForwardingParameters(IE_Compound):
    name = "IE Update Forwarding Parameters"
    ie_type = 11


class IE_UpdateBAR_SRR(IE_Compound):
    name = "IE Update BAR (PFCP Session Report Response)"
    ie_type = 12


class IE_UpdateURR(IE_Compound):
    name = "IE Update URR"
    ie_type = 13


class IE_UpdateQER(IE_Compound):
    name = "IE Update QER"
    ie_type = 14


class IE_RemovePDR(IE_Compound):
    name = "IE Remove PDR"
    ie_type = 15


class IE_RemoveFAR(IE_Compound):
    name = "IE Remove FAR"
    ie_type = 16


class IE_RemoveURR(IE_Compound):
    name = "IE Remove URR"
    ie_type = 17


class IE_RemoveQER(IE_Compound):
    name = "IE Remove QER"
    ie_type = 18


class IE_LoadControlInformation(IE_Compound):
    name = "IE Load Control Information"
    ie_type = 51


class IE_OverloadControlInformation(IE_Compound):
    name = "IE Overload Control Information"
    ie_type = 54


class IE_ApplicationID_PFDs(IE_Compound):
    name = "IE Application ID's PFDs"
    ie_type = 58


class IE_PFDContext(IE_Compound):
    name = "IE PFD context"
    ie_type = 59


class IE_ApplicationDetectionInformation(IE_Compound):
    name = "IE Application Detection Information"
    ie_type = 68


class IE_QueryURR(IE_Compound):
    name = "IE Query URR"
    ie_type = 77


class IE_UsageReport_SMR(IE_Compound):
    name = "IE Usage Report (Session Modification Response)"
    ie_type = 78


class IE_UsageReport_SDR(IE_Compound):
    name = "IE Usage Report (Session Deletion Response)"
    ie_type = 79


class IE_UsageReport_SRR(IE_Compound):
    name = "IE Usage Report (Session Report Request)"
    ie_type = 80


class IE_DownlinkDataReport(IE_Compound):
    name = "IE Downlink Data Report"
    ie_type = 83


class IE_Create_BAR(IE_Compound):
    name = "IE Create BAR"
    ie_type = 85


class IE_Update_BAR_SMR(IE_Compound):
    name = "IE Update BAR (Session Modification Request)"
    ie_type = 86


class IE_Remove_BAR(IE_Compound):
    name = "IE Remove BAR"
    ie_type = 87


class IE_ErrorIndicationReport(IE_Compound):
    name = "IE Error Indication Report"
    ie_type = 99


class IE_UserPlanePathFailureReport(IE_Compound):
    name = "IE User Plane Path Failure Report"
    ie_type = 102


class IE_UpdateDuplicatingParameters(IE_Compound):
    name = "IE Update Duplicating Parameters"
    ie_type = 105


class IE_AggregatedURRs(IE_Compound):
    name = "IE Aggregated URRs"
    ie_type = 118


class IE_CreateTrafficEndpoint(IE_Compound):
    name = "IE Create Traffic Endpoint"
    ie_type = 127


class IE_CreatedTrafficEndpoint(IE_Compound):
    name = "IE Created Traffic Endpoint"
    ie_type = 128


class IE_UpdateTrafficEndpoint(IE_Compound):
    name = "IE Update Traffic Endpoint"
    ie_type = 129


class IE_RemoveTrafficEndpoint(IE_Compound):
    name = "IE Remove Traffic Endpoint"
    ie_type = 130


class IE_EthernetPacketFilter(IE_Compound):
    name = "IE Ethernet Packet Filter"
    ie_type = 132


class IE_EthernetTrafficInformation(IE_Compound):
    name = "IE Ethernet Traffic Information"
    ie_type = 143


class IE_AdditionalMonitoringTime(IE_Compound):
    name = "IE Additional Monitoring Time"
    ie_type = 147


class IE_Cause(IE_Base):
    ie_type = 19
    name = "IE Cause"
    fields_desc = IE_Base.fields_desc + [
        ByteEnumField("cause", None, CauseValues)
    ]


class IE_SourceInterface(IE_Base):
    name = "IE Source Interface"
    ie_type = 20
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitEnumField("interface", "Access", 4, SourceInterface),
        ExtraDataField("extra_data"),
    ]


class IE_FTEID(IE_Base):
    name = "IE F-TEID"
    ie_type = 21
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitField("CHID", 0, 1),
        BitField("CH", 0, 1),
        BitField("V6", 0, 1),
        BitField("V4", 0, 1),
        ConditionalField(XIntField("TEID", 0), lambda x: x.CH == 0),
        ConditionalField(IPField("ipv4", 0),
                         lambda x: x.V4 == 1 and x.CH == 0),
        ConditionalField(IP6Field("ipv6", 0),
                         lambda x: x.V6 == 1 and x.CH == 0),
        ConditionalField(ByteField("choose_id", 0),
                         lambda x: x.CHID == 1),
        ExtraDataField("extra_data"),
    ]


class IE_NetworkInstance(IE_Base):
    name = "IE Network Instance"
    ie_type = 22
    fields_desc = IE_Base.fields_desc + [
        APNStrLenField("instance", "", length_from=lambda x: x.length)
    ]


class IE_SDF_Filter(IE_Base):
    name = "IE SDF Filter"
    ie_type = 23
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 3),
        BitField("BID", 0, 1),
        BitField("FL", 0, 1),
        BitField("SPI", 0, 1),
        BitField("TTC", 0, 1),
        BitField("FD", 0, 1),
        ByteField("spare_oct", 0),
        ConditionalField(FieldLenField("flow_description_length", None,
                                       length_of="flow_description"),
                         lambda pkt: pkt.FD == 1),
        ConditionalField(StrLenField("flow_description", "",
                                     length_from=lambda pkt:
                                     pkt.flow_description_length),
                         lambda pkt: pkt.FD == 1),
        ConditionalField(ByteField("tos_traffic_class", 0),
                         lambda pkt: pkt.TTC == 1),
        ConditionalField(ByteField("tos_traffic_mask", 0),
                         lambda pkt: pkt.TTC == 1),
        ConditionalField(IntField("security_parameter_index", 0),
                         lambda pkt: pkt.SPI == 1),
        ConditionalField(ThreeBytesField("flow_label", 0),
                         lambda pkt: pkt.FL == 1),
        ConditionalField(IntField("sdf_filter_id", 0),
                         lambda pkt: pkt.BID == 1),
        ExtraDataField("extra_data"),
    ]


class IE_ApplicationId(IE_Base):
    name = "IE Application ID"
    ie_type = 24
    fields_desc = IE_Base.fields_desc + [
        StrLenField("id", "", length_from=lambda x: x.length),
    ]


class IE_GateStatus(IE_Base):
    name = "IE Gate Status"
    ie_type = 25
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitEnumField("ul", "OPEN", 2, GateStatus),
        BitEnumField("dl", "OPEN", 2, GateStatus),
        ExtraDataField("extra_data"),
    ]


class IE_MBR(IE_Base):
    name = "IE MBR"
    ie_type = 26
    fields_desc = IE_Base.fields_desc + [
        Int40Field("ul", 0),
        Int40Field("dl", 0),
        ExtraDataField("extra_data"),
    ]


class IE_GBR(IE_Base):
    name = "IE GBR"
    ie_type = 27
    fields_desc = IE_Base.fields_desc + [
        Int40Field("ul", 0),
        Int40Field("dl", 0),
        ExtraDataField("extra_data"),
    ]


class IE_QERCorrelationId(IE_Base):
    name = "IE QER Correlation ID"
    ie_type = 28
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_Precedence(IE_Base):
    name = "IE Precedence"
    ie_type = 29
    fields_desc = IE_Base.fields_desc + [
        IntField("precedence", 0),
        ExtraDataField("extra_data"),
    ]


class IE_TransportLevelMarking(IE_Base):
    name = "IE Transport Level Marking"
    ie_type = 30
    fields_desc = IE_Base.fields_desc + [
        XByteField("tos", 0),
        XByteField("traffic_class", 0),
        ExtraDataField("extra_data"),
    ]


class IE_VolumeThreshold(IE_Base):
    name = "IE Volume Threshold"
    ie_type = 31
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("DLVOL", 0, 1),
        BitField("ULVOL", 0, 1),
        BitField("TOVOL", 0, 1),
        ConditionalField(XLongField("total", 0), lambda x: x.TOVOL == 1),
        ConditionalField(XLongField("uplink", 0), lambda x: x.ULVOL == 1),
        ConditionalField(XLongField("downlink", 0), lambda x: x.DLVOL == 1),
        ExtraDataField("extra_data"),
    ]


class IE_TimeThreshold(IE_Base):
    name = "IE Time Threshold"
    ie_type = 32
    fields_desc = IE_Base.fields_desc + [
        IntField("threshold", 0),
        ExtraDataField("extra_data"),
    ]


class IE_MonitoringTime(IE_Base):
    name = "IE Monitoring Time"
    ie_type = 33
    fields_desc = IE_Base.fields_desc + [
        IntField("time_value", 0),
        ExtraDataField("extra_data"),
    ]


class IE_SubsequentVolumeThreshold(IE_Base):
    name = "IE Subsequent Volume Threshold"
    ie_type = 34
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("DLVOL", 0, 1),
        BitField("ULVOL", 0, 1),
        BitField("TOVOL", 0, 1),
        ConditionalField(XLongField("total", 0), lambda x: x.TOVOL == 1),
        ConditionalField(XLongField("uplink", 0), lambda x: x.ULVOL == 1),
        ConditionalField(XLongField("downlink", 0), lambda x: x.DLVOL == 1),
        ExtraDataField("extra_data"),
    ]


class IE_SubsequentTimeThreshold(IE_Base):
    name = "IE Subsequent Time Threshold"
    ie_type = 35
    fields_desc = IE_Base.fields_desc + [
        IntField("threshold", 0),
        ExtraDataField("extra_data"),
    ]


class IE_InactivityDetectionTime(IE_Base):
    name = "IE Inactivity Detection Time"
    ie_type = 36
    fields_desc = IE_Base.fields_desc + [
        IntField("time_value", 0),
        ExtraDataField("extra_data"),
    ]


class IE_ReportingTriggers(IE_Base):
    name = "IE Reporting Triggers"
    ie_type = 37
    fields_desc = IE_Base.fields_desc + [
        BitField("linked_usage_reporting", 0, 1),
        BitField("dropped_dl_traffic_threshold", 0, 1),
        BitField("stop_of_traffic", 0, 1),
        BitField("start_of_traffic", 0, 1),
        BitField("quota_holding_time", 0, 1),
        BitField("time_threshold", 0, 1),
        BitField("volume_threshold", 0, 1),
        BitField("periodic_reporting", 0, 1),
        XBitField("spare", 0, 2),
        BitField("event_quota", 0, 1),
        BitField("event_threshold", 0, 1),
        BitField("mac_addresses_reporting", 0, 1),
        BitField("envelope_closure", 0, 1),
        BitField("time_quota", 0, 1),
        BitField("volume_quota", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_RedirectInformation(IE_Base):
    name = "IE Redirect Information"
    ie_type = 38
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitEnumField("type", "IPv4 address", 4, RedirectAddressType),
        FieldLenField("address_length", None, length_of="address"),
        StrLenField("address", "", length_from=lambda pkt: pkt.address_length),
        ExtraDataField("extra_data"),
    ]


class IE_ReportType(IE_Base):
    name = "IE Report Type"
    ie_type = 39
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitField("UPIR", 0, 1),
        BitField("ERIR", 0, 1),
        BitField("USAR", 0, 1),
        BitField("DLDR", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_OffendingIE(IE_Base):
    name = "IE Offending IE"
    ie_type = 40
    fields_desc = IE_Base.fields_desc + [
        ShortEnumField("type", None, IEType)
    ]


class IE_ForwardingPolicy(IE_Base):
    name = "IE Forwarding Policy"
    ie_type = 41
    fields_desc = IE_Base.fields_desc + [
        FieldLenField("policy_identifier_length", None,
                      length_of="policy_identifier", fmt="B"),
        StrLenField("policy_identifier", "",
                    length_from=lambda pkt: pkt.policy_identifier_length)
    ]


class IE_DestinationInterface(IE_Base):
    name = "IE Destination Interface"
    ie_type = 42
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitEnumField("interface", "Access", 4, DestinationInterface),
        ExtraDataField("extra_data"),
    ]


class IE_UPFunctionFeatures(IE_Base):
    name = "IE UP Function Features"
    ie_type = 43
    default_length = 2
    fields_desc = IE_Base.fields_desc + [
        ConditionalField(BitField("TREU", None, 1), lambda x: x.length > 0),
        ConditionalField(BitField("HEEU", None, 1), lambda x: x.length > 0),
        ConditionalField(BitField("PFDM", None, 1), lambda x: x.length > 0),
        ConditionalField(BitField("FTUP", None, 1), lambda x: x.length > 0),

        ConditionalField(BitField("TRST", None, 1), lambda x: x.length > 0),
        ConditionalField(BitField("DLBD", None, 1), lambda x: x.length > 0),
        ConditionalField(BitField("DDND", None, 1), lambda x: x.length > 0),
        ConditionalField(BitField("BUCP", None, 1), lambda x: x.length > 0),

        ConditionalField(BitField("spare", None, 1), lambda x: x.length > 1),
        ConditionalField(BitField("PFDE", None, 1), lambda x: x.length > 1),
        ConditionalField(BitField("FRRT", None, 1), lambda x: x.length > 1),
        ConditionalField(BitField("TRACE", None, 1), lambda x: x.length > 1),

        ConditionalField(BitField("QUOAC", None, 1), lambda x: x.length > 1),
        ConditionalField(BitField("UDBC", None, 1), lambda x: x.length > 1),
        ConditionalField(BitField("PDIU", None, 1), lambda x: x.length > 1),
        ConditionalField(BitField("EMPU", None, 1), lambda x: x.length > 1),

        ExtraDataField("extra_data"),
    ]


class IE_ApplyAction(IE_Base):
    name = "IE Apply Action"
    ie_type = 44
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 3),
        BitField("DUPL", 0, 1),
        BitField("NOCP", 0, 1),
        BitField("BUFF", 0, 1),
        BitField("FORW", 0, 1),
        BitField("DROP", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_DownlinkDataServiceInformation(IE_Base):
    name = "IE Downlink Data Service Information"
    ie_type = 45
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", None, 6),
        BitField("QFII", 0, 1),
        BitField("PPI", 0, 1),
        ConditionalField(
            XBitField("spare_2", None, 2),
            lambda x: x.PPI == 1),
        ConditionalField(
            XBitField("ppi_val", None, 6),
            lambda x: x.PPI == 1),
        ConditionalField(
            XBitField("spare_3", None, 2),
            lambda x: x.QFII == 1),
        ConditionalField(
            XBitField("qfi_val", None, 6),
            lambda x: x.QFII == 1),
        ExtraDataField("extra_data"),
    ]


class IE_DownlinkDataNotificationDelay(IE_Base):
    name = "IE Downlink Data Notification Delay"
    ie_type = 46
    fields_desc = IE_Base.fields_desc + [
        ByteField("delay", 0),  # in multiples of 50
        ExtraDataField("extra_data"),
    ]


class IE_DLBufferingDuration(IE_Base):
    name = "IE DL Buffering Duration"
    ie_type = 47
    fields_desc = IE_Base.fields_desc + [
        BitEnumField("timer_unit", "2 seconds", 3, TimerUnit),
        BitField("timer_value", 0, 5),
        ExtraDataField("extra_data"),
    ]


class IE_DLBufferingSuggestedPacketCount(IE_Base):
    name = "IE DL Buffering Suggested Packet Count"
    ie_type = 48
    fields_desc = IE_Base.fields_desc + [
        MultipleTypeField([
            (
                ByteField("count", 0),
                (lambda x: x.length == 1,
                 lambda x, val: x.length == 1 or
                 (x.length is None and val < 256)),
            ),
            (
                ShortField("count", 0),
                (lambda x: x.length == 2,
                 lambda x, val: x.length == 1 or
                 (x.length is None and val >= 256))
            ),
        ], ByteField("count", 0))
    ]


class IE_PFCPSMReqFlags(IE_Base):
    name = "IE PFCPSMReq-Flags"
    ie_type = 49
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 5),
        BitField("QUARR", 0, 1),
        BitField("SNDEM", 0, 1),
        BitField("DROBU", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_PFCPSRRspFlags(IE_Base):
    name = "IE PFCPSRRsp-Flags"
    ie_type = 50
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 7),
        BitField("DROBU", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_SequenceNumber(IE_Base):
    name = "IE Sequence Number"
    ie_type = 52
    fields_desc = IE_Base.fields_desc + [
        IntField("number", 0),
    ]


class IE_Metric(IE_Base):
    name = "IE Metric"
    ie_type = 53
    fields_desc = IE_Base.fields_desc + [
        ByteField("metric", 0),
    ]


class IE_Timer(IE_Base):
    name = "IE Timer"
    ie_type = 55
    fields_desc = IE_Base.fields_desc + [
        BitEnumField("timer_unit", "2 seconds", 3, TimerUnit),
        BitField("timer_value", 0, 5),
        ExtraDataField("extra_data"),
    ]


class IE_PDR_Id(IE_Base):
    name = "IE PDR ID"
    ie_type = 56
    fields_desc = IE_Base.fields_desc + [
        ShortField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_FSEID(IE_Base):
    name = "IE F-SEID"
    ie_type = 57
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 6),
        BitField("v4", 0, 1),
        BitField("v6", 0, 1),
        XLongField("seid", 0),
        ConditionalField(IPField("ipv4", 0),
                         lambda x: x.v4 == 1),
        ConditionalField(IP6Field("ipv6", 0),
                         lambda x: x.v6 == 1),
        ExtraDataField("extra_data"),
    ]


class IE_NodeId(IE_Base):
    name = "IE Node ID"
    ie_type = 60
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitEnumField("id_type", "IPv4", 4, NodeIdType),
        ConditionalField(IPField("ipv4", 0),
                         lambda x: x.id_type == 0),
        ConditionalField(IP6Field("ipv6", 0),
                         lambda x: x.id_type == 1),
        ConditionalField(
            APNStrLenField("id", "", length_from=lambda x: x.length - 1),
            lambda x: x.id_type == 2),
        ExtraDataField("extra_data"),
    ]


class IE_PFDContents(IE_Base):
    name = "IE PFD contents"
    ie_type = 61
    fields_desc = IE_Base.fields_desc + [
        BitField("ADNP", 0, 1),
        BitField("AURL", 0, 1),
        BitField("AFD", 0, 1),
        BitField("DNP", 0, 1),
        BitField("CP", 0, 1),
        BitField("DN", 0, 1),
        BitField("URL", 0, 1),
        BitField("FD", 0, 1),
        ByteField("spare_2", 0),
        ConditionalField(FieldLenField("flow_length", None, length_of="flow"),
                         lambda pkt: pkt.FD == 1),
        ConditionalField(StrLenField("flow", "",
                                     length_from=lambda pkt: pkt.flow_length),
                         lambda pkt: pkt.FD == 1),
        ConditionalField(FieldLenField("url_length", None, length_of="url"),
                         lambda pkt: pkt.URL == 1),
        ConditionalField(StrLenField("url", "",
                                     length_from=lambda pkt: pkt.url_length),
                         lambda pkt: pkt.URL == 1),
        ConditionalField(FieldLenField("domain_length", None,
                                       length_of="domain"),
                         lambda pkt: pkt.DN == 1),
        ConditionalField(
            StrLenField("domain", "",
                        length_from=lambda pkt: pkt.domain_length),
            lambda pkt: pkt.DN == 1),
        ConditionalField(FieldLenField("custom_length", None,
                                       length_of="custom"),
                         lambda pkt: pkt.CP == 1),
        ConditionalField(
            StrLenField("custom", "",
                        length_from=lambda pkt: pkt.custom_length),
            lambda pkt: pkt.CP == 1),
        ConditionalField(FieldLenField("dnp_length", None, length_of="dnp"),
                         lambda pkt: pkt.DNP == 1),
        ConditionalField(StrLenField("dnp", "",
                                     length_from=lambda pkt: pkt.dnp_length),
                         lambda pkt: pkt.DNP == 1),
        ConditionalField(FieldLenField("additional_flow_length", None,
                                       length_of="additional_flow"),
                         lambda pkt: pkt.AFD == 1),
        ConditionalField(
            StrLenField("additional_flow", "",
                        length_from=lambda pkt: pkt.additional_flow_length),
            lambda pkt: pkt.AFD == 1),
        ConditionalField(FieldLenField("additional_url_length", None,
                                       length_of="additional_url"),
                         lambda pkt: pkt.AURL == 1),
        ConditionalField(
            StrLenField("additional_url", "",
                        length_from=lambda pkt: pkt.additional_url_length),
            lambda pkt: pkt.AURL == 1),
        ConditionalField(
            FieldLenField("additional_dn_dnp_length", None,
                          length_of="additional_dn_dnp"),
            lambda pkt: pkt.ADNP == 1),
        ConditionalField(
            StrLenField("additional_dn_dnp", "",
                        length_from=lambda pkt: pkt.additional_dn_dnp_length),
            lambda pkt: pkt.ADNP == 1),
        ExtraDataField("extra_data"),
    ]


class IE_MeasurementMethod(IE_Base):
    name = "IE Measurement Method"
    ie_type = 62
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("EVENT", 0, 1),
        BitField("VOLUM", 0, 1),
        BitField("DURAT", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_UsageReportTrigger(IE_Base):
    name = "IE Usage Report Trigger"
    ie_type = 63
    fields_desc = IE_Base.fields_desc + [
        BitField("IMMER", 0, 1),
        BitField("DROTH", 0, 1),
        BitField("STOPT", 0, 1),
        BitField("START", 0, 1),
        BitField("QUHTI", 0, 1),
        BitField("TIMTH", 0, 1),
        BitField("VOLTH", 0, 1),
        BitField("PERIO", 0, 1),
        BitField("EVETH", 0, 1),
        BitField("MACAR", 0, 1),
        BitField("ENVCL", 0, 1),
        BitField("MONIT", 0, 1),
        BitField("TERMR", 0, 1),
        BitField("LIUSA", 0, 1),
        BitField("TIMQU", 0, 1),
        BitField("VOLQU", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_MeasurementPeriod(IE_Base):
    name = "IE Measurement Period"
    ie_type = 64
    fields_desc = IE_Base.fields_desc + [
        IntField("period", 0),
        ExtraDataField("extra_data"),
    ]


class IE_FqCSID(IE_Base):
    name = "IE FQ-CSID"
    ie_type = 65
    fields_desc = IE_Base.fields_desc + [
        BitEnumField("node_id_type", "IPv4", 4, FqCSIDNodeIdType),
        BitFieldLenField("num_csids", None, 4, count_of="csids"),
        ConditionalField(IPField("ipv4", 0),
                         lambda x: x.node_id_type == 0),
        ConditionalField(IP6Field("ipv6", 0),
                         lambda x: x.node_id_type == 1),
        ConditionalField(
            # FIXME: split (value = mcc * 1000 + mnc)
            BitField("mcc_mnc", 0, 20),
            lambda x: x.node_id_type == 2),
        # "Least significant 12 bits is a 12 bit integer assigned by
        # an operator to an MME, SGW-C, SGW-U, PGW-C or PGW-U."
        ConditionalField(
            BitField("extra_id", 0, 12),
            lambda x: x.node_id_type == 2),
        FieldListField("csids", None, ShortField("csid", 0),
                       count_from=lambda x: x.num_csids),
        ExtraDataField("extra_data"),
    ]


class IE_VolumeMeasurement(IE_Base):
    name = "IE Volume Measurement"
    ie_type = 66
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("DLVOL", 0, 1),
        BitField("ULVOL", 0, 1),
        BitField("TOVOL", 0, 1),
        ConditionalField(XLongField("total", 0), lambda x: x.TOVOL == 1),
        ConditionalField(XLongField("uplink", 0), lambda x: x.ULVOL == 1),
        ConditionalField(XLongField("downlink", 0), lambda x: x.DLVOL == 1),
        ExtraDataField("extra_data"),
    ]


class IE_DurationMeasurement(IE_Base):
    name = "IE Duration Measurement"
    ie_type = 67
    fields_desc = IE_Base.fields_desc + [
        IntField("duration", 0),
        ExtraDataField("extra_data"),
    ]


class IE_TimeOfFirstPacket(IE_Base):
    name = "IE Time of First Packet"
    ie_type = 69
    fields_desc = IE_Base.fields_desc + [
        IntField("timestamp", 0),
        ExtraDataField("extra_data"),
    ]


class IE_TimeOfLastPacket(IE_Base):
    name = "IE Time of Last Packet"
    ie_type = 70
    fields_desc = IE_Base.fields_desc + [
        IntField("timestamp", 0),
        ExtraDataField("extra_data"),
    ]


class IE_QuotaHoldingTime(IE_Base):
    name = "IE Quota Holding Time"
    ie_type = 71
    fields_desc = IE_Base.fields_desc + [
        IntField("time_value", 0),
        ExtraDataField("extra_data"),
    ]


class IE_DroppedDLTrafficThreshold(IE_Base):
    name = "IE Dropped DL Traffic Threshold"
    ie_type = 72
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 6),
        BitField("DLBY", 0, 1),
        BitField("DLPA", 0, 1),
        ConditionalField(LongField("packet_count", 0),
                         lambda x: x.DLPA == 1),
        ConditionalField(LongField("byte_count", 0),
                         lambda x: x.DLBY == 1),
        ExtraDataField("extra_data"),
    ]


class IE_VolumeQuota(IE_Base):
    name = "IE Volume Quota"
    ie_type = 73
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("DLVOL", 0, 1),
        BitField("ULVOL", 0, 1),
        BitField("TOVOL", 0, 1),
        ConditionalField(XLongField("total", 0), lambda x: x.TOVOL == 1),
        ConditionalField(XLongField("uplink", 0), lambda x: x.ULVOL == 1),
        ConditionalField(XLongField("downlink", 0), lambda x: x.DLVOL == 1),
        ExtraDataField("extra_data"),
    ]


class IE_TimeQuota(IE_Base):
    name = "IE Time Quota"
    ie_type = 74
    fields_desc = IE_Base.fields_desc + [
        IntField("quota", 0),
        ExtraDataField("extra_data"),
    ]


class IE_StartTime(IE_Base):
    name = "IE Start Time"
    ie_type = 75
    fields_desc = IE_Base.fields_desc + [
        IntField("timestamp", 0),
        ExtraDataField("extra_data"),
    ]


class IE_EndTime(IE_Base):
    name = "IE End Time"
    ie_type = 76
    fields_desc = IE_Base.fields_desc + [
        IntField("timestamp", 0),
        ExtraDataField("extra_data"),
    ]


class IE_URR_Id(IE_Base):
    name = "IE URR ID"
    ie_type = 81
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_LinkedURR_Id(IE_Base):
    name = "IE Linked URR ID"
    ie_type = 82
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_OuterHeaderCreation(IE_Base):
    name = "IE Outer Header Creation"
    ie_type = 84
    fields_desc = IE_Base.fields_desc + [
        BitField("STAG", 0, 1),
        BitField("CTAG", 0, 1),
        BitField("IPV6", 0, 1),
        BitField("IPV4", 0, 1),
        BitField("UDPIPV6", 0, 1),
        BitField("UDPIPV4", 0, 1),
        BitField("GTPUUDPIPV6", 0, 1),
        BitField("GTPUUDPIPV4", 0, 1),
        ByteField("spare", 0),
        ConditionalField(XIntField("TEID", 0),
                         lambda x: x.GTPUUDPIPV4 == 1 or x.GTPUUDPIPV6 == 1),
        ConditionalField(IPField("ipv4", 0),
                         lambda x:
                         x.IPV4 == 1 or x.UDPIPV4 == 1 or x.GTPUUDPIPV4 == 1),
        ConditionalField(IP6Field("ipv6", 0),
                         lambda x:
                         x.IPV6 == 1 or x.UDPIPV6 == 1 or x.GTPUUDPIPV6 == 1),
        ConditionalField(ShortField("port", 0),
                         lambda x: x.UDPIPV4 == 1 or x.UDPIPV6 == 1),
        ConditionalField(ThreeBytesField("ctag", 0),
                         lambda x: x.CTAG == 1),
        ConditionalField(ThreeBytesField("stag", 0),
                         lambda x: x.STAG == 1),
        ExtraDataField("extra_data"),
    ]


class IE_BAR_Id(IE_Base):
    name = "IE BAR ID"
    ie_type = 88
    fields_desc = IE_Base.fields_desc + [
        ByteField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_CPFunctionFeatures(IE_Base):
    name = "IE CP Function Features"
    ie_type = 89
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 6),
        BitField("OVRL", 0, 1),
        BitField("LOAD", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_UsageInformation(IE_Base):
    name = "IE Usage Information"
    ie_type = 90
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitField("UBE", 0, 1),
        BitField("UAE", 0, 1),
        BitField("AFT", 0, 1),
        BitField("BEF", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_ApplicationInstanceId(IE_Base):
    name = "IE Application Instance ID"
    ie_type = 91
    fields_desc = IE_Base.fields_desc + [
        StrLenField("id", "", length_from=lambda x: x.length)
    ]


class IE_FlowInformation(IE_Base):
    name = "IE Flow Information"
    ie_type = 92
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitEnumField("direction", "Unspecified", 3, FlowDirection),
        FieldLenField("flow_length", None, length_of="flow"),
        StrLenField("flow", "", length_from=lambda x: x.flow_length),
        ExtraDataField("extra_data"),
    ]


class IE_UE_IP_Address(IE_Base):
    name = "IE UE IP Address"
    ie_type = 93
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("SD", 0, 1),  # source or dest
        BitField("V4", 0, 1),
        BitField("V6", 0, 1),
        ConditionalField(IPField("ipv4", 0), lambda x: x.V4 == 1),
        ConditionalField(IP6Field("ipv6", 0), lambda x: x.V6 == 1),
        ExtraDataField("extra_data"),
    ]


class IE_PacketRate(IE_Base):
    name = "IE Packet Rate"
    ie_type = 94
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", 0, 6),
        BitField("DLPR", 0, 1),
        BitField("ULPR", 0, 1),
        ConditionalField(BitField("spare_2", 0, 5), lambda x: x.ULPR == 1),
        ConditionalField(BitEnumField("ul_time_unit", "minute", 3, TimeUnit),
                         lambda x: x.ULPR == 1),
        ConditionalField(ShortField("ul_max_packet_rate", 0),
                         lambda x: x.ULPR == 1),
        ConditionalField(BitField("spare_3", 0, 5), lambda x: x.DLPR == 1),
        ConditionalField(BitEnumField("dl_time_unit", "minute", 3, TimeUnit),
                         lambda x: x.DLPR == 1),
        ConditionalField(ShortField("dl_max_packet_rate", 0),
                         lambda x: x.DLPR == 1),
        ExtraDataField("extra_data"),
    ]


class IE_OuterHeaderRemoval(IE_Base):
    name = "IE Outer Header Removal"
    ie_type = 95
    fields_desc = IE_Base.fields_desc + [
        ByteEnumField("header", None, OuterHeaderRemovalDescription),
        ConditionalField(XBitField("spare", None, 7),
                         lambda x: x.length is not None and x.length > 1),
        ConditionalField(BitField("pdu_session_container", None, 1),
                         lambda x: x.length is not None and x.length > 1),
        ExtraDataField("extra_data"),
    ]


class IE_RecoveryTimeStamp(IE_Base):
    name = "IE Recovery Time Stamp"
    ie_type = 96
    default_length = 4
    fields_desc = IE_Base.fields_desc + [
        IntField("timestamp", 0),
        ExtraDataField("extra_data"),
    ]


class IE_DLFlowLevelMarking(IE_Base):
    name = "IE DL Flow Level Marking"
    ie_type = 97
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", 0, 6),
        BitField("SCI", 0, 1),
        BitField("TTC", 0, 1),
        ConditionalField(ByteField("traffic_class", 0), lambda x: x.TTC),
        ConditionalField(ByteField("traffic_class_mask", 0), lambda x: x.TTC),
        ConditionalField(ByteField("service_class_indicator", 0),
                         lambda x: x.SCI),
        ConditionalField(ByteField("spare_2", 0), lambda x: x.SCI),
        ExtraDataField("extra_data"),
    ]


class IE_HeaderEnrichment(IE_Base):
    name = "IE Header Enrichment"
    ie_type = 98
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 3),
        BitEnumField("header_type", "HTTP", 5, HeaderType),
        FieldLenField("name_length", None, fmt="B", length_of="name"),
        StrLenField("name", "", length_from=lambda x: x.name_length),
        FieldLenField("value_length", None, fmt="B", length_of="value"),
        StrLenField("value", "", length_from=lambda x: x.value_length),
        ExtraDataField("extra_data"),
    ]


class IE_MeasurementInformation(IE_Base):
    name = "IE Measurement Information"
    ie_type = 100
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 3),
        BitField("MNOP", 0, 1),
        BitField("ISTM", 0, 1),
        BitField("RADI", 0, 1),
        BitField("INAM", 0, 1),
        BitField("MBQE", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_NodeReportType(IE_Base):
    name = "IE Node Report Type"
    ie_type = 101
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 7),
        BitField("UPFR", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_RemoteGTP_U_Peer(IE_Base):
    name = "IE Remote GTP-U Peer"
    ie_type = 103
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", 0, 4),
        BitField("NI", 0, 1),
        BitField("DI", 0, 1),
        BitField("V4", 0, 1),
        BitField("V6", 0, 1),
        ConditionalField(IPField("ipv4", 0), lambda x: x.V4 == 1),
        ConditionalField(IP6Field("ipv6", 0), lambda x: x.V6 == 1),
        ConditionalField(ByteField("dest_interface_length", 1),
                         lambda x: x.DI == 1),
        ConditionalField(XBitField("spare_2", 0, 4), lambda x: x.DI == 1),
        ConditionalField(
            BitEnumField("dest_interface", "Access", 4, DestinationInterface),
            lambda x: x.DI == 1),
        ConditionalField(
            FieldLenField("network_instance_length", 1,
                          length_of="network_instance"),
            lambda x: x.NI == 1),
        ConditionalField(
            APNStrLenField("network_instance", "",
                           length_from=lambda x: x.network_instance_length),
            lambda x: x.NI == 1),
        ExtraDataField("extra_data"),
    ]


class IE_UR_SEQN(IE_Base):
    name = "IE UR-SEQN"
    ie_type = 104
    fields_desc = IE_Base.fields_desc + [
        IntField("number", 0),
    ]


class IE_ActivatePredefinedRules(IE_Base):
    name = "IE Activate Predefined Rules"
    ie_type = 106
    fields_desc = IE_Base.fields_desc + [
        StrLenField("name", "", length_from=lambda x: x.length)
    ]


class IE_DeactivatePredefinedRules(IE_Base):
    name = "IE Deactivate Predefined Rules"
    ie_type = 107
    fields_desc = IE_Base.fields_desc + [
        StrLenField("name", "", length_from=lambda x: x.length)
    ]


class IE_FAR_Id(IE_Base):
    name = "IE FAR ID"
    ie_type = 108
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_QER_Id(IE_Base):
    name = "IE QER ID"
    ie_type = 109
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_OCIFlags(IE_Base):
    name = "IE OCI Flags"
    ie_type = 110
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 7),
        BitField("AOCI", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_PFCPAssociationReleaseRequest(IE_Base):
    name = "IE PFCP Association Release Request"
    ie_type = 111
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 7),
        BitField("SARR", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_GracefulReleasePeriod(IE_Base):
    name = "IE Graceful Release Period"
    ie_type = 112
    fields_desc = IE_Base.fields_desc + [
        BitEnumField("release_timer_unit", "2 seconds", 3, TimerUnit),
        BitField("release_timer_value", 0, 5),
        ExtraDataField("extra_data"),
    ]


class IE_PDNType(IE_Base):
    name = "IE PDN Type"
    ie_type = 113
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitEnumField("pdn_type", "IPv4", 3, PDNType),
        ExtraDataField("extra_data"),
    ]


class IE_FailedRuleId(IE_Base):
    name = "IE Failed Rule ID"
    ie_type = 114
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 3),
        BitEnumField("type", "PDR", 5, RuleIDType),
        ConditionalField(ShortField("pdr_id", 0),
                         lambda x: x.type == 0),
        ConditionalField(IntField("far_id", 0),
                         lambda x: x.type == 1 or x.type > 4),
        ConditionalField(IntField("qer_id", 0), lambda x: x.type == 2),
        ConditionalField(IntField("urr_id", 0), lambda x: x.type == 3),
        ConditionalField(ByteField("bar_id", 0),
                         lambda x: x.type == 4),
        ExtraDataField("extra_data"),
    ]


class IE_TimeQuotaMechanism(IE_Base):
    name = "IE Time Quota Mechanism"
    ie_type = 115
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 6),
        BitEnumField("base_time_interval_type", "CTP", 2, BaseTimeInterval),
        IntField("interval", 0),
        ExtraDataField("extra_data"),
    ]


class IE_UserPlaneIPResourceInformation(IE_Base):
    name = "IE User Plane IP Resource Information"
    ie_type = 116
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare1", 0, 1),
        BitField("ASSOSI", 0, 1),
        BitField("ASSONI", 0, 1),
        BitField("TEIDRI", 0, 3),
        BitField("V6", 0, 1),
        BitField("V4", 0, 1),
        ConditionalField(XByteField("teid_range", 0), lambda x: x.TEIDRI != 0),
        ConditionalField(IPField("ipv4", 0), lambda x: x.V4 == 1),
        ConditionalField(IP6Field("ipv6", 0),
                         lambda x: x.V6 == 1),
        ConditionalField(
            APNStrLenField("network_instance", "",
                           length_from=lambda x:
                           x.length - 1 - (1 if x.TEIDRI != 0 else 0) -
                           (x.V4 * 4) - (x.V6 * 16) - x.ASSOSI),
            lambda x: x.ASSONI == 1),
        ConditionalField(
            XBitField("spare2", None, 4),
            lambda x: x.ASSOSI == 1),
        ConditionalField(
            BitEnumField("interface", "Access", 4, SourceInterface),
            lambda x: x.ASSOSI == 1),
        ExtraDataField("extra_data"),
    ]


class IE_UserPlaneInactivityTimer(IE_Base):
    name = "IE User Plane Inactivity Timer"
    ie_type = 117
    fields_desc = IE_Base.fields_desc + [
        IntField("timer", 0),
        ExtraDataField("extra_data"),
    ]


class IE_Multiplier(IE_Base):
    name = "IE Multiplier"
    ie_type = 119
    fields_desc = IE_Base.fields_desc + [
        SignedLongField("digits", 0),
        SignedIntField("exponent", 0),
    ]


class IE_AggregatedURR_Id(IE_Base):
    name = "IE Aggregated URR ID"
    ie_type = 120
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
    ]


class IE_SubsequentVolumeQuota(IE_Base):
    name = "IE Subsequent Volume Quota"
    ie_type = 121
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("DLVOL", 0, 1),
        BitField("ULVOL", 0, 1),
        BitField("TOVOL", 0, 1),
        ConditionalField(XLongField("total", 0), lambda x: x.TOVOL == 1),
        ConditionalField(XLongField("uplink", 0), lambda x: x.ULVOL == 1),
        ConditionalField(XLongField("downlink", 0), lambda x: x.DLVOL == 1),
        ExtraDataField("extra_data"),
    ]


class IE_SubsequentTimeQuota(IE_Base):
    name = "IE Subsequent Time Quota"
    ie_type = 122
    fields_desc = IE_Base.fields_desc + [
        IntField("quota", 0),
        ExtraDataField("extra_data"),
    ]


class IE_RQI(IE_Base):
    name = "IE RQI"
    ie_type = 123
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 7),
        BitField("RQI", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_QFI(IE_Base):
    name = "IE QFI"
    ie_type = 124
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", None, 2),
        BitField("QFI", 0, 6),
        ExtraDataField("extra_data"),
    ]


class IE_QueryURRReference(IE_Base):
    name = "IE Query URR Reference"
    ie_type = 125
    fields_desc = IE_Base.fields_desc + [
        IntField("reference", 0),
        ExtraDataField("extra_data"),
    ]


class IE_AdditionalUsageReportsInformation(IE_Base):
    name = "IE Additional Usage Reports Information"
    ie_type = 126
    fields_desc = IE_Base.fields_desc + [
        BitField("AURI", 0, 1),
        BitField("reports", 0, 15),
        ExtraDataField("extra_data"),
    ]


class IE_TrafficEndpointId(IE_Base):
    name = "IE Traffic Endpoint ID"
    ie_type = 131
    fields_desc = IE_Base.fields_desc + [
        ByteField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_MACAddress(IE_Base):
    name = "IE MAC Address"
    ie_type = 133
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitField("UDES", 0, 1),
        BitField("USOU", 0, 1),
        BitField("DEST", 0, 1),
        BitField("SOUR", 0, 1),
        ConditionalField(MACField("source_mac", 0),
                         lambda x: x.SOUR == 1),
        ConditionalField(MACField("destination_mac", 0),
                         lambda x: x.DEST == 1),
        ConditionalField(MACField("upper_source_mac", 0),
                         lambda x: x.USOU == 1),
        ConditionalField(MACField("upper_destination_mac", 0),
                         lambda x: x.UDES == 1),
        ExtraDataField("extra_data"),
    ]


class IE_C_TAG(IE_Base):
    name = "IE C-TAG"
    ie_type = 134
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", 0, 5),
        BitField("VID", 0, 1),
        BitField("DEI", 0, 1),
        BitField("PCP", 0, 1),
        # TODO: fix cvid_value
        ConditionalField(
            BitField("cvid_value_hi", 0, 4), lambda x: x.VID == 1),
        ConditionalField(BitField("spare_2", 0, 4), lambda x: x.VID == 0),
        ConditionalField(BitField("dei_flag", 0, 1), lambda x: x.DEI == 1),
        ConditionalField(BitField("spare_3", 0, 1), lambda x: x.DEI == 0),
        ConditionalField(BitField("pcp_value", 0, 3), lambda x: x.PCP == 1),
        ConditionalField(BitField("spare_4", 0, 3), lambda x: x.PCP == 0),
        ConditionalField(ByteField("cvid_value_low", 0),
                         lambda x: x.VID == 1),
        ConditionalField(ByteField("spare_5", 0), lambda x: x.VID == 0),
        ExtraDataField("extra_data"),
    ]


class IE_S_TAG(IE_Base):
    name = "IE S-TAG"
    ie_type = 135
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", 0, 5),
        BitField("VID", 0, 1),
        BitField("DEI", 0, 1),
        BitField("PCP", 0, 1),
        # TODO: fix svid_value
        ConditionalField(BitField("svid_value_hi", 0, 4),
                         lambda x: x.VID == 1),
        ConditionalField(BitField("spare_2", 0, 4), lambda x: x.VID == 0),
        ConditionalField(BitField("dei_flag", 0, 1), lambda x: x.DEI == 1),
        ConditionalField(BitField("spare_3", 0, 1), lambda x: x.DEI == 0),
        ConditionalField(BitField("pcp_value", 0, 3), lambda x: x.PCP == 1),
        ConditionalField(BitField("spare_4", 0, 3), lambda x: x.PCP == 0),
        ConditionalField(ByteField("svid_value_low", 0),
                         lambda x: x.VID == 1),
        ConditionalField(ByteField("spare_5", 0), lambda x: x.VID == 0),
        ExtraDataField("extra_data"),
    ]


class IE_Ethertype(IE_Base):
    name = "IE Ethertype"
    ie_type = 136
    fields_desc = IE_Base.fields_desc + [
        ShortField("type", 0),
        ExtraDataField("extra_data"),
    ]


class IE_Proxying(IE_Base):
    name = "IE Proxying"
    ie_type = 137
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 6),
        BitField("INS", 0, 1),
        BitField("ARP", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_EthernetFilterId(IE_Base):
    name = "IE Ethernet Filter ID"
    ie_type = 138
    fields_desc = IE_Base.fields_desc + [
        IntField("id", 0),
        ExtraDataField("extra_data"),
    ]


class IE_EthernetFilterProperties(IE_Base):
    name = "IE Ethernet Filter Properties"
    ie_type = 139
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 7),
        BitField("BIDE", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_SuggestedBufferingPacketsCount(IE_Base):
    name = "IE Suggested Buffering Packets Count"
    ie_type = 140
    fields_desc = IE_Base.fields_desc + [
        ByteField("count", 0),
        ExtraDataField("extra_data"),
    ]


class IE_UserId(IE_Base):
    name = "IE User ID"
    ie_type = 141
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 4),
        BitField("NAIF", 0, 1),
        BitField("MSISDNF", 0, 1),
        BitField("IMEIF", 0, 1),
        BitField("IMSIF", 0, 1),
        ConditionalField(
            FieldLenField("imsi_length", None, length_of="imsi", fmt="B"),
            lambda x: x.IMSIF == 1),
        ConditionalField(
            StrLenField("imsi", "", length_from=lambda x: x.imsi_length),
            lambda x: x.IMSIF == 1),
        ConditionalField(
            FieldLenField("imei_length", None, length_of="imei", fmt="B"),
            lambda x: x.IMEIF == 1),
        ConditionalField(
            StrLenField("imei", "", length_from=lambda x: x.imei_length),
            lambda x: x.IMEIF == 1),
        ConditionalField(
            FieldLenField("msisdn_length", None, length_of="msisdn", fmt="B"),
            lambda x: x.MSISDNF == 1),
        ConditionalField(
            StrLenField("msisdn", "", length_from=lambda x: x.msisdn_length),
            lambda x: x.MSISDNF == 1),
        ConditionalField(
            FieldLenField("nai_length", None, length_of="nai", fmt="B"),
            lambda x: x.NAIF == 1),
        ConditionalField(
            StrLenField("nai", "", length_from=lambda x: x.nai_length),
            lambda x: x.NAIF == 1),
        ExtraDataField("extra_data"),
    ]


class IE_EthernetPDUSessionInformation(IE_Base):
    name = "IE Ethernet PDU Session Information"
    ie_type = 142
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 7),
        BitField("ETHI", 0, 1),
        ExtraDataField("extra_data"),
    ]


class IE_MACAddressesDetected(IE_Base):
    name = "IE MAC Addresses Detected"
    ie_type = 144
    fields_desc = IE_Base.fields_desc + [
        FieldLenField("num_macs", None, count_of="macs", fmt="B"),
        FieldListField("macs", None, MACField("mac", 0),
                       count_from=lambda x: x.num_macs),
        ExtraDataField("extra_data"),
    ]


class IE_MACAddressesRemoved(IE_Base):
    name = "IE MAC Addresses Removed"
    ie_type = 145
    fields_desc = IE_Base.fields_desc + [
        FieldLenField("num_macs", None, count_of="macs", fmt="B"),
        FieldListField("macs", None, MACField("mac", 0),
                       count_from=lambda x: x.num_macs),
        ExtraDataField("extra_data"),
    ]


class IE_EthernetInactivityTimer(IE_Base):
    name = "IE Ethernet Inactivity Timer"
    ie_type = 146
    fields_desc = IE_Base.fields_desc + [
        IntField("timer", 0),
        ExtraDataField("extra_data"),
    ]


class IE_EventQuota(IE_Base):
    name = "IE Event Quota"
    ie_type = 148
    fields_desc = IE_Base.fields_desc + [
        IntField("event_quota", 0),
        ExtraDataField("extra_data"),
    ]


class IE_EventThreshold(IE_Base):
    name = "IE Event Threshold"
    ie_type = 149
    fields_desc = IE_Base.fields_desc + [
        IntField("event_threshold", 0),
        ExtraDataField("extra_data"),
    ]


class IE_SubsequentEventQuota(IE_Base):
    name = "IE Subsequent Event Quota"
    ie_type = 150
    fields_desc = IE_Base.fields_desc + [
        IntField("subsequent_event_quota", 0),
        ExtraDataField("extra_data"),
    ]


class IE_SubsequentEventThreshold(IE_Base):
    name = "IE Subsequent Event Threshold"
    ie_type = 151
    fields_desc = IE_Base.fields_desc + [
        IntField("subsequent_event_threshold", 0),
        ExtraDataField("extra_data"),
    ]


class IE_TraceInformation(IE_Base):
    # TODO: more detailed decoding
    # TODO: fix IP address handling
    name = "IE Trace Information"
    ie_type = 152
    fields_desc = IE_Base.fields_desc + [
        BitField("mcc_digit_2", 0, 4),
        BitField("mcc_digit_1", 0, 4),
        BitField("mnc_digit_3", 0, 4),
        BitField("mcc_digit_3", 0, 4),
        BitField("mnc_digit_2", 0, 4),
        BitField("mnc_digit_1", 0, 4),
        ThreeBytesField("trace_id", 0),  # FIXME
        FieldLenField("triggering_events_length", None,
                      length_of="triggering_events", fmt="B"),
        StrLenField("triggering_events", "",
                    length_from=lambda x: x.triggering_events_length),
        ByteField("session_trace_depth", 0),
        FieldLenField("list_of_interfaces_length", None,
                      length_of="list_of_interfaces", fmt="B"),
        StrLenField("list_of_interfaces", "",
                    length_from=lambda x: x.list_of_interfaces_length),
        FieldLenField("ip_address_length", None,
                      length_of="ip_address", fmt="B"),
        StrLenField("ip_address", "",
                    length_from=lambda x: x.ip_address_length),
        ExtraDataField("extra_data"),
    ]


class IE_FramedRoute(IE_Base):
    name = "IE Framed-Route"
    ie_type = 153
    fields_desc = IE_Base.fields_desc + [
        StrLenField("framed_route", "", length_from=lambda x: x.length)
    ]


class IE_FramedRouting(IE_Base):
    name = "IE Framed-Routing"
    ie_type = 154
    fields_desc = IE_Base.fields_desc + [
        StrLenField("framed_routing", "", length_from=lambda x: x.length)
    ]


class IE_FramedIPv6Route(IE_Base):
    name = "IE Framed-IPv6-Route"
    ie_type = 155
    fields_desc = IE_Base.fields_desc + [
        StrLenField("framed_ipv6_route", "", length_from=lambda x: x.length)
    ]


class IE_EventTimeStamp(IE_Base):
    name = "IE Event Time Stamp"
    ie_type = 156
    fields_desc = IE_Base.fields_desc + [
        IntField("timestamp", 0),
        ExtraDataField("extra_data"),
    ]


class IE_AveragingWindow(IE_Base):
    name = "IE Averaging Window"
    ie_type = 157
    fields_desc = IE_Base.fields_desc + [
        IntField("averaging_window", 0),
        ExtraDataField("extra_data"),
    ]


class IE_PagingPolicyIndicator(IE_Base):
    name = "IE Paging Policy Indicator"
    ie_type = 158
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare", 0, 5),
        BitField("ppi", 0, 3),
        ExtraDataField("extra_data"),
    ]


class IE_APN_DNN(IE_Base):
    name = "IE APN/DNN"
    ie_type = 159
    fields_desc = IE_Base.fields_desc + [
        APNStrLenField("apn_dnn", "", length_from=lambda x: x.length)
    ]


class IE_3GPP_InterfaceType(IE_Base):
    name = "IE 3GPP Interface Type"
    ie_type = 160
    fields_desc = IE_Base.fields_desc + [
        XBitField("spare_1", 0, 2),
        BitEnumField("interface_type", "S1-U", 6, InterfaceType),
        ExtraDataField("extra_data"),
    ]


class IE_EnterpriseSpecific(IE_Base):
    name = "Enterpise Specific"
    ie_type = None
    fields_desc = IE_Base.fields_desc + [
        ShortEnumField("enterprise_id", None, IANA_ENTERPRISE_NUMBERS),
        StrLenField("data", "", length_from=lambda x: x.length - 2),
    ]


class IE_NotImplemented(IE_Base):
    name = "IE not implemented"
    ie_type = 0
    fields_desc = IE_Base.fields_desc + [
        StrLenField("data", "", length_from=lambda x: x.length)
    ]


ietypecls = {
    1: IE_CreatePDR,
    2: IE_PDI,
    3: IE_CreateFAR,
    4: IE_ForwardingParameters,
    5: IE_DuplicatingParameters,
    6: IE_CreateURR,
    7: IE_CreateQER,
    8: IE_CreatedPDR,
    9: IE_UpdatePDR,
    10: IE_UpdateFAR,
    11: IE_UpdateForwardingParameters,
    12: IE_UpdateBAR_SRR,
    13: IE_UpdateURR,
    14: IE_UpdateQER,
    15: IE_RemovePDR,
    16: IE_RemoveFAR,
    17: IE_RemoveURR,
    18: IE_RemoveQER,
    19: IE_Cause,
    20: IE_SourceInterface,
    21: IE_FTEID,
    22: IE_NetworkInstance,
    23: IE_SDF_Filter,
    24: IE_ApplicationId,
    25: IE_GateStatus,
    26: IE_MBR,
    27: IE_GBR,
    28: IE_QERCorrelationId,
    29: IE_Precedence,
    30: IE_TransportLevelMarking,
    31: IE_VolumeThreshold,
    32: IE_TimeThreshold,
    33: IE_MonitoringTime,
    34: IE_SubsequentVolumeThreshold,
    35: IE_SubsequentTimeThreshold,
    36: IE_InactivityDetectionTime,
    37: IE_ReportingTriggers,
    38: IE_RedirectInformation,
    39: IE_ReportType,
    40: IE_OffendingIE,
    41: IE_ForwardingPolicy,
    42: IE_DestinationInterface,
    43: IE_UPFunctionFeatures,
    44: IE_ApplyAction,
    45: IE_DownlinkDataServiceInformation,
    46: IE_DownlinkDataNotificationDelay,
    47: IE_DLBufferingDuration,
    48: IE_DLBufferingSuggestedPacketCount,
    49: IE_PFCPSMReqFlags,
    50: IE_PFCPSRRspFlags,
    51: IE_LoadControlInformation,
    52: IE_SequenceNumber,
    53: IE_Metric,
    54: IE_OverloadControlInformation,
    55: IE_Timer,
    56: IE_PDR_Id,
    57: IE_FSEID,
    58: IE_ApplicationID_PFDs,
    59: IE_PFDContext,
    60: IE_NodeId,
    61: IE_PFDContents,
    62: IE_MeasurementMethod,
    63: IE_UsageReportTrigger,
    64: IE_MeasurementPeriod,
    65: IE_FqCSID,
    66: IE_VolumeMeasurement,
    67: IE_DurationMeasurement,
    68: IE_ApplicationDetectionInformation,
    69: IE_TimeOfFirstPacket,
    70: IE_TimeOfLastPacket,
    71: IE_QuotaHoldingTime,
    72: IE_DroppedDLTrafficThreshold,
    73: IE_VolumeQuota,
    74: IE_TimeQuota,
    75: IE_StartTime,
    76: IE_EndTime,
    77: IE_QueryURR,
    78: IE_UsageReport_SMR,
    79: IE_UsageReport_SDR,
    80: IE_UsageReport_SRR,
    81: IE_URR_Id,
    82: IE_LinkedURR_Id,
    83: IE_DownlinkDataReport,
    84: IE_OuterHeaderCreation,
    85: IE_Create_BAR,
    86: IE_Update_BAR_SMR,
    87: IE_Remove_BAR,
    88: IE_BAR_Id,
    89: IE_CPFunctionFeatures,
    90: IE_UsageInformation,
    91: IE_ApplicationInstanceId,
    92: IE_FlowInformation,
    93: IE_UE_IP_Address,
    94: IE_PacketRate,
    95: IE_OuterHeaderRemoval,
    96: IE_RecoveryTimeStamp,
    97: IE_DLFlowLevelMarking,
    98: IE_HeaderEnrichment,
    99: IE_ErrorIndicationReport,
    100: IE_MeasurementInformation,
    101: IE_NodeReportType,
    102: IE_UserPlanePathFailureReport,
    103: IE_RemoteGTP_U_Peer,
    104: IE_UR_SEQN,
    105: IE_UpdateDuplicatingParameters,
    106: IE_ActivatePredefinedRules,
    107: IE_DeactivatePredefinedRules,
    108: IE_FAR_Id,
    109: IE_QER_Id,
    110: IE_OCIFlags,
    111: IE_PFCPAssociationReleaseRequest,
    112: IE_GracefulReleasePeriod,
    113: IE_PDNType,
    114: IE_FailedRuleId,
    115: IE_TimeQuotaMechanism,
    116: IE_UserPlaneIPResourceInformation,
    117: IE_UserPlaneInactivityTimer,
    118: IE_AggregatedURRs,
    119: IE_Multiplier,
    120: IE_AggregatedURR_Id,
    121: IE_SubsequentVolumeQuota,
    122: IE_SubsequentTimeQuota,
    123: IE_RQI,
    124: IE_QFI,
    125: IE_QueryURRReference,
    126: IE_AdditionalUsageReportsInformation,
    127: IE_CreateTrafficEndpoint,
    128: IE_CreatedTrafficEndpoint,
    129: IE_UpdateTrafficEndpoint,
    130: IE_RemoveTrafficEndpoint,
    131: IE_TrafficEndpointId,
    132: IE_EthernetPacketFilter,
    133: IE_MACAddress,
    134: IE_C_TAG,
    135: IE_S_TAG,
    136: IE_Ethertype,
    137: IE_Proxying,
    138: IE_EthernetFilterId,
    139: IE_EthernetFilterProperties,
    140: IE_SuggestedBufferingPacketsCount,
    141: IE_UserId,
    142: IE_EthernetPDUSessionInformation,
    143: IE_EthernetTrafficInformation,
    144: IE_MACAddressesDetected,
    145: IE_MACAddressesRemoved,
    146: IE_EthernetInactivityTimer,
    147: IE_AdditionalMonitoringTime,
    148: IE_EventQuota,
    149: IE_EventThreshold,
    150: IE_SubsequentEventQuota,
    151: IE_SubsequentEventThreshold,
    152: IE_TraceInformation,
    153: IE_FramedRoute,
    154: IE_FramedRouting,
    155: IE_FramedIPv6Route,
    156: IE_EventTimeStamp,
    157: IE_AveragingWindow,
    158: IE_PagingPolicyIndicator,
    159: IE_APN_DNN,
    160: IE_3GPP_InterfaceType,
}


#
# PFCP Messages
# 3GPP TS 29.244 V15.6.0 (2019-07)
#

# class PFCPMessage(Packet):
#     fields_desc = [PacketListField("IE_list", None, IE_Dispatcher)]


class PFCPHeartbeatRequest(Packet):
    name = "PFCP Heartbeat Request"
    fields_desc = [
        PacketListField("IE_list", [IE_RecoveryTimeStamp()], IE_Dispatcher)
    ]


class PFCPHeartbeatResponse(Packet):
    name = "PFCP Heartbeat Response"
    fields_desc = [
        PacketListField("IE_list", [IE_RecoveryTimeStamp()], IE_Dispatcher)
    ]

    def answers(self, other):
        return isinstance(other, PFCPHeartbeatRequest)


class PFCPPFDManagementRequest(Packet):
    name = "PFCP PFD Management Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPPFDManagementResponse(Packet):
    name = "PFCP PFD Management Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPPFDManagementRequest)


class PFCPAssociationSetupRequest(Packet):
    name = "PFCP Association Setup Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationSetupResponse(Packet):
    name = "PFCP Association Setup Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPAssociationSetupRequest)


class PFCPAssociationUpdateRequest(Packet):
    name = "PFCP Association Update Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationUpdateResponse(Packet):
    name = "PFCP Association Update Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPAssociationUpdateRequest)


class PFCPAssociationReleaseRequest(Packet):
    name = "PFCP Association Release Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationReleaseResponse(Packet):
    name = "PFCP Association Release Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPAssociationReleaseRequest)


class PFCPVersionNotSupportedResponse(Packet):
    name = "PFCP Version Not Supported Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]
    # TODO: answers()


class PFCPNodeReportRequest(Packet):
    name = "PFCP Node Report Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPNodeReportResponse(Packet):
    name = "PFCP Node Report Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPNodeReportRequest)


class PFCPSessionSetDeletionRequest(Packet):
    name = "PFCP Session Set Deletion Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionSetDeletionResponse(Packet):
    name = "PFCP Session Set Deletion Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPSessionSetDeletionRequest)


class PFCPSessionEstablishmentRequest(Packet):
    name = "PFCP Session Establishment Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionEstablishmentResponse(Packet):
    name = "PFCP Session Establishment Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPSessionEstablishmentRequest)


class PFCPSessionModificationRequest(Packet):
    name = "PFCP Session Modification Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionModificationResponse(Packet):
    name = "PFCP Session Modification Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPSessionModificationRequest)


class PFCPSessionDeletionRequest(Packet):
    name = "PFCP Session Deletion Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionDeletionResponse(Packet):
    name = "PFCP Session Deletion Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPSessionDeletionRequest)


class PFCPSessionReportRequest(Packet):
    name = "PFCP Session Report Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionReportResponse(Packet):
    name = "PFCP Session Report Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return isinstance(other, PFCPSessionReportRequest)


bind_bottom_up(UDP, PFCP, dport=8805)
bind_bottom_up(UDP, PFCP, sport=8805)
bind_layers(UDP, PFCP, dport=8805, sport=8805)
bind_layers(PFCP, PFCPHeartbeatRequest, message_type=1)
bind_layers(PFCP, PFCPHeartbeatResponse, message_type=2)
bind_layers(PFCP, PFCPPFDManagementRequest, message_type=3)
bind_layers(PFCP, PFCPPFDManagementResponse, message_type=4)
bind_layers(PFCP, PFCPAssociationSetupRequest, message_type=5)
bind_layers(PFCP, PFCPAssociationSetupResponse, message_type=6)
bind_layers(PFCP, PFCPAssociationUpdateRequest, message_type=7)
bind_layers(PFCP, PFCPAssociationUpdateResponse, message_type=8)
bind_layers(PFCP, PFCPAssociationReleaseRequest, message_type=9)
bind_layers(PFCP, PFCPAssociationReleaseResponse, message_type=10)
bind_layers(PFCP, PFCPVersionNotSupportedResponse, message_type=11)
bind_layers(PFCP, PFCPNodeReportRequest, message_type=12)
bind_layers(PFCP, PFCPNodeReportResponse, message_type=13)
bind_layers(PFCP, PFCPSessionSetDeletionRequest, message_type=14)
bind_layers(PFCP, PFCPSessionSetDeletionResponse, message_type=15)
bind_layers(PFCP, PFCPSessionEstablishmentRequest, message_type=50)
bind_layers(PFCP, PFCPSessionEstablishmentResponse, message_type=51)
bind_layers(PFCP, PFCPSessionModificationRequest, message_type=52)
bind_layers(PFCP, PFCPSessionModificationResponse, message_type=53)
bind_layers(PFCP, PFCPSessionDeletionRequest, message_type=54)
bind_layers(PFCP, PFCPSessionDeletionResponse, message_type=55)
bind_layers(PFCP, PFCPSessionReportRequest, message_type=56)
bind_layers(PFCP, PFCPSessionReportResponse, message_type=57)

# FIXME: the following fails with pfcplib-generated pcaps:
# bind_layers(PFCP, PFCPSessionEstablishmentRequest, message_type=50, S=1)
# bind_layers(PFCP, PFCPSessionEstablishmentResponse, message_type=51, S=1)
# bind_layers(PFCP, PFCPSessionModificationRequest, message_type=52, S=1)
# bind_layers(PFCP, PFCPSessionModificationResponse, message_type=53, S=1)
# bind_layers(PFCP, PFCPSessionDeletionRequest, message_type=54, S=1)
# bind_layers(PFCP, PFCPSessionDeletionResponse, message_type=55, S=1)
# bind_layers(PFCP, PFCPSessionReportRequest, message_type=56, S=1)
# bind_layers(PFCP, PFCPSessionReportResponse, message_type=57, S=1)

# TODO: limit possible child IEs based on IE type

IE_UE_IP_Address(SD=0, V4=0, V6=0, spare=0)
