# Copyright (C) 2018 Leonardo Monteiro <decastromonteiro@gmail.com>
#               2017 Alexis Sultan    <alexis.sultan@sfr.com>
#               2017 Alessio Deiana <adeiana@gmail.com>
#               2014 Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
#               2012 ffranz <ffranz@iniqua.com>
##
# This program is published under a GPLv2 license

# scapy.contrib.description = GPRS Tunneling Protocol (GTP)
# scapy.contrib.status = loads

from __future__ import absolute_import
import struct


from scapy.compat import chb, orb, bytes_encode
from scapy.error import warning
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, FieldLenField, FieldListField, FlagsField, IntField, \
    IPField, PacketListField, ShortField, StrFixedLenField, StrLenField, \
    XBitField, XByteField, XIntField
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IP6Field
from scapy.layers.ppp import PPP
from scapy.modules.six.moves import range
from scapy.packet import bind_layers, bind_bottom_up, bind_top_down, \
    Packet, Raw
from scapy.volatile import RandInt, RandIP, RandNum, RandString


# GTP Data types

RATType = {
    1: "UTRAN",
    2: "GETRAN",
    3: "WLAN",
    4: "GAN",
    5: "HSPA"
}

GTPmessageType = {1: "echo_request",
                  2: "echo_response",
                  16: "create_pdp_context_req",
                  17: "create_pdp_context_res",
                  18: "update_pdp_context_req",
                  19: "update_pdp_context_resp",
                  20: "delete_pdp_context_req",
                  21: "delete_pdp_context_res",
                  26: "error_indication",
                  27: "pdu_notification_req",
                  31: "supported_extension_headers_notification",
                  254: "end_marker",
                  255: "g_pdu"}

IEType = {1: "Cause",
             2: "IMSI",
             3: "RAI",
             4: "TLLI",
             5: "P_TMSI",
             8: "IE_ReorderingRequired",
          14: "Recovery",
          15: "SelectionMode",
          16: "TEIDI",
          17: "TEICP",
          19: "TeardownInd",
          20: "NSAPI",
          26: "ChargingChrt",
          27: "TraceReference",
          28: "TraceType",
          127: "ChargingId",
          128: "EndUserAddress",
          131: "AccessPointName",
          132: "ProtocolConfigurationOptions",
          133: "GSNAddress",
          134: "MSInternationalNumber",
          135: "QoS",
          148: "CommonFlags",
          149: "APNRestriction",
          151: "RatType",
          152: "UserLocationInformation",
          153: "MSTimeZone",
          154: "IMEI",
          181: "MSInfoChangeReportingAction",
          184: "BearerControlMode",
          191: "EvolvedAllocationRetentionPriority",
          255: "PrivateExtention"}

CauseValues = {0: "Request IMSI",
               1: "Request IMEI",
               2: "Request IMSI and IMEI",
               3: "No identity needed",
               4: "MS Refuses",
               5: "MS is not GPRS Responding",
               128: "Request accepted",
               129: "New PDP type due to network preference",
               130: "New PDP type due to single address bearer only",
               192: "Non-existent",
               193: "Invalid message format",
               194: "IMSI not known",
               195: "MS is GPRS Detached",
               196: "MS is not GPRS Responding",
               197: "MS Refuses",
               198: "Version not supported",
               199: "No resources available",
               200: "Service not supported",
               201: "Mandatory IE incorrect",
               202: "Mandatory IE missing",
               203: "Optional IE incorrect",
               204: "System failure",
               205: "Roaming restriction",
               206: "P-TMSI Signature mismatch",
               207: "GPRS connection suspended",
               208: "Authentication failure",
               209: "User authentication failed",
               210: "Context not found",
               211: "All dynamic PDP addresses are occupied",
               212: "No memory is available",
               213: "Reallocation failure",
               214: "Unknown mandatory extension header",
               215: "Semantic error in the TFT operation",
               216: "Syntactic error in TFT operation",
               217: "Semantic errors in packet filter(s)",
               218: "Syntactic errors in packet filter(s)",
               219: "Missing or unknown APN",
               220: "Unknown PDP address or PDP type",
               221: "PDP context without TFT already activated",
               222: "APN access denied : no subscription",
               223: "APN Restriction type incompatibility with currently active PDP Contexts",  # noqa: E501
               224: "MS MBMS Capabilities Insufficient",
               225: "Invalid Correlation : ID",
               226: "MBMS Bearer Context Superseded",
               227: "Bearer Control Mode violation",
               228: "Collision with network initiated request"}

Selection_Mode = {11111100: "MS or APN",
                  11111101: "MS",
                  11111110: "NET",
                  11111111: "FutureUse"}

TrueFalse_value = {254: "False",
                   255: "True"}

# http://www.arib.or.jp/IMT-2000/V720Mar09/5_Appendix/Rel8/29/29281-800.pdf
ExtensionHeadersTypes = {
    0: "No more extension headers",
    1: "Reserved",
    2: "Reserved",
    64: "UDP Port",
    133: "PDU Session Container",
    192: "PDCP PDU Number",
    193: "Reserved",
    194: "Reserved"
}


class TBCDByteField(StrFixedLenField):

    def i2h(self, pkt, val):
        return val

    def m2i(self, pkt, val):
        ret = []
        for v in val:
            byte = orb(v)
            left = byte >> 4
            right = byte & 0xf
            if left == 0xf:
                ret.append(TBCD_TO_ASCII[right:right + 1])
            else:
                ret += [
                    TBCD_TO_ASCII[right:right + 1],
                    TBCD_TO_ASCII[left:left + 1]
                ]
        return b"".join(ret)

    def i2m(self, pkt, val):
        if not isinstance(val, bytes):
            val = bytes_encode(val)
        ret_string = b""
        for i in range(0, len(val), 2):
            tmp = val[i:i + 2]
            if len(tmp) == 2:
                ret_string += chb(int(tmp[::-1], 16))
            else:
                ret_string += chb(int(b"F" + tmp[:1], 16))
        return ret_string


TBCD_TO_ASCII = b"0123456789*#abc"


class GTP_ExtensionHeader(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return GTP_UDPPort_ExtensionHeader
        return cls


class GTP_UDPPort_ExtensionHeader(GTP_ExtensionHeader):
    fields_desc = [ByteField("length", 0x40),
                   ShortField("udp_port", None),
                   ByteEnumField("next_ex", 0, ExtensionHeadersTypes), ]


class GTP_PDCP_PDU_ExtensionHeader(GTP_ExtensionHeader):
    fields_desc = [ByteField("length", 0x01),
                   ShortField("pdcp_pdu", None),
                   ByteEnumField("next_ex", 0, ExtensionHeadersTypes), ]


class GTPHeader(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP-C Header"
    fields_desc = [BitField("version", 1, 3),
                   BitField("PT", 1, 1),
                   BitField("reserved", 0, 1),
                   BitField("E", 0, 1),
                   BitField("S", 0, 1),
                   BitField("PN", 0, 1),
                   ByteEnumField("gtp_type", None, GTPmessageType),
                   ShortField("length", None),
                   IntField("teid", 0),
                   ConditionalField(XBitField("seq", 0, 16), lambda pkt:pkt.E == 1 or pkt.S == 1 or pkt.PN == 1),  # noqa: E501
                   ConditionalField(ByteField("npdu", 0), lambda pkt:pkt.E == 1 or pkt.S == 1 or pkt.PN == 1),  # noqa: E501
                   ConditionalField(ByteEnumField("next_ex", 0, ExtensionHeadersTypes), lambda pkt:pkt.E == 1 or pkt.S == 1 or pkt.PN == 1), ]  # noqa: E501

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            tmp_len = len(p) - 8
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p

    def hashret(self):
        return struct.pack("B", self.version) + self.payload.hashret()

    def answers(self, other):
        return (isinstance(other, GTPHeader) and
                self.version == other.version and
                self.payload.answers(other.payload))

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            if (orb(_pkt[0]) >> 5) & 0x7 == 2:
                from . import gtp_v2
                return gtp_v2.GTPHeader
        if _pkt and len(_pkt) >= 8:
            _gtp_type = orb(_pkt[1:2])
            return GTPforcedTypes.get(_gtp_type, GTPHeader)
        return cls


class GTP_U_Header(GTPHeader):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP-U Header"
    # GTP-U protocol is used to transmit T-PDUs between GSN pairs (or between an SGSN and an RNC in UMTS),  # noqa: E501
    # encapsulated in G-PDUs. A G-PDU is a packet including a GTP-U header and a T-PDU. The Path Protocol  # noqa: E501
    # defines the path and the GTP-U header defines the tunnel. Several tunnels may be multiplexed on a single path.  # noqa: E501

    def guess_payload_class(self, payload):
        # Snooped from Wireshark
        # https://github.com/boundary/wireshark/blob/07eade8124fd1d5386161591b52e177ee6ea849f/epan/dissectors/packet-gtp.c#L8195  # noqa: E501
        if self.E == 1:
            if self.next_ex == 0x85:
                return GTPPDUSessionContainer
            return GTPHeader.guess_payload_class(self, payload)

        if self.gtp_type == 255:
            sub_proto = orb(payload[0])
            if sub_proto >= 0x45 and sub_proto <= 0x4e:
                return IP
            elif (sub_proto & 0xf0) == 0x60:
                return IPv6
            else:
                return PPP
        return GTPHeader.guess_payload_class(self, payload)


# Some gtp_types have to be associated with a certain type of header
GTPforcedTypes = {
    16: GTPHeader,
    17: GTPHeader,
    18: GTPHeader,
    19: GTPHeader,
    20: GTPHeader,
    21: GTPHeader,
    26: GTP_U_Header,
    27: GTPHeader,
    254: GTP_U_Header,
    255: GTP_U_Header
}


class GTPPDUSessionContainer(Packet):
    name = "GTP PDU Session Container"
    fields_desc = [ByteField("ExtHdrLen", None),
                   BitField("type", 0, 4),
                   BitField("spare1", 0, 4),
                   BitField("P", 0, 1),
                   BitField("R", 0, 1),
                   BitField("QFI", 0, 6),
                   ConditionalField(XBitField("PPI", 0, 3),
                                    lambda pkt: pkt.P == 1),
                   ConditionalField(XBitField("spare2", 0, 5),
                                    lambda pkt: pkt.P == 1),
                   ConditionalField(ByteField("pad1", 0),
                                    lambda pkt: pkt.P == 1),
                   ConditionalField(ByteField("pad2", 0),
                                    lambda pkt: pkt.P == 1),
                   ConditionalField(ByteField("pad3", 0),
                                    lambda pkt: pkt.P == 1),
                   ByteEnumField("NextExtHdr", 0, ExtensionHeadersTypes), ]

    def guess_payload_class(self, payload):
        if self.NextExtHdr == 0:
            sub_proto = orb(payload[0])
            if sub_proto >= 0x45 and sub_proto <= 0x4e:
                return IP
            elif (sub_proto & 0xf0) == 0x60:
                return IPv6
            else:
                return PPP
        return GTPHeader.guess_payload_class(self, payload)

    def post_build(self, p, pay):
        p += pay
        if self.ExtHdrLen is None:
            if self.P == 1:
                hdr_len = 2
            else:
                hdr_len = 1
            p = struct.pack("!B", hdr_len) + p[1:]
        return p

    def hashret(self):
        return struct.pack("H", self.seq)


class GTPEchoRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Echo Request"

    def hashret(self):
        return struct.pack("H", self.seq)


class IE_Base(Packet):

    def extract_padding(self, pkt):
        return "", pkt


class IE_Cause(IE_Base):
    name = "Cause"
    fields_desc = [ByteEnumField("ietype", 1, IEType),
                   ByteEnumField("CauseValue", None, CauseValues)]


class IE_IMSI(IE_Base):
    name = "IMSI - Subscriber identity of the MS"
    fields_desc = [ByteEnumField("ietype", 2, IEType),
                   TBCDByteField("imsi", str(RandNum(0, 999999999999999)), 8)]


class IE_Routing(IE_Base):
    name = "Routing Area Identity"
    fields_desc = [ByteEnumField("ietype", 3, IEType),
                   TBCDByteField("MCC", "", 2),
                   # MNC: if the third digit of MCC is 0xf,
                   # then the length of MNC is 1 byte
                   TBCDByteField("MNC", "", 1),
                   ShortField("LAC", None),
                   ByteField("RAC", None)]


class IE_ReorderingRequired(IE_Base):
    name = "Recovery"
    fields_desc = [ByteEnumField("ietype", 8, IEType),
                   ByteEnumField("reordering_required", 254, TrueFalse_value)]


class IE_Recovery(IE_Base):
    name = "Recovery"
    fields_desc = [ByteEnumField("ietype", 14, IEType),
                   ByteField("restart_counter", 24)]


class IE_SelectionMode(IE_Base):
    # Indicates the origin of the APN in the message
    name = "Selection Mode"
    fields_desc = [ByteEnumField("ietype", 15, IEType),
                   BitEnumField("SelectionMode", "MS or APN",
                                8, Selection_Mode)]


class IE_TEIDI(IE_Base):
    name = "Tunnel Endpoint Identifier Data"
    fields_desc = [ByteEnumField("ietype", 16, IEType),
                   XIntField("TEIDI", RandInt())]


class IE_TEICP(IE_Base):
    name = "Tunnel Endpoint Identifier Control Plane"
    fields_desc = [ByteEnumField("ietype", 17, IEType),
                   XIntField("TEICI", RandInt())]


class IE_Teardown(IE_Base):
    name = "Teardown Indicator"
    fields_desc = [ByteEnumField("ietype", 19, IEType),
                   ByteEnumField("indicator", "True", TrueFalse_value)]


class IE_NSAPI(IE_Base):
    # Identifies a PDP context in a mobility management context specified by TEICP  # noqa: E501
    name = "NSAPI"
    fields_desc = [ByteEnumField("ietype", 20, IEType),
                   XBitField("sparebits", 0x0000, 4),
                   XBitField("NSAPI", RandNum(0, 15), 4)]


class IE_ChargingCharacteristics(IE_Base):
    # Way of informing both the SGSN and GGSN of the rules for
    name = "Charging Characteristics"
    fields_desc = [ByteEnumField("ietype", 26, IEType),
                   # producing charging information based on operator configured triggers.  # noqa: E501
                   #    0000 .... .... .... : spare
                   #    .... 1... .... .... : normal charging
                   #    .... .0.. .... .... : prepaid charging
                   #    .... ..0. .... .... : flat rate charging
                   #    .... ...0 .... .... : hot billing charging
                   #    .... .... 0000 0000 : reserved
                   XBitField("Ch_ChSpare", None, 4),
                   XBitField("normal_charging", None, 1),
                   XBitField("prepaid_charging", None, 1),
                   XBitField("flat_rate_charging", None, 1),
                   XBitField("hot_billing_charging", None, 1),
                   XBitField("Ch_ChReserved", 0, 8)]


class IE_TraceReference(IE_Base):
    # Identifies a record or a collection of records for a particular trace.
    name = "Trace Reference"
    fields_desc = [ByteEnumField("ietype", 27, IEType),
                   XBitField("Trace_reference", None, 16)]


class IE_TraceType(IE_Base):
    # Indicates the type of the trace
    name = "Trace Type"
    fields_desc = [ByteEnumField("ietype", 28, IEType),
                   XBitField("Trace_type", None, 16)]


class IE_ChargingId(IE_Base):
    name = "Charging ID"
    fields_desc = [ByteEnumField("ietype", 127, IEType),
                   XIntField("Charging_id", RandInt())]


class IE_EndUserAddress(IE_Base):
    # Supply protocol specific information of the external packet
    name = "End User Address"
    fields_desc = [ByteEnumField("ietype", 128, IEType),
                   #         data network accessed by the GGPRS subscribers.
                   #            - Request
                   #                1    Type (1byte)
                   #                2-3    Length (2bytes) - value 2
                   #                4    Spare + PDP Type Organization
                   #                5    PDP Type Number
                   #            - Response
                   #                6-n    PDP Address
                   ShortField("length", 2),
                   BitField("SPARE", 15, 4),
                   BitField("PDPTypeOrganization", 1, 4),
                   XByteField("PDPTypeNumber", None),
                   ConditionalField(IPField("PDPAddress", RandIP()),
                                    lambda pkt: pkt.length == 6 or pkt.length == 22),  # noqa: E501
                   ConditionalField(IP6Field("IPv6_PDPAddress", '::1'),
                                    lambda pkt: pkt.length == 18 or pkt.length == 22)]  # noqa: E501


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
        if not isinstance(s, bytes):
            s = bytes_encode(s)
        s = b"".join(chb(len(x)) + x for x in s.split(b"."))
        return s


class IE_AccessPointName(IE_Base):
    # Sent by SGSN or by GGSN as defined in 3GPP TS 23.060
    name = "Access Point Name"
    fields_desc = [ByteEnumField("ietype", 131, IEType),
                   ShortField("length", None),
                   APNStrLenField("APN", "nternet", length_from=lambda x: x.length)]  # noqa: E501

    def post_build(self, p, pay):
        if self.length is None:
            tmp_len = len(p) - 3
            p = p[:2] + struct.pack("!B", tmp_len) + p[3:]
        return p


class IE_ProtocolConfigurationOptions(IE_Base):
    name = "Protocol Configuration Options"
    fields_desc = [ByteEnumField("ietype", 132, IEType),
                   ShortField("length", 4),
                   StrLenField("Protocol_Configuration", "",
                               length_from=lambda x: x.length)]


class IE_GSNAddress(IE_Base):
    name = "GSN Address"
    fields_desc = [ByteEnumField("ietype", 133, IEType),
                   ShortField("length", None),
                   ConditionalField(IPField("ipv4_address", RandIP()),
                                    lambda pkt: pkt.length == 4),
                   ConditionalField(IP6Field("ipv6_address", '::1'),
                                    lambda pkt: pkt.length == 16)]

    def post_build(self, p, pay):
        if self.length is None:
            tmp_len = len(p) - 3
            p = p[:2] + struct.pack("!B", tmp_len) + p[3:]
        return p


class IE_MSInternationalNumber(IE_Base):
    name = "MS International Number"
    fields_desc = [ByteEnumField("ietype", 134, IEType),
                   ShortField("length", None),
                   FlagsField("flags", 0x91, 8, ["Extension", "", "", "International Number", "", "", "", "ISDN numbering"]),  # noqa: E501
                   TBCDByteField("digits", "33607080910", length_from=lambda x: x.length - 1)]  # noqa: E501


class QoS_Profile(IE_Base):
    name = "QoS profile"
    fields_desc = [ByteField("qos_ei", 0),
                   ByteField("length", None),
                   XBitField("spare", 0x00, 2),
                   XBitField("delay_class", 0x000, 3),
                   XBitField("reliability_class", 0x000, 3),
                   XBitField("peak_troughput", 0x0000, 4),
                   BitField("spare", 0, 1),
                   XBitField("precedence_class", 0x000, 3),
                   XBitField("spare", 0x000, 3),
                   XBitField("mean_troughput", 0x00000, 5),
                   XBitField("traffic_class", 0x000, 3),
                   XBitField("delivery_order", 0x00, 2),
                   XBitField("delivery_of_err_sdu", 0x000, 3),
                   ByteField("max_sdu_size", None),
                   ByteField("max_bitrate_up", None),
                   ByteField("max_bitrate_down", None),
                   XBitField("redidual_ber", 0x0000, 4),
                   XBitField("sdu_err_ratio", 0x0000, 4),
                   XBitField("transfer_delay", 0x00000, 5),
                   XBitField("traffic_handling_prio", 0x000, 3),
                   ByteField("guaranteed_bit_rate_up", None),
                   ByteField("guaranteed_bit_rate_down", None)]


class IE_QoS(IE_Base):
    name = "QoS"
    fields_desc = [ByteEnumField("ietype", 135, IEType),
                   ShortField("length", None),
                   ByteField("allocation_retention_prioiry", 1),

                   ConditionalField(XBitField("spare", 0x00, 2),
                                    lambda p: p.length and p.length > 1),
                   ConditionalField(XBitField("delay_class", 0x000, 3),
                                    lambda p: p.length and p.length > 1),
                   ConditionalField(XBitField("reliability_class", 0x000, 3),
                                    lambda p: p.length and p.length > 1),

                   ConditionalField(XBitField("peak_troughput", 0x0000, 4),
                                    lambda p: p.length and p.length > 2),
                   ConditionalField(BitField("spare", 0, 1),
                                    lambda p: p.length and p.length > 2),
                   ConditionalField(XBitField("precedence_class", 0x000, 3),
                                    lambda p: p.length and p.length > 2),

                   ConditionalField(XBitField("spare", 0x000, 3),
                                    lambda p: p.length and p.length > 3),
                   ConditionalField(XBitField("mean_troughput", 0x00000, 5),
                                    lambda p: p.length and p.length > 3),

                   ConditionalField(XBitField("traffic_class", 0x000, 3),
                                    lambda p: p.length and p.length > 4),
                   ConditionalField(XBitField("delivery_order", 0x00, 2),
                                    lambda p: p.length and p.length > 4),
                   ConditionalField(XBitField("delivery_of_err_sdu", 0x000, 3),
                                    lambda p: p.length and p.length > 4),

                   ConditionalField(ByteField("max_sdu_size", None),
                                    lambda p: p.length and p.length > 5),
                   ConditionalField(ByteField("max_bitrate_up", None),
                                    lambda p: p.length and p.length > 6),
                   ConditionalField(ByteField("max_bitrate_down", None),
                                    lambda p: p.length and p.length > 7),

                   ConditionalField(XBitField("redidual_ber", 0x0000, 4),
                                    lambda p: p.length and p.length > 8),
                   ConditionalField(XBitField("sdu_err_ratio", 0x0000, 4),
                                    lambda p: p.length and p.length > 8),
                   ConditionalField(XBitField("transfer_delay", 0x00000, 6),
                                    lambda p: p.length and p.length > 9),
                   ConditionalField(XBitField("traffic_handling_prio",
                                              0x000,
                                              2),
                                    lambda p: p.length and p.length > 9),

                   ConditionalField(ByteField("guaranteed_bit_rate_up", None),
                                    lambda p: p.length and p.length > 10),
                   ConditionalField(ByteField("guaranteed_bit_rate_down",
                                              None),
                                    lambda p: p.length and p.length > 11),

                   ConditionalField(XBitField("spare", 0x000, 3),
                                    lambda p: p.length and p.length > 12),
                   ConditionalField(BitField("signaling_indication", 0, 1),
                                    lambda p: p.length and p.length > 12),
                   ConditionalField(XBitField("source_stats_desc", 0x0000, 4),
                                    lambda p: p.length and p.length > 12),

                   ConditionalField(ByteField("max_bitrate_down_ext", None),
                                    lambda p: p.length and p.length > 13),
                   ConditionalField(ByteField("guaranteed_bitrate_down_ext",
                                              None),
                                    lambda p: p.length and p.length > 14),
                   ConditionalField(ByteField("max_bitrate_up_ext", None),
                                    lambda p: p.length and p.length > 15),
                   ConditionalField(ByteField("guaranteed_bitrate_up_ext",
                                              None),
                                    lambda p: p.length and p.length > 16),
                   ConditionalField(ByteField("max_bitrate_down_ext2", None),
                                    lambda p: p.length and p.length > 17),
                   ConditionalField(ByteField("guaranteed_bitrate_down_ext2",
                                              None),
                                    lambda p: p.length and p.length > 18),
                   ConditionalField(ByteField("max_bitrate_up_ext2", None),
                                    lambda p: p.length and p.length > 19),
                   ConditionalField(ByteField("guaranteed_bitrate_up_ext2",
                                              None),
                                    lambda p: p.length and p.length > 20)]


class IE_CommonFlags(IE_Base):
    name = "Common Flags"
    fields_desc = [ByteEnumField("ietype", 148, IEType),
                   ShortField("length", None),
                   BitField("dual_addr_bearer_fl", 0, 1),
                   BitField("upgrade_qos_supported", 0, 1),
                   BitField("nrsn", 0, 1),
                   BitField("no_qos_nego", 0, 1),
                   BitField("mbms_cnting_info", 0, 1),
                   BitField("ran_procedure_ready", 0, 1),
                   BitField("mbms_service_type", 0, 1),
                   BitField("prohibit_payload_compression", 0, 1)]


class IE_APNRestriction(IE_Base):
    name = "APN Restriction"
    fields_desc = [ByteEnumField("ietype", 149, IEType),
                   ShortField("length", 1),
                   ByteField("restriction_type_value", 0)]


class IE_RATType(IE_Base):
    name = "Rat Type"
    fields_desc = [ByteEnumField("ietype", 151, IEType),
                   ShortField("length", 1),
                   ByteEnumField("RAT_Type", None, RATType)]


class IE_UserLocationInformation(IE_Base):
    name = "User Location Information"
    fields_desc = [ByteEnumField("ietype", 152, IEType),
                   ShortField("length", None),
                   ByteField("type", 1),
                   # Only type 1 is currently supported
                   TBCDByteField("MCC", "", 2),
                   # MNC: if the third digit of MCC is 0xf, then the length of MNC is 1 byte  # noqa: E501
                   TBCDByteField("MNC", "", 1),
                   ShortField("LAC", None),
                   ShortField("SAC", None)]


class IE_MSTimeZone(IE_Base):
    name = "MS Time Zone"
    fields_desc = [ByteEnumField("ietype", 153, IEType),
                   ShortField("length", None),
                   ByteField("timezone", 0),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   XBitField("daylight_saving_time", 0x00, 2)]


class IE_IMEI(IE_Base):
    name = "IMEI"
    fields_desc = [ByteEnumField("ietype", 154, IEType),
                   ShortField("length", None),
                   TBCDByteField("IMEI", "", length_from=lambda x: x.length)]


class IE_MSInfoChangeReportingAction(IE_Base):
    name = "MS Info Change Reporting Action"
    fields_desc = [ByteEnumField("ietype", 181, IEType),
                   ShortField("length", 1),
                   ByteField("Action", 0)]


class IE_DirectTunnelFlags(IE_Base):
    name = "Direct Tunnel Flags"
    fields_desc = [ByteEnumField("ietype", 182, IEType),
                   ShortField("length", 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("EI", 0, 1),
                   BitField("GCSI", 0, 1),
                   BitField("DTI", 0, 1)]


class IE_BearerControlMode(IE_Base):
    name = "Bearer Control Mode"
    fields_desc = [ByteEnumField("ietype", 184, IEType),
                   ShortField("length", 1),
                   ByteField("bearer_control_mode", 0)]


class IE_EvolvedAllocationRetentionPriority(IE_Base):
    name = "Evolved Allocation/Retention Priority"
    fields_desc = [ByteEnumField("ietype", 191, IEType),
                   ShortField("length", 1),
                   BitField("Spare", 0, 1),
                   BitField("PCI", 0, 1),
                   XBitField("PL", 0x0000, 4),
                   BitField("Spare", 0, 1),
                   BitField("PVI", 0, 1)]


class IE_CharginGatewayAddress(IE_Base):
    name = "Chargin Gateway Address"
    fields_desc = [ByteEnumField("ietype", 251, IEType),
                   ShortField("length", 4),
                   ConditionalField(IPField("ipv4_address", "127.0.0.1"),
                                    lambda
                                    pkt: pkt.length == 4),
                   ConditionalField(IP6Field("ipv6_address", "::1"), lambda
                                    pkt: pkt.length == 16)]


class IE_PrivateExtension(IE_Base):
    name = "Private Extension"
    fields_desc = [ByteEnumField("ietype", 255, IEType),
                   ShortField("length", 1),
                   ByteField("extension identifier", 0),
                   StrLenField("extention_value", "",
                               length_from=lambda x: x.length)]


class IE_ExtensionHeaderList(IE_Base):
    name = "Extension Header List"
    fields_desc = [ByteEnumField("ietype", 141, IEType),
                   FieldLenField("length", None, length_of="extension_headers"),  # noqa: E501
                   FieldListField("extension_headers", [64, 192], ByteField("", 0))]  # noqa: E501


class IE_NotImplementedTLV(Packet):
    name = "IE not implemented"
    fields_desc = [ByteEnumField("ietype", 0, IEType),
                   ShortField("length", None),
                   StrLenField("data", "", length_from=lambda x: x.length)]

    def extract_padding(self, pkt):
        return "", pkt


ietypecls = {1: IE_Cause,
             2: IE_IMSI,
             3: IE_Routing,
             8: IE_ReorderingRequired,
             14: IE_Recovery,
             15: IE_SelectionMode,
             16: IE_TEIDI,
             17: IE_TEICP,
             19: IE_Teardown,
             20: IE_NSAPI,
             26: IE_ChargingCharacteristics,
             27: IE_TraceReference,
             28: IE_TraceType,
             127: IE_ChargingId,
             128: IE_EndUserAddress,
             131: IE_AccessPointName,
             132: IE_ProtocolConfigurationOptions,
             133: IE_GSNAddress,
             134: IE_MSInternationalNumber,
             135: IE_QoS,
             141: IE_ExtensionHeaderList,
             148: IE_CommonFlags,
             149: IE_APNRestriction,
             151: IE_RATType,
             152: IE_UserLocationInformation,
             153: IE_MSTimeZone,
             154: IE_IMEI,
             181: IE_MSInfoChangeReportingAction,
             182: IE_DirectTunnelFlags,
             184: IE_BearerControlMode,
             191: IE_EvolvedAllocationRetentionPriority,
             251: IE_CharginGatewayAddress,
             255: IE_PrivateExtension}


def IE_Dispatcher(s):
    """Choose the correct Information Element class."""
    if len(s) < 1:
        return Raw(s)
    # Get the IE type
    ietype = orb(s[0])
    cls = ietypecls.get(ietype, Raw)

    # if ietype greater than 128 are TLVs
    if cls == Raw and ietype & 128 == 128:
        cls = IE_NotImplementedTLV
    return cls(s)


class GTPEchoResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Echo Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.seq)

    def answers(self, other):
        return self.seq == other.seq


class GTPCreatePDPContextRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Create PDP Context Request"
    fields_desc = [PacketListField("IE_list", [IE_TEIDI(), IE_NSAPI(), IE_GSNAddress(length=4, ipv4_address=RandIP()),  # noqa: E501
                                               IE_GSNAddress(length=4, ipv4_address=RandIP()),  # noqa: E501
                                               IE_NotImplementedTLV(ietype=135, length=15, data=RandString(15))],  # noqa: E501
                                   IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.seq)


class GTPCreatePDPContextResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Create PDP Context Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.seq)

    def answers(self, other):
        return self.seq == other.seq


class GTPUpdatePDPContextRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Update PDP Context Request"
    fields_desc = [PacketListField("IE_list", [
        IE_Cause(),
        IE_Recovery(),
        IE_TEIDI(),
        IE_TEICP(),
        IE_ChargingId(),
        IE_ProtocolConfigurationOptions(),
        IE_GSNAddress(),
        IE_GSNAddress(),
        IE_GSNAddress(),
        IE_GSNAddress(),
        IE_QoS(),
        IE_CharginGatewayAddress(),
        IE_CharginGatewayAddress(),
        IE_CommonFlags(),
        IE_APNRestriction(),
        IE_BearerControlMode(),
        IE_MSInfoChangeReportingAction(),
        IE_EvolvedAllocationRetentionPriority(),
        IE_PrivateExtension()],
        IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.seq)


class GTPUpdatePDPContextResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Update PDP Context Response"
    fields_desc = [PacketListField("IE_list", None, IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.seq)


class GTPErrorIndication(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Error Indication"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class GTPDeletePDPContextRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Delete PDP Context Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class GTPDeletePDPContextResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Delete PDP Context Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class GTPPDUNotificationRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP PDU Notification Request"
    fields_desc = [PacketListField("IE_list", [IE_IMSI(),
                                               IE_TEICP(TEICI=RandInt()),
                                               IE_EndUserAddress(PDPTypeNumber=0x21),  # noqa: E501
                                               IE_AccessPointName(),
                                               IE_GSNAddress(ipv4_address="127.0.0.1"),  # noqa: E501
                                               ], IE_Dispatcher)]


class GTPSupportedExtensionHeadersNotification(Packet):
    name = "GTP Supported Extension Headers Notification"
    fields_desc = [PacketListField("IE_list", [IE_ExtensionHeaderList(),
                                               ], IE_Dispatcher)]


class GTPmorethan1500(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP More than 1500"
    fields_desc = [ByteEnumField("IE_Cause", "Cause", IEType),
                   BitField("IE", 1, 12000), ]


# Bind GTP-C
bind_bottom_up(UDP, GTPHeader, dport=2123)
bind_bottom_up(UDP, GTPHeader, sport=2123)
bind_layers(UDP, GTPHeader, dport=2123, sport=2123)
bind_layers(GTPHeader, GTPEchoRequest, gtp_type=1, S=1)
bind_layers(GTPHeader, GTPEchoResponse, gtp_type=2, S=1)
bind_layers(GTPHeader, GTPCreatePDPContextRequest, gtp_type=16)
bind_layers(GTPHeader, GTPCreatePDPContextResponse, gtp_type=17)
bind_layers(GTPHeader, GTPUpdatePDPContextRequest, gtp_type=18)
bind_layers(GTPHeader, GTPUpdatePDPContextResponse, gtp_type=19)
bind_layers(GTPHeader, GTPDeletePDPContextRequest, gtp_type=20)
bind_layers(GTPHeader, GTPDeletePDPContextResponse, gtp_type=21)
bind_layers(GTPHeader, GTPPDUNotificationRequest, gtp_type=27)
bind_layers(GTPHeader, GTPSupportedExtensionHeadersNotification, gtp_type=31, S=1)  # noqa: E501
bind_layers(GTPHeader, GTP_UDPPort_ExtensionHeader, next_ex=64, E=1)
bind_layers(GTPHeader, GTP_PDCP_PDU_ExtensionHeader, next_ex=192, E=1)

# Bind GTP-U
bind_bottom_up(UDP, GTP_U_Header, dport=2152)
bind_bottom_up(UDP, GTP_U_Header, sport=2152)
bind_layers(UDP, GTP_U_Header, dport=2152, sport=2152)
bind_layers(GTP_U_Header, GTPErrorIndication, gtp_type=26, S=1)
bind_layers(GTP_U_Header, GTPPDUSessionContainer,
            gtp_type=255, E=1, next_ex=0x85)
bind_top_down(GTP_U_Header, IP, gtp_type=255)
bind_top_down(GTP_U_Header, IPv6, gtp_type=255)
bind_top_down(GTP_U_Header, PPP, gtp_type=255)
