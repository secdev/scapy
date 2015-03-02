#! /usr/bin/env python

## Copyright (C) 2014 Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
##               2014 Alexis Sultan    <alexis.sultan@sfr.com>
##               2012 ffranz <ffranz@iniqua.com>
##
## This program is published under a GPLv2 license

# scapy.contrib.description = GTP
# scapy.contrib.status = loads

import time
import logging

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP, UDP

# GTP Data types

GTPmessageType = {   1: "echo_request",
                     2: "echo_response",
                    16: "create_pdp_context_req",
                    17: "create_pdp_context_res",
                    20: "delete_pdp_context_req",
                    21: "delete_pdp_context_res",
                    26: "error_indication",
                    27: "pdu_notification_req",
                   255: "gtp_u_header" }

IEType = {   1: "Cause",
             2: "IMSI",
             3: "RAI",
             4: "TLLI",
             5: "P_TMSI",
            14: "Recovery",
            15: "SelectionMode",
            16: "TEIDI",
            17: "TEICP",
            19: "TeardownInd",
            20: "NSAPI",
            26: "ChargingChrt",
            27: "TraceReference",
            28: "TraceType",
           128: "EndUserAddress",
           131: "AccessPointName",
           132: "ProtocolConfigurationOptions",
           133: "GSNAddress",
           134: "MSInternationalNumber",
           135: "QoS",
           148: "CommonFlags",
           151: "RatType",
           152: "UserLocationInformation",
           153: "MSTimeZone",
           154: "IMEI" }

CauseValues = {  0: "Request IMSI",
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
               223: "APN Restriction type incompatibility with currently active PDP Contexts",
               224: "MS MBMS Capabilities Insufficient",
               225: "Invalid Correlation : ID",
               226: "MBMS Bearer Context Superseded",
               227: "Bearer Control Mode violation",
               228: "Collision with network initiated request" }

Selection_Mode = { 11111100: "MS or APN",
                   11111101: "MS",
                   11111110: "NET",
                   11111111: "FutureUse" }

TeardownInd_value = { 254: "False",
                      255: "True" }
 
class TBCDByteField(StrFixedLenField):

    def i2h(self, pkt, val):
        ret = []
        for i in range(len(val)):
           byte = ord(val[i])
           left = byte >> 4
           right = byte & 0xF
           if left == 0xF:
               ret += [ "%d" % right ]
           else:
               ret += [ "%d" % right, "%d" % left ]
        return "".join(ret)

    def i2repr(self, pkt, x):
        return repr(self.i2h(pkt,x))

    def i2m(self, pkt, val):
        ret_string = ""
        for i in range(0, len(val), 2):
            tmp = val[i:i+2]
            if len(tmp) == 2:
              ret_string += chr(int(tmp[1] + tmp[0], 16))
            else:
              ret_string += chr(int("F" + tmp[0], 16))
        return ret_string

class GTPHeader(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Header"
    fields_desc=[ BitField("version", 1, 3),
                  BitField("PT", 1, 1),
                  BitField("reserved", 0, 1),
                  BitField("E", 0, 1),
                  BitField("S", 1, 1),
                  BitField("PN", 0, 1),
                  ByteEnumField("gtp_type", None, GTPmessageType),
                  ShortField("length", None),
                  IntField("teid", 0) ]

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            l = len(p)-8
            p = p[:2] + struct.pack("!H", l)+ p[4:]
        return p

    def hashret(self):
        return struct.pack("B", self.version) + self.payload.hashret()

    def answers(self, other):
        return (isinstance(other, GTPHeader) and
                self.version == other.version and
                self.payload.answers(other.payload))

class GTPEchoRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Echo Request"
    fields_desc = [ XBitField("seq", 0, 16),
                    ByteField("npdu", 0),
                    ByteField("next_ex", 0),]

    def hashret(self):
        return struct.pack("H", self.seq)

class IE_Cause(Packet):
    name = "Cause"
    fields_desc = [ ByteEnumField("ietype", 1, IEType),
                    BitField("Response", None, 1),
                    BitField("Rejection", None, 1),
                    BitEnumField("CauseValue", None, 6,  CauseValues) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_IMSI(Packet):
    name = "IMSI - Subscriber identity of the MS"
    fields_desc = [ ByteEnumField("ietype", 2, IEType),
                    TBCDByteField("imsi", str(RandNum(0, 999999999999999)), 8) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_Routing(Packet):
    name = "Routing Area Identity"
    fields_desc = [ ByteEnumField("ietype", 3, IEType),
                    TBCDByteField("MCC", "", 2),
                    # MNC: if the third digit of MCC is 0xf, then the length of MNC is 1 byte
                    TBCDByteField("MNC", "", 1),
                    ShortField("LAC", None),
                    ByteField("RAC", None) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_Recovery(Packet):
    name = "Recovery"
    fields_desc = [ ByteEnumField("ietype", 14, IEType),
                    ByteField("res-counter", 24) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_SelectionMode(Packet):
    # Indicates the origin of the APN in the message
    name = "Selection Mode"
    fields_desc = [ ByteEnumField("ietype", 15, IEType),
                    BitEnumField("SelectionMode", "MS or APN", 8, Selection_Mode) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_TEIDI(Packet):
    name = "Tunnel Endpoint Identifier Data"
    fields_desc = [ ByteEnumField("ietype", 16, IEType),
                    XIntField("TEIDI", RandInt()) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_TEICP(Packet):
    name = "Tunnel Endpoint Identifier Control Plane"
    fields_desc = [ ByteEnumField("ietype", 17, IEType),
                    XIntField("TEICI", RandInt())]
    def extract_padding(self, pkt):
        return "",pkt

class IE_Teardown(Packet):
    name = "Teardown Indicator"
    fields_desc = [ ByteEnumField("ietype", 19, IEType),
                    ByteEnumField("indicator", "True", TeardownInd_value) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_NSAPI(Packet):
    # Identifies a PDP context in a mobility management context specified by TEICP
    name = "NSAPI"
    fields_desc = [ ByteEnumField("ietype", 20, IEType),
                    XBitField("sparebits", 0x0000, 4),
                    XBitField("NSAPI", RandNum(0, 15), 4) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_ChargingCharacteristics(Packet):
    # Way of informing both the SGSN and GGSN of the rules for 
    name = "Charging Characteristics"
    fields_desc = [ ByteEnumField("ietype", 26, IEType),
                    # producing charging information based on operator configured triggers.
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
                    XBitField("Ch_ChReserved", 0, 8) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_TraceReference(Packet):
    # Identifies a record or a collection of records for a particular trace.
    name = "Trace Reference"
    fields_desc = [ ByteEnumField("ietype", 27, IEType),
                    XBitField("Trace_reference", None, 16) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_TraceType(Packet):
    # Indicates the type of the trace
    name = "Trace Type"
    fields_desc = [ ByteEnumField("ietype", 28, IEType),
                    XBitField("Trace_type", None, 16) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_EndUserAddress(Packet):
    # Supply protocol specific information of the external packet 
    name = "End User Addresss"
    fields_desc = [ ByteEnumField("ietype", 128, IEType),
                    #         data network accessed by the GGPRS subscribers.
                    #            - Request
                    #                1    Type (1byte)
                    #                2-3    Length (2bytes) - value 2
                    #                4    Spare + PDP Type Organization
                    #                5    PDP Type Number    
                    #            - Response
                    #                6-n    PDP Address
                    BitField("EndUserAddressLength", 2, 16),
                    BitField("EndUserAddress", 1111, 4),
                    BitField("PDPTypeOrganization", 1, 4),
                    XByteField("PDPTypeNumber", None) ]
    def extract_padding(self, pkt):
        return "",pkt

class APNStrLenField(StrLenField):
    # Inspired by DNSStrField
    def m2i(self, pkt, s):
        ret_s = ""
        tmp_s = s
        while tmp_s:
            tmp_len = struct.unpack("!B", tmp_s[0])[0] + 1
            if tmp_len > len(tmp_s):
                warning("APN prematured end of character-string (size=%i, remaining bytes=%i)" % (tmp_len, len(tmp_s)))
            ret_s +=  tmp_s[1:tmp_len] 
            tmp_s = tmp_s[tmp_len:]
            if len(tmp_s) :
                ret_s += "."
        s = ret_s
        return s
    def i2m(self, pkt, s):
        s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
        return s


class IE_AccessPointName(Packet):
    # Sent by SGSN or by GGSN as defined in 3GPP TS 23.060
    name = "Access Point Name"
    fields_desc = [ ByteEnumField("ietype", 131, IEType),
                    ShortField("length",  None),
                    APNStrLenField("APN", "nternet", length_from=lambda x: x.length) ]
    def extract_padding(self, pkt):
        return "",pkt
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)-3
            p = p[:2] + struct.pack("!B", l)+ p[3:]
        return p

class IE_ProtocolConfigurationOptions(Packet):
    name = "Protocol Configuration Options"
    fields_desc = [ ByteEnumField("ietype", 132, IEType),
            ShortField("length", 4),
            StrLenField("Protocol Configuration", "", length_from=lambda x: x.length) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_GSNAddress(Packet):
    name = "GSN Address"
    fields_desc = [ ByteEnumField("ietype", 133, IEType),
                    ShortField("length", 4),
                    IPField("address", RandIP()) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_MSInternationalNumber(Packet):
    name = "MS International Number"
    fields_desc = [ ByteEnumField("ietype", 134, IEType),
                    ShortField("length", None),
                    FlagsField("flags", 0x91, 8, ["Extension","","","International Number","","","","ISDN numbering"]),
                    TBCDByteField("digits", "33607080910", length_from=lambda x: x.length-1) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_UserLocationInformation(Packet):
    name = "User Location Information"
    fields_desc = [ ByteEnumField("ietype", 152, IEType),
                    ShortField("length", None),
                    ByteField("type", 1),
                    # Only type 1 is currently supported
                    TBCDByteField("MCC", "", 2),
                    # MNC: if the third digit of MCC is 0xf, then the length of MNC is 1 byte
                    TBCDByteField("MNC", "", 1),
                    ShortField("LAC", None),
                    ShortField("SAC", None) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_IMEI(Packet):
    name = "IMEI"
    fields_desc = [ ByteEnumField("ietype", 154, IEType),
                    ShortField("length", None),
                    TBCDByteField("IMEI", "", length_from=lambda x: x.length) ]
    def extract_padding(self, pkt):
        return "",pkt

class IE_NotImplementedTLV(Packet):
    name = "IE not implemented"
    fields_desc = [ ByteEnumField("ietype", 0, IEType),
                    ShortField("length",  None),
                    StrLenField("data", "", length_from=lambda x: x.length) ]
    def extract_padding(self, pkt):
        return "",pkt

ietypecls = {   1: IE_Cause, 2: IE_IMSI, 3: IE_Routing, 14: IE_Recovery, 15: IE_SelectionMode, 16: IE_TEIDI,
               17: IE_TEICP, 19: IE_Teardown, 20: IE_NSAPI, 26: IE_ChargingCharacteristics,
               27: IE_TraceReference, 28: IE_TraceType,
              128: IE_EndUserAddress, 131: IE_AccessPointName, 132: IE_ProtocolConfigurationOptions,
              133: IE_GSNAddress, 134: IE_MSInternationalNumber, 152: IE_UserLocationInformation, 154: IE_IMEI } 

def IE_Dispatcher(s):
  """Choose the correct Information Element class."""

  if len(s) < 1:
    return Raw(s)

  # Get the IE type
  ietype = ord(s[0])
  cls = ietypecls.get(ietype, Raw)

  # if ietype greater than 128 are TLVs
  if cls == Raw and ietype & 128 == 128:
    cls = IE_NotImplementedTLV

  return cls(s)

class GTPEchoResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Echo Response"
    fields_desc = [ XBitField("seq", 0, 16),
                    ByteField("npdu", 0),
                    ByteField("next_ex", 0),
                    PacketListField("IE_list", [], IE_Dispatcher) ]

    def hashret(self):
        return struct.pack("H", self.seq)

    def answers(self, other):
        return self.seq == other.seq


class GTPCreatePDPContextRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Create PDP Context Request"
    fields_desc = [ ShortField("seq", RandShort()),
                    ByteField("npdu", 0),
                    ByteField("next_ex", 0),
                    PacketListField("IE_list", [ IE_TEIDI(), IE_NSAPI(), IE_GSNAddress(),
                                                 IE_GSNAddress(),
                                                 IE_NotImplementedTLV(ietype=135, length=15,data=RandString(15)) ],
                                    IE_Dispatcher) ]
    def hashret(self):
        return struct.pack("H", self.seq)

class GTPCreatePDPContextResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Create PDP Context Response"
    fields_desc = [ ShortField("seq", RandShort()),
                    ByteField("npdu", 0),
                    ByteField("next_ex", 0),
                    PacketListField("IE_list", [], IE_Dispatcher) ]

    def hashret(self):
        return struct.pack("H", self.seq)

    def answers(self, other):
        return self.seq == other.seq

class GTPErrorIndication(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Error Indication"
    fields_desc = [ XBitField("seq", 0, 16),
                    ByteField("npdu", 0),
                    ByteField("next_ex",0),
                    PacketListField("IE_list", [], IE_Dispatcher) ]

class GTPDeletePDPContextRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Delete PDP Context Request"
    fields_desc = [ XBitField("seq", 0, 16),
                    ByteField("npdu", 0),
                    ByteField("next_ex", 0),
                    PacketListField("IE_list", [], IE_Dispatcher) ]

class GTPDeletePDPContextResponse(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP Delete PDP Context Response"
    fields_desc = [ XBitField("seq", 0, 16),
                    ByteField("npdu", 0),
                    ByteField("next_ex",0),
                    PacketListField("IE_list", [], IE_Dispatcher) ]

class GTPPDUNotificationRequest(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP PDU Notification Request"
    fields_desc = [ XBitField("seq", 0, 16),
                    ByteField("npdu", 0),
                    ByteField("next_ex", 0),
                    PacketListField("IE_list", [ IE_IMSI(),
                        IE_TEICP(TEICI=RandInt()),
                        IE_EndUserAddress(PDPTypeNumber=0x21),
                        IE_AccessPointName(),
                        IE_GSNAddress(address="127.0.0.1"),
                        ], IE_Dispatcher) ]

class GTP_U_Header(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP-U Header"
    # GTP-U protocol is used to transmit T-PDUs between GSN pairs (or between an SGSN and an RNC in UMTS), 
    # encapsulated in G-PDUs. A G-PDU is a packet including a GTP-U header and a T-PDU. The Path Protocol 
    # defines the path and the GTP-U header defines the tunnel. Several tunnels may be multiplexed on a single path. 
    fields_desc = [ BitField("version", 1,3),
                    BitField("PT", 1, 1),
                    BitField("Reserved", 0, 1),
                    BitField("E", 0,1),
                    BitField("S", 0, 1),
                    BitField("PN", 0, 1),
                    ByteEnumField("gtp_type", None, GTPmessageType),
                    BitField("length", None, 16),
                    XBitField("TEID", 0, 32),
                    ConditionalField(XBitField("seq", 0, 16), lambda pkt:pkt.E==1 or pkt.S==1 or pkt.PN==1),
                    ConditionalField(ByteField("npdu", 0), lambda pkt:pkt.E==1 or pkt.S==1 or pkt.PN==1),
                    ConditionalField(ByteField("next_ex", 0), lambda pkt:pkt.E==1 or pkt.S==1 or pkt.PN==1),
            ]

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            l = len(p)-8
            p = p[:2] + struct.pack("!H", l)+ p[4:]
        return p

class GTPmorethan1500(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP More than 1500"
    fields_desc = [ ByteEnumField("IE_Cause", "Cause", IEType),
                    BitField("IE", 1, 12000),]

# Bind GTP-C
bind_layers(UDP, GTPHeader, dport = 2123)
bind_layers(UDP, GTPHeader, sport = 2123)
bind_layers(GTPHeader, GTPEchoRequest, gtp_type = 1)
bind_layers(GTPHeader, GTPEchoResponse, gtp_type = 2)
bind_layers(GTPHeader, GTPCreatePDPContextRequest, gtp_type = 16)
bind_layers(GTPHeader, GTPCreatePDPContextResponse, gtp_type = 17)
bind_layers(GTPHeader, GTPDeletePDPContextRequest, gtp_type = 20)
bind_layers(GTPHeader, GTPDeletePDPContextResponse, gtp_type = 21)
bind_layers(GTPHeader, GTPPDUNotificationRequest, gtp_type = 27)

# Bind GTP-U
bind_layers(UDP, GTP_U_Header, dport = 2152)
bind_layers(UDP, GTP_U_Header, sport = 2152)
bind_layers(GTP_U_Header, IP, gtp_type = 255)

if __name__ == "__main__":
    from scapy.all import *
    interact(mydict=globals(), mybanner="GTPv1 add-on")
