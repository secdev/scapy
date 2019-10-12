#! /usr/bin/env python

# Copyright (C) 2017 Alessio Deiana <adeiana@gmail.com>
# 2017 Alexis Sultan <alexis.sultan@sfr.com>

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

# scapy.contrib.description = GPRS Tunneling Protocol v2 (GTPv2)
# scapy.contrib.status = loads

import struct


from scapy.compat import orb
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, IntField, IPField, LongField, PacketField, \
    PacketListField, ShortEnumField, ShortField, StrFixedLenField, \
    StrLenField, ThreeBytesField, XBitField, XIntField, XShortField
from scapy.packet import bind_layers, Packet, Raw
from scapy.volatile import RandIP, RandShort


from scapy.contrib import gtp


RATType = {
    6: "EUTRAN",
}

# 3GPP TS 29.274 v16.1.0 table 6.1-1
GTPmessageType = {
    1: "echo_request",
    2: "echo_response",
    3: "version_not_supported",

    # 4-16: S101 interface, TS 29.276.
    # 17-24: S121 interface, TS 29.276.
    # 25-31: Sv interface, TS 29.280.

    # SGSN/MME/ TWAN/ePDG to PGW (S4/S11, S5/S8, S2a, S2b)
    32: "create_session_req",
    33: "create_session_res",
    36: "delete_session_req",
    37: "delete_session_res",

    # SGSN/MME/ePDG to PGW (S4/S11, S5/S8, S2b)
    34: "modify_bearer_req",
    35: "modify_bearer_res",

    # MME to PGW (S11, S5/S8)
    40: "remote_ue_report_notif",
    41: "remote_ue_report_ack",

    # SGSN/MME to PGW (S4/S11, S5/S8)
    38: "change_notif_req",
    39: "change_notif_res",
    # 42-46: For future use.
    164: "resume_notif",
    165: "resume_ack",

    # Messages without explicit response
    64: "modify_bearer_cmd",
    65: "modify_bearer_failure_indic",
    66: "delete_bearer_cmd",
    67: "delete_bearer_failure_indic",
    68: "bearer_resource_cmd",
    69: "bearer_resource_failure_indic",
    70: "downlink_data_notif_failure_indic",
    71: "trace_session_activation",
    72: "trace_session_deactivation",
    73: "stop_paging_indic",
    # 74-94: For future use.

    # PGW to SGSN/MME/ TWAN/ePDG (S5/S8, S4/S11, S2a, S2b)
    95: "create_bearer_req",
    96: "create_bearer_res",
    97: "update_bearer_req",
    98: "update_bearer_res",
    99: "delete_bearer_req",
    100: "delete_bearer_res",

    # PGW to MME, MME to PGW, SGW to PGW, SGW to MME, PGW to TWAN/ePDG,
    # TWAN/ePDG to PGW (S5/S8, S11, S2a, S2b)
    101: "delete_pdn_connection_set_req",
    102: "delete_pdn_connection_set_res",

    # PGW to SGSN/MME (S5, S4/S11)
    103: "pgw_downlink_triggering_notif",
    104: "pgw_downlink_triggering_ack",
    # 105-127: For future use.

    # MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN, MME to AMF,
    # AMF to MME (S3/S10/S16/N26)
    128: "identification_req",
    129: "identification_res",
    130: "context_req",
    131: "context_res",
    132: "context_ack",
    133: "forward_relocation_req",
    134: "forward_relocation_res",
    135: "forward_relocation_complete_notif",
    136: "forward_relocation_complete_ack",
    137: "forward_access_context_notif",
    138: "forward_access_context_ack",
    139: "relocation_cancel_req",
    140: "relocation_cancel_res",
    141: "configuration_transfer_tunnel",
    # 142-148: For future use.
    152: "ran_information_relay",

    # SGSN to MME, MME to SGSN (S3)
    149: "detach_notif",
    150: "detach_ack",
    151: "cs_paging_indic",
    153: "alert_mme_notif",
    154: "alert_mme_ack",
    155: "ue_activity_notif",
    156: "ue_activity_ack",
    157: "isr_status_indic",
    158: "ue_registration_query_req",
    159: "ue_registration_query_res",

    # SGSN/MME to SGW, SGSN to MME (S4/S11/S3)
    # SGSN to SGSN (S16), SGW to PGW (S5/S8)
    162: "suspend_notif",
    163: "suspend_ack",

    # SGSN/MME to SGW (S4/S11)
    160: "create_forwarding_tunnel_req",
    161: "create_forwarding_tunnel_res",
    166: "create_indirect_data_forwarding_tunnel_req",
    167: "create_indirect_data_forwarding_tunnel_res",
    168: "delete_indirect_data_forwarding_tunnel_req",
    169: "delete_indirect_data_forwarding_tunnel_res",
    170: "realease_bearers_req",
    171: "realease_bearers_res",
    # 172-175: For future use

    # SGW to SGSN/MME (S4/S11)
    176: "downlink_data_notif",
    177: "downlink_data_notif_ack",
    179: "pgw_restart_notif",
    180: "pgw_restart_notif_ack",

    # SGW to SGSN (S4)
    # 178: Reserved. Allocated in earlier version of the specification.
    # 181-199: For future use.

    # SGW to PGW, PGW to SGW (S5/S8)
    200: "update_pdn_connection_set_req",
    201: "update_pdn_connection_set_res",
    # 202-210: For future use.

    # MME to SGW (S11)
    211: "modify_access_bearers_req",
    212: "modify_access_bearers_res",
    # 213-230: For future use.

    # MBMS GW to MME/SGSN (Sm/Sn)
    231: "mbms_session_start_req",
    232: "mbms_session_start_res",
    233: "mbms_session_update_req",
    234: "mbms_session_update_res",
    235: "mbms_session_stop_req",
    236: "mbms_session_stop_res",
    # 237-239: For future use.

    # Other
    # 240-247: Reserved for Sv interface (see also types 25 to 31, and
    #          TS 29.280).
    # 248-255: For future use.
}

IEType = {1: "IMSI",
             2: "Cause",
             3: "Recovery Restart",
             71: "APN",
             72: "AMBR",
             73: "EPS Bearer ID",
             74: "IPv4",
             75: "MEI",
             76: "MSISDN",
             77: "Indication",
             78: "Protocol Configuration Options",
             79: "PAA",
             80: "Bearer QoS",
             82: "RAT",
             83: "Serving Network",
             86: "ULI",
             87: "F-TEID",
             93: "Bearer Context",
             94: "Charging ID",
             95: "Charging Characteristics",
             99: "PDN Type",
             114: "UE Time zone",
             126: "Port Number",
             127: "APN Restriction",
             128: "Selection Mode",
             161: "Max MBR/APN-AMBR (MMBR)"
          }

CauseValues = {
    16: "Request Accepted",
}


class GTPHeader(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    # without the version
    name = "GTP v2 Header"
    fields_desc = [BitField("version", 2, 3),
                   BitField("P", 1, 1),
                   BitField("T", 1, 1),
                   BitField("SPARE", 0, 1),
                   BitField("SPARE", 0, 1),
                   BitField("SPARE", 0, 1),
                   ByteEnumField("gtp_type", None, GTPmessageType),
                   ShortField("length", None),
                   ConditionalField(XIntField("teid", 0),
                                    lambda pkt:pkt.T == 1),
                   ThreeBytesField("seq", RandShort()),
                   ByteField("SPARE", 0)
                   ]

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


class IE_IPv4(gtp.IE_Base):
    name = "IE IPv4"
    fields_desc = [ByteEnumField("ietype", 74, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   IPField("address", RandIP())]


class IE_MEI(gtp.IE_Base):
    name = "IE MEI"
    fields_desc = [ByteEnumField("ietype", 75, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   LongField("MEI", 0)]


def IE_Dispatcher(s):
    """Choose the correct Information Element class."""

    # Get the IE type
    ietype = orb(s[0])
    cls = ietypecls.get(ietype, Raw)

    # if ietype greater than 128 are TLVs
    if cls is Raw and ietype > 128:
        cls = IE_NotImplementedTLV

    return cls(s)


class IE_EPSBearerID(gtp.IE_Base):
    name = "IE EPS Bearer ID"
    fields_desc = [ByteEnumField("ietype", 73, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ByteField("EBI", 0)]


class IE_RAT(gtp.IE_Base):
    name = "IE RAT"
    fields_desc = [ByteEnumField("ietype", 82, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ByteEnumField("RAT_type", None, RATType)]


class IE_ServingNetwork(gtp.IE_Base):
    name = "IE Serving Network"
    fields_desc = [ByteEnumField("ietype", 83, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   gtp.TBCDByteField("MCC", "", 2),
                   gtp.TBCDByteField("MNC", "", 1)]


class ULI_RAI(gtp.IE_Base):
    name = "IE Tracking Area Identity"
    fields_desc = [
        gtp.TBCDByteField("MCC", "", 2),
        # MNC: if the third digit of MCC is 0xf, then the length of
        # MNC is 1 byte
        gtp.TBCDByteField("MNC", "", 1),
        ShortField("LAC", 0),
        ShortField("RAC", 0)]


class ULI_SAI(gtp.IE_Base):
    name = "IE Tracking Area Identity"
    fields_desc = [
        gtp.TBCDByteField("MCC", "", 2),
        gtp.TBCDByteField("MNC", "", 1),
        ShortField("LAC", 0),
        ShortField("SAC", 0)]


class ULI_TAI(gtp.IE_Base):
    name = "IE Tracking Area Identity"
    fields_desc = [
        gtp.TBCDByteField("MCC", "", 2),
        gtp.TBCDByteField("MNC", "", 1),
        ShortField("TAC", 0)]


class ULI_ECGI(gtp.IE_Base):
    name = "IE E-UTRAN Cell Identifier"
    fields_desc = [
        gtp.TBCDByteField("MCC", "", 2),
        gtp.TBCDByteField("MNC", "", 1),
        BitField("SPARE", 0, 4),
        BitField("ECI", 0, 28)]


class IE_ULI(gtp.IE_Base):
    name = "IE ULI"
    fields_desc = [ByteEnumField("ietype", 86, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("SPARE", 0, 2),
                   BitField("LAI_Present", 0, 1),
                   BitField("ECGI_Present", 0, 1),
                   BitField("TAI_Present", 0, 1),
                   BitField("RAI_Present", 0, 1),
                   BitField("SAI_Present", 0, 1),
                   BitField("CGI_Present", 0, 1),
                   ConditionalField(
        PacketField("SAI", 0, ULI_SAI), lambda pkt: bool(pkt.SAI_Present)),
        ConditionalField(
        PacketField("RAI", 0, ULI_RAI), lambda pkt: bool(pkt.RAI_Present)),
        ConditionalField(
        PacketField("TAI", 0, ULI_TAI), lambda pkt: bool(pkt.TAI_Present)),
        ConditionalField(PacketField("ECGI", 0, ULI_ECGI),
                         lambda pkt: bool(pkt.ECGI_Present))]


# 3GPP TS 29.274 v12.12.0 section 8.22
INTERFACE_TYPES = {
    0: "S1-U eNodeB GTP-U interface",
    1: "S1-U SGW GTP-U interface",
    2: "S12 RNC GTP-U interface",
    3: "S12 SGW GTP-U interface",
    4: "S5/S8 SGW GTP-U interface",
    5: "S5/S8 PGW GTP-U interface",
    6: "S5/S8 SGW GTP-C interface",
    7: "S5/S8 PGW GTP-C interface",
    8: "S5/S8 SGW PMIPv6 interface",
    9: "S5/S8 PGW PMIPv6 interface",
    10: "S11 MME GTP-C interface",
    11: "S11/S4 SGW GTP-C interface",
    12: "S10 MME GTP-C interface",
    13: "S3 MME GTP-C interface",
    14: "S3 SGSN GTP-C interface",
    15: "S4 SGSN GTP-U interface",
    16: "S4 SGW GTP-U interface",
    17: "S4 SGSN GTP-C interface",
    18: "S16 SGSN GTP-C interface",
    19: "eNodeB GTP-U interface for DL data forwarding",
    20: "eNodeB GTP-U interface for UL data forwarding",
    21: "RNC GTP-U interface for data forwarding",
    22: "SGSN GTP-U interface for data forwarding",
    23: "SGW GTP-U interface for DL data forwarding",
    24: "Sm MBMS GW GTP-C interface",
    25: "Sn MBMS GW GTP-C interface",
    26: "Sm MME GTP-C interface",
    27: "Sn SGSN GTP-C interface",
    28: "SGW GTP-U interface for UL data forwarding",
    29: "Sn SGSN GTP-U interface",
    30: "S2b ePDG GTP-C interface",
    31: "S2b-U ePDG GTP-U interface",
    32: "S2b PGW GTP-C interface",
    33: "S2b-U PGW GTP-U interface",
    34: "S2a TWAN GTP-U interface",
    35: "S2a TWAN GTP-C interface",
    36: "S2a PGW GTP-C interface",
    37: "S2a PGW GTP-U interface",
}


class IE_FTEID(gtp.IE_Base):
    name = "IE F-TEID"
    fields_desc = [ByteEnumField("ietype", 87, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("ipv4_present", 0, 1),
                   BitField("ipv6_present", 0, 1),
                   BitEnumField("InterfaceType", 0, 6, INTERFACE_TYPES),
                   XIntField("GRE_Key", 0),
                   ConditionalField(
        IPField("ipv4", RandIP()), lambda pkt: pkt.ipv4_present),
        ConditionalField(XBitField("ipv6", "2001::", 128),
                         lambda pkt: pkt.ipv6_present)]


class IE_BearerContext(gtp.IE_Base):
    name = "IE Bearer Context"
    fields_desc = [ByteEnumField("ietype", 93, IEType),
                   ShortField("length", 0),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]


class IE_NotImplementedTLV(gtp.IE_Base):
    name = "IE not implemented"
    fields_desc = [ByteEnumField("ietype", 0, IEType),
                   ShortField("length", None),
                   StrLenField("data", "", length_from=lambda x: x.length)]


class IE_IMSI(gtp.IE_Base):
    name = "IE IMSI"
    fields_desc = [ByteEnumField("ietype", 1, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   gtp.TBCDByteField("IMSI", "33607080910",
                                     length_from=lambda x: x.length)]


class IE_Cause(gtp.IE_Base):
    name = "IE Cause"
    fields_desc = [ByteEnumField("ietype", 2, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ByteEnumField("Cause", 1, CauseValues),
                   BitField("SPARE", 0, 5),
                   BitField("PCE", 0, 1),
                   BitField("BCE", 0, 1),
                   BitField("CS", 0, 1)]


class IE_RecoveryRestart(gtp.IE_Base):
    name = "IE Recovery Restart"
    fields_desc = [ByteEnumField("ietype", 3, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ByteField("restart_counter", 0)]


class IE_APN(gtp.IE_Base):
    name = "IE APN"
    fields_desc = [ByteEnumField("ietype", 71, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   gtp.APNStrLenField("APN", "internet",
                                      length_from=lambda x: x.length)]


class IE_AMBR(gtp.IE_Base):
    name = "IE AMBR"
    fields_desc = [ByteEnumField("ietype", 72, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   IntField("AMBR_Uplink", 0),
                   IntField("AMBR_Downlink", 0)]


class IE_MSISDN(gtp.IE_Base):
    name = "IE MSISDN"
    fields_desc = [ByteEnumField("ietype", 76, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   gtp.TBCDByteField("digits", "33123456789",
                                     length_from=lambda x: x.length)]


class IE_Indication(gtp.IE_Base):
    name = "IE Cause"
    fields_desc = [ByteEnumField("ietype", 77, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("DAF", 0, 1),
                   BitField("DTF", 0, 1),
                   BitField("HI", 0, 1),
                   BitField("DFI", 0, 1),
                   BitField("OI", 0, 1),
                   BitField("ISRSI", 0, 1),
                   BitField("ISRAI", 0, 1),
                   BitField("SGWCI", 0, 1),
                   BitField("SQCI", 0, 1),
                   BitField("UIMSI", 0, 1),
                   BitField("CFSI", 0, 1),
                   BitField("CRSI", 0, 1),
                   BitField("PS", 0, 1),
                   BitField("PT", 0, 1),
                   BitField("SI", 0, 1),
                   BitField("MSV", 0, 1),

                   ConditionalField(
                       BitField("RetLoc", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("PBIC", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("SRNI", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("S6AF", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("S4AF", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("MBMDT", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("ISRAU", 0, 1), lambda pkt: pkt.length > 2),
                   ConditionalField(
                       BitField("CCRSI", 0, 1), lambda pkt: pkt.length > 2),

                   ConditionalField(
        BitField("CPRAI", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("ARRL", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("PPOFF", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("PPON", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("PPSI", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("CSFBI", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("CLII", 0, 1), lambda pkt: pkt.length > 3),
        ConditionalField(
        BitField("CPSR", 0, 1), lambda pkt: pkt.length > 3),

    ]


PDN_TYPES = {
    1: "IPv4",
    2: "IPv6",
    3: "IPv4/IPv6",
}

PCO_OPTION_TYPES = {
    3: "IPv4",
    129: "Primary DNS Server IP address",
    130: "Primary NBNS Server IP address",
    131: "Secondary DNS Server IP address",
    132: "Secondary NBNS Server IP address",
}


class PCO_Option(Packet):
    def extract_padding(self, pkt):
        return "", pkt


class PCO_IPv4(PCO_Option):
    name = "IPv4"
    fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
                   ByteField("length", 0),
                   IPField("address", RandIP())]


class PCO_Primary_DNS(PCO_Option):
    name = "Primary DNS Server IP Address"
    fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
                   ByteField("length", 0),
                   IPField("address", RandIP())]


class PCO_Primary_NBNS(PCO_Option):
    name = "Primary DNS Server IP Address"
    fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
                   ByteField("length", 0),
                   IPField("address", RandIP())]


class PCO_Secondary_DNS(PCO_Option):
    name = "Secondary DNS Server IP Address"
    fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
                   ByteField("length", 0),
                   IPField("address", RandIP())]


class PCO_Secondary_NBNS(PCO_Option):
    name = "Secondary NBNS Server IP Address"
    fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
                   ByteField("length", 0),
                   IPField("address", RandIP())]


PCO_PROTOCOL_TYPES = {
    0x0001: 'P-CSCF IPv6 Address Request',
    0x0003: 'DNS Server IPv6 Address Request',
    0x0005: 'MS Support of Network Requested Bearer Control indicator',
    0x000a: 'IP Allocation via NAS',
    0x000d: 'DNS Server IPv4 Address Request',
    0x000c: 'P-CSCF IPv4 Address Request',
    0x0010: 'IPv4 Link MTU Request',
    0x8021: 'IPCP',
    0xc023: 'Password Authentication Protocol',
    0xc223: 'Challenge Handshake Authentication Protocol',
}

PCO_OPTION_CLASSES = {
    3: PCO_IPv4,
    129: PCO_Primary_DNS,
    130: PCO_Primary_NBNS,
    131: PCO_Secondary_DNS,
    132: PCO_Secondary_NBNS,
}


def PCO_option_dispatcher(s):
    """Choose the correct PCO element."""
    option = orb(s[0])

    cls = PCO_OPTION_CLASSES.get(option, Raw)
    return cls(s)


def len_options(pkt):
    return pkt.length - 4 if pkt.length else 0


class PCO_P_CSCF_IPv6_Address_Request(PCO_Option):
    name = "PCO PCO-P CSCF IPv6 Address Request"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   ConditionalField(XBitField("address",
                                              "2001:db8:0:42::", 128),
                                    lambda pkt: pkt.length)]


class PCO_DNS_Server_IPv6(PCO_Option):
    name = "PCO DNS Server IPv6 Address Request"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   ConditionalField(XBitField("address",
                                              "2001:db8:0:42::", 128),
                                    lambda pkt: pkt.length)]


class PCO_SOF(PCO_Option):
    name = "PCO MS Support of Network Requested Bearer Control indicator"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   ]


class PCO_PPP(PCO_Option):
    name = "PPP IP Control Protocol"
    fields_desc = [ByteField("Code", 0),
                   ByteField("Identifier", 0),
                   ShortField("length", 0),
                   PacketListField("Options", None, PCO_option_dispatcher,
                                   length_from=len_options)]

    def extract_padding(self, pkt):
        return "", pkt


class PCO_IP_Allocation_via_NAS(PCO_Option):
    name = "PCO IP Address allocation via NAS Signaling"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   PacketListField("Options", None, PCO_option_dispatcher,
                                   length_from=len_options)]


class PCO_P_CSCF_IPv4_Address_Request(PCO_Option):
    name = "PCO PCO-P CSCF IPv4 Address Request"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   ConditionalField(IPField("address", RandIP()),
                                    lambda pkt: pkt.length)]


class PCO_DNS_Server_IPv4(PCO_Option):
    name = "PCO DNS Server IPv4 Address Request"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   ConditionalField(IPField("address", RandIP()),
                                    lambda pkt: pkt.length)]


class PCO_IPv4_Link_MTU_Request(PCO_Option):
    name = "PCO IPv4 Link MTU Request"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   ConditionalField(ShortField("MTU_size", 1500),
                                    lambda pkt: pkt.length)]


class PCO_IPCP(PCO_Option):
    name = "PCO Internet Protocol Control Protocol"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   PacketField("PPP", None, PCO_PPP)]


class PCO_PPP_Auth(PCO_Option):
    name = "PPP Password Authentication Protocol"
    fields_desc = [ByteField("Code", 0),
                   ByteField("Identifier", 0),
                   ShortField("length", 0),
                   ByteField("PeerID_length", 0),
                   ConditionalField(StrFixedLenField(
                       "PeerID",
                       "",
                       length_from=lambda pkt: pkt.PeerID_length),
                       lambda pkt: pkt.PeerID_length),
                   ByteField("Password_length", 0),
                   ConditionalField(
                       StrFixedLenField(
                           "Password",
                           "",
                           length_from=lambda pkt: pkt.Password_length),
                       lambda pkt: pkt.Password_length)]


class PCO_PasswordAuthentificationProtocol(PCO_Option):
    name = "PCO Password Authentication Protocol"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   PacketField("PPP", None, PCO_PPP_Auth)]


class PCO_PPP_Challenge(PCO_Option):
    name = "PPP Password Authentication Protocol"
    fields_desc = [ByteField("Code", 0),
                   ByteField("Identifier", 0),
                   ShortField("length", 0),
                   ByteField("value_size", 0),
                   ConditionalField(StrFixedLenField(
                       "value", "",
                       length_from=lambda pkt: pkt.value_size),
                       lambda pkt: pkt.value_size),
                   ConditionalField(StrFixedLenField(
                       "name", "",
                       length_from=lambda pkt: pkt.length - pkt.value_size - 5),  # noqa: E501
                       lambda pkt: pkt.length)]


class PCO_ChallengeHandshakeAuthenticationProtocol(PCO_Option):
    name = "PCO Password Authentication Protocol"
    fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
                   ByteField("length", 0),
                   PacketField("PPP", None, PCO_PPP_Challenge)]


PCO_PROTOCOL_CLASSES = {
    0x0001: PCO_P_CSCF_IPv6_Address_Request,
    0x0003: PCO_DNS_Server_IPv6,
    0x0005: PCO_SOF,
    0x000a: PCO_IP_Allocation_via_NAS,
    0x000c: PCO_P_CSCF_IPv4_Address_Request,
    0x000d: PCO_DNS_Server_IPv4,
    0x0010: PCO_IPv4_Link_MTU_Request,
    0x8021: PCO_IPCP,
    0xc023: PCO_PasswordAuthentificationProtocol,
    0xc223: PCO_ChallengeHandshakeAuthenticationProtocol,
}


def PCO_protocol_dispatcher(s):
    """Choose the correct PCO element."""
    proto_num = orb(s[0]) * 256 + orb(s[1])
    cls = PCO_PROTOCOL_CLASSES.get(proto_num, Raw)
    return cls(s)


class IE_PCO(gtp.IE_Base):
    name = "IE Protocol Configuration Options"
    fields_desc = [ByteEnumField("ietype", 78, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("Extension", 0, 1),
                   BitField("SPARE", 0, 4),
                   BitField("PPP", 0, 3),
                   PacketListField("Protocols", None, PCO_protocol_dispatcher,
                                   length_from=lambda pkt: pkt.length - 1)]


class IE_PAA(gtp.IE_Base):
    name = "IE PAA"
    fields_desc = [ByteEnumField("ietype", 79, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("SPARE", 0, 5),
                   BitEnumField("PDN_type", None, 3, PDN_TYPES),
                   ConditionalField(
                       ByteField("ipv6_prefix_length", 8),
                       lambda pkt: pkt.PDN_type in (2, 3)),
                   ConditionalField(
                       XBitField("ipv6", "2001:db8:0:42::", 128),
                       lambda pkt: pkt.PDN_type in (2, 3)),
                   ConditionalField(
                       IPField("ipv4", 0), lambda pkt: pkt.PDN_type in (1, 3)),
                   ]


class IE_Bearer_QoS(gtp.IE_Base):
    name = "IE Bearer Quality of Service"
    fields_desc = [ByteEnumField("ietype", 80, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("SPARE", 0, 1),
                   BitField("PCI", 0, 1),
                   BitField("PriorityLevel", 0, 4),
                   BitField("SPARE", 0, 1),
                   BitField("PVI", 0, 1),
                   ByteField("QCI", 0),
                   BitField("MaxBitRateForUplink", 0, 40),
                   BitField("MaxBitRateForDownlink", 0, 40),
                   BitField("GuaranteedBitRateForUplink", 0, 40),
                   BitField("GuaranteedBitRateForDownlink", 0, 40)]


class IE_ChargingID(gtp.IE_Base):
    name = "IE Charging ID"
    fields_desc = [ByteEnumField("ietype", 94, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   IntField("ChargingID", 0)]


class IE_ChargingCharacteristics(gtp.IE_Base):
    name = "IE Charging ID"
    fields_desc = [ByteEnumField("ietype", 95, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   XShortField("ChargingCharacteristric", 0)]


class IE_PDN_type(gtp.IE_Base):
    name = "IE PDN Type"
    fields_desc = [ByteEnumField("ietype", 99, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("SPARE", 0, 5),
                   BitEnumField("PDN_type", None, 3, PDN_TYPES)]


class IE_UE_Timezone(gtp.IE_Base):
    name = "IE UE Time zone"
    fields_desc = [ByteEnumField("ietype", 114, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ByteField("Timezone", 0),
                   ByteField("DST", 0)]


class IE_Port_Number(gtp.IE_Base):
    name = "IE Port Number"
    fields_desc = [ByteEnumField("ietype", 126, IEType),
                   ShortField("length", 2),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ShortField("PortNumber", RandShort())]


class IE_APN_Restriction(gtp.IE_Base):
    name = "IE APN Restriction"
    fields_desc = [ByteEnumField("ietype", 127, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   ByteField("APN_Restriction", 0)]


class IE_SelectionMode(gtp.IE_Base):
    name = "IE Selection Mode"
    fields_desc = [ByteEnumField("ietype", 128, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   BitField("SPARE", 0, 6),
                   BitField("SelectionMode", 0, 2)]


class IE_MMBR(gtp.IE_Base):
    name = "IE Max MBR/APN-AMBR (MMBR)"
    fields_desc = [ByteEnumField("ietype", 72, IEType),
                   ShortField("length", None),
                   BitField("CR_flag", 0, 4),
                   BitField("instance", 0, 4),
                   IntField("uplink_rate", 0),
                   IntField("downlink_rate", 0)]


ietypecls = {1: IE_IMSI,
             2: IE_Cause,
             3: IE_RecoveryRestart,
             71: IE_APN,
             72: IE_AMBR,
             73: IE_EPSBearerID,
             74: IE_IPv4,
             75: IE_MEI,
             76: IE_MSISDN,
             77: IE_Indication,
             78: IE_PCO,
             79: IE_PAA,
             80: IE_Bearer_QoS,
             82: IE_RAT,
             83: IE_ServingNetwork,
             86: IE_ULI,
             87: IE_FTEID,
             93: IE_BearerContext,
             94: IE_ChargingID,
             95: IE_ChargingCharacteristics,
             99: IE_PDN_type,
             114: IE_UE_Timezone,
             126: IE_Port_Number,
             127: IE_APN_Restriction,
             128: IE_SelectionMode,
             161: IE_MMBR}

#
# GTPv2 Commands
# 3GPP TS 29.060 V9.1.0 (2009-12)
#


class GTPV2Command(Packet):
    fields_desc = [PacketListField("IE_list", None, IE_Dispatcher)]


class GTPV2EchoRequest(GTPV2Command):
    name = "GTPv2 Echo Request"


class GTPV2EchoResponse(GTPV2Command):
    name = "GTPv2 Echo Response"


class GTPV2CreateSessionRequest(GTPV2Command):
    name = "GTPv2 Create Session Request"


class GTPV2CreateSessionResponse(GTPV2Command):
    name = "GTPv2 Create Session Response"


class GTPV2DeleteSessionRequest(GTPV2Command):
    name = "GTPv2 Delete Session Request"


class GTPV2DeleteSessionResponse(GTPV2Command):
    name = "GTPv2 Delete Session Request"


class GTPV2ModifyBearerCommand(GTPV2Command):
    name = "GTPv2 Modify Bearer Command"


class GTPV2ModifyBearerFailureNotification(GTPV2Command):
    name = "GTPv2 Modify Bearer Command"


class GTPV2DownlinkDataNotifFailureIndication(GTPV2Command):
    name = "GTPv2 Downlink Data Notification Failure Indication"


class GTPV2ModifyBearerRequest(GTPV2Command):
    name = "GTPv2 Modify Bearer Request"


class GTPV2ModifyBearerResponse(GTPV2Command):
    name = "GTPv2 Modify Bearer Response"


class GTPV2UpdateBearerRequest(GTPV2Command):
    name = "GTPv2 Update Bearer Request"


class GTPV2UpdateBearerResponse(GTPV2Command):
    name = "GTPv2 Update Bearer Response"


class GTPV2DeleteBearerRequest(GTPV2Command):
    name = "GTPv2 Delete Bearer Request"


class GTPV2SuspendNotification(GTPV2Command):
    name = "GTPv2 Suspend Notification"


class GTPV2SuspendAcknowledge(GTPV2Command):
    name = "GTPv2 Suspend Acknowledge"


class GTPV2ResumeNotification(GTPV2Command):
    name = "GTPv2 Resume Notification"


class GTPV2ResumeAcknowledge(GTPV2Command):
    name = "GTPv2 Resume Acknowledge"


class GTPV2DeleteBearerResponse(GTPV2Command):
    name = "GTPv2 Delete Bearer Response"


class GTPV2CreateIndirectDataForwardingTunnelRequest(GTPV2Command):
    name = "GTPv2 Create Indirect Data Forwarding Tunnel Request"


class GTPV2CreateIndirectDataForwardingTunnelResponse(GTPV2Command):
    name = "GTPv2 Create Indirect Data Forwarding Tunnel Response"


class GTPV2DeleteIndirectDataForwardingTunnelRequest(GTPV2Command):
    name = "GTPv2 Delete Indirect Data Forwarding Tunnel Request"


class GTPV2DeleteIndirectDataForwardingTunnelResponse(GTPV2Command):
    name = "GTPv2 Delete Indirect Data Forwarding Tunnel Response"


class GTPV2ReleaseBearerRequest(GTPV2Command):
    name = "GTPv2 Release Bearer Request"


class GTPV2ReleaseBearerResponse(GTPV2Command):
    name = "GTPv2 Release Bearer Response"


class GTPV2DownlinkDataNotif(GTPV2Command):
    name = "GTPv2 Download Data Notification"


class GTPV2DownlinkDataNotifAck(GTPV2Command):
    name = "GTPv2 Download Data Notification Acknowledgment"


bind_layers(GTPHeader, GTPV2EchoRequest, gtp_type=1, T=0)
bind_layers(GTPHeader, GTPV2EchoResponse, gtp_type=2, T=0)
bind_layers(GTPHeader, GTPV2CreateSessionRequest, gtp_type=32)
bind_layers(GTPHeader, GTPV2CreateSessionResponse, gtp_type=33)
bind_layers(GTPHeader, GTPV2ModifyBearerRequest, gtp_type=34)
bind_layers(GTPHeader, GTPV2ModifyBearerResponse, gtp_type=35)
bind_layers(GTPHeader, GTPV2DeleteSessionRequest, gtp_type=36)
bind_layers(GTPHeader, GTPV2DeleteSessionResponse, gtp_type=37)
bind_layers(GTPHeader, GTPV2ModifyBearerCommand, gtp_type=64)
bind_layers(GTPHeader, GTPV2ModifyBearerFailureNotification, gtp_type=65)
bind_layers(GTPHeader, GTPV2DownlinkDataNotifFailureIndication, gtp_type=70)
bind_layers(GTPHeader, GTPV2UpdateBearerRequest, gtp_type=97)
bind_layers(GTPHeader, GTPV2UpdateBearerResponse, gtp_type=98)
bind_layers(GTPHeader, GTPV2DeleteBearerRequest, gtp_type=99)
bind_layers(GTPHeader, GTPV2DeleteBearerResponse, gtp_type=100)
bind_layers(GTPHeader, GTPV2SuspendNotification, gtp_type=162)
bind_layers(GTPHeader, GTPV2SuspendAcknowledge, gtp_type=163)
bind_layers(GTPHeader, GTPV2ResumeNotification, gtp_type=164)
bind_layers(GTPHeader, GTPV2ResumeAcknowledge, gtp_type=165)
bind_layers(
    GTPHeader, GTPV2CreateIndirectDataForwardingTunnelRequest, gtp_type=166)
bind_layers(
    GTPHeader, GTPV2CreateIndirectDataForwardingTunnelResponse, gtp_type=167)
bind_layers(
    GTPHeader, GTPV2DeleteIndirectDataForwardingTunnelRequest, gtp_type=168)
bind_layers(
    GTPHeader, GTPV2DeleteIndirectDataForwardingTunnelResponse, gtp_type=169)
bind_layers(GTPHeader, GTPV2ReleaseBearerRequest, gtp_type=170)
bind_layers(GTPHeader, GTPV2ReleaseBearerResponse, gtp_type=171)
bind_layers(GTPHeader, GTPV2DownlinkDataNotif, gtp_type=176)
bind_layers(GTPHeader, GTPV2DownlinkDataNotifAck, gtp_type=177)
