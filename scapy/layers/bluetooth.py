# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Mike Ryan <mikeryan@lacklustre.net>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# Copyright (C) Haram Park <freehr94@korea.ac.kr>

"""
Bluetooth layers, sockets and send/receive functions.
"""

import ctypes
import functools
import socket
import struct
import select
from ctypes import sizeof

from scapy.config import conf
from scapy.data import (
    DLT_BLUETOOTH_HCI_H4,
    DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
    DLT_BLUETOOTH_LINUX_MONITOR,
    BLUETOOTH_CORE_COMPANY_IDENTIFIERS
)
from scapy.packet import bind_layers, Packet
from scapy.fields import (
    BitField,
    XBitField,
    ByteEnumField,
    ByteField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IntField,
    LEShortEnumField,
    LEShortField,
    LEIntField,
    LenField,
    MultipleTypeField,
    NBytesField,
    PacketListField,
    PadField,
    ShortField,
    SignedByteField,
    StrField,
    StrFixedLenField,
    StrLenField,
    StrNullField,
    UUIDField,
    XByteField,
    XLE3BytesField,
    XLELongField,
    XStrLenField,
    XLEShortField,
    XLEIntField,
    LEMACField,
    BitEnumField,
    LEThreeBytesField,
)
from scapy.supersocket import SuperSocket
from scapy.sendrecv import sndrcv
from scapy.data import MTU
from scapy.consts import WINDOWS
from scapy.error import warning


############
#  Consts  #
############

# From hci.h
HCI_CHANNEL_RAW = 0
HCI_CHANNEL_USER = 1
HCI_CHANNEL_MONITOR = 2
HCI_CHANNEL_CONTROL = 3
HCI_CHANNEL_LOGGING = 4

HCI_DEV_NONE = 0xffff


##########
# Layers #
##########

# See bluez/lib/hci.h for details

# Transport layers

class HCI_PHDR_Hdr(Packet):
    name = "HCI PHDR transport layer"
    fields_desc = [IntField("direction", 0)]


# Real layers

_bluetooth_packet_types = {
    0: "Acknowledgement",
    1: "Command",
    2: "ACL Data",
    3: "Synchronous",
    4: "Event",
    5: "Reserve",
    14: "Vendor",
    15: "Link Control"
}

_bluetooth_error_codes = {
    0x00: "Success",
    0x01: "Unknown HCI Command",
    0x02: "Unknown Connection Identifier",
    0x03: "Hardware Failure",
    0x04: "Page Timeout",
    0x05: "Authentication Failure",
    0x06: "PIN or Key Missing",
    0x07: "Memory Capacity Exceeded",
    0x08: "Connection Timeout",
    0x09: "Connection Limit Exceeded",
    0x0A: "Synchronous Connection Limit To A Device Exceeded",
    0x0B: "Connection Already Exists",
    0x0C: "Command Disallowed",
    0x0D: "Connection Rejected due to Limited Resources",
    0x0E: "Connection Rejected Due To Security Reasons",
    0x0F: "Connection Rejected due to Unacceptable BD_ADDR",
    0x10: "Connection Accept Timeout Exceeded",
    0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters",
    0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated Connection due to Low Resources",
    0x15: "Remote Device Terminated Connection due to Power Off",
    0x16: "Connection Terminated By Local Host",
    0x17: "Repeated Attempts",
    0x18: "Pairing Not Allowed",
    0x19: "Unknown LMP PDU",
    0x1A: "Unsupported Remote Feature / Unsupported LMP Feature",
    0x1B: "SCO Offset Rejected",
    0x1C: "SCO Interval Rejected",
    0x1D: "SCO Air Mode Rejected",
    0x1E: "Invalid LMP Parameters / Invalid LL Parameters",
    0x1F: "Unspecified Error",
    0x20: "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
    0x21: "Role Change Not Allowed",
    0x22: "LMP Response Timeout / LL Response Timeout",
    0x23: "LMP Error Transaction Collision / LL Procedure Collision",
    0x24: "LMP PDU Not Allowed",
    0x25: "Encryption Mode Not Acceptable",
    0x26: "Link Key cannot be Changed",
    0x27: "Requested QoS Not Supported",
    0x28: "Instant Passed",
    0x29: "Pairing With Unit Key Not Supported",
    0x2A: "Different Transaction Collision",
    0x2B: "Reserved for future use",
    0x2C: "QoS Unacceptable Parameter",
    0x2D: "QoS Rejected",
    0x2E: "Channel Classification Not Supported",
    0x2F: "Insufficient Security",
    0x30: "Parameter Out Of Mandatory Range",
    0x31: "Reserved for future use",
    0x32: "Role Switch Pending",
    0x33: "Reserved for future use",
    0x34: "Reserved Slot Violation",
    0x35: "Role Switch Failed",
    0x36: "Extended Inquiry Response Too Large",
    0x37: "Secure Simple Pairing Not Supported By Host",
    0x38: "Host Busy - Pairing",
    0x39: "Connection Rejected due to No Suitable Channel Found",
    0x3A: "Controller Busy",
    0x3B: "Unacceptable Connection Parameters",
    0x3C: "Advertising Timeout",
    0x3D: "Connection Terminated due to MIC Failure",
    0x3E: "Connection Failed to be Established / Synchronization Timeout",
    0x3F: "MAC Connection Failed",
    0x40: "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock"
          " Dragging",
    0x41: "Type0 Submap Not Defined",
    0x42: "Unknown Advertising Identifier",
    0x43: "Limit Reached",
    0x44: "Operation Cancelled by Host",
    0x45: "Packet Too Long"
}

_att_error_codes = {
    0x01: "invalid handle",
    0x02: "read not permitted",
    0x03: "write not permitted",
    0x04: "invalid pdu",
    0x05: "insufficient auth",
    0x06: "unsupported req",
    0x07: "invalid offset",
    0x08: "insufficient author",
    0x09: "prepare queue full",
    0x0a: "attr not found",
    0x0b: "attr not long",
    0x0c: "insufficient key size",
    0x0d: "invalid value size",
    0x0e: "unlikely",
    0x0f: "insufficiet encrypt",
    0x10: "unsupported gpr type",
    0x11: "insufficient resources",
}

_bluetooth_features = [
    '3_slot_packets',
    '5_slot_packets',
    'encryption',
    'slot_offset',
    'timing_accuracy',
    'role_switch',
    'hold_mode',
    'sniff_mode',
    'park_mode',
    'power_control_requests',
    'channel_quality_driven_data_rate',
    'sco_link',
    'hv2_packets',
    'hv3_packets',
    'u_law_log_synchronous_data',
    'a_law_log_synchronous_data',
    'cvsd_synchronous_data',
    'paging_parameter_negotiation',
    'power_control',
    'transparent_synchronous_data',
    'flow_control_lag_4_bit0',
    'flow_control_lag_4_bit1',
    'flow_control_lag_4_bit2',
    'broadband_encryption',
    'cvsd_synchronous_data',
    'edr_acl_2_mbps_mode',
    'edr_acl_3_mbps_mode',
    'enhanced_inquiry_scan',
    'interlaced_inquiry_scan',
    'interlaced_page_scan',
    'rssi_with_inquiry_results',
    'ev3_packets',
    'ev4_packets',
    'ev5_packets',
    'reserved',
    'afh_capable_slave',
    'afh_classification_slave',
    'br_edr_not_supported',
    'le_supported_controller',
    '3_slot_edr_acl_packets',
    '5_slot_edr_acl_packets',
    'sniff_subrating',
    'pause_encryption',
    'afh_capable_master',
    'afh_classification_master',
    'edr_esco_2_mbps_mode',
    'edr_esco_3_mbps_mode',
    '3_slot_edr_esco_packets',
    'extended_inquiry_response',
    'simultaneous_le_and_br_edr_to_same_device_capable_controller',
    'reserved2',
    'secure_simple_pairing',
    'encapsulated_pdu',
    'erroneous_data_reporting',
    'non_flushable_packet_boundary_flag',
    'reserved3',
    'link_supervision_timeout_changed_event',
    'inquiry_tx_power_level',
    'enhanced_power_control',
    'reserved4_bit0',
    'reserved4_bit1',
    'reserved4_bit2',
    'reserved4_bit3',
    'extended_features',
]

_bluetooth_core_specification_versions = {
    0x00: '1.0b',
    0x01: '1.1',
    0x02: '1.2',
    0x03: '2.0+EDR',
    0x04: '2.1+EDR',
    0x05: '3.0+HS',
    0x06: '4.0',
    0x07: '4.1',
    0x08: '4.2',
    0x09: '5.0',
    0x0a: '5.1',
    0x0b: '5.2',
    0x0c: '5.3',
    0x0d: '5.4',
    0x0e: '6.0',
}


class HCI_Hdr(Packet):
    name = "HCI header"
    fields_desc = [ByteEnumField("type", 2, _bluetooth_packet_types)]

    def mysummary(self):
        return self.sprintf("HCI %type%")


class HCI_ACL_Hdr(Packet):
    name = "HCI ACL header"
    fields_desc = [BitField("BC", 0, 2, tot_size=-2),
                   BitField("PB", 0, 2),
                   BitField("handle", 0, 12, end_tot_size=-2),
                   LEShortField("len", None), ]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            p = p[:2] + struct.pack("<H", len(pay)) + p[4:]
        return p


class L2CAP_Hdr(Packet):
    name = "L2CAP header"
    fields_desc = [LEShortField("len", None),
                   LEShortEnumField("cid", 0, {1: "control", 4: "attribute"}), ]  # noqa: E501

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            p = struct.pack("<H", len(pay)) + p[2:]
        return p


class L2CAP_CmdHdr(Packet):
    name = "L2CAP command header"
    fields_desc = [
        ByteEnumField("code", 8, {1: "rej",
                                  2: "conn_req",
                                  3: "conn_resp",
                                  4: "conf_req",
                                  5: "conf_resp",
                                  6: "disconn_req",
                                  7: "disconn_resp",
                                  8: "echo_req",
                                  9: "echo_resp",
                                  10: "info_req",
                                  11: "info_resp",
                                  12: "create_channel_req",
                                  13: "create_channel_resp",
                                  14: "move_channel_req",
                                  15: "move_channel_resp",
                                  16: "move_channel_confirm_req",
                                  17: "move_channel_confirm_resp",
                                  18: "conn_param_update_req",
                                  19: "conn_param_update_resp",
                                  20: "LE_credit_based_conn_req",
                                  21: "LE_credit_based_conn_resp",
                                  22: "flow_control_credit_ind",
                                  23: "credit_based_conn_req",
                                  24: "credit_based_conn_resp",
                                  25: "credit_based_reconf_req",
                                  26: "credit_based_reconf_resp"}),
        ByteField("id", 1),
        LEShortField("len", None)]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            p = p[:2] + struct.pack("<H", len(pay)) + p[4:]
        return p

    def answers(self, other):
        if other.id == self.id:
            if self.code == 1:
                return 1
            if other.code in [2, 4, 6, 8, 10, 18] and self.code == other.code + 1:  # noqa: E501
                if other.code == 8:
                    return 1
                return self.payload.answers(other.payload)
        return 0


class L2CAP_ConnReq(Packet):
    name = "L2CAP Conn Req"
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP",
                                               3: "RFCOMM",
                                               5: "TCS-BIN",
                                               7: "TCS-BIN-CORDLESS",
                                               15: "BNEP",
                                               17: "HID-Control",
                                               19: "HID-Interrupt",
                                               21: "UPnP",
                                               23: "AVCTP-Control",
                                               25: "AVDTP",
                                               27: "AVCTP-Browsing",
                                               29: "UDI_C-Plane",
                                               31: "ATT",
                                               33: "3DSP",
                                               35: "IPSP",
                                               37: "OTS"}),
                   LEShortField("scid", 0),
                   ]


class L2CAP_ConnResp(Packet):
    name = "L2CAP Conn Resp"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0),
                   LEShortEnumField("result", 0, ["success", "pend", "cr_bad_psm", "cr_sec_block", "cr_no_mem", "reserved", "cr_inval_scid", "cr_scid_in_use"]),  # noqa: E501
                   LEShortEnumField("status", 0, ["no_info", "authen_pend", "author_pend", "reserved"]),  # noqa: E501
                   ]

    def answers(self, other):
        # dcid Resp == scid Req. Therefore compare SCIDs
        return isinstance(other, L2CAP_ConnReq) and self.scid == other.scid


class L2CAP_CmdRej(Packet):
    name = "L2CAP Command Rej"
    fields_desc = [LEShortField("reason", 0),
                   ]


class L2CAP_ConfReq(Packet):
    name = "L2CAP Conf Req"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("flags", 0),
                   ]


class L2CAP_ConfResp(Packet):
    name = "L2CAP Conf Resp"
    fields_desc = [LEShortField("scid", 0),
                   LEShortField("flags", 0),
                   LEShortEnumField("result", 0, ["success", "unaccept", "reject", "unknown"]),  # noqa: E501
                   ]

    def answers(self, other):
        # Req and Resp contain either the SCID or the DCID.
        return isinstance(other, L2CAP_ConfReq)


class L2CAP_DisconnReq(Packet):
    name = "L2CAP Disconn Req"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0), ]


class L2CAP_DisconnResp(Packet):
    name = "L2CAP Disconn Resp"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0), ]

    def answers(self, other):
        return self.scid == other.scid


class L2CAP_EchoReq(Packet):
    name = "L2CAP Echo Req"
    fields_desc = [StrField("data", ""), ]


class L2CAP_EchoResp(Packet):
    name = "L2CAP Echo Resp"
    fields_desc = [StrField("data", ""), ]


class L2CAP_InfoReq(Packet):
    name = "L2CAP Info Req"
    fields_desc = [LEShortEnumField("type", 0, {1: "CL_MTU", 2: "FEAT_MASK"}),
                   StrField("data", "")
                   ]


class L2CAP_InfoResp(Packet):
    name = "L2CAP Info Resp"
    fields_desc = [LEShortField("type", 0),
                   LEShortEnumField("result", 0, ["success", "not_supp"]),
                   StrField("data", ""), ]

    def answers(self, other):
        return self.type == other.type


class L2CAP_Create_Channel_Request(Packet):
    name = "L2CAP Create Channel Request"
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP",
                                               3: "RFCOMM",
                                               5: "TCS-BIN",
                                               7: "TCS-BIN-CORDLESS",
                                               15: "BNEP",
                                               17: "HID-Control",
                                               19: "HID-Interrupt",
                                               21: "UPnP",
                                               23: "AVCTP-Control",
                                               25: "AVDTP",
                                               27: "AVCTP-Browsing",
                                               29: "UDI_C-Plane",
                                               31: "ATT",
                                               33: "3DSP",
                                               35: "IPSP",
                                               37: "OTS"}),
                   LEShortField("scid", 0),
                   ByteField("controller_id", 0), ]


class L2CAP_Create_Channel_Response(Packet):
    name = "L2CAP Create Channel Response"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0),
                   LEShortEnumField("result", 0, {
                       0: "Connection successful",
                       1: "Connection pending",
                       2: "Connection refused - PSM not supported",
                       3: "Connection refused - security block",
                       4: "Connection refused - no resources available",
                       5: "Connection refused - cont_ID not supported",
                       6: "Connection refused - invalid scid",
                       7: "Connection refused - scid already allocated"}),
                   LEShortEnumField("status", 0, {
                       0: "No further information available",
                       1: "Authentication pending",
                       2: "Authorization pending"}), ]


class L2CAP_Move_Channel_Request(Packet):
    name = "L2CAP Move Channel Request"
    fields_desc = [LEShortField("icid", 0),
                   ByteField("dest_controller_id", 0), ]


class L2CAP_Move_Channel_Response(Packet):
    name = "L2CAP Move Channel Response"
    fields_desc = [LEShortField("icid", 0),
                   LEShortEnumField("result", 0, {
                       0: "Move success",
                       1: "Move pending",
                       2: "Move refused - Cont_ID not supported",
                       3: "Move refused - Cont_ID is same as old one",
                       4: "Move refused - Configuration not supported",
                       5: "Move refused - Move channel collision",
                       6: "Move refused - Not allowed to be moved"}), ]


class L2CAP_Move_Channel_Confirmation_Request(Packet):
    name = "L2CAP Move Channel Confirmation Request"
    fields_desc = [LEShortField("icid", 0),
                   LEShortEnumField("result", 0, {0: "Move success",
                                                  1: "Move failure"}), ]


class L2CAP_Move_Channel_Confirmation_Response(Packet):
    name = "L2CAP Move Channel Confirmation Response"
    fields_desc = [LEShortField("icid", 0), ]


class L2CAP_Connection_Parameter_Update_Request(Packet):
    name = "L2CAP Connection Parameter Update Request"
    fields_desc = [LEShortField("min_interval", 0),
                   LEShortField("max_interval", 0),
                   LEShortField("slave_latency", 0),
                   LEShortField("timeout_mult", 0), ]


class L2CAP_Connection_Parameter_Update_Response(Packet):
    name = "L2CAP Connection Parameter Update Response"
    fields_desc = [LEShortField("move_result", 0), ]


class L2CAP_LE_Credit_Based_Connection_Request(Packet):
    name = "L2CAP LE Credit Based Connection Request"
    fields_desc = [LEShortField("spsm", 0),
                   LEShortField("scid", 0),
                   LEShortField("mtu", 0),
                   LEShortField("mps", 0),
                   LEShortField("initial_credits", 0), ]


class L2CAP_LE_Credit_Based_Connection_Response(Packet):
    name = "L2CAP LE Credit Based Connection Response"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("mtu", 0),
                   LEShortField("mps", 0),
                   LEShortField("initial_credits", 0),
                   LEShortEnumField("result", 0, {
                       0: "Connection successful",
                       2: "Connection refused - SPSM not supported",
                       4: "Connection refused - no resources available",
                       5: "Connection refused - authentication error",
                       6: "Connection refused - authorization error",
                       7: "Connection refused - encrypt_key size error",
                       8: "Connection refused - insufficient encryption",
                       9: "Connection refused - invalid scid",
                       10: "Connection refused - scid already allocated",
                       11: "Connection refused - parameters error"}), ]


class L2CAP_Flow_Control_Credit_Ind(Packet):
    name = "L2CAP Flow Control Credit Ind"
    fields_desc = [LEShortField("cid", 0),
                   LEShortField("credits", 0), ]


class L2CAP_Credit_Based_Connection_Request(Packet):
    name = "L2CAP Credit Based Connection Request"
    fields_desc = [LEShortField("spsm", 0),
                   LEShortField("mtu", 0),
                   LEShortField("mps", 0),
                   LEShortField("initial_credits", 0),
                   LEShortField("scid", 0), ]


class L2CAP_Credit_Based_Connection_Response(Packet):
    name = "L2CAP Credit Based Connection Response"
    fields_desc = [LEShortField("mtu", 0),
                   LEShortField("mps", 0),
                   LEShortField("initial_credits", 0),
                   LEShortEnumField("result", 0, {
                       0: "All connection successful",
                       2: "All connection refused - SPSM not supported",
                       4: "Some connections refused - resources error",
                       5: "All connection refused - authentication error",
                       6: "All connection refused - authorization error",
                       7: "All connection refused - encrypt_key size error",
                       8: "All connection refused - encryption error",
                       9: "Some connection refused - invalid scid",
                       10: "Some connection refused - scid already allocated",
                       11: "All Connection refused - unacceptable parameters",
                       12: "All connections refused - invalid parameters"}),
                   LEShortField("dcid", 0), ]


class L2CAP_Credit_Based_Reconfigure_Request(Packet):
    name = "L2CAP Credit Based Reconfigure Request"
    fields_desc = [LEShortField("mtu", 0),
                   LEShortField("mps", 0),
                   LEShortField("dcid", 0), ]


class L2CAP_Credit_Based_Reconfigure_Response(Packet):
    name = "L2CAP Credit Based Reconfigure Response"
    fields_desc = [LEShortEnumField("result", 0, {
                   0: "Reconfig successful",
                   1: "Reconfig failed - MTU size reduction not allowed",
                   2: "Reconfig failed - MPS size reduction not allowed",
                   3: "Reconfig failed - one or more dcids invalid",
                   4: "Reconfig failed - unacceptable parameters"}), ]


class ATT_Hdr(Packet):
    name = "ATT header"
    fields_desc = [XByteField("opcode", None), ]


class ATT_Handle(Packet):
    name = "ATT Short Handle"
    fields_desc = [XLEShortField("handle", 0),
                   XLEShortField("value", 0)]

    def extract_padding(self, s):
        return b'', s


class ATT_Handle_UUID128(Packet):
    name = "ATT Handle (UUID 128)"
    fields_desc = [XLEShortField("handle", 0),
                   UUIDField("value", None, uuid_fmt=UUIDField.FORMAT_REV)]

    def extract_padding(self, s):
        return b'', s


class ATT_Error_Response(Packet):
    name = "Error Response"
    fields_desc = [XByteField("request", 0),
                   LEShortField("handle", 0),
                   ByteEnumField("ecode", 0, _att_error_codes), ]


class ATT_Exchange_MTU_Request(Packet):
    name = "Exchange MTU Request"
    fields_desc = [LEShortField("mtu", 0), ]


class ATT_Exchange_MTU_Response(Packet):
    name = "Exchange MTU Response"
    fields_desc = [LEShortField("mtu", 0), ]


class ATT_Find_Information_Request(Packet):
    name = "Find Information Request"
    fields_desc = [XLEShortField("start", 0x0000),
                   XLEShortField("end", 0xffff), ]


class ATT_Find_Information_Response(Packet):
    name = "Find Information Response"
    fields_desc = [
        XByteField("format", 1),
        MultipleTypeField(
            [
                (PacketListField("handles", [], ATT_Handle),
                    lambda pkt: pkt.format == 1),
                (PacketListField("handles", [], ATT_Handle_UUID128),
                    lambda pkt: pkt.format == 2),
            ],
            StrFixedLenField("handles", "", length=0)
        )
    ]


class ATT_Find_By_Type_Value_Request(Packet):
    name = "Find By Type Value Request"
    fields_desc = [XLEShortField("start", 0x0001),
                   XLEShortField("end", 0xffff),
                   XLEShortField("uuid", None),
                   StrField("data", ""), ]


class ATT_Find_By_Type_Value_Response(Packet):
    name = "Find By Type Value Response"
    fields_desc = [PacketListField("handles", [], ATT_Handle)]


class ATT_Read_By_Type_Request_128bit(Packet):
    name = "Read By Type Request"
    fields_desc = [XLEShortField("start", 0x0001),
                   XLEShortField("end", 0xffff),
                   XLELongField("uuid1", None),
                   XLELongField("uuid2", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) == 6:
            return ATT_Read_By_Type_Request
        return ATT_Read_By_Type_Request_128bit


class ATT_Read_By_Type_Request(Packet):
    name = "Read By Type Request"
    fields_desc = [XLEShortField("start", 0x0001),
                   XLEShortField("end", 0xffff),
                   XLEShortField("uuid", None)]


class ATT_Handle_Variable(Packet):
    __slots__ = ["val_length"]
    fields_desc = [XLEShortField("handle", 0),
                   XStrLenField(
                       "value", 0,
                       length_from=lambda pkt: pkt.val_length)]

    def __init__(self, _pkt=b"", val_length=2, **kwargs):
        self.val_length = val_length
        Packet.__init__(self, _pkt, **kwargs)

    def extract_padding(self, s):
        return b"", s


class ATT_Read_By_Type_Response(Packet):
    name = "Read By Type Response"
    fields_desc = [ByteField("len", 4),
                   PacketListField(
                       "handles", [],
                       next_cls_cb=lambda pkt, *args: (
                           pkt._next_cls_cb(pkt, *args)
                       ))]

    @classmethod
    def _next_cls_cb(cls, pkt, lst, p, remain):
        if len(remain) >= pkt.len:
            return functools.partial(
                ATT_Handle_Variable,
                val_length=pkt.len - 2
            )
        return None


class ATT_Read_Request(Packet):
    name = "Read Request"
    fields_desc = [XLEShortField("gatt_handle", 0), ]


class ATT_Read_Response(Packet):
    name = "Read Response"
    fields_desc = [StrField("value", "")]


class ATT_Read_Multiple_Request(Packet):
    name = "Read Multiple Request"
    fields_desc = [FieldListField("handles", [], XLEShortField("", 0))]


class ATT_Read_Multiple_Response(Packet):
    name = "Read Multiple Response"
    fields_desc = [StrField("values", "")]


class ATT_Read_By_Group_Type_Request(Packet):
    name = "Read By Group Type Request"
    fields_desc = [XLEShortField("start", 0),
                   XLEShortField("end", 0xffff),
                   XLEShortField("uuid", 0), ]


class ATT_Read_By_Group_Type_Response(Packet):
    name = "Read By Group Type Response"
    fields_desc = [XByteField("length", 0),
                   StrField("data", ""), ]


class ATT_Write_Request(Packet):
    name = "Write Request"
    fields_desc = [XLEShortField("gatt_handle", 0),
                   StrField("data", ""), ]


class ATT_Write_Command(Packet):
    name = "Write Request"
    fields_desc = [XLEShortField("gatt_handle", 0),
                   StrField("data", ""), ]


class ATT_Write_Response(Packet):
    name = "Write Response"


class ATT_Prepare_Write_Request(Packet):
    name = "Prepare Write Request"
    fields_desc = [
        XLEShortField("gatt_handle", 0),
        LEShortField("offset", 0),
        StrField("data", "")
    ]


class ATT_Prepare_Write_Response(ATT_Prepare_Write_Request):
    name = "Prepare Write Response"


class ATT_Handle_Value_Notification(Packet):
    name = "Handle Value Notification"
    fields_desc = [XLEShortField("gatt_handle", 0),
                   StrField("value", ""), ]


class ATT_Execute_Write_Request(Packet):
    name = "Execute Write Request"
    fields_desc = [
        ByteEnumField("flags", 1, {
            0: "Cancel all prepared writes",
            1: "Immediately write all pending prepared values",
        }),
    ]


class ATT_Execute_Write_Response(Packet):
    name = "Execute Write Response"


class ATT_Read_Blob_Request(Packet):
    name = "Read Blob Request"
    fields_desc = [
        XLEShortField("gatt_handle", 0),
        LEShortField("offset", 0)
    ]


class ATT_Read_Blob_Response(Packet):
    name = "Read Blob Response"
    fields_desc = [
        StrField("value", "")
    ]


class ATT_Handle_Value_Indication(Packet):
    name = "Handle Value Indication"
    fields_desc = [
        XLEShortField("gatt_handle", 0),
        StrField("value", ""),
    ]


class SM_Hdr(Packet):
    name = "SM header"
    fields_desc = [ByteField("sm_command", None)]


class SM_Pairing_Request(Packet):
    name = "Pairing Request"
    fields_desc = [ByteEnumField("iocap", 3, {0: "DisplayOnly", 1: "DisplayYesNo", 2: "KeyboardOnly", 3: "NoInputNoOutput", 4: "KeyboardDisplay"}),  # noqa: E501
                   ByteEnumField("oob", 0, {0: "Not Present", 1: "Present (from remote device)"}),  # noqa: E501
                   BitField("authentication", 0, 8),
                   ByteField("max_key_size", 16),
                   ByteField("initiator_key_distribution", 0),
                   ByteField("responder_key_distribution", 0), ]


class SM_Pairing_Response(Packet):
    name = "Pairing Response"
    fields_desc = [ByteEnumField("iocap", 3, {0: "DisplayOnly", 1: "DisplayYesNo", 2: "KeyboardOnly", 3: "NoInputNoOutput", 4: "KeyboardDisplay"}),  # noqa: E501
                   ByteEnumField("oob", 0, {0: "Not Present", 1: "Present (from remote device)"}),  # noqa: E501
                   BitField("authentication", 0, 8),
                   ByteField("max_key_size", 16),
                   ByteField("initiator_key_distribution", 0),
                   ByteField("responder_key_distribution", 0), ]


class SM_Confirm(Packet):
    name = "Pairing Confirm"
    fields_desc = [StrFixedLenField("confirm", b'\x00' * 16, 16)]


class SM_Random(Packet):
    name = "Pairing Random"
    fields_desc = [StrFixedLenField("random", b'\x00' * 16, 16)]


class SM_Failed(Packet):
    name = "Pairing Failed"
    fields_desc = [XByteField("reason", 0)]


class SM_Encryption_Information(Packet):
    name = "Encryption Information"
    fields_desc = [StrFixedLenField("ltk", b"\x00" * 16, 16), ]


class SM_Master_Identification(Packet):
    name = "Master Identification"
    fields_desc = [XLEShortField("ediv", 0),
                   StrFixedLenField("rand", b'\x00' * 8, 8), ]


class SM_Identity_Information(Packet):
    name = "Identity Information"
    fields_desc = [StrFixedLenField("irk", b'\x00' * 16, 16), ]


class SM_Identity_Address_Information(Packet):
    name = "Identity Address Information"
    fields_desc = [ByteEnumField("atype", 0, {0: "public"}),
                   LEMACField("address", None), ]


class SM_Signing_Information(Packet):
    name = "Signing Information"
    fields_desc = [StrFixedLenField("csrk", b'\x00' * 16, 16), ]


class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [BitField("auth_req", 0, 8), ]


class SM_Public_Key(Packet):
    name = "Public Key"
    fields_desc = [StrFixedLenField("key_x", b'\x00' * 32, 32),
                   StrFixedLenField("key_y", b'\x00' * 32, 32), ]


class SM_DHKey_Check(Packet):
    name = "DHKey Check"
    fields_desc = [StrFixedLenField("dhkey_check", b'\x00' * 16, 16), ]


class EIR_Hdr(Packet):
    name = "EIR Header"
    fields_desc = [
        LenField("len", None, fmt="B", adjust=lambda x: x + 1),  # Add bytes mark  # noqa: E501
        # https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile
        ByteEnumField("type", 0, {
            0x01: "flags",
            0x02: "incomplete_list_16_bit_svc_uuids",
            0x03: "complete_list_16_bit_svc_uuids",
            0x04: "incomplete_list_32_bit_svc_uuids",
            0x05: "complete_list_32_bit_svc_uuids",
            0x06: "incomplete_list_128_bit_svc_uuids",
            0x07: "complete_list_128_bit_svc_uuids",
            0x08: "shortened_local_name",
            0x09: "complete_local_name",
            0x0a: "tx_power_level",
            0x0d: "class_of_device",
            0x0e: "simple_pairing_hash",
            0x0f: "simple_pairing_rand",

            0x10: "sec_mgr_tk",
            0x11: "sec_mgr_oob_flags",
            0x12: "slave_conn_intvl_range",
            0x14: "list_16_bit_svc_sollication_uuids",
            0x15: "list_128_bit_svc_sollication_uuids",
            0x16: "svc_data_16_bit_uuid",
            0x17: "pub_target_addr",
            0x18: "rand_target_addr",
            0x19: "appearance",
            0x1a: "adv_intvl",
            0x1b: "le_addr",
            0x1c: "le_role",
            0x1d: "simple_pairing_hash_256",
            0x1e: "simple_pairing_rand_256",
            0x1f: "list_32_bit_svc_sollication_uuids",

            0x20: "svc_data_32_bit_uuid",
            0x21: "svc_data_128_bit_uuid",
            0x22: "sec_conn_confirm",
            0x23: "sec_conn_rand",
            0x24: "uri",
            0x25: "indoor_positioning",
            0x26: "transport_discovery",
            0x27: "le_supported_features",
            0x28: "channel_map_update",
            0x29: "mesh_pb_adv",
            0x2a: "mesh_message",
            0x2b: "mesh_beacon",

            0x3d: "3d_information",

            0xff: "mfg_specific_data",
        }),
    ]

    def mysummary(self):
        return self.sprintf("EIR %type%")

    def guess_payload_class(self, payload):
        if self.len == 0:
            # For Extended_Inquiry_Response, stop when len=0
            return conf.padding_layer
        return super(EIR_Hdr, self).guess_payload_class(payload)


class EIR_Element(Packet):
    name = "EIR Element"

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        return b'', s

    @staticmethod
    def length_from(pkt):
        if not pkt.underlayer:
            warning("Missing an upper-layer")
            return 0
        # 'type' byte is included in the length, so subtract 1:
        return pkt.underlayer.len - 1


class EIR_Raw(EIR_Element):
    name = "EIR Raw"
    fields_desc = [
        StrLenField("data", "", length_from=EIR_Element.length_from)
    ]


class EIR_Flags(EIR_Element):
    name = "Flags"
    fields_desc = [
        FlagsField("flags", 0x2, 8,
                   ["limited_disc_mode", "general_disc_mode",
                    "br_edr_not_supported", "simul_le_br_edr_ctrl",
                    "simul_le_br_edr_host"] + 3 * ["reserved"])
    ]


class EIR_CompleteList16BitServiceUUIDs(EIR_Element):
    name = "Complete list of 16-bit service UUIDs"
    fields_desc = [
        # https://www.bluetooth.com/specifications/assigned-numbers/16-bit-uuids-for-members
        FieldListField("svc_uuids", None, XLEShortField("uuid", 0),
                       length_from=EIR_Element.length_from)
    ]


class EIR_IncompleteList16BitServiceUUIDs(EIR_CompleteList16BitServiceUUIDs):
    name = "Incomplete list of 16-bit service UUIDs"


class EIR_CompleteList32BitServiceUUIDs(EIR_Element):
    name = 'Complete list of 32-bit service UUIDs'
    fields_desc = [
        # https://www.bluetooth.com/specifications/assigned-numbers
        FieldListField('svc_uuids', None, XLEIntField('uuid', 0),
                       length_from=EIR_Element.length_from)
    ]


class EIR_IncompleteList32BitServiceUUIDs(EIR_CompleteList32BitServiceUUIDs):
    name = 'Incomplete list of 32-bit service UUIDs'


class EIR_CompleteList128BitServiceUUIDs(EIR_Element):
    name = "Complete list of 128-bit service UUIDs"
    fields_desc = [
        FieldListField("svc_uuids", None,
                       UUIDField("uuid", None, uuid_fmt=UUIDField.FORMAT_REV),
                       length_from=EIR_Element.length_from)
    ]


class EIR_IncompleteList128BitServiceUUIDs(EIR_CompleteList128BitServiceUUIDs):
    name = "Incomplete list of 128-bit service UUIDs"


class EIR_CompleteLocalName(EIR_Element):
    name = "Complete Local Name"
    fields_desc = [
        StrLenField("local_name", "", length_from=EIR_Element.length_from)
    ]


class EIR_ShortenedLocalName(EIR_CompleteLocalName):
    name = "Shortened Local Name"


class EIR_TX_Power_Level(EIR_Element):
    name = "TX Power Level"
    fields_desc = [SignedByteField("level", 0)]


class EIR_ClassOfDevice(EIR_Element):
    name = 'Class of device'
    fields_desc = [
        FlagsField('major_service_classes', 0, 11, [
            'limited_discoverable_mode',
            'le_audio',
            'reserved',
            'positioning',
            'networking',
            'rendering',
            'capturing',
            'object_transfer',
            'audio',
            'telephony',
            'information'
        ], tot_size=-3),
        BitEnumField('major_device_class', 0, 5, {
            0x00: 'miscellaneous',
            0x01: 'computer',
            0x02: 'phone',
            0x03: 'lan',
            0x04: 'audio_video',
            0x05: 'peripheral',
            0x06: 'imaging',
            0x07: 'wearable',
            0x08: 'toy',
            0x09: 'health',
            0x1f: 'uncategorized'
        }),
        BitField('minor_device_class', 0, 6),
        BitField('fixed', 0, 2, end_tot_size=-3)
    ]


class EIR_SecureSimplePairingHashC192(EIR_Element):
    name = 'Secure Simple Pairing Hash C-192'
    fields_desc = [NBytesField('hash', 0, 16)]


class EIR_SecureSimplePairingRandomizerR192(EIR_Element):
    name = 'Secure Simple Pairing Randomizer R-192'
    fields_desc = [NBytesField('randomizer', 0, 16)]


class EIR_SecurityManagerOOBFlags(EIR_Element):
    name = 'Security Manager Out of Band Flags'
    fields_desc = [
        BitField('oob_flags_field', 0, 1),
        BitField('le_supported', 0, 1),
        BitField('previously_used', 0, 1),
        BitField('address_type', 0, 1),
        BitField('reserved', 0, 4)
    ]


class EIR_PeripheralConnectionIntervalRange(EIR_Element):
    name = 'Peripheral Connection Interval Range'
    fields_desc = [
        LEShortField('conn_interval_min', 0xFFFF),
        LEShortField('conn_interval_max', 0xFFFF)
    ]


class EIR_Manufacturer_Specific_Data(EIR_Element):
    name = "EIR Manufacturer Specific Data"
    deprecated_fields = {
        "company_id": ("company_identifier", "2.6.2"),
    }
    fields_desc = [
        # https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers
        LEShortEnumField("company_identifier", None,
                         BLUETOOTH_CORE_COMPANY_IDENTIFIERS),
    ]

    registered_magic_payloads = {}

    @classmethod
    def register_magic_payload(cls, payload_cls, magic_check=None):
        """
        Registers a payload type that uses magic data.

        Traditional payloads require registration of a Bluetooth Company ID
        (requires company membership of the Bluetooth SIG), or a Bluetooth
        Short UUID (requires a once-off payment).

        There are alternatives which don't require registration (such as
        128-bit UUIDs), but the biggest consumer of energy in a beacon is the
        radio -- so the energy consumption of a beacon is proportional to the
        number of bytes in a beacon frame.

        Some beacon formats side-step this issue by using the Company ID of
        their beacon hardware manufacturer, and adding a "magic data sequence"
        at the start of the Manufacturer Specific Data field.

        Examples of this are AltBeacon and GeoBeacon.

        For an example of this method in use, see ``scapy.contrib.altbeacon``.

        :param Type[scapy.packet.Packet] payload_cls:
            A reference to a Packet subclass to register as a payload.
        :param Callable[[bytes], bool] magic_check:
            (optional) callable to use to if a payload should be associated
            with this type. If not supplied, ``payload_cls.magic_check`` is
            used instead.
        :raises TypeError: If ``magic_check`` is not specified,
                           and ``payload_cls.magic_check`` is not implemented.
        """
        if magic_check is None:
            if hasattr(payload_cls, "magic_check"):
                magic_check = payload_cls.magic_check
            else:
                raise TypeError("magic_check not specified, and {} has no "
                                "attribute magic_check".format(payload_cls))

        cls.registered_magic_payloads[payload_cls] = magic_check

    def default_payload_class(self, payload):
        for cls, check in (
            EIR_Manufacturer_Specific_Data.registered_magic_payloads.items()
        ):
            if check(payload):
                return cls

        return Packet.default_payload_class(self, payload)

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        plen = EIR_Element.length_from(self) - 2
        return s[:plen], s[plen:]


class EIR_Device_ID(EIR_Element):
    name = "Device ID"
    fields_desc = [
        XLEShortField("vendor_id_source", 0),
        XLEShortField("vendor_id", 0),
        XLEShortField("product_id", 0),
        XLEShortField("version", 0),
    ]


class EIR_ServiceSolicitation16BitUUID(EIR_Element):
    name = "EIR Service Solicitation - 16-bit UUID"
    fields_desc = [
        XLEShortField("svc_uuid", None)
    ]

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        plen = EIR_Element.length_from(self) - 2
        return s[:plen], s[plen:]


class EIR_ServiceSolicitation128BitUUID(EIR_Element):
    name = "EIR Service Solicitation - 128-bit UUID"
    fields_desc = [
        UUIDField('svc_uuid', None, uuid_fmt=UUIDField.FORMAT_REV)
    ]

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        plen = EIR_Element.length_from(self) - 2
        return s[:plen], s[plen:]


class EIR_ServiceData16BitUUID(EIR_Element):
    name = "EIR Service Data - 16-bit UUID"
    fields_desc = [
        # https://www.bluetooth.com/specifications/assigned-numbers/16-bit-uuids-for-members
        XLEShortField("svc_uuid", None),
    ]

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        plen = EIR_Element.length_from(self) - 2
        return s[:plen], s[plen:]


class EIR_PublicTargetAddress(EIR_Element):
    name = "Public Target Address"
    fields_desc = [
        LEMACField('bd_addr', None)
    ]


class EIR_AdvertisingInterval(EIR_Element):
    name = "Advertising Interval"
    fields_desc = [
        MultipleTypeField(
            [
                (ByteField("advertising_interval", 0),
                 lambda p: p.underlayer.len - 1 == 1),
                (LEShortField("advertising_interval", 0),
                 lambda p: p.underlayer.len - 1 == 2),
                (LEThreeBytesField("advertising_interval", 0),
                 lambda p: p.underlayer.len - 1 == 3),
                (LEIntField("advertising_interval", 0),
                 lambda p: p.underlayer.len - 1 == 4),
            ],
            LEShortField("advertising_interval", 0)
        )
    ]


class EIR_LEBluetoothDeviceAddress(EIR_Element):
    name = "LE Bluetooth Device Address"
    fields_desc = [
        XBitField('reserved', 0, 7, tot_size=-1),
        BitEnumField('addr_type', 0, 1, end_tot_size=-1, enum={
            0x0: 'Public',
            0x1: 'Random'
        }),
        LEMACField('bd_addr', None)
    ]


class EIR_Appearance(EIR_Element):
    name = "EIR_Appearance"
    fields_desc = [
        BitEnumField('category', 0, 10, tot_size=-2, enum={
            0x000: 'Unknown',
            0x001: 'Phone',
            0x002: 'Computer',
            0x003: 'Watch',
            0x004: 'Clock',
            0x005: 'Display',
            0x006: 'Remote Control',
            0x007: 'Eyeglasses',
            0x008: 'Tag',
            0x009: 'Keyring',
            0x00A: 'Media Player',
            0x00B: 'Barcode Scanner',
            0x00C: 'Thermometer',
            0x00D: 'Heart Rate Sensor',
            0x00E: 'Blood Pressure',
            0x00F: 'Human Interface Device',
            0x010: 'Glucose Meter',
            0x011: 'Running Walking Sensor',
            0x012: 'Cycling',
            0x013: 'Control Device',
            0x014: 'Network Device',
            0x015: 'Sensor',
            0x016: 'Light Fixtures',
            0x017: 'Fan',
            0x018: 'HVAC',
            0x019: 'Air Conditioning',
            0x01A: 'Humidifier',
            0x01B: 'Heating',
            0x01C: 'Access Control',
            0x01D: 'Motorized Device',
            0x01E: 'Power Device',
            0x01F: 'Light Source',
            0x020: 'Window Covering',
            0x021: 'Audio Sink',
            0x022: 'Audio Source',
            0x023: 'Motorized Vehicle',
            0x024: 'Domestic Appliance',
            0x025: 'Wearable Audio Device',
            0x026: 'Aircraft',
            0x027: 'AV Equipment',
            0x028: 'Display Equipment',
            0x029: 'Hearing aid',
            0x02A: 'Gaming',
            0x02B: 'Signage',
            0x031: 'Pulse Oximeter',
            0x032: 'Weight Scale',
            0x033: 'Personal Mobility Device',
            0x034: 'Continuous Glucose Monitor',
            0x035: 'Insulin Pump',
            0x036: 'Medication Delivery',
            0x037: 'Spirometer',
            0x051: 'Outdoor Sports Activity'
        }),
        XBitField('subcategory', 0, 6, end_tot_size=-2)
    ]

    @property
    def appearance(self):
        return (self.category << 6) + self.subcategory


class EIR_ServiceData32BitUUID(EIR_Element):
    name = 'EIR Service Data - 32-bit UUID'
    fields_desc = [
        XLEIntField('svc_uuid', 0),
    ]

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        plen = EIR_Element.length_from(self) - 4
        return s[:plen], s[plen:]


class EIR_ServiceData128BitUUID(EIR_Element):
    name = 'EIR Service Data - 128-bit UUID'
    fields_desc = [
        UUIDField('svc_uuid', None, uuid_fmt=UUIDField.FORMAT_REV)
    ]

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        plen = EIR_Element.length_from(self) - 16
        return s[:plen], s[plen:]


class EIR_URI(EIR_Element):
    name = 'EIR URI'
    fields_desc = [
        ByteEnumField('scheme', 0, {
            0x01: '',
            0x02: 'aaa:',
            0x03: 'aaas:',
            0x04: 'about:',
            0x05: 'acap:',
            0x06: 'acct:',
            0x07: 'cap:',
            0x08: 'cid:',
            0x09: 'coap:',
            0x0A: 'coaps:',
            0x0B: 'crid:',
            0x0C: 'data:',
            0x0D: 'dav:',
            0x0E: 'dict:',
            0x0F: 'dns:',
            0x10: 'file:',
            0x11: 'ftp:',
            0x12: 'geo:',
            0x13: 'go:',
            0x14: 'gopher:',
            0x15: 'h323:',
            0x16: 'http:',
            0x17: 'https:',
            0x18: 'iax:',
            0x19: 'icap:',
            0x1A: 'im:',
            0x1B: 'imap:',
            0x1C: 'info:',
            0x1D: 'ipp:',
            0x1E: 'ipps:',
            0x1F: 'iris:',
            0x20: 'iris.beep:',
            0x21: 'iris.xpc:',
            0x22: 'iris.xpcs:',
            0x23: 'iris.lwz:',
            0x24: 'jabber:',
            0x25: 'ldap:',
            0x26: 'mailto:',
            0x27: 'mid:',
            0x28: 'msrp:',
            0x29: 'msrps:',
            0x2A: 'mtqp:',
            0x2B: 'mupdate:',
            0x2C: 'news:',
            0x2D: 'nfs:',
            0x2E: 'ni:',
            0x2F: 'nih:',
            0x30: 'nntp:',
            0x31: 'opaquelocktoken:',
            0x32: 'pop:',
            0x33: 'pres:',
            0x34: 'reload:',
            0x35: 'rtsp:',
            0x36: 'rtsps:',
            0x37: 'rtspu:',
            0x38: 'service:',
            0x39: 'session:',
            0x3A: 'shttp:',
            0x3B: 'sieve:',
            0x3C: 'sip:',
            0x3D: 'sips:',
            0x3E: 'sms:',
            0x3F: 'snmp:',
            0x40: 'soap.beep:',
            0x41: 'soap.beeps:',
            0x42: 'stun:',
            0x43: 'stuns:',
            0x44: 'tag:',
            0x45: 'tel:',
            0x46: 'telnet:',
            0x47: 'tftp:',
            0x48: 'thismessage:',
            0x49: 'tn3270:',
            0x4A: 'tip:',
            0x4B: 'turn:',
            0x4C: 'turns:',
            0x4D: 'tv:',
            0x4E: 'urn:',
            0x4F: 'vemmi:',
            0x50: 'ws:',
            0x51: 'wss:',
            0x52: 'xcon:',
            0x53: 'xconuserid:',
            0x54: 'xmlrpc.beep:',
            0x55: 'xmlrpc.beeps:',
            0x56: 'xmpp:',
            0x57: 'z39.50r:',
            0x58: 'z39.50s:',
            0x59: 'acr:',
            0x5A: 'adiumxtra:',
            0x5B: 'afp:',
            0x5C: 'afs:',
            0x5D: 'aim:',
            0x5E: 'apt:',
            0x5F: 'attachment:',
            0x60: 'aw:',
            0x61: 'barion:',
            0x62: 'beshare:',
            0x63: 'bitcoin:',
            0x64: 'bolo:',
            0x65: 'callto:',
            0x66: 'chrome:',
            0x67: 'chromeextension:',
            0x68: 'comeventbriteattendee:',
            0x69: 'content:',
            0x6A: 'cvs:',
            0x6B: 'dlnaplaysingle:',
            0x6C: 'dlnaplaycontainer:',
            0x6D: 'dtn:',
            0x6E: 'dvb:',
            0x6F: 'ed2k:',
            0x70: 'facetime:',
            0x71: 'feed:',
            0x72: 'feedready:',
            0x73: 'finger:',
            0x74: 'fish:',
            0x75: 'gg:',
            0x76: 'git:',
            0x77: 'gizmoproject:',
            0x78: 'gtalk:',
            0x79: 'ham:',
            0x7A: 'hcp:',
            0x7B: 'icon:',
            0x7C: 'ipn:',
            0x7D: 'irc:',
            0x7E: 'irc6:',
            0x7F: 'ircs:',
            0x80: 'itms:',
            0x81: 'jar:',
            0x82: 'jms:',
            0x83: 'keyparc:',
            0x84: 'lastfm:',
            0x85: 'ldaps:',
            0x86: 'magnet:',
            0x87: 'maps:',
            0x88: 'market:',
            0x89: 'message:',
            0x8A: 'mms:',
            0x8B: 'mshelp:',
            0x8C: 'mssettingspower:',
            0x8D: 'msnim:',
            0x8E: 'mumble:',
            0x8F: 'mvn:',
            0x90: 'notes:',
            0x91: 'oid:',
            0x92: 'palm:',
            0x93: 'paparazzi:',
            0x94: 'pkcs11:',
            0x95: 'platform:',
            0x96: 'proxy:',
            0x97: 'psyc:',
            0x98: 'query:',
            0x99: 'res:',
            0x9A: 'resource:',
            0x9B: 'rmi:',
            0x9C: 'rsync:',
            0x9D: 'rtmfp:',
            0x9E: 'rtmp:',
            0x9F: 'secondlife:',
            0xA0: 'sftp:',
            0xA1: 'sgn:',
            0xA2: 'skype:',
            0xA3: 'smb:',
            0xA4: 'smtp:',
            0xA5: 'soldat:',
            0xA6: 'spotify:',
            0xA7: 'ssh:',
            0xA8: 'steam:',
            0xA9: 'submit:',
            0xAA: 'svn:',
            0xAB: 'teamspeak:',
            0xAC: 'teliaeid:',
            0xAD: 'things:',
            0xAE: 'udp:',
            0xAF: 'unreal:',
            0xB0: 'ut2004:',
            0xB1: 'ventrilo:',
            0xB2: 'viewsource:',
            0xB3: 'webcal:',
            0xB4: 'wtai:',
            0xB5: 'wyciwyg:',
            0xB6: 'xfire:',
            0xB7: 'xri:',
            0xB8: 'ymsgr:',
            0xB9: 'example:',
            0xBA: 'mssettingscloudstorage:'
        }),
        StrLenField('uri_hier_part', None, length_from=EIR_Element.length_from)
    ]

    @property
    def uri(self):
        return EIR_URI.scheme.i2s[self.scheme] + self.uri_hier_part.decode('utf-8')


class HCI_Command_Hdr(Packet):
    name = "HCI Command header"
    fields_desc = [XBitField("ogf", 0, 6, tot_size=-2),
                   XBitField("ocf", 0, 10, end_tot_size=-2),
                   LenField("len", None, fmt="B"), ]

    def answers(self, other):
        return False

    @property
    def opcode(self):
        return (self.ogf << 10) + self.ocf

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            p = p[:2] + struct.pack("B", len(pay)) + p[3:]
        return p


# BUETOOTH CORE SPECIFICATION 5.4 | Vol 3, Part C
# 8 EXTENDED INQUIRY RESPONSE

class HCI_Extended_Inquiry_Response(Packet):
    fields_desc = [
        PadField(
            PacketListField(
                "eir_data", [],
                next_cls_cb=lambda *args: (
                    (not args[2] or args[2].len != 0) and EIR_Hdr or conf.raw_layer
                )
            ),
            align=31, padwith=b"\0",
        ),
    ]


# BLUETOOTH CORE SPECIFICATION Version 5.4 | Vol 4, Part E
# 7 HCI COMMANDS AND EVENTS
# 7.1 LINK CONTROL COMMANDS, the OGF is defined as 0x01

class HCI_Cmd_Inquiry(Packet):
    """
    7.1.1 Inquiry command
    """
    name = "HCI_Inquiry"
    fields_desc = [XLE3BytesField("lap", 0x9E8B33),
                   ByteField("inquiry_length", 0),
                   ByteField("num_responses", 0)]


class HCI_Cmd_Inquiry_Cancel(Packet):
    """
    7.1.2 Inquiry Cancel command
    """
    name = "HCI_Inquiry_Cancel"


class HCI_Cmd_Periodic_Inquiry_Mode(Packet):
    """
    7.1.3 Periodic Inquiry Mode command
    """
    name = "HCI_Periodic_Inquiry_Mode"
    fields_desc = [LEShortField("max_period_length", 0x0003),
                   LEShortField("min_period_length", 0x0002),
                   XLE3BytesField("lap", 0x9E8B33),
                   ByteField("inquiry_length", 0),
                   ByteField("num_responses", 0)]


class HCI_Cmd_Exit_Peiodic_Inquiry_Mode(Packet):
    """
    7.1.4 Exit Periodic Inquiry Mode command
    """
    name = "HCI_Exit_Periodic_Inquiry_Mode"


class HCI_Cmd_Create_Connection(Packet):
    """
    7.1.5 Create Connection command
    """
    name = "HCI_Create_Connection"
    fields_desc = [LEMACField("bd_addr", None),
                   LEShortField("packet_type", 0xcc18),
                   ByteField("page_scan_repetition_mode", 0x02),
                   ByteField("reserved", 0x0),
                   LEShortField("clock_offset", 0x0),
                   ByteField("allow_role_switch", 0x1), ]


class HCI_Cmd_Disconnect(Packet):
    """
    7.1.6 Disconnect command
    """
    name = "HCI_Disconnect"
    fields_desc = [XLEShortField("handle", 0),
                   ByteField("reason", 0x13), ]


class HCI_Cmd_Create_Connection_Cancel(Packet):
    """
    7.1.7 Create Connection Cancel command
    """
    name = "HCI_Create_Connection_Cancel"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_Accept_Connection_Request(Packet):
    """
    7.1.8 Accept Connection Request command
    """
    name = "HCI_Accept_Connection_Request"
    fields_desc = [LEMACField("bd_addr", None),
                   ByteField("role", 0x1), ]


class HCI_Cmd_Reject_Connection_Response(Packet):
    """
    7.1.9 Reject Connection Request command
    """
    name = "HCI_Reject_Connection_Response"
    fields_desc = [LEMACField("bd_addr", None),
                   ByteField("reason", 0x1), ]


class HCI_Cmd_Link_Key_Request_Reply(Packet):
    """
    7.1.10 Link Key Request Reply command
    """
    name = "HCI_Link_Key_Request_Reply"
    fields_desc = [LEMACField("bd_addr", None),
                   NBytesField("link_key", None, 16), ]


class HCI_Cmd_Link_Key_Request_Negative_Reply(Packet):
    """
    7.1.11 Link Key Request Negative Reply command
    """
    name = "HCI_Link_Key_Request_Negative_Reply"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_PIN_Code_Request_Reply(Packet):
    """
    7.1.12 PIN Code Request Reply command
    """
    name = "HCI_PIN_Code_Request_Reply"
    fields_desc = [LEMACField("bd_addr", None),
                   ByteField("pin_code_length", 7),
                   NBytesField("pin_code", b"\x00" * 16, sz=16), ]


class HCI_Cmd_PIN_Code_Request_Negative_Reply(Packet):
    """
    7.1.13 PIN Code Request Negative Reply command
    """
    name = "HCI_PIN_Code_Request_Negative_Reply"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_Change_Connection_Packet_Type(Packet):
    """
    7.1.14 Change Connection Packet Type command
    """
    name = "HCI_Cmd_Change_Connection_Packet_Type"
    fields_desc = [XLEShortField("connection_handle", None),
                   LEShortField("packet_type", 0), ]


class HCI_Cmd_Authentication_Requested(Packet):
    """
    7.1.15 Authentication Requested command
    """
    name = "HCI_Authentication_Requested"
    fields_desc = [LEShortField("handle", 0)]


class HCI_Cmd_Set_Connection_Encryption(Packet):
    """
    7.1.16 Set Connection Encryption command
    """
    name = "HCI_Set_Connection_Encryption"
    fields_desc = [LEShortField("handle", 0), ByteField("encryption_enable", 0)]


class HCI_Cmd_Change_Connection_Link_Key(Packet):
    """
    7.1.17 Change Connection Link Key command
    """
    name = "HCI_Change_Connection_Link_Key"
    fields_desc = [LEShortField("handle", 0), ]


class HCI_Cmd_Link_Key_Selection(Packet):
    """
    7.1.18 Change Connection Link Key command
    """
    name = "HCI_Cmd_Link_Key_Selection"
    fields_desc = [ByteEnumField("handle", 0, {0: "Use semi-permanent Link Keys",
                                               1: "Use Temporary Link Key", }), ]


class HCI_Cmd_Remote_Name_Request(Packet):
    """
    7.1.19 Remote Name Request command
    """
    name = "HCI_Remote_Name_Request"
    fields_desc = [LEMACField("bd_addr", None),
                   ByteField("page_scan_repetition_mode", 0x02),
                   ByteField("reserved", 0x0),
                   LEShortField("clock_offset", 0x0), ]


class HCI_Cmd_Remote_Name_Request_Cancel(Packet):
    """
    7.1.20 Remote Name Request Cancel command
    """
    name = "HCI_Remote_Name_Request_Cancel"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_Read_Remote_Supported_Features(Packet):
    """
    7.1.21 Read Remote Supported Features command
    """
    name = "HCI_Read_Remote_Supported_Features"
    fields_desc = [LEShortField("connection_handle", None), ]


class HCI_Cmd_Read_Remote_Extended_Features(Packet):
    """
    7.1.22 Read Remote Extended Features command
    """
    name = "HCI_Read_Remote_Supported_Features"
    fields_desc = [LEShortField("connection_handle", None),
                   ByteField("page_number", None), ]


class HCI_Cmd_IO_Capability_Request_Reply(Packet):
    """
    7.1.29 IO Capability Request Reply command
    """
    name = "HCI_Read_Remote_Supported_Features"
    fields_desc = [LEMACField("bd_addr", None),
                   ByteEnumField("io_capability", None, {0x00: "DisplayOnly",
                                                         0x01: "DisplayYesNo",
                                                         0x02: "KeyboardOnly",
                                                         0x03: "NoInputNoOutput", }),
                   ByteEnumField("oob_data_present", None, {0x00: "Not Present",
                                                            0x01: "P-192",
                                                            0x02: "P-256",
                                                            0x03: "P-192 + P-256", }),
                   ByteEnumField("authentication_requirement", None,
                                 {0x00: "MITM Not Required",
                                  0x01: "MITM Required, No Bonding",
                                  0x02: "MITM Not Required + Dedicated Pairing",
                                  0x03: "MITM Required + Dedicated Pairing",
                                  0x04: "MITM Not Required, General Bonding",
                                  0x05: "MITM Required + General Bonding"}), ]


class HCI_Cmd_User_Confirmation_Request_Reply(Packet):
    """
    7.1.30 User Confirmation Request Reply command
    """
    name = "HCI_User_Confirmation_Request_Reply"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_User_Confirmation_Request_Negative_Reply(Packet):
    """
    7.1.31 User Confirmation Request Negative Reply command
    """
    name = "HCI_User_Confirmation_Request_Negative_Reply"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_User_Passkey_Request_Reply(Packet):
    """
    7.1.32 User Passkey Request Reply command
    """
    name = "HCI_User_Passkey_Request_Reply"
    fields_desc = [LEMACField("bd_addr", None),
                   LEIntField("numeric_value", None), ]


class HCI_Cmd_User_Passkey_Request_Negative_Reply(Packet):
    """
    7.1.33 User Passkey Request Negative Reply command
    """
    name = "HCI_User_Passkey_Request_Negative_Reply"
    fields_desc = [LEMACField("bd_addr", None), ]


class HCI_Cmd_Remote_OOB_Data_Request_Reply(Packet):
    """
    7.1.34 Remote OOB Data Request Reply command
    """
    name = "HCI_Remote_OOB_Data_Request_Reply"
    fields_desc = [LEMACField("bd_addr", None),
                   NBytesField("C", b"\x00" * 16, sz=16),
                   NBytesField("R", b"\x00" * 16, sz=16), ]


class HCI_Cmd_Remote_OOB_Data_Request_Negative_Reply(Packet):
    """
    7.1.35 Remote OOB Data Request Negative Reply command
    """
    name = "HCI_Remote_OOB_Data_Request_Negative_Reply"
    fields_desc = [LEMACField("bd_addr", None), ]


# 7.2 Link Policy commands, the OGF is defined as 0x02

class HCI_Cmd_Hold_Mode(Packet):
    name = "HCI_Hold_Mode"
    fields_desc = [LEShortField("connection_handle", 0),
                   LEShortField("hold_mode_max_interval", 0x0002),
                   LEShortField("hold_mode_min_interval", 0x0002), ]


# 7.3 CONTROLLER & BASEBAND COMMANDS, the OGF is defined as 0x03

class HCI_Cmd_Set_Event_Mask(Packet):
    """
    7.3.1 Set Event Mask command
    """
    name = "HCI_Set_Event_Mask"
    fields_desc = [StrFixedLenField("mask", b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d", 8)]  # noqa: E501


class HCI_Cmd_Reset(Packet):
    """
    7.3.2 Reset command
    """
    name = "HCI_Reset"


class HCI_Cmd_Set_Event_Filter(Packet):
    """
    7.3.3 Set Event Filter command
    """
    name = "HCI_Set_Event_Filter"
    fields_desc = [ByteEnumField("type", 0, {0: "clear"}), ]


class HCI_Cmd_Write_Local_Name(Packet):
    """
    7.3.11 Write Local Name command
    """
    name = "HCI_Write_Local_Name"
    fields_desc = [StrFixedLenField('name', '', length=248)]


class HCI_Cmd_Read_Local_Name(Packet):
    """
    7.3.12 Read Local Name command
    """
    name = "HCI_Read_Local_Name"


class HCI_Cmd_Write_Connect_Accept_Timeout(Packet):
    name = "HCI_Write_Connection_Accept_Timeout"
    fields_desc = [LEShortField("timeout", 32000)]  # 32000 slots is 20000 msec


class HCI_Cmd_Write_Extended_Inquiry_Response(Packet):
    name = "HCI_Write_Extended_Inquiry_Response"
    fields_desc = [ByteField("fec_required", 0),
                   HCI_Extended_Inquiry_Response]


class HCI_Cmd_Read_LE_Host_Support(Packet):
    name = "HCI_Read_LE_Host_Support"


class HCI_Cmd_Write_LE_Host_Support(Packet):
    name = "HCI_Write_LE_Host_Support"
    fields_desc = [ByteField("supported", 1),
                   ByteField("unused", 1), ]


# 7.4 INFORMATIONAL PARAMETERS, the OGF is defined as 0x04

class HCI_Cmd_Read_Local_Version_Information(Packet):
    """
    7.4.1 Read Local Version Information command
    """
    name = "HCI_Read_Local_Version_Information"


class HCI_Cmd_Read_Local_Extended_Features(Packet):
    """
    7.4.4 Read Local Extended Features command
    """
    name = "HCI_Read_Local_Extended_Features"
    fields_desc = [ByteField("page_number", 0)]


class HCI_Cmd_Read_BD_Addr(Packet):
    """
    7.4.6 Read BD_ADDR command
    """
    name = "HCI_Read_BD_ADDR"


# 7.5 STATUS PARAMETERS, the OGF is defined as 0x05

class HCI_Cmd_Read_Link_Quality(Packet):
    name = "HCI_Read_Link_Quality"
    fields_desc = [LEShortField("handle", 0)]


class HCI_Cmd_Read_RSSI(Packet):
    name = "HCI_Read_RSSI"
    fields_desc = [LEShortField("handle", 0)]


# 7.6 TESTING COMMANDS, the OGF is defined as 0x06

class HCI_Cmd_Read_Loopback_Mode(Packet):
    name = "HCI_Read_Loopback_Mode"


class HCI_Cmd_Write_Loopback_Mode(Packet):
    name = "HCI_Write_Loopback_Mode"
    fields_desc = [ByteEnumField("loopback_mode", 0,
                                 {0: "no loopback",
                                  1: "enable local loopback",
                                  2: "enable remote loopback"})]


# 7.8 LE CONTROLLER COMMANDS, the OGF code is defined as 0x08

class HCI_Cmd_LE_Read_Buffer_Size_V1(Packet):
    name = "HCI_LE_Read_Buffer_Size [v1]"


class HCI_Cmd_LE_Read_Buffer_Size_V2(Packet):
    name = "HCI_LE_Read_Buffer_Size [v2]"


class HCI_Cmd_LE_Read_Local_Supported_Features(Packet):
    name = "HCI_LE_Read_Local_Supported_Features"


class HCI_Cmd_LE_Set_Random_Address(Packet):
    name = "HCI_LE_Set_Random_Address"
    fields_desc = [LEMACField("address", None)]


class HCI_Cmd_LE_Set_Advertising_Parameters(Packet):
    name = "HCI_LE_Set_Advertising_Parameters"
    fields_desc = [LEShortField("interval_min", 0x0800),
                   LEShortField("interval_max", 0x0800),
                   ByteEnumField("adv_type", 0, {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_SCAN_IND", 3: "ADV_NONCONN_IND", 4: "ADV_DIRECT_IND_LOW"}),  # noqa: E501
                   ByteEnumField("oatype", 0, {0: "public", 1: "random"}),
                   ByteEnumField("datype", 0, {0: "public", 1: "random"}),
                   LEMACField("daddr", None),
                   ByteField("channel_map", 7),
                   ByteEnumField("filter_policy", 0, {0: "all:all", 1: "connect:all scan:whitelist", 2: "connect:whitelist scan:all", 3: "all:whitelist"}), ]  # noqa: E501


class HCI_Cmd_LE_Set_Advertising_Data(Packet):
    name = "HCI_LE_Set_Advertising_Data"
    fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
                   PadField(
                       PacketListField("data", [], EIR_Hdr,
                                       length_from=lambda pkt: pkt.len),
                       align=31, padwith=b"\0"), ]


class HCI_Cmd_LE_Set_Scan_Response_Data(Packet):
    name = "HCI_LE_Set_Scan_Response_Data"
    fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
                   StrLenField("data", "", length_from=lambda pkt: pkt.len), ]


class HCI_Cmd_LE_Set_Advertise_Enable(Packet):
    name = "HCI_LE_Set_Advertising_Enable"
    fields_desc = [ByteField("enable", 0)]


class HCI_Cmd_LE_Set_Scan_Parameters(Packet):
    name = "HCI_LE_Set_Scan_Parameters"
    fields_desc = [ByteEnumField("type", 0, {0: "passive", 1: "active"}),
                   XLEShortField("interval", 16),
                   XLEShortField("window", 16),
                   ByteEnumField("atype", 0, {0: "public",
                                              1: "random",
                                              2: "rpa (pub)",
                                              3: "rpa (random)"}),
                   ByteEnumField("policy", 0, {0: "all", 1: "whitelist"})]


class HCI_Cmd_LE_Set_Scan_Enable(Packet):
    name = "HCI_LE_Set_Scan_Enable"
    fields_desc = [ByteField("enable", 1),
                   ByteField("filter_dups", 1), ]


class HCI_Cmd_LE_Create_Connection(Packet):
    name = "HCI_LE_Create_Connection"
    fields_desc = [LEShortField("interval", 96),
                   LEShortField("window", 48),
                   ByteEnumField("filter", 0, {0: "address"}),
                   ByteEnumField("patype", 0, {0: "public", 1: "random"}),
                   LEMACField("paddr", None),
                   ByteEnumField("atype", 0, {0: "public", 1: "random"}),
                   LEShortField("min_interval", 40),
                   LEShortField("max_interval", 56),
                   LEShortField("latency", 0),
                   LEShortField("timeout", 42),
                   LEShortField("min_ce", 0),
                   LEShortField("max_ce", 0), ]


class HCI_Cmd_LE_Create_Connection_Cancel(Packet):
    name = "HCI_LE_Create_Connection_Cancel"


class HCI_Cmd_LE_Read_Filter_Accept_List_Size(Packet):
    name = "HCI_LE_Read_Filter_Accept_List_Size"


class HCI_Cmd_LE_Clear_Filter_Accept_List(Packet):
    name = "HCI_LE_Clear_Filter_Accept_List"


class HCI_Cmd_LE_Add_Device_To_Filter_Accept_List(Packet):
    name = "HCI_LE_Add_Device_To_Filter_Accept_List"
    fields_desc = [ByteEnumField("address_type", 0, {0: "public",
                                                     1: "random",
                                                     0xff: "anonymous"}),
                   LEMACField("address", None)]


class HCI_Cmd_LE_Remove_Device_From_Filter_Accept_List(HCI_Cmd_LE_Add_Device_To_Filter_Accept_List):  # noqa: E501
    name = "HCI_LE_Remove_Device_From_Filter_Accept_List"


class HCI_Cmd_LE_Connection_Update(Packet):
    name = "HCI_LE_Connection_Update"
    fields_desc = [XLEShortField("handle", 0),
                   XLEShortField("min_interval", 0),
                   XLEShortField("max_interval", 0),
                   XLEShortField("latency", 0),
                   XLEShortField("timeout", 0),
                   LEShortField("min_ce", 0),
                   LEShortField("max_ce", 0xffff), ]


class HCI_Cmd_LE_Read_Remote_Features(Packet):
    name = "HCI_LE_Read_Remote_Features"
    fields_desc = [LEShortField("handle", 64)]


class HCI_Cmd_LE_Enable_Encryption(Packet):
    name = "HCI_LE_Enable_Encryption"
    fields_desc = [LEShortField("handle", 0),
                   StrFixedLenField("rand", None, 8),
                   XLEShortField("ediv", 0),
                   StrFixedLenField("ltk", b'\x00' * 16, 16), ]


class HCI_Cmd_LE_Long_Term_Key_Request_Reply(Packet):
    name = "HCI_LE_Long_Term_Key_Request_Reply"
    fields_desc = [LEShortField("handle", 0),
                   StrFixedLenField("ltk", b'\x00' * 16, 16), ]


class HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(Packet):
    name = "HCI_LE_Long_Term_Key_Request _Negative_Reply"
    fields_desc = [LEShortField("handle", 0), ]


class HCI_Event_Hdr(Packet):
    name = "HCI Event header"
    fields_desc = [XByteField("code", 0),
                   LenField("len", None, fmt="B"), ]

    def answers(self, other):
        if HCI_Command_Hdr not in other:
            return False

        # Delegate answers to event types
        return self.payload.answers(other)


class HCI_Event_Inquiry_Complete(Packet):
    """
    7.7.1 Inquiry Complete event
    """
    name = "HCI_Inquiry_Complete"
    fields_desc = [
        ByteEnumField('status', 0, _bluetooth_error_codes)
    ]


class HCI_Event_Inquiry_Result(Packet):
    """
    7.7.2 Inquiry Result event
    """
    name = "HCI_Inquiry_Result"
    fields_desc = [
        ByteField("num_response", 0x00),
        FieldListField("addr", None, LEMACField("addr", None),
                       count_from=lambda p: p.num_response),
        FieldListField("page_scan_repetition_mode", None,
                       ByteField("page_scan_repetition_mode", 0),
                       count_from=lambda p: p.num_response),
        FieldListField("reserved", None, LEShortField("reserved", 0),
                       count_from=lambda p: p.num_response),
        FieldListField("device_class", None, XLE3BytesField("device_class", 0),
                       count_from=lambda p: p.num_response),
        FieldListField("clock_offset", None, LEShortField("clock_offset", 0),
                       count_from=lambda p: p.num_response)
    ]


class HCI_Event_Connection_Complete(Packet):
    """
    7.7.3 Connection Complete event
    """
    name = "HCI_Connection_Complete"
    fields_desc = [ByteEnumField('status', 0, _bluetooth_error_codes),
                   LEShortField("handle", 0x0100),
                   LEMACField("bd_addr", None),
                   ByteEnumField("link_type", 0, {0: "SCO connection",
                                                  1: "ACL connection", }),
                   ByteEnumField("encryption_enabled", 0,
                                 {0: "link level encryption disabled",
                                  1: "link level encryption enabled", }), ]


class HCI_Event_Disconnection_Complete(Packet):
    """
    7.7.5 Disconnection Complete event
    """
    name = "HCI_Disconnection_Complete"
    fields_desc = [ByteEnumField("status", 0, _bluetooth_error_codes),
                   LEShortField("handle", 0),
                   XByteField("reason", 0), ]


class HCI_Event_Remote_Name_Request_Complete(Packet):
    """
    7.7.7 Remote Name Request Complete event
    """
    name = "HCI_Remote_Name_Request_Complete"
    fields_desc = [ByteEnumField("status", 0, _bluetooth_error_codes),
                   LEMACField("bd_addr", None),
                   StrFixedLenField("remote_name", b"\x00", 248), ]


class HCI_Event_Encryption_Change(Packet):
    """
    7.7.8 Encryption Change event
    """
    name = "HCI_Encryption_Change"
    fields_desc = [ByteEnumField("status", 0, {0: "change has occurred"}),
                   LEShortField("handle", 0),
                   ByteEnumField("enabled", 0, {0: "OFF", 1: "ON (LE)", 2: "ON (BR/EDR)"}), ]  # noqa: E501


class HCI_Event_Read_Remote_Supported_Features_Complete(Packet):
    """
    7.7.11 Read Remote Supported Features Complete event
    """
    name = "HCI_Read_Remote_Supported_Features_Complete"
    fields_desc = [
        ByteEnumField('status', 0, _bluetooth_error_codes),
        LEShortField('handle', 0),
        FlagsField('lmp_features', 0, -64, _bluetooth_features)
    ]


class HCI_Event_Read_Remote_Version_Information_Complete(Packet):
    """
    7.7.12 Read Remote Version Information Complete event
    """
    name = "HCI_Read_Remote_Version_Information"
    fields_desc = [
        ByteEnumField('status', 0, _bluetooth_error_codes),
        LEShortField('handle', 0),
        ByteField('version', 0x00),
        LEShortField('manufacturer_name', 0x0000),
        LEShortField('subversion', 0x0000)
    ]


class HCI_Event_Command_Complete(Packet):
    """
    7.7.14 Command Complete event
    """
    name = "HCI_Command_Complete"
    fields_desc = [ByteField("number", 0),
                   XLEShortField("opcode", 0),
                   ByteEnumField("status", 0, _bluetooth_error_codes)]

    def answers(self, other):
        if HCI_Command_Hdr not in other:
            return False

        return other[HCI_Command_Hdr].opcode == self.opcode


class HCI_Event_Command_Status(Packet):
    """
    7.7.15 Command Status event
    """
    name = "HCI_Command_Status"
    fields_desc = [ByteEnumField("status", 0, {0: "pending"}),
                   ByteField("number", 0),
                   XLEShortField("opcode", None), ]

    def answers(self, other):
        if HCI_Command_Hdr not in other:
            return False

        return other[HCI_Command_Hdr].opcode == self.opcode


class HCI_Event_Number_Of_Completed_Packets(Packet):
    """
    7.7.19 Number Of Completed Packets event
    """
    name = "HCI_Number_Of_Completed_Packets"
    fields_desc = [ByteField("num_handles", 0),
                   FieldListField("connection_handle_list", None,
                                  LEShortField("connection_handle", 0),
                                  count_from=lambda p: p.num_handles),
                   FieldListField("num_completed_packets_list", None,
                                  LEShortField("num_completed_packets", 0),
                                  count_from=lambda p: p.num_handles)]


class HCI_Event_Link_Key_Request(Packet):
    """
    7.7.23 Link Key Request event
    """
    name = 'HCI_Link_Key_Request'
    fields_desc = [
        LEMACField('bd_addr', None)
    ]


class HCI_Event_Inquiry_Result_With_Rssi(Packet):
    """
    7.7.33 Inquiry Result with RSSI event
    """
    name = "HCI_Inquiry_Result_with_RSSI"
    fields_desc = [
        ByteField("num_response", 0x00),
        FieldListField("bd_addr", None, LEMACField,
                       count_from=lambda p: p.num_response),
        FieldListField("page_scan_repetition_mode", None, ByteField,
                       count_from=lambda p: p.num_response),
        FieldListField("reserved", None, LEShortField,
                       count_from=lambda p: p.num_response),
        FieldListField("device_class", None, XLE3BytesField,
                       count_from=lambda p: p.num_response),
        FieldListField("clock_offset", None, LEShortField,
                       count_from=lambda p: p.num_response),
        FieldListField("rssi", None, SignedByteField,
                       count_from=lambda p: p.num_response)
    ]


class HCI_Event_Read_Remote_Extended_Features_Complete(Packet):
    """
    7.7.34 Read Remote Extended Features Complete event
    """
    name = "HCI_Read_Remote_Extended_Features_Complete"
    fields_desc = [
        ByteEnumField('status', 0, _bluetooth_error_codes),
        LEShortField('handle', 0),
        ByteField('page', 0x00),
        ByteField('max_page', 0x00),
        XLELongField('extended_features', 0)
    ]


class HCI_Event_Extended_Inquiry_Result(Packet):
    """
    7.7.38 Extended Inquiry Result event
    """
    name = "HCI_Extended_Inquiry_Result"
    fields_desc = [
        ByteField('num_response', 0x01),
        LEMACField('bd_addr', None),
        ByteField('page_scan_repetition_mode', 0x00),
        ByteField('reserved', 0x00),
        XLE3BytesField('device_class', 0x000000),
        LEShortField('clock_offset', 0x0000),
        SignedByteField('rssi', 0x00),
        HCI_Extended_Inquiry_Response,
    ]


class HCI_Event_IO_Capability_Response(Packet):
    """
    7.7.41 IO Capability Response event
    """
    name = "HCI_IO_Capability_Response"
    fields_desc = [
        LEMACField('bd_addr', None),
        ByteField('io_capability', 0x00),
        ByteField('oob_data_present', 0x00),
        ByteField('authentication_requirements', 0x00)
    ]


class HCI_Event_LE_Meta(Packet):
    """
    7.7.65 LE Meta event
    """
    name = "HCI_LE_Meta"
    fields_desc = [ByteEnumField("event", 0, {
                   0x01: "connection_complete",
                   0x02: "advertising_report",
                   0x03: "connection_update_complete",
                   0x04: "read_remote_features_page_0_complete",
                   0x05: "long_term_key_request",
                   0x06: "remote_connection_parameter_request",
                   0x07: "data_length_change",
                   0x08: "read_local_p256_public_key_complete",
                   0x09: "generate_dhkey_complete",
                   0x0a: "enhanced_connection_complete_v1",
                   0x0b: "directed_advertising_report",
                   0x0c: "phy_update_complete",
                   0x0d: "extended_advertising_report",
                   0x29: "enhanced_connection_complete_v2"
                   }), ]

    def answers(self, other):
        if not self.payload:
            return False

        # Delegate answers to payload
        return self.payload.answers(other)


class HCI_Cmd_Complete_Read_Local_Name(Packet):
    """
    7.3.12 Read Local Name command complete
    """
    name = 'Read Local Name command complete'
    fields_desc = [StrFixedLenField('local_name', '', length=248)]


class HCI_Cmd_Complete_Read_Local_Version_Information(Packet):
    """
    7.4.1 Read Local Version Information command complete
    """
    name = 'Read Local Version Information'
    fields_desc = [
        ByteEnumField('hci_version', 0, _bluetooth_core_specification_versions),
        LEShortField('hci_subversion', 0),
        ByteEnumField('lmp_version', 0, _bluetooth_core_specification_versions),
        LEShortEnumField('company_identifier', 0, BLUETOOTH_CORE_COMPANY_IDENTIFIERS),
        LEShortField('lmp_subversion', 0)]


class HCI_Cmd_Complete_Read_Local_Extended_Features(Packet):
    """
    7.4.4 Read Local Extended Features command complete
    """
    name = 'Read Local Extended Features command complete'
    fields_desc = [
        ByteField('page', 0x00),
        ByteField('max_page', 0x00),
        XLELongField('extended_features', 0)
    ]


class HCI_Cmd_Complete_Read_BD_Addr(Packet):
    """
    7.4.6 Read BD_ADDR command complete
    """
    name = "Read BD Addr"
    fields_desc = [LEMACField("addr", None), ]


class HCI_Cmd_Complete_LE_Read_White_List_Size(Packet):
    name = "LE Read White List Size"
    fields_desc = [ByteField("status", 0),
                   ByteField("size", 0), ]


class HCI_LE_Meta_Connection_Complete(Packet):
    name = "Connection Complete"
    fields_desc = [ByteEnumField("status", 0, {0: "success"}),
                   LEShortField("handle", 0),
                   ByteEnumField("role", 0, {0: "master"}),
                   ByteEnumField("patype", 0, {0: "public", 1: "random"}),
                   LEMACField("paddr", None),
                   LEShortField("interval", 54),
                   LEShortField("latency", 0),
                   LEShortField("supervision", 42),
                   XByteField("clock_latency", 5), ]

    def answers(self, other):
        if HCI_Cmd_LE_Create_Connection not in other:
            return False

        return (other[HCI_Cmd_LE_Create_Connection].patype == self.patype and
                other[HCI_Cmd_LE_Create_Connection].paddr == self.paddr)


class HCI_LE_Meta_Connection_Update_Complete(Packet):
    name = "Connection Update Complete"
    fields_desc = [ByteEnumField("status", 0, {0: "success"}),
                   LEShortField("handle", 0),
                   LEShortField("interval", 54),
                   LEShortField("latency", 0),
                   LEShortField("timeout", 42), ]


class HCI_LE_Meta_Advertising_Report(Packet):
    name = "Advertising Report"
    fields_desc = [ByteEnumField("type", 0, {0: "conn_und", 4: "scan_rsp"}),
                   ByteEnumField("atype", 0, {0: "public", 1: "random"}),
                   LEMACField("addr", None),
                   FieldLenField("len", None, length_of="data", fmt="B"),
                   PacketListField("data", [], EIR_Hdr,
                                   length_from=lambda pkt: pkt.len),
                   SignedByteField("rssi", 0)]

    def extract_padding(self, s):
        return '', s


class HCI_LE_Meta_Advertising_Reports(Packet):
    name = "Advertising Reports"
    fields_desc = [FieldLenField("len", None, count_of="reports", fmt="B"),
                   PacketListField("reports", None,
                                   HCI_LE_Meta_Advertising_Report,
                                   count_from=lambda pkt: pkt.len)]


class HCI_LE_Meta_Long_Term_Key_Request(Packet):
    name = "Long Term Key Request"
    fields_desc = [LEShortField("handle", 0),
                   StrFixedLenField("rand", None, 8),
                   XLEShortField("ediv", 0), ]


class HCI_LE_Meta_Extended_Advertising_Report(Packet):
    name = "Extended Advertising Report"
    fields_desc = [
        BitField("reserved0", 0, 1),
        BitEnumField("data_status", 0, 2, {
            0b00: "complete",
            0b01: "incomplete",
            0b10: "incomplete_truncated",
            0b11: "reserved"
        }),
        BitField("legacy", 0, 1),
        BitField("scan_response", 0, 1),
        BitField("directed", 0, 1),
        BitField("scannable", 0, 1),
        BitField("connectable", 0, 1),
        ByteField("reserved", 0),
        ByteEnumField("address_type", 0, {
            0x00: "public_device_address",
            0x01: "random_device_address",
            0x02: "public_identity_address",
            0x03: "random_identity_address",
            0xff: "anonymous"
        }),
        LEMACField('address', None),
        ByteEnumField("primary_phy", 0, {
            0x01: "le_1m",
            0x03: "le_coded_s8",
            0x04: "le_coded_s2"
        }),
        ByteEnumField("secondary_phy", 0, {
            0x01: "le_1m",
            0x02: "le_2m",
            0x03: "le_coded_s8",
            0x04: "le_coded_s2"
        }),
        ByteField("advertising_sid", 0xff),
        ByteField("tx_power", 0x7f),
        SignedByteField("rssi", 0x00),
        LEShortField("periodic_advertising_interval", 0x0000),
        ByteEnumField("direct_address_type", 0, {
            0x00: "public_device_address",
            0x01: "non_resolvable_private_address",
            0x02: "resolvable_private_address_resolved_0",
            0x03: "resolvable_private_address_resolved_1",
            0xfe: "resolvable_private_address_unable_resolve"}),
        LEMACField("direct_address", None),
        FieldLenField("data_length", None, length_of="data", fmt="B"),
        PacketListField("data", [], EIR_Hdr,
                        length_from=lambda pkt: pkt.data_length),
    ]

    def extract_padding(self, s):
        return '', s


class HCI_LE_Meta_Extended_Advertising_Reports(Packet):
    name = "Extended Advertising Reports"
    fields_desc = [FieldLenField("num_reports", None, count_of="reports", fmt="B"),
                   PacketListField("reports", None,
                                   HCI_LE_Meta_Extended_Advertising_Report,
                                   count_from=lambda pkt: pkt.num_reports)]


bind_layers(HCI_PHDR_Hdr, HCI_Hdr)

bind_layers(HCI_Hdr, HCI_Command_Hdr, type=1)
bind_layers(HCI_Hdr, HCI_ACL_Hdr, type=2)
bind_layers(HCI_Hdr, HCI_Event_Hdr, type=4)
bind_layers(HCI_Hdr, conf.raw_layer,)

conf.l2types.register(DLT_BLUETOOTH_HCI_H4, HCI_Hdr)
conf.l2types.register(DLT_BLUETOOTH_HCI_H4_WITH_PHDR, HCI_PHDR_Hdr)


# 7.1 LINK CONTROL COMMANDS, the OGF is defined as 0x01
bind_layers(HCI_Command_Hdr, HCI_Cmd_Inquiry, ogf=0x01, ocf=0x0001)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Inquiry_Cancel, ogf=0x01, ocf=0x0002)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Periodic_Inquiry_Mode, ogf=0x01, ocf=0x0003)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Exit_Peiodic_Inquiry_Mode, ogf=0x01, ocf=0x0004)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Create_Connection, ogf=0x01, ocf=0x0005)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Disconnect, ogf=0x01, ocf=0x0006)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Create_Connection_Cancel, ogf=0x01, ocf=0x0008)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Accept_Connection_Request, ogf=0x01, ocf=0x0009)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Reject_Connection_Response, ogf=0x01, ocf=0x000a)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Link_Key_Request_Reply, ogf=0x01, ocf=0x000b)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Link_Key_Request_Negative_Reply,
            ogf=0x01, ocf=0x000c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_PIN_Code_Request_Reply, ogf=0x01, ocf=0x000d)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Change_Connection_Packet_Type,
            ogf=0x01, ocf=0x000f)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Authentication_Requested, ogf=0x01, ocf=0x0011)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Set_Connection_Encryption, ogf=0x01, ocf=0x0013)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Change_Connection_Link_Key, ogf=0x01, ocf=0x0017)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Remote_Name_Request, ogf=0x01, ocf=0x0019)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Remote_Name_Request_Cancel, ogf=0x01, ocf=0x001a)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Remote_Supported_Features,
            ogf=0x01, ocf=0x001b)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Remote_Extended_Features,
            ogf=0x01, ocf=0x001c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_IO_Capability_Request_Reply, ogf=0x01, ocf=0x002b)
bind_layers(HCI_Command_Hdr, HCI_Cmd_User_Confirmation_Request_Reply,
            ogf=0x01, ocf=0x002c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_User_Confirmation_Request_Negative_Reply,
            ogf=0x01, ocf=0x002d)
bind_layers(HCI_Command_Hdr, HCI_Cmd_User_Passkey_Request_Reply, ogf=0x01, ocf=0x002e)
bind_layers(HCI_Command_Hdr, HCI_Cmd_User_Passkey_Request_Negative_Reply,
            ogf=0x01, ocf=0x002f)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Remote_OOB_Data_Request_Reply,
            ogf=0x01, ocf=0x0030)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Remote_OOB_Data_Request_Negative_Reply,
            ogf=0x01, ocf=0x0033)

# 7.2 Link Policy commands, the OGF is defined as 0x02
bind_layers(HCI_Command_Hdr, HCI_Cmd_Hold_Mode, ogf=0x02, ocf=0x0001)

# 7.3 CONTROLLER & BASEBAND COMMANDS, the OGF is defined as 0x03
bind_layers(HCI_Command_Hdr, HCI_Cmd_Set_Event_Mask, ogf=0x03, ocf=0x0001)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Reset, ogf=0x03, ocf=0x0003)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Set_Event_Filter, ogf=0x03, ocf=0x0005)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Local_Name, ogf=0x03, ocf=0x0013)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Name, ogf=0x03, ocf=0x0014)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Connect_Accept_Timeout, ogf=0x03, ocf=0x0016)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Extended_Inquiry_Response, ogf=0x03, ocf=0x0052)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_LE_Host_Support, ogf=0x03, ocf=0x006c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_LE_Host_Support, ogf=0x03, ocf=0x006d)

# 7.4 INFORMATIONAL PARAMETERS, the OGF is defined as 0x04
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Version_Information, ogf=0x04, ocf=0x0001)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Extended_Features, ogf=0x04, ocf=0x0004)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_BD_Addr, ogf=0x04, ocf=0x0009)

# 7.5 STATUS PARAMETERS, the OGF is defined as 0x05
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Link_Quality, ogf=0x05, ocf=0x0003)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_RSSI, ogf=0x05, ocf=0x0005)

# 7.6 TESTING COMMANDS, the OGF is defined as 0x06
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Loopback_Mode, ogf=0x06, ocf=0x0001)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Loopback_Mode, ogf=0x06, ocf=0x0002)

# 7.8 LE CONTROLLER COMMANDS, the OGF code is defined as 0x08
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Buffer_Size_V1, ogf=0x08, ocf=0x0002)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Buffer_Size_V2, ogf=0x08, ocf=0x0060)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Local_Supported_Features,
            ogf=0x08, ocf=0x0003)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Random_Address, ogf=0x08, ocf=0x0005)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertising_Parameters, ogf=0x08, ocf=0x0006)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertising_Data, ogf=0x08, ocf=0x0008)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Response_Data, ogf=0x08, ocf=0x0009)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertise_Enable, ogf=0x08, ocf=0x000a)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Parameters, ogf=0x08, ocf=0x000b)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Enable, ogf=0x08, ocf=0x000c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Create_Connection, ogf=0x08, ocf=0x000d)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Create_Connection_Cancel, ogf=0x08, ocf=0x000e)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Filter_Accept_List_Size,
            ogf=0x08, ocf=0x000f)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Clear_Filter_Accept_List, ogf=0x08, ocf=0x0010)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Add_Device_To_Filter_Accept_List, ogf=0x08, ocf=0x0011)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Remove_Device_From_Filter_Accept_List, ogf=0x08, ocf=0x0012)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Connection_Update, ogf=0x08, ocf=0x0013)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Remote_Features, ogf=0x08, ocf=0x0016)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Enable_Encryption, ogf=0x08, ocf=0x0019)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Long_Term_Key_Request_Reply, ogf=0x08, ocf=0x001a)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply, ogf=0x08, ocf=0x001b)  # noqa: E501

# 7.7 EVENTS
bind_layers(HCI_Event_Hdr, HCI_Event_Inquiry_Complete, code=0x01)
bind_layers(HCI_Event_Hdr, HCI_Event_Inquiry_Result, code=0x02)
bind_layers(HCI_Event_Hdr, HCI_Event_Connection_Complete, code=0x03)
bind_layers(HCI_Event_Hdr, HCI_Event_Disconnection_Complete, code=0x05)
bind_layers(HCI_Event_Hdr, HCI_Event_Remote_Name_Request_Complete, code=0x07)
bind_layers(HCI_Event_Hdr, HCI_Event_Encryption_Change, code=0x08)
bind_layers(HCI_Event_Hdr, HCI_Event_Read_Remote_Supported_Features_Complete, code=0x0b)
bind_layers(HCI_Event_Hdr, HCI_Event_Read_Remote_Version_Information_Complete, code=0x0c)  # noqa: E501
bind_layers(HCI_Event_Hdr, HCI_Event_Command_Complete, code=0x0e)
bind_layers(HCI_Event_Hdr, HCI_Event_Command_Status, code=0x0f)
bind_layers(HCI_Event_Hdr, HCI_Event_Number_Of_Completed_Packets, code=0x13)
bind_layers(HCI_Event_Hdr, HCI_Event_Link_Key_Request, code=0x17)
bind_layers(HCI_Event_Hdr, HCI_Event_Inquiry_Result_With_Rssi, code=0x22)
bind_layers(HCI_Event_Hdr, HCI_Event_Read_Remote_Extended_Features_Complete, code=0x23)
bind_layers(HCI_Event_Hdr, HCI_Event_Extended_Inquiry_Result, code=0x2f)
bind_layers(HCI_Event_Hdr, HCI_Event_IO_Capability_Response, code=0x32)
bind_layers(HCI_Event_Hdr, HCI_Event_LE_Meta, code=0x3e)

bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Name, opcode=0x0c14)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Version_Information, opcode=0x1001)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Extended_Features, opcode=0x1004)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_BD_Addr, opcode=0x1009)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_LE_Read_White_List_Size, opcode=0x200f)  # noqa: E501

bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Connection_Complete, event=0x01)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Reports, event=0x02)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Connection_Update_Complete, event=0x03)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Long_Term_Key_Request, event=0x05)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Extended_Advertising_Reports, event=0x0d)

bind_layers(EIR_Hdr, EIR_Flags, type=0x01)
bind_layers(EIR_Hdr, EIR_IncompleteList16BitServiceUUIDs, type=0x02)
bind_layers(EIR_Hdr, EIR_CompleteList16BitServiceUUIDs, type=0x03)
bind_layers(EIR_Hdr, EIR_IncompleteList32BitServiceUUIDs, type=0x04)
bind_layers(EIR_Hdr, EIR_CompleteList32BitServiceUUIDs, type=0x05)
bind_layers(EIR_Hdr, EIR_IncompleteList128BitServiceUUIDs, type=0x06)
bind_layers(EIR_Hdr, EIR_CompleteList128BitServiceUUIDs, type=0x07)
bind_layers(EIR_Hdr, EIR_ShortenedLocalName, type=0x08)
bind_layers(EIR_Hdr, EIR_CompleteLocalName, type=0x09)
bind_layers(EIR_Hdr, EIR_Device_ID, type=0x10)
bind_layers(EIR_Hdr, EIR_TX_Power_Level, type=0x0a)
bind_layers(EIR_Hdr, EIR_ClassOfDevice, type=0x0d)
bind_layers(EIR_Hdr, EIR_SecureSimplePairingHashC192, type=0x0e)
bind_layers(EIR_Hdr, EIR_SecureSimplePairingRandomizerR192, type=0x0f)
bind_layers(EIR_Hdr, EIR_SecurityManagerOOBFlags, type=0x11)
bind_layers(EIR_Hdr, EIR_PeripheralConnectionIntervalRange, type=0x12)
bind_layers(EIR_Hdr, EIR_ServiceSolicitation16BitUUID, type=0x14)
bind_layers(EIR_Hdr, EIR_ServiceSolicitation128BitUUID, type=0x15)
bind_layers(EIR_Hdr, EIR_ServiceData16BitUUID, type=0x16)
bind_layers(EIR_Hdr, EIR_PublicTargetAddress, type=0x17)
bind_layers(EIR_Hdr, EIR_Appearance, type=0x19)
bind_layers(EIR_Hdr, EIR_AdvertisingInterval, type=0x1a)
bind_layers(EIR_Hdr, EIR_LEBluetoothDeviceAddress, type=0x1b)
bind_layers(EIR_Hdr, EIR_ServiceData32BitUUID, type=0x20)
bind_layers(EIR_Hdr, EIR_ServiceData128BitUUID, type=0x21)
bind_layers(EIR_Hdr, EIR_URI, type=0x24)
bind_layers(EIR_Hdr, EIR_Manufacturer_Specific_Data, type=0xff)
bind_layers(EIR_Hdr, EIR_Raw)

bind_layers(HCI_ACL_Hdr, L2CAP_Hdr,)
bind_layers(L2CAP_Hdr, L2CAP_CmdHdr, cid=1)
bind_layers(L2CAP_Hdr, L2CAP_CmdHdr, cid=5)  # LE L2CAP Signaling Channel
bind_layers(L2CAP_CmdHdr, L2CAP_CmdRej, code=1)
bind_layers(L2CAP_CmdHdr, L2CAP_ConnReq, code=2)
bind_layers(L2CAP_CmdHdr, L2CAP_ConnResp, code=3)
bind_layers(L2CAP_CmdHdr, L2CAP_ConfReq, code=4)
bind_layers(L2CAP_CmdHdr, L2CAP_ConfResp, code=5)
bind_layers(L2CAP_CmdHdr, L2CAP_DisconnReq, code=6)
bind_layers(L2CAP_CmdHdr, L2CAP_DisconnResp, code=7)
bind_layers(L2CAP_CmdHdr, L2CAP_EchoReq, code=8)
bind_layers(L2CAP_CmdHdr, L2CAP_EchoResp, code=9)
bind_layers(L2CAP_CmdHdr, L2CAP_InfoReq, code=10)
bind_layers(L2CAP_CmdHdr, L2CAP_InfoResp, code=11)
bind_layers(L2CAP_CmdHdr, L2CAP_Create_Channel_Request, code=12)
bind_layers(L2CAP_CmdHdr, L2CAP_Create_Channel_Response, code=13)
bind_layers(L2CAP_CmdHdr, L2CAP_Move_Channel_Request, code=14)
bind_layers(L2CAP_CmdHdr, L2CAP_Move_Channel_Response, code=15)
bind_layers(L2CAP_CmdHdr, L2CAP_Move_Channel_Confirmation_Request, code=16)
bind_layers(L2CAP_CmdHdr, L2CAP_Move_Channel_Confirmation_Response, code=17)
bind_layers(L2CAP_CmdHdr, L2CAP_Connection_Parameter_Update_Request, code=18)
bind_layers(L2CAP_CmdHdr, L2CAP_Connection_Parameter_Update_Response, code=19)
bind_layers(L2CAP_CmdHdr, L2CAP_LE_Credit_Based_Connection_Request, code=20)
bind_layers(L2CAP_CmdHdr, L2CAP_LE_Credit_Based_Connection_Response, code=21)
bind_layers(L2CAP_CmdHdr, L2CAP_Flow_Control_Credit_Ind, code=22)
bind_layers(L2CAP_CmdHdr, L2CAP_Credit_Based_Connection_Request, code=23)
bind_layers(L2CAP_CmdHdr, L2CAP_Credit_Based_Connection_Response, code=24)
bind_layers(L2CAP_CmdHdr, L2CAP_Credit_Based_Reconfigure_Request, code=25)
bind_layers(L2CAP_CmdHdr, L2CAP_Credit_Based_Reconfigure_Response, code=26)
bind_layers(L2CAP_Hdr, ATT_Hdr, cid=4)
bind_layers(ATT_Hdr, ATT_Error_Response, opcode=0x1)
bind_layers(ATT_Hdr, ATT_Exchange_MTU_Request, opcode=0x2)
bind_layers(ATT_Hdr, ATT_Exchange_MTU_Response, opcode=0x3)
bind_layers(ATT_Hdr, ATT_Find_Information_Request, opcode=0x4)
bind_layers(ATT_Hdr, ATT_Find_Information_Response, opcode=0x5)
bind_layers(ATT_Hdr, ATT_Find_By_Type_Value_Request, opcode=0x6)
bind_layers(ATT_Hdr, ATT_Find_By_Type_Value_Response, opcode=0x7)
bind_layers(ATT_Hdr, ATT_Read_By_Type_Request_128bit, opcode=0x8)
bind_layers(ATT_Hdr, ATT_Read_By_Type_Request, opcode=0x8)
bind_layers(ATT_Hdr, ATT_Read_By_Type_Response, opcode=0x9)
bind_layers(ATT_Hdr, ATT_Read_Request, opcode=0xa)
bind_layers(ATT_Hdr, ATT_Read_Response, opcode=0xb)
bind_layers(ATT_Hdr, ATT_Read_Blob_Request, opcode=0xc)
bind_layers(ATT_Hdr, ATT_Read_Blob_Response, opcode=0xd)
bind_layers(ATT_Hdr, ATT_Read_Multiple_Request, opcode=0xe)
bind_layers(ATT_Hdr, ATT_Read_Multiple_Response, opcode=0xf)
bind_layers(ATT_Hdr, ATT_Read_By_Group_Type_Request, opcode=0x10)
bind_layers(ATT_Hdr, ATT_Read_By_Group_Type_Response, opcode=0x11)
bind_layers(ATT_Hdr, ATT_Write_Request, opcode=0x12)
bind_layers(ATT_Hdr, ATT_Write_Response, opcode=0x13)
bind_layers(ATT_Hdr, ATT_Prepare_Write_Request, opcode=0x16)
bind_layers(ATT_Hdr, ATT_Prepare_Write_Response, opcode=0x17)
bind_layers(ATT_Hdr, ATT_Execute_Write_Request, opcode=0x18)
bind_layers(ATT_Hdr, ATT_Execute_Write_Response, opcode=0x19)
bind_layers(ATT_Hdr, ATT_Write_Command, opcode=0x52)
bind_layers(ATT_Hdr, ATT_Handle_Value_Notification, opcode=0x1b)
bind_layers(ATT_Hdr, ATT_Handle_Value_Indication, opcode=0x1d)
bind_layers(L2CAP_Hdr, SM_Hdr, cid=6)
bind_layers(SM_Hdr, SM_Pairing_Request, sm_command=0x01)
bind_layers(SM_Hdr, SM_Pairing_Response, sm_command=0x02)
bind_layers(SM_Hdr, SM_Confirm, sm_command=0x03)
bind_layers(SM_Hdr, SM_Random, sm_command=0x04)
bind_layers(SM_Hdr, SM_Failed, sm_command=0x05)
bind_layers(SM_Hdr, SM_Encryption_Information, sm_command=0x06)
bind_layers(SM_Hdr, SM_Master_Identification, sm_command=0x07)
bind_layers(SM_Hdr, SM_Identity_Information, sm_command=0x08)
bind_layers(SM_Hdr, SM_Identity_Address_Information, sm_command=0x09)
bind_layers(SM_Hdr, SM_Signing_Information, sm_command=0x0a)
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0b)
bind_layers(SM_Hdr, SM_Public_Key, sm_command=0x0c)
bind_layers(SM_Hdr, SM_DHKey_Check, sm_command=0x0d)


###############
# HCI Monitor #
###############


# https://elixir.bootlin.com/linux/v6.4.2/source/include/net/bluetooth/hci_mon.h#L27
class HCI_Mon_Hdr(Packet):
    name = 'Bluetooth Linux Monitor Transport Header'
    fields_desc = [
        LEShortEnumField('opcode', None, {
            0: "New index",
            1: "Delete index",
            2: "Command pkt",
            3: "Event pkt",
            4: "ACL TX pkt",
            5: "ACL RX pkt",
            6: "SCO TX pkt",
            7: "SCO RX pkt",
            8: "Open index",
            9: "Close index",
            10: "Index info",
            11: "Vendor diag",
            12: "System note",
            13: "User logging",
            14: "Ctrl open",
            15: "Ctrl close",
            16: "Ctrl command",
            17: "Ctrl event",
            18: "ISO TX pkt",
            19: "ISO RX pkt",
        }),
        LEShortField('adapter_id', None),
        LEShortField('len', None)
    ]


# https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LINUX_MONITOR.html
class HCI_Mon_Pcap_Hdr(HCI_Mon_Hdr):
    name = 'Bluetooth Linux Monitor Transport Pcap Header'
    fields_desc = [
        ShortField('adapter_id', None),
        ShortField('opcode', None)
    ]


class HCI_Mon_New_Index(Packet):
    name = 'Bluetooth Linux Monitor Transport New Index Packet'
    fields_desc = [
        ByteEnumField('bus', 0, {
            0x00: "BR/EDR",
            0x01: "AMP"
        }),
        ByteEnumField('type', 0, {
            0x00: "Virtual",
            0x01: "USB",
            0x02: "PC Card",
            0x03: "UART",
            0x04: "RS232",
            0x05: "PCI",
            0x06: "SDIO"
        }),
        LEMACField('addr', None),
        StrFixedLenField('devname', None, 8)
    ]


class HCI_Mon_Index_Info(Packet):
    name = 'Bluetooth Linux Monitor Transport Index Info Packet'
    fields_desc = [
        LEMACField('addr', None),
        XLEShortField('manufacturer', None)
    ]


class HCI_Mon_System_Note(Packet):
    name = 'Bluetooth Linux Monitor Transport System Note Packet'
    fields_desc = [
        StrNullField('note', None)
    ]


# https://elixir.bootlin.com/linux/v6.4.2/source/include/net/bluetooth/hci_mon.h#L34
bind_layers(HCI_Mon_Hdr, HCI_Mon_New_Index, opcode=0)
bind_layers(HCI_Mon_Hdr, HCI_Command_Hdr, opcode=2)
bind_layers(HCI_Mon_Hdr, HCI_Event_Hdr, opcode=3)
bind_layers(HCI_Mon_Hdr, HCI_ACL_Hdr, opcode=5)
bind_layers(HCI_Mon_Hdr, HCI_Mon_Index_Info, opcode=10)
bind_layers(HCI_Mon_Hdr, HCI_Mon_System_Note, opcode=12)

conf.l2types.register(DLT_BLUETOOTH_LINUX_MONITOR, HCI_Mon_Pcap_Hdr)


###########
# Helpers #
###########

class LowEnergyBeaconHelper:
    """
    Helpers for building packets for Bluetooth Low Energy Beacons.

    Implementers provide a :meth:`build_eir` implementation.

    This is designed to be used as a mix-in -- see
    ``scapy.contrib.eddystone`` and ``scapy.contrib.ibeacon`` for examples.
    """

    # Basic flags that should be used by most beacons.
    base_eir = [EIR_Hdr() / EIR_Flags(flags=[
        "general_disc_mode", "br_edr_not_supported"]), ]

    def build_eir(self):
        """
        Builds a list of EIR messages to wrap this frame.

        Users of this helper must implement this method.

        :return: List of HCI_Hdr with payloads that describe this beacon type
        :rtype: list[scapy.bluetooth.HCI_Hdr]
        """
        raise NotImplementedError("build_eir")

    def build_advertising_report(self):
        """
        Builds a HCI_LE_Meta_Advertising_Report containing this frame.

        :rtype: scapy.bluetooth.HCI_LE_Meta_Advertising_Report
        """

        return HCI_LE_Meta_Advertising_Report(
            type=0,   # Undirected
            atype=1,  # Random address
            data=self.build_eir()
        )

    def build_set_advertising_data(self):
        """Builds a HCI_Cmd_LE_Set_Advertising_Data containing this frame.

        This includes the :class:`HCI_Hdr` and :class:`HCI_Command_Hdr` layers.

        :rtype: scapy.bluetooth.HCI_Hdr
        """

        return HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_LE_Set_Advertising_Data(
            data=self.build_eir()
        )


###########
# Sockets #
###########

class BluetoothSocketError(BaseException):
    pass


class BluetoothCommandError(BaseException):
    pass


class BluetoothL2CAPSocket(SuperSocket):
    desc = "read/write packets on a connected L2CAP socket"

    def __init__(self, bt_address):
        if WINDOWS:
            warning("Not available on Windows")
            return
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                          socket.BTPROTO_L2CAP)
        s.connect((bt_address, 0))
        self.ins = self.outs = s

    def recv(self, x=MTU):
        return L2CAP_CmdHdr(self.ins.recv(x))


class BluetoothRFCommSocket(BluetoothL2CAPSocket):
    """read/write packets on a connected RFCOMM socket"""

    def __init__(self, bt_address, port=0):
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                          socket.BTPROTO_RFCOMM)
        s.connect((bt_address, port))
        self.ins = self.outs = s


class BluetoothHCISocket(SuperSocket):
    desc = "read/write on a BlueTooth HCI socket"

    def __init__(self, iface=0x10000, type=None):
        if WINDOWS:
            warning("Not available on Windows")
            return
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)  # noqa: E501
        s.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR, 1)
        s.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP, 1)
        s.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIh2x", 0xffffffff, 0xffffffff, 0xffffffff, 0))  # type mask, event mask, event mask, opcode  # noqa: E501
        s.bind((iface,))
        self.ins = self.outs = s
#        s.connect((peer,0))

    def recv(self, x=MTU):
        return HCI_Hdr(self.ins.recv(x))


class sockaddr_hci(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("hci_dev", ctypes.c_ushort),
        ("hci_channel", ctypes.c_ushort),
    ]


class _BluetoothLibcSocket(SuperSocket):
    def __init__(self, socket_domain, socket_type, socket_protocol, sock_address):
        # type: (int, int, int, sockaddr_hci) -> None
        if WINDOWS:
            warning("Not available on Windows")
            return
        # Python socket and bind implementations do not allow us to pass down
        # the correct parameters. We must call libc functions directly via
        # ctypes.
        sockaddr_hcip = ctypes.POINTER(sockaddr_hci)
        from ctypes.util import find_library
        libc = ctypes.cdll.LoadLibrary(find_library("c"))

        socket_c = libc.socket
        socket_c.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
        socket_c.restype = ctypes.c_int

        bind = libc.bind
        bind.argtypes = (ctypes.c_int,
                         ctypes.POINTER(sockaddr_hci),
                         ctypes.c_int)
        bind.restype = ctypes.c_int

        # Socket
        s = socket_c(socket_domain, socket_type, socket_protocol)
        if s < 0:
            raise BluetoothSocketError(
                f"Unable to open socket({socket_domain}, {socket_type}, "
                f"{socket_protocol})")

        # Bind
        r = bind(s, sockaddr_hcip(sock_address), sizeof(sock_address))
        if r != 0:
            raise BluetoothSocketError("Unable to bind")

        self.hci_fd = s
        self.ins = self.outs = socket.fromfd(
            s, socket_domain, socket_type, socket_protocol)

    def readable(self, timeout=0):
        (ins, _, _) = select.select([self.ins], [], [], timeout)
        return len(ins) > 0

    def flush(self):
        while self.readable():
            self.recv()

    def close(self):
        if self.closed:
            return

        # Properly close socket so we can free the device
        from ctypes.util import find_library
        libc = ctypes.cdll.LoadLibrary(find_library("c"))

        close = libc.close
        close.restype = ctypes.c_int
        self.closed = True
        if hasattr(self, "outs"):
            if not hasattr(self, "ins") or self.ins != self.outs:
                if self.outs and (WINDOWS or self.outs.fileno() != -1):
                    close(self.outs.fileno())
        if hasattr(self, "ins"):
            if self.ins and (WINDOWS or self.ins.fileno() != -1):
                close(self.ins.fileno())
        if hasattr(self, "hci_fd"):
            close(self.hci_fd)


class BluetoothUserSocket(_BluetoothLibcSocket):
    desc = "read/write H4 over a Bluetooth user channel"

    def __init__(self, adapter_index=0):
        sa = sockaddr_hci()
        sa.sin_family = socket.AF_BLUETOOTH
        sa.hci_dev = adapter_index
        sa.hci_channel = HCI_CHANNEL_USER
        super().__init__(
            socket_domain=socket.AF_BLUETOOTH,
            socket_type=socket.SOCK_RAW,
            socket_protocol=socket.BTPROTO_HCI,
            sock_address=sa)

    def send_command(self, cmd):
        opcode = cmd[HCI_Command_Hdr].opcode
        self.send(cmd)
        while True:
            r = self.recv()
            if r.type == 0x04 and r.code == 0xe and r.opcode == opcode:
                if r.status != 0:
                    raise BluetoothCommandError("Command %x failed with %x" % (opcode, r.status))  # noqa: E501
                return r

    def recv(self, x=MTU):
        return HCI_Hdr(self.ins.recv(x))


class BluetoothMonitorSocket(_BluetoothLibcSocket):
    desc = "Read/write over a Bluetooth monitor channel"

    def __init__(self):
        sa = sockaddr_hci()
        sa.sin_family = socket.AF_BLUETOOTH
        sa.hci_dev = HCI_DEV_NONE
        sa.hci_channel = HCI_CHANNEL_MONITOR
        super().__init__(
            socket_domain=socket.AF_BLUETOOTH,
            socket_type=socket.SOCK_RAW,
            socket_protocol=socket.BTPROTO_HCI,
            sock_address=sa)

    def recv(self, x=MTU):
        return HCI_Mon_Hdr(self.ins.recv(x))


conf.BTsocket = BluetoothRFCommSocket

# Bluetooth


@conf.commands.register
def srbt(bt_address, pkts, inter=0.1, *args, **kargs):
    """send and receive using a bluetooth socket"""
    if "port" in kargs:
        s = conf.BTsocket(bt_address=bt_address, port=kargs.pop("port"))
    else:
        s = conf.BTsocket(bt_address=bt_address)
    a, b = sndrcv(s, pkts, inter=inter, *args, **kargs)
    s.close()
    return a, b


@conf.commands.register
def srbt1(bt_address, pkts, *args, **kargs):
    """send and receive 1 packet using a bluetooth socket"""
    a, b = srbt(bt_address, pkts, *args, **kargs)
    if len(a) > 0:
        return a[0][1]
