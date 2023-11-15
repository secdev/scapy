# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Mike Ryan <mikeryan@lacklustre.net>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>

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
    DLT_BLUETOOTH_LINUX_MONITOR
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
    UUIDField,
    XByteField,
    XLE3BytesField,
    XLELongField,
    XStrLenField,
    XLEShortField,
    LEMACField,
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


class BT_Mon_Hdr(Packet):
    name = 'Bluetooth Linux Monitor Transport Header'
    fields_desc = [
        LEShortField('opcode', None),
        LEShortField('adapter_id', None),
        LEShortField('len', None)
    ]


# https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LINUX_MONITOR.html
class BT_Mon_Pcap_Hdr(BT_Mon_Hdr):
    name = 'Bluetooth Linux Monitor Transport Pcap Header'
    fields_desc = [
        ShortField('adapter_id', None),
        ShortField('opcode', None)
    ]


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
        ByteEnumField("code", 8, {1: "rej", 2: "conn_req", 3: "conn_resp",
                                  4: "conf_req", 5: "conf_resp", 6: "disconn_req",  # noqa: E501
                                  7: "disconn_resp", 8: "echo_req", 9: "echo_resp",  # noqa: E501
                                  10: "info_req", 11: "info_resp", 18: "conn_param_update_req",  # noqa: E501
                                  19: "conn_param_update_resp"}),
        ByteField("id", 0),
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
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP", 3: "RFCOMM", 5: "telephony control"}),  # noqa: E501
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


class L2CAP_Connection_Parameter_Update_Request(Packet):
    name = "L2CAP Connection Parameter Update Request"
    fields_desc = [LEShortField("min_interval", 0),
                   LEShortField("max_interval", 0),
                   LEShortField("slave_latency", 0),
                   LEShortField("timeout_mult", 0), ]


class L2CAP_Connection_Parameter_Update_Response(Packet):
    name = "L2CAP Connection Parameter Update Response"
    fields_desc = [LEShortField("move_result", 0), ]


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


class EIR_Manufacturer_Specific_Data(EIR_Element):
    name = "EIR Manufacturer Specific Data"
    fields_desc = [
        # https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers
        XLEShortField("company_id", None),
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
    name = "HCI_Set_Event_Mask"
    fields_desc = [StrFixedLenField("mask", b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d", 8)]  # noqa: E501


class HCI_Cmd_Reset(Packet):
    name = "HCI_Reset"


class HCI_Cmd_Set_Event_Filter(Packet):
    name = "HCI_Set_Event_Filter"
    fields_desc = [ByteEnumField("type", 0, {0: "clear"}), ]


class HCI_Cmd_Write_Local_Name(Packet):
    name = "HCI_Write_Local_Name"
    fields_desc = [StrField("name", "")]


class HCI_Cmd_Write_Connect_Accept_Timeout(Packet):
    name = "HCI_Write_Connection_Accept_Timeout"
    fields_desc = [LEShortField("timeout", 32000)]  # 32000 slots is 20000 msec


class HCI_Cmd_Write_Extended_Inquiry_Response(Packet):
    name = "HCI_Write_Extended_Inquiry_Response"
    fields_desc = [ByteField("fec_required", 0),
                   PacketListField("eir_data", [], EIR_Hdr,
                                   length_from=lambda pkt:pkt.len)]


class HCI_Cmd_Read_LE_Host_Support(Packet):
    name = "HCI_Read_LE_Host_Support"


class HCI_Cmd_Write_LE_Host_Support(Packet):
    name = "HCI_Write_LE_Host_Support"
    fields_desc = [ByteField("supported", 1),
                   ByteField("unused", 1), ]


# 7.4 INFORMATIONAL PARAMETERS, the OGF is defined as 0x04
class HCI_Cmd_Read_BD_Addr(Packet):
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
                                       length_from=lambda pkt:pkt.len),
                       align=31, padwith=b"\0"), ]


class HCI_Cmd_LE_Set_Scan_Response_Data(Packet):
    name = "HCI_LE_Set_Scan_Response_Data"
    fields_desc = [FieldLenField("len", None, length_of="data", fmt="B"),
                   StrLenField("data", "", length_from=lambda pkt:pkt.len), ]


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
    fields_desc = [ByteField("status", 0), ]


class HCI_Event_Connection_Complete(Packet):
    """
    7.7.3 Connection Complete event
    """

    name = "HCI_Connection_Complete"
    fields_desc = [ByteField("status", 0),
                   LEShortField("handle", 0x0100),
                   LEMACField("bd_addr", None),
                   ByteEnumField("link_type", 0, {0: "SCO connection",
                                                  1: "ACL connection", }),
                   ByteEnumField("encryption_enaled", 0,
                                 {0: "link level encryption disabled",
                                  1: "link level encryption enabled", }), ]


class HCI_Event_Disconnection_Complete(Packet):
    name = "Disconnection Complete"
    fields_desc = [ByteEnumField("status", 0, {0: "success"}),
                   LEShortField("handle", 0),
                   XByteField("reason", 0), ]


class HCI_Event_Remote_Name_Request_Complete(Packet):
    name = "Remote Name Request Complete"
    fields_desc = [ByteField("status", 0),
                   LEMACField("bd_addr", None),
                   StrFixedLenField("remote_name", b"\x00", 248), ]


class HCI_Event_Encryption_Change(Packet):
    name = "Encryption Change"
    fields_desc = [ByteEnumField("status", 0, {0: "change has occurred"}),
                   LEShortField("handle", 0),
                   ByteEnumField("enabled", 0, {0: "OFF", 1: "ON (LE)", 2: "ON (BR/EDR)"}), ]  # noqa: E501


class HCI_Event_Command_Complete(Packet):
    name = "Command Complete"
    fields_desc = [ByteField("number", 0),
                   XLEShortField("opcode", 0),
                   ByteEnumField("status", 0, _bluetooth_error_codes)]

    def answers(self, other):
        if HCI_Command_Hdr not in other:
            return False

        return other[HCI_Command_Hdr].opcode == self.opcode


class HCI_Cmd_Complete_Read_BD_Addr(Packet):
    name = "Read BD Addr"
    fields_desc = [LEMACField("addr", None), ]


class HCI_Cmd_Complete_LE_Read_White_List_Size(Packet):
    name = "LE Read White List Size"
    fields_desc = [ByteField("status", 0),
                   ByteField("size", 0), ]


class HCI_Event_Command_Status(Packet):
    name = "Command Status"
    fields_desc = [ByteEnumField("status", 0, {0: "pending"}),
                   ByteField("number", 0),
                   XLEShortField("opcode", None), ]

    def answers(self, other):
        if HCI_Command_Hdr not in other:
            return False

        return other[HCI_Command_Hdr].opcode == self.opcode


class HCI_Event_Number_Of_Completed_Packets(Packet):
    name = "Number Of Completed Packets"
    fields_desc = [ByteField("number", 0)]


class HCI_Event_LE_Meta(Packet):
    name = "LE Meta"
    fields_desc = [ByteEnumField("event", 0, {
                   1: "connection_complete",
                   2: "advertising_report",
                   3: "connection_update_complete",
                   5: "long_term_key_request",
                   }), ]

    def answers(self, other):
        if not self.payload:
            return False

        # Delegate answers to payload
        return self.payload.answers(other)


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
                                   length_from=lambda pkt:pkt.len),
                   SignedByteField("rssi", 0)]

    def extract_padding(self, s):
        return '', s


class HCI_LE_Meta_Advertising_Reports(Packet):
    name = "Advertising Reports"
    fields_desc = [FieldLenField("len", None, count_of="reports", fmt="B"),
                   PacketListField("reports", None,
                                   HCI_LE_Meta_Advertising_Report,
                                   count_from=lambda pkt:pkt.len)]


class HCI_LE_Meta_Long_Term_Key_Request(Packet):
    name = "Long Term Key Request"
    fields_desc = [LEShortField("handle", 0),
                   StrFixedLenField("rand", None, 8),
                   XLEShortField("ediv", 0), ]


bind_layers(HCI_PHDR_Hdr, HCI_Hdr)

bind_layers(HCI_Hdr, HCI_Command_Hdr, type=1)
bind_layers(HCI_Hdr, HCI_ACL_Hdr, type=2)
bind_layers(HCI_Hdr, HCI_Event_Hdr, type=4)
bind_layers(HCI_Hdr, conf.raw_layer,)

conf.l2types.register(DLT_BLUETOOTH_HCI_H4, HCI_Hdr)
conf.l2types.register(DLT_BLUETOOTH_HCI_H4_WITH_PHDR, HCI_PHDR_Hdr)
conf.l2types.register(DLT_BLUETOOTH_LINUX_MONITOR, BT_Mon_Pcap_Hdr)


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
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Remote_Supported_Features,
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
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Connect_Accept_Timeout, ogf=0x03, ocf=0x0016)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Extended_Inquiry_Response, ogf=0x03, ocf=0x0052)  # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_LE_Host_Support, ogf=0x03, ocf=0x006c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_LE_Host_Support, ogf=0x03, ocf=0x006d)

# 7.4 INFORMATIONAL PARAMETERS, the OGF is defined as 0x04
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

bind_layers(HCI_Event_Hdr, HCI_Event_Connection_Complete, code=0x03)
bind_layers(HCI_Event_Hdr, HCI_Event_Disconnection_Complete, code=0x05)
bind_layers(HCI_Event_Hdr, HCI_Event_Remote_Name_Request_Complete, code=0x07)
bind_layers(HCI_Event_Hdr, HCI_Event_Encryption_Change, code=0x08)
bind_layers(HCI_Event_Hdr, HCI_Event_Command_Complete, code=0x0e)
bind_layers(HCI_Event_Hdr, HCI_Event_Command_Status, code=0x0f)
bind_layers(HCI_Event_Hdr, HCI_Event_Number_Of_Completed_Packets, code=0x13)
bind_layers(HCI_Event_Hdr, HCI_Event_LE_Meta, code=0x3e)

bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_BD_Addr, opcode=0x1009)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_LE_Read_White_List_Size, opcode=0x200f)  # noqa: E501

bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Connection_Complete, event=1)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Reports, event=2)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Connection_Update_Complete, event=3)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Long_Term_Key_Request, event=5)

bind_layers(EIR_Hdr, EIR_Flags, type=0x01)
bind_layers(EIR_Hdr, EIR_IncompleteList16BitServiceUUIDs, type=0x02)
bind_layers(EIR_Hdr, EIR_CompleteList16BitServiceUUIDs, type=0x03)
bind_layers(EIR_Hdr, EIR_IncompleteList128BitServiceUUIDs, type=0x06)
bind_layers(EIR_Hdr, EIR_CompleteList128BitServiceUUIDs, type=0x07)
bind_layers(EIR_Hdr, EIR_ShortenedLocalName, type=0x08)
bind_layers(EIR_Hdr, EIR_CompleteLocalName, type=0x09)
bind_layers(EIR_Hdr, EIR_Device_ID, type=0x10)
bind_layers(EIR_Hdr, EIR_TX_Power_Level, type=0x0a)
bind_layers(EIR_Hdr, EIR_ServiceData16BitUUID, type=0x16)
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
bind_layers(L2CAP_CmdHdr, L2CAP_InfoReq, code=10)
bind_layers(L2CAP_CmdHdr, L2CAP_InfoResp, code=11)
bind_layers(L2CAP_CmdHdr, L2CAP_Connection_Parameter_Update_Request, code=18)
bind_layers(L2CAP_CmdHdr, L2CAP_Connection_Parameter_Update_Response, code=19)
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
bind_layers(SM_Hdr, SM_Pairing_Request, sm_command=1)
bind_layers(SM_Hdr, SM_Pairing_Response, sm_command=2)
bind_layers(SM_Hdr, SM_Confirm, sm_command=3)
bind_layers(SM_Hdr, SM_Random, sm_command=4)
bind_layers(SM_Hdr, SM_Failed, sm_command=5)
bind_layers(SM_Hdr, SM_Encryption_Information, sm_command=6)
bind_layers(SM_Hdr, SM_Master_Identification, sm_command=7)
bind_layers(SM_Hdr, SM_Identity_Information, sm_command=8)
bind_layers(SM_Hdr, SM_Identity_Address_Information, sm_command=9)
bind_layers(SM_Hdr, SM_Signing_Information, sm_command=0x0a)
bind_layers(SM_Hdr, SM_Public_Key, sm_command=0x0c)
bind_layers(SM_Hdr, SM_DHKey_Check, sm_command=0x0d)


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
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")

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
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")

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
        opcode = cmd.opcode
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
    desc = "read/write over a Bluetooth monitor channel"

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
        return BT_Mon_Hdr(self.ins.recv(x))


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
