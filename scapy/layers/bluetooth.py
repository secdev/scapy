## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Copyright (C) Mike Ryan <mikeryan@lacklustre.net>
## This program is published under a GPLv2 license

"""
Bluetooth layers, sockets and send/receive functions.
"""

import socket,struct,array
from ctypes import *
from select import select

from scapy.all import *
from scapy.config import conf
from scapy.packet import *
from scapy.fields import *
from scapy.supersocket import SuperSocket
from scapy.sendrecv import sndrcv
from scapy.data import MTU

##########
# Fields #
##########

class XLEShortField(LEShortField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class XLELongField(LEShortField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class LEMACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")
    def i2m(self, pkt, x):
        if x is None:
            return "\0\0\0\0\0\0"
        return mac2str(x)[::-1]
    def m2i(self, pkt, x):
        return str2mac(x[::-1])
    def any2i(self, pkt, x):
        if type(x) is str and len(x) is 6:
            x = self.m2i(pkt, x)
        return x
    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        if self in conf.resolve:
            x = conf.manufdb._resolve_MAC(x)
        return x
    def randval(self):
        return RandMAC()


class HCI_Hdr(Packet):
    name = "HCI header"
    fields_desc = [ ByteEnumField("type",2,{1:"command",2:"ACLdata",3:"SCOdata",4:"event",5:"vendor"}),]

    def mysummary(self):
        return self.sprintf("HCI %type%")

class HCI_ACL_Hdr(Packet):
    name = "HCI ACL header"
    fields_desc = [ ByteField("handle",0), # Actually, handle is 12 bits and flags is 4.
                    ByteField("flags",0),  # I wait to write a LEBitField
                    LEShortField("len",None), ]
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-4
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p


class L2CAP_Hdr(Packet):
    name = "L2CAP header"
    fields_desc = [ LEShortField("len",None),
            LEShortEnumField("cid",0,{1:"control", 4:"attribute"}),]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(pay)
            p = chr(l&0xff)+chr((l>>8)&0xff)+p[2:]
        return p



class L2CAP_CmdHdr(Packet):
    name = "L2CAP command header"
    fields_desc = [
        ByteEnumField("code",8,{1:"rej",2:"conn_req",3:"conn_resp",
                                4:"conf_req",5:"conf_resp",6:"disconn_req",
                                7:"disconn_resp",8:"echo_req",9:"echo_resp",
                                10:"info_req",11:"info_resp", 18:"conn_param_update_req",
                                19:"conn_param_update_resp"}),
        ByteField("id",0),
        LEShortField("len",None) ]
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-4
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p
    def answers(self, other):
        if other.id == self.id:
            if self.code == 1:
                return 1
            if other.code in [2,4,6,8,10,18] and self.code == other.code+1:
                if other.code == 8:
                    return 1
                return self.payload.answers(other.payload)
        return 0

class L2CAP_ConnReq(Packet):
    name = "L2CAP Conn Req"
    fields_desc = [ LEShortEnumField("psm",0,{1:"SDP",3:"RFCOMM",5:"telephony control"}),
                    LEShortField("scid",0),
                    ]

class L2CAP_ConnResp(Packet):
    name = "L2CAP Conn Resp"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("scid",0),
                    LEShortEnumField("result",0,["success", "pend", "cr_bad_psm", "cr_sec_block", "cr_no_mem", "reserved","cr_inval_scid", "cr_scid_in_use"]),
                    LEShortEnumField("status",0,["no_info", "authen_pend", "author_pend", "reserved"]),
                    ]
    def answers(self, other):
        return self.scid == other.scid

class L2CAP_CmdRej(Packet):
    name = "L2CAP Command Rej"
    fields_desc = [ LEShortField("reason",0),
                    ]


class L2CAP_ConfReq(Packet):
    name = "L2CAP Conf Req"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("flags",0),
                    ]

class L2CAP_ConfResp(Packet):
    name = "L2CAP Conf Resp"
    fields_desc = [ LEShortField("scid",0),
                    LEShortField("flags",0),
                    LEShortEnumField("result",0,["success","unaccept","reject","unknown"]),
                    ]
    def answers(self, other):
        return self.scid == other.scid


class L2CAP_DisconnReq(Packet):
    name = "L2CAP Disconn Req"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("scid",0), ]

class L2CAP_DisconnResp(Packet):
    name = "L2CAP Disconn Resp"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("scid",0), ]
    def answers(self, other):
        return self.scid == other.scid



class L2CAP_InfoReq(Packet):
    name = "L2CAP Info Req"
    fields_desc = [ LEShortEnumField("type",0,{1:"CL_MTU",2:"FEAT_MASK"}),
                    StrField("data","")
                    ]


class L2CAP_InfoResp(Packet):
    name = "L2CAP Info Resp"
    fields_desc = [ LEShortField("type",0),
                    LEShortEnumField("result",0,["success","not_supp"]),
                    StrField("data",""), ]
    def answers(self, other):
        return self.type == other.type

    
class L2CAP_Connection_Parameter_Update_Request(Packet):
    name = "L2CAP Connection Parameter Update Request"
    fields_desc = [ LEShortField("min_interval", 0),
                    LEShortField("max_interval", 0),
                    LEShortField("slave_latency", 0),
                    LEShortField("timeout_mult", 0), ]

    
class L2CAP_Connection_Parameter_Update_Response(Packet):
    name = "L2CAP Connection Parameter Update Response"
    fields_desc = [ LEShortField("move_result", 0), ]


class ATT_Hdr(Packet):
    name = "ATT header"
    fields_desc = [ XByteField("opcode", None), ]


class ATT_Error_Response(Packet):
    name = "Error Response"
    fields_desc = [ XByteField("request", 0),
                    LEShortField("handle", 0),
                    XByteField("ecode", 0), ]

class ATT_Exchange_MTU_Request(Packet):
    name = "Exchange MTU Request"
    fields_desc = [ LEShortField("mtu", 0), ]

class ATT_Exchange_MTU_Response(Packet):
    name = "Exchange MTU Response"
    fields_desc = [ LEShortField("mtu", 0), ]

class ATT_Find_Information_Request(Packet):
    name = "Find Information Request"
    fields_desc = [ XLEShortField("start", 0x0000),
                    XLEShortField("end", 0xffff), ]

class ATT_Find_Information_Response(Packet):
    name = "Find Information Reponse"
    fields_desc = [ XByteField("format", 1),
                    StrField("data", "") ]

class ATT_Find_By_Type_Value_Request(Packet):
    name = "Find By Type Value Request"
    fields_desc = [ XLEShortField("start", 0x0001),
                    XLEShortField("end", 0xffff),
                    XLEShortField("uuid", None),
                    StrField("data", ""), ]

class ATT_Find_By_Type_Value_Response(Packet):
    name = "Find By Type Value Response"
    fields_desc = [ StrField("handles", ""), ]

class ATT_Read_By_Type_Request_128bit(Packet):
    name = "Read By Type Request"
    fields_desc = [ XLEShortField("start", 0x0001),
                    XLEShortField("end", 0xffff),
                    XLELongField("uuid1", None),
                    XLELongField("uuid2", None)]

class ATT_Read_By_Type_Request(Packet):
    name = "Read By Type Request"
    fields_desc = [ XLEShortField("start", 0x0001),
                    XLEShortField("end", 0xffff),
                    XLEShortField("uuid", None)]

class ATT_Read_By_Type_Response(Packet):
    name = "Read By Type Response"
    # fields_desc = [ FieldLenField("len", None, length_of="data", fmt="B"),
    #                 StrLenField("data", "", length_from=lambda pkt:pkt.len), ]
    fields_desc = [ StrField("data", "") ]

class ATT_Read_Request(Packet):
    name = "Read Request"
    fields_desc = [ XLEShortField("gatt_handle", 0), ]

class ATT_Read_Response(Packet):
    name = "Read Response"
    fields_desc = [ StrField("value", ""), ]

class ATT_Read_By_Group_Type_Request(Packet):
    name = "Read By Group Type Request"
    fields_desc = [ XLEShortField("start", 0),
                    XLEShortField("end", 0xffff),
                    XLEShortField("uuid", 0), ]

class ATT_Read_By_Group_Type_Response(Packet):
    name = "Read By Group Type Response"
    fields_desc = [ XByteField("length", 0),
                    StrField("data", ""), ]

class ATT_Write_Request(Packet):
    name = "Write Request"
    fields_desc = [ XLEShortField("gatt_handle", 0),
                    StrField("data", ""), ]

class ATT_Write_Command(Packet):
    name = "Write Request"
    fields_desc = [ XLEShortField("gatt_handle", 0),
                    StrField("data", ""), ]

class ATT_Write_Response(Packet):
    name = "Write Response"
    fields_desc = [ ]

class ATT_Handle_Value_Notification(Packet):
    name = "Handle Value Notification"
    fields_desc = [ XLEShortField("handle", 0),
                    StrField("value", ""), ]


class SM_Hdr(Packet):
    name = "SM header"
    fields_desc = [ ByteField("sm_command", None) ]


class SM_Pairing_Request(Packet):
    name = "Pairing Request"
    fields_desc = [ ByteEnumField("iocap", 3, {0:"DisplayOnly", 1:"DisplayYesNo", 2:"KeyboardOnly", 3:"NoInputNoOutput", 4:"KeyboardDisplay"}),
                    ByteEnumField("oob", 0, {0:"Not Present", 1:"Present (from remote device)"}),
                    BitField("authentication", 0, 8),
                    ByteField("max_key_size", 16),
                    ByteField("initiator_key_distribution", 0),
                    ByteField("responder_key_distribution", 0), ]

class SM_Pairing_Response(Packet):
    name = "Pairing Response"
    fields_desc = [ ByteEnumField("iocap", 3, {0:"DisplayOnly", 1:"DisplayYesNo", 2:"KeyboardOnly", 3:"NoInputNoOutput", 4:"KeyboardDisplay"}),
                    ByteEnumField("oob", 0, {0:"Not Present", 1:"Present (from remote device)"}),
                    BitField("authentication", 0, 8),
                    ByteField("max_key_size", 16),
                    ByteField("initiator_key_distribution", 0),
                    ByteField("responder_key_distribution", 0), ]


class SM_Confirm(Packet):
    name = "Pairing Confirm"
    fields_desc = [ StrFixedLenField("confirm", '\x00' * 16, 16) ]

class SM_Random(Packet):
    name = "Pairing Random"
    fields_desc = [ StrFixedLenField("random", '\x00' * 16, 16) ]

class SM_Failed(Packet):
    name = "Pairing Failed"
    fields_desc = [ XByteField("reason", 0) ]

class SM_Encryption_Information(Packet):
    name = "Encryption Information"
    fields_desc = [ StrFixedLenField("ltk", "\x00" * 16, 16), ]

class SM_Master_Identification(Packet):
    name = "Master Identification"
    fields_desc = [ XLEShortField("ediv", 0),
                    StrFixedLenField("rand", '\x00' * 8, 8), ]
    
class SM_Identity_Information(Packet):
    name = "Identity Information"
    fields_desc = [ StrFixedLenField("irk", '\x00' * 16, 16), ]

class SM_Identity_Address_Information(Packet):
    name = "Identity Address Information"
    fields_desc = [ ByteEnumField("atype", 0, {0:"public"}),
                    LEMACField("address", None), ]
    
class SM_Signing_Information(Packet):
    name = "Signing Information"
    fields_desc = [ StrFixedLenField("csrk", '\x00' * 16, 16), ]


class EIR_Hdr(Packet):
    name = "EIR Header"
    fields_desc = [
        FieldLenField("len", 0, fmt="B"),
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
            0x17: "pub_target_addr",
            0x18: "rand_target_addr",
            0x19: "appearance",
            0x1a: "adv_intvl",
            0x1b: "le_addr",
            0x1c: "le_role",
            0x14: "list_16_bit_svc_sollication_uuids",
            0x1f: "list_32_bit_svc_sollication_uuids",
            0x15: "list_128_bit_svc_sollication_uuids",
            0x16: "svc_data_16_bit_uuid",
            0x20: "svc_data_32_bit_uuid",
            0x21: "svc_data_128_bit_uuid",
            0x22: "sec_conn_confirm",
            0x22: "sec_conn_rand",
            0x24: "uri",
            0xff: "mfg_specific_data",
        }),
    ]

    def mysummary(self):
        return self.sprintf("EIR %type%")

class EIR_Element(Packet):
    name = "EIR Element"

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        return '', s

    @staticmethod
    def length_from(pkt):
        # 'type' byte is included in the length, so substract 1:
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
                    "simul_le_br_edr_host"] + 3*["reserved"])
    ]

class EIR_CompleteList16BitServiceUUIDs(EIR_Element):
    name = "Complete list of 16-bit service UUIDs"
    fields_desc = [
        FieldListField("svc_uuids", None, XLEShortField("uuid", 0),
                       length_from=EIR_Element.length_from)
    ]

class EIR_IncompleteList16BitServiceUUIDs(EIR_CompleteList16BitServiceUUIDs):
    name = "Incomplete list of 16-bit service UUIDs"

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
        XLEShortField("company_id", 0),
        StrLenField("data", "",
                    length_from=lambda pkt: EIR_Element.length_from(pkt) - 2)
    ]


class HCI_Command_Hdr(Packet):
    name = "HCI Command header"
    fields_desc = [ XLEShortField("opcode", 0),
                    ByteField("len", None), ]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-3
            p = p[:2]+chr(l&0xff)+p[3:]
        return p

class HCI_Cmd_Reset(Packet):
    name = "Reset"

class HCI_Cmd_Set_Event_Filter(Packet):
    name = "Set Event Filter"
    fields_desc = [ ByteEnumField("type", 0, {0:"clear"}), ]

class HCI_Cmd_Connect_Accept_Timeout(Packet):
    name = "Connection Attempt Timeout"
    fields_desc = [ LEShortField("timeout", 32000) ] # 32000 slots is 20000 msec

class HCI_Cmd_LE_Host_Supported(Packet):
    name = "LE Host Supported"
    fields_desc = [ ByteField("supported", 1),
                    ByteField("simultaneous", 1), ]

class HCI_Cmd_Set_Event_Mask(Packet):
    name = "Set Event Mask"
    fields_desc = [ StrFixedLenField("mask", "\xff\xff\xfb\xff\x07\xf8\xbf\x3d", 8) ]

class HCI_Cmd_Read_BD_Addr(Packet):
    name = "Read BD Addr"


class HCI_Cmd_LE_Set_Scan_Parameters(Packet):
    name = "LE Set Scan Parameters"
    fields_desc = [ ByteEnumField("type", 1, {1:"active"}),
                    XLEShortField("interval", 16),
                    XLEShortField("window", 16),
                    ByteEnumField("atype", 0, {0:"public"}),
                    ByteEnumField("policy", 0, {0:"all"}), ]

class HCI_Cmd_LE_Set_Scan_Enable(Packet):
    name = "LE Set Scan Enable"
    fields_desc = [ ByteField("enable", 1),
                    ByteField("filter_dups", 1), ]

class HCI_Cmd_Disconnect(Packet):
    name = "Disconnect"
    fields_desc = [ XLEShortField("handle", 0),
                    ByteField("reason", 0x13), ]

class HCI_Cmd_LE_Create_Connection(Packet):
    name = "LE Create Connection"
    fields_desc = [ LEShortField("interval", 96),
                    LEShortField("window", 48),
                    ByteEnumField("filter", 0, {0:"address"}),
                    ByteEnumField("patype", 0, {0:"public", 1:"random"}),
                    LEMACField("paddr", None),
                    ByteEnumField("atype", 0, {0:"public", 1:"random"}),
                    LEShortField("min_interval", 40),
                    LEShortField("max_interval", 56),
                    LEShortField("latency", 0),
                    LEShortField("timeout", 42),
                    LEShortField("min_ce", 0),
                    LEShortField("max_ce", 0), ]
    
class HCI_Cmd_LE_Create_Connection_Cancel(Packet):
    name = "LE Create Connection Cancel"

class HCI_Cmd_LE_Connection_Update(Packet):
    name = "LE Connection Update"
    fields_desc = [ XLEShortField("handle", 0),
                    XLEShortField("min_interval", 0),
                    XLEShortField("max_interval", 0),
                    XLEShortField("latency", 0),
                    XLEShortField("timeout", 0),
                    LEShortField("min_ce", 0),
                    LEShortField("max_ce", 0xffff), ]

class HCI_Cmd_LE_Read_Buffer_Size(Packet):
    name = "LE Read Buffer Size"

class HCI_Cmd_LE_Set_Random_Address(Packet):
    name = "LE Set Random Address"
    fields_desc = [ LEMACField("address", None) ]

class HCI_Cmd_LE_Set_Advertising_Parameters(Packet):
    name = "LE Set Advertising Parameters"
    fields_desc = [ LEShortField("interval_min", 0x0800),
                    LEShortField("interval_max", 0x0800),
                    ByteEnumField("adv_type", 0, {0:"ADV_IND", 1:"ADV_DIRECT_IND", 2:"ADV_SCAN_IND", 3:"ADV_NONCONN_IND", 4:"ADV_DIRECT_IND_LOW"}),
                    ByteEnumField("oatype", 0, {0:"public", 1:"random"}),
                    ByteEnumField("datype", 0, {0:"public", 1:"random"}),
                    LEMACField("daddr", None),
                    ByteField("channel_map", 7),
                    ByteEnumField("filter_policy", 0, {0:"all:all", 1:"connect:all scan:whitelist", 2:"connect:whitelist scan:all", 3:"all:whitelist"}), ]

class HCI_Cmd_LE_Set_Advertising_Data(Packet):
    name = "LE Set Advertising Data"
    fields_desc = [ FieldLenField("len", None, length_of="data", fmt="B"),
                    StrLenField("data", "", length_from=lambda pkt:pkt.len), ]

class HCI_Cmd_LE_Set_Advertise_Enable(Packet):
    name = "LE Set Advertise Enable"
    fields_desc = [ ByteField("enable", 0) ]

class HCI_Cmd_LE_Start_Encryption_Request(Packet):
    name = "LE Start Encryption"
    fields_desc = [ LEShortField("handle", 0),
                    StrFixedLenField("rand", None, 8),
                    XLEShortField("ediv", 0),
                    StrFixedLenField("ltk", '\x00' * 16, 16), ]

class HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(Packet):
    name = "LE Long Term Key Request Negative Reply"
    fields_desc = [ LEShortField("handle", 0), ]

class HCI_Cmd_LE_Long_Term_Key_Request_Reply(Packet):
    name = "LE Long Term Key Request Reply"
    fields_desc = [ LEShortField("handle", 0),
                    StrFixedLenField("ltk", '\x00' * 16, 16), ]

class HCI_Event_Hdr(Packet):
    name = "HCI Event header"
    fields_desc = [ XByteField("code", 0),
                    ByteField("length", 0), ]


class HCI_Event_Disconnection_Complete(Packet):
    name = "Disconnection Complete"
    fields_desc = [ ByteEnumField("status", 0, {0:"success"}),
                    LEShortField("handle", 0),
                    XByteField("reason", 0), ]


class HCI_Event_Encryption_Change(Packet):
    name = "Encryption Change"
    fields_desc = [ ByteEnumField("status", 0, {0:"change has occurred"}),
                    LEShortField("handle", 0),
                    ByteEnumField("enabled", 0, {0:"OFF", 1:"ON (LE)", 2:"ON (BR/EDR)"}), ]

class HCI_Event_Command_Complete(Packet):
    name = "Command Complete"
    fields_desc = [ ByteField("number", 0),
                    XLEShortField("opcode", 0),
                    ByteEnumField("status", 0, {0:"success"}), ]


class HCI_Cmd_Complete_Read_BD_Addr(Packet):
    name = "Read BD Addr"
    fields_desc = [ LEMACField("addr", None), ]



class HCI_Event_Command_Status(Packet):
    name = "Command Status"
    fields_desc = [ ByteEnumField("status", 0, {0:"pending"}),
                    ByteField("number", 0),
                    XLEShortField("opcode", None), ]

class HCI_Event_Number_Of_Completed_Packets(Packet):
    name = "Number Of Completed Packets"
    fields_desc = [ ByteField("number", 0) ]

class HCI_Event_LE_Meta(Packet):
    name = "LE Meta"
    fields_desc = [ ByteEnumField("event", 0, {2:"advertising_report"}) ]

class HCI_LE_Meta_Connection_Complete(Packet):
    name = "Connection Complete"
    fields_desc = [ ByteEnumField("status", 0, {0:"success"}),
                    LEShortField("handle", 0),
                    ByteEnumField("role", 0, {0:"master"}),
                    ByteEnumField("patype", 0, {0:"public", 1:"random"}),
                    LEMACField("paddr", None),
                    LEShortField("interval", 54),
                    LEShortField("latency", 0),
                    LEShortField("supervision", 42),
                    XByteField("clock_latency", 5), ]

class HCI_LE_Meta_Connection_Update_Complete(Packet):
    name = "Connection Update Complete"
    fields_desc = [ ByteEnumField("status", 0, {0:"success"}),
                    LEShortField("handle", 0),
                    LEShortField("interval", 54),
                    LEShortField("latency", 0),
                    LEShortField("timeout", 42), ]

class HCI_LE_Meta_Advertising_Report(Packet):
    name = "Advertising Report"
    fields_desc = [ ByteField("number", 0),
                    ByteEnumField("type", 0, {0:"conn_und", 4:"scan_rsp"}),
                    ByteEnumField("atype", 0, {0:"public", 1:"random"}),
                    LEMACField("addr", None),
                    FieldLenField("len", None, length_of="data", fmt="B"),
                    PacketListField("data", [], EIR_Hdr,
                                    length_from=lambda pkt:pkt.len),
                    SignedByteField("rssi", 0)]


class HCI_LE_Meta_Long_Term_Key_Request(Packet):
    name = "Long Term Key Request"
    fields_desc = [ LEShortField("handle", 0),
                    StrFixedLenField("rand", None, 8),
                    XLEShortField("ediv", 0), ]


bind_layers( HCI_Hdr,       HCI_Command_Hdr,    type=1)
bind_layers( HCI_Hdr,       HCI_ACL_Hdr,        type=2)
bind_layers( HCI_Hdr,       HCI_Event_Hdr,      type=4)
bind_layers( HCI_Hdr,       conf.raw_layer,           )

bind_layers( HCI_Command_Hdr, HCI_Cmd_Reset, opcode=0x0c03)
bind_layers( HCI_Command_Hdr, HCI_Cmd_Set_Event_Mask, opcode=0x0c01)
bind_layers( HCI_Command_Hdr, HCI_Cmd_Set_Event_Filter, opcode=0x0c05)
bind_layers( HCI_Command_Hdr, HCI_Cmd_Connect_Accept_Timeout, opcode=0x0c16)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Host_Supported, opcode=0x0c6d)
bind_layers( HCI_Command_Hdr, HCI_Cmd_Read_BD_Addr, opcode=0x1009)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Read_Buffer_Size, opcode=0x2002)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Set_Random_Address, opcode=0x2005)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertising_Parameters, opcode=0x2006)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertising_Data, opcode=0x2008)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Set_Advertise_Enable, opcode=0x200a)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Parameters, opcode=0x200b)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Set_Scan_Enable, opcode=0x200c)
bind_layers( HCI_Command_Hdr, HCI_Cmd_Disconnect, opcode=0x406)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Create_Connection, opcode=0x200d)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Create_Connection_Cancel, opcode=0x200e)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Connection_Update, opcode=0x2013)


bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Start_Encryption_Request, opcode=0x2019)

bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Long_Term_Key_Request_Reply, opcode=0x201a)
bind_layers( HCI_Command_Hdr, HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply, opcode=0x201b)

bind_layers( HCI_Event_Hdr, HCI_Event_Disconnection_Complete, code=0x5)
bind_layers( HCI_Event_Hdr, HCI_Event_Encryption_Change, code=0x8)
bind_layers( HCI_Event_Hdr, HCI_Event_Command_Complete, code=0xe)
bind_layers( HCI_Event_Hdr, HCI_Event_Command_Status, code=0xf)
bind_layers( HCI_Event_Hdr, HCI_Event_Number_Of_Completed_Packets, code=0x13)
bind_layers( HCI_Event_Hdr, HCI_Event_LE_Meta, code=0x3e)

bind_layers( HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_BD_Addr, opcode=0x1009)

bind_layers( HCI_Event_LE_Meta, HCI_LE_Meta_Connection_Complete, event=1)
bind_layers( HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Report, event=2)
bind_layers( HCI_Event_LE_Meta, HCI_LE_Meta_Connection_Update_Complete, event=3)
bind_layers( HCI_Event_LE_Meta, HCI_LE_Meta_Long_Term_Key_Request, event=5)

bind_layers(EIR_Hdr, EIR_Flags, type=0x01)
bind_layers(EIR_Hdr, EIR_IncompleteList16BitServiceUUIDs, type=0x02)
bind_layers(EIR_Hdr, EIR_CompleteList16BitServiceUUIDs, type=0x03)
bind_layers(EIR_Hdr, EIR_ShortenedLocalName, type=0x08)
bind_layers(EIR_Hdr, EIR_CompleteLocalName, type=0x09)
bind_layers(EIR_Hdr, EIR_TX_Power_Level, type=0x0a)
bind_layers(EIR_Hdr, EIR_Manufacturer_Specific_Data, type=0xff)
bind_layers(EIR_Hdr, EIR_Raw)

bind_layers( HCI_ACL_Hdr,   L2CAP_Hdr,     )
bind_layers( L2CAP_Hdr,     L2CAP_CmdHdr,      cid=1)
bind_layers( L2CAP_Hdr,     L2CAP_CmdHdr,      cid=5) #LE L2CAP Signaling Channel
bind_layers( L2CAP_CmdHdr,  L2CAP_CmdRej,      code=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnReq,     code=2)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnResp,    code=3)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfReq,     code=4)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfResp,    code=5)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnReq,  code=6)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnResp, code=7)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoReq,     code=10)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoResp,    code=11)
bind_layers( L2CAP_CmdHdr,  L2CAP_Connection_Parameter_Update_Request,    code=18)
bind_layers( L2CAP_CmdHdr,  L2CAP_Connection_Parameter_Update_Response,    code=19)
bind_layers( L2CAP_Hdr,     ATT_Hdr,           cid=4)
bind_layers( ATT_Hdr,       ATT_Error_Response, opcode=0x1)
bind_layers( ATT_Hdr,       ATT_Exchange_MTU_Request, opcode=0x2)
bind_layers( ATT_Hdr,       ATT_Exchange_MTU_Response, opcode=0x3)
bind_layers( ATT_Hdr,       ATT_Find_Information_Request, opcode=0x4)
bind_layers( ATT_Hdr,       ATT_Find_Information_Response, opcode=0x5)
bind_layers( ATT_Hdr,       ATT_Find_By_Type_Value_Request, opcode=0x6)
bind_layers( ATT_Hdr,       ATT_Find_By_Type_Value_Response, opcode=0x7)
bind_layers( ATT_Hdr,       ATT_Read_By_Type_Request, opcode=0x8)
bind_layers( ATT_Hdr,       ATT_Read_By_Type_Request_128bit, opcode=0x8)
bind_layers( ATT_Hdr,       ATT_Read_By_Type_Response, opcode=0x9)
bind_layers( ATT_Hdr,       ATT_Read_Request, opcode=0xa)
bind_layers( ATT_Hdr,       ATT_Read_Response, opcode=0xb)
bind_layers( ATT_Hdr,       ATT_Read_By_Group_Type_Request, opcode=0x10)
bind_layers( ATT_Hdr,       ATT_Read_By_Group_Type_Response, opcode=0x11)
bind_layers( ATT_Hdr,       ATT_Write_Request, opcode=0x12)
bind_layers( ATT_Hdr,       ATT_Write_Response, opcode=0x13)
bind_layers( ATT_Hdr,       ATT_Write_Command, opcode=0x52)
bind_layers( ATT_Hdr,       ATT_Handle_Value_Notification, opcode=0x1b)
bind_layers( L2CAP_Hdr,     SM_Hdr,            cid=6)
bind_layers( SM_Hdr,        SM_Pairing_Request, sm_command=1)
bind_layers( SM_Hdr,        SM_Pairing_Response, sm_command=2)
bind_layers( SM_Hdr,        SM_Confirm,        sm_command=3)
bind_layers( SM_Hdr,        SM_Random,         sm_command=4)
bind_layers( SM_Hdr,        SM_Failed,         sm_command=5)
bind_layers( SM_Hdr,        SM_Encryption_Information, sm_command=6)
bind_layers( SM_Hdr,        SM_Master_Identification, sm_command=7)
bind_layers( SM_Hdr,        SM_Identity_Information, sm_command=8)
bind_layers( SM_Hdr,        SM_Identity_Address_Information, sm_command=9)
bind_layers( SM_Hdr,        SM_Signing_Information, sm_command=0x0a)


class BluetoothL2CAPSocket(SuperSocket):
    desc = "read/write packets on a connected L2CAP socket"
    def __init__(self, peer):
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW,
                          socket.BTPROTO_L2CAP)
        s.connect((peer,0))

        self.ins = self.outs = s

    def recv(self, x=MTU):
        return L2CAP_CmdHdr(self.ins.recv(x))


class BluetoothHCISocket(SuperSocket):
    desc = "read/write on a BlueTooth HCI socket"
    def __init__(self, iface=0x10000, type=None):
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        s.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR,1)
        s.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP,1)
        s.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIh2x", 0xffffffffL,0xffffffffL,0xffffffffL,0)) #type mask, event mask, event mask, opcode
        s.bind((iface,))
        self.ins = self.outs = s
#        s.connect((peer,0))


    def recv(self, x):
        return HCI_Hdr(self.ins.recv(x))

class sockaddr_hci(Structure):
    _fields_ = [
        ("sin_family",      c_ushort),
        ("hci_dev",         c_ushort),
        ("hci_channel",     c_ushort),
    ]

class BluetoothSocketError(BaseException):
    pass

class BluetoothCommandError(BaseException):
    pass

class BluetoothUserSocket(SuperSocket):
    desc = "read/write H4 over a Bluetooth user channel"
    def __init__(self, adapter=0):
        # s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        # s.bind((0,1))

        # yeah, if only
        # thanks to Python's weak ass socket and bind implementations, we have
        # to call down into libc with ctypes

        sockaddr_hcip = POINTER(sockaddr_hci)
        cdll.LoadLibrary("libc.so.6")
        libc = CDLL("libc.so.6")

        socket_c = libc.socket
        socket_c.argtypes = (c_int, c_int, c_int);
        socket_c.restype = c_int

        bind = libc.bind
        bind.argtypes = (c_int, POINTER(sockaddr_hci), c_int)
        bind.restype = c_int

        ########
        ## actual code

        s = socket_c(31, 3, 1) # (AF_BLUETOOTH, SOCK_RAW, HCI_CHANNEL_USER)
        if s < 0:
            raise BluetoothSocketError("Unable to open PF_BLUETOOTH socket")

        sa = sockaddr_hci()
        sa.sin_family = 31  # AF_BLUETOOTH
        sa.hci_dev = adapter # adapter index
        sa.hci_channel = 1   # HCI_USER_CHANNEL

        r = bind(s, sockaddr_hcip(sa), sizeof(sa))
        if r != 0:
            raise BluetoothSocketError("Unable to bind")

        self.ins = self.outs = socket.fromfd(s, 31, 3, 1)

    def send_command(self, cmd):
        opcode = cmd.opcode
        self.send(cmd)
        while True:
            r = self.recv()
            if r.type == 0x04 and r.code == 0xe and r.opcode == opcode:
                if r.status != 0:
                    raise BluetoothCommandError("Command %x failed with %x" % (opcode, r.status))
                return r

    def recv(self, x=512):
        return HCI_Hdr(self.ins.recv(x))

    def readable(self, timeout=0):
        (ins, outs, foo) = select([self.ins], [], [], timeout)
        return len(ins) > 0

    def flush(self):
        while self.readable():
            self.recv()

## Bluetooth


@conf.commands.register
def srbt(peer, pkts, inter=0.1, *args, **kargs):
    """send and receive using a bluetooth socket"""
    s = conf.BTsocket(peer=peer)
    a,b = sndrcv(s,pkts,inter=inter,*args,**kargs)
    s.close()
    return a,b

@conf.commands.register
def srbt1(peer, pkts, *args, **kargs):
    """send and receive 1 packet using a bluetooth socket"""
    a,b = srbt(peer, pkts, *args, **kargs)
    if len(a) > 0:
        return a[0][1]



conf.BTsocket = BluetoothL2CAPSocket
