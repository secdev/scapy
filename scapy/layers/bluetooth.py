## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import socket,struct

from scapy.config import conf
from scapy.packet import *
from scapy.fields import *
from scapy.supersocket import SuperSocket
from scapy.data import MTU


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
                    LEShortEnumField("cid",0,{1:"control"}),]
    
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            l = len(p)-4
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p
                    
                

class L2CAP_CmdHdr(Packet):
    name = "L2CAP command header"
    fields_desc = [
        ByteEnumField("code",8,{1:"rej",2:"conn_req",3:"conn_resp",
                                4:"conf_req",5:"conf_resp",6:"disconn_req",
                                7:"disconn_resp",8:"echo_req",9:"echo_resp",
                                10:"info_req",11:"info_resp"}),
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
            if other.code in [2,4,6,8,10] and self.code == other.code+1:
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
                    LEShortEnumField("result",0,["no_info","authen_pend","author_pend"]),
                    LEShortEnumField("status",0,["success","pend","bad_psm",
                                               "cr_sec_block","cr_no_mem"]),
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



bind_layers( HCI_Hdr,       HCI_ACL_Hdr,   type=2)
bind_layers( HCI_Hdr,       Raw,           )
bind_layers( HCI_ACL_Hdr,   L2CAP_Hdr,     )
bind_layers( L2CAP_Hdr,     L2CAP_CmdHdr,      cid=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_CmdRej,      code=1)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnReq,     code=2)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConnResp,    code=3)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfReq,     code=4)
bind_layers( L2CAP_CmdHdr,  L2CAP_ConfResp,    code=5)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnReq,  code=6)
bind_layers( L2CAP_CmdHdr,  L2CAP_DisconnResp, code=7)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoReq,     code=10)
bind_layers( L2CAP_CmdHdr,  L2CAP_InfoResp,    code=11)
        
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
