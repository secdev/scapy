# Copyright 2012, The MITRE Corporation
#
#                             NOTICE
#    This software/technical data was produced for the U.S. Government
#    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
#      and is subject to FAR 52.227-14 (6/87) Rights in Data General,
#        and Article GP-51, Rights in Data  General, respectively.
#
#      This software is publicly released under MITRE case #12-3054


from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP
from scapy.layers.ltp import *
from sdnv import *


class SDNV2(Field):
    """ SDNV2 field """

    def __init__(self, name):
        Field.__init__(self, name, None)

    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def i2m(self, pkt, x):
        return x

    def m2i(self, pkt, x):
        return x

    def addfield(self, pkt, s, val):
        return s + str(toSDNV(val))

    def getfield(self, pkt, s):
        b = bytearray(s)
        val, len = extractSDNVFromByteArray(b, 0)
        return s[len:], val


class BP(Packet):
    name = "BP"
    fields_desc = [ByteField('version', 0),
                   SDNV2('ProcFlags', 0),
                   SDNV2('BlockLen', 0),
                   SDNV2('DSO', 0),
                   SDNV2('DSSO', 0),
                   SDNV2('SSO', 0),
                   SDNV2('SSSO', 0),
                   SDNV2('RTSO', 0),
                   SDNV2('RTSSO', 0),
                   SDNV2('CSO', 0),
                   SDNV2('CSSO', 0),
                   SDNV2('CT', 0),
                   SDNV2('CTSN', 0),
                   SDNV2('LT', 0),
                   SDNV2('DL', 0),
                   ConditionalField(SDNV2("FO", 0), lambda Packet: (
                       Packet.ProcFlags & 0x01)),
                   ConditionalField(SDNV2("ADUL", 0), lambda Packet: (
                       Packet.ProcFlags & 0x01)),
                   ]

    def mysummary(self):
        tmp = ""
        tmp += "BP(%version%) flags( "
        if (self.ProcFlags & 0x01):
            tmp += ' FR'
        if (self.ProcFlags & 0x02):
            tmp += ' AR'
        if (self.ProcFlags & 0x04):
            tmp += ' DF'
        if (self.ProcFlags & 0x08):
            tmp += ' CT'
        if (self.ProcFlags & 0x10):
            tmp += ' S'
        if (self.ProcFlags & 0x20):
            tmp += ' ACKME'
        RAWCOS = (self.ProcFlags & 0x0180)
        COS = (self.ProcFlags & 0x180) >> 7
        tmp += ' Pr: '
        if COS == 0x00:
            tmp += 'B '
        if COS == 0x01:
            tmp += 'N '
        if COS == 0x02:
            tmp += 'E '
        if COS & 0xFE000:
            tmp += 'SRR: ('
        if COS & 0x02000:
            tmp += 'Rec '
        if COS & 0x04000:
            tmp += 'CA '
        if COS & 0x08000:
            tmp += 'FWD '
        if COS & 0x10000:
            tmp += 'DLV '
        if COS & 0x20000:
            tmp += 'DEL '
        if COS & 0xFE000:
            tmp += ') '

        tmp += " ) len(%BlockLen%) "
        if self.DL == 0:
            tmp += "CBHE: d[%DSO%,%DSSO%] s[%SSO%, %SSSO%] r[%RTSO%, %RTSSO%] c[%CSO%, %CSSO%] "
        else:
            tmp += "dl[%DL%] "
        tmp += "ct[%CT%] ctsn[%CTSN%] lt[%LT%] "
        if (self.ProcFlags & 0x01):
            tmp += "fo[%FO%] "
            tmp += "tl[%ADUL%]"

        return self.sprintf(tmp), [LTP]


class BPBLOCK(Packet):
    fields_desc = [ByteField('Type', 0),
                   SDNV2('ProcFlags', 0),
                   SDNV2('BlockLen', 0),
                   StrLenField("the_varfield", "the_default_value",
                               length_from=lambda pkt: pkt.BlockLen)
                   ]

    def mysummary(self):
        tmp = ""
        tmp += "BLOCK(%Type%) Flags: %ProcFlags% Len: %BlockLen%"
        return self.sprintf(tmp), [BP]


class BPBLOCK2(Packet):
    fields_desc = [ByteField('Type', 0),
                   SDNV2('ProcFlags', 0),
                   SDNV2('BlockLen', 0),
                   StrLenField("the_varfield", "the_default_value",
                               length_from=lambda pkt: pkt.BlockLen)
                   ]

    def mysummary(self):
        tmp = ""
        tmp += "BLOCK(%Type%) Flags: %ProcFlags% Len: %BlockLen%"
        return self.sprintf(tmp), [BPBLOCK]


class BPBLOCK3(Packet):
    fields_desc = [ByteField('Type', 0),
                   SDNV2('ProcFlags', 0),
                   SDNV2('BlockLen', 0),
                   StrLenField("the_varfield", "the_default_value",
                               length_from=lambda pkt: pkt.BlockLen)
                   ]

    def mysummary(self):
        tmp = ""
        tmp += "BLOCK(%Type%) Flags: %ProcFlags% Len: %BlockLen%"
        return self.sprintf(tmp), [BPBLOCK2]


bind_layers(LTP,                    BP, ClientServiceID=1)
bind_layers(BP,                     BPBLOCK)
bind_layers(BPBLOCK,                BPBLOCK2)
bind_layers(BPBLOCK2,               BPBLOCK3)
