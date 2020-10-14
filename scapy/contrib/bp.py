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

"""
 Copyright 2012, The MITRE Corporation::

                              NOTICE
    This software/technical data was produced for the U.S. Government
    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
      and is subject to FAR 52.227-14 (6/87) Rights in Data General,
        and Article GP-51, Rights in Data  General, respectively.
       This software is publicly released under MITRE case #12-3054
"""

# scapy.contrib.description = Bundle Protocol (BP)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    StrLenField
from scapy.contrib.sdnv import SDNV2FieldLenField, SDNV2LenField, SDNV2
from scapy.contrib.ltp import LTP, ltp_bind_payload


class BP(Packet):
    name = "BP"
    fields_desc = [ByteField('version', 0x06),
                   SDNV2('ProcFlags', 0),
                   SDNV2LenField('BlockLen', None),
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
                   ConditionalField(SDNV2("FO", 0), lambda x: (
                       x.ProcFlags & 0x01)),
                   ConditionalField(SDNV2("ADUL", 0), lambda x: (
                       x.ProcFlags & 0x01)),
                   ]

    def mysummary(self):
        tmp = "BP(%version%) flags("
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
        COS = RAWCOS >> 7
        cos_tmp = ''
        if COS == 0x00:
            cos_tmp += 'B '
        if COS == 0x01:
            cos_tmp += 'N '
        if COS == 0x02:
            cos_tmp += 'E '
        if COS & 0xFE000:
            cos_tmp += 'SRR: ('
        if COS & 0x02000:
            cos_tmp += 'Rec '
        if COS & 0x04000:
            cos_tmp += 'CA '
        if COS & 0x08000:
            cos_tmp += 'FWD '
        if COS & 0x10000:
            cos_tmp += 'DLV '
        if COS & 0x20000:
            cos_tmp += 'DEL '
        if COS & 0xFE000:
            cos_tmp += ') '

        if cos_tmp:
            tmp += ' Pr: ' + cos_tmp

        tmp += " ) len(%BlockLen%) "
        if self.DL == 0:
            tmp += "CBHE: d[%DSO%,%DSSO%] s[%SSO%, %SSSO%] r[%RTSO%, %RTSSO%] c[%CSO%, %CSSO%] "  # noqa: E501
        else:
            tmp += "dl[%DL%] "
        tmp += "ct[%CT%] ctsn[%CTSN%] lt[%LT%] "
        if (self.ProcFlags & 0x01):
            tmp += "fo[%FO%] "
            tmp += "tl[%ADUL%]"

        return self.sprintf(tmp), [LTP]


class BPBLOCK(Packet):
    fields_desc = [ByteEnumField('Type', 1, {1: "Bundle payload block"}),
                   SDNV2('ProcFlags', 0),
                   SDNV2FieldLenField('BlockLen', None, length_of="load"),
                   StrLenField("load", "",
                               length_from=lambda pkt: pkt.BlockLen,
                               max_length=65535)
                   ]

    def mysummary(self):
        return self.sprintf("BPBLOCK(%Type%) Flags: %ProcFlags% Len: %BlockLen%")  # noqa: E501


ltp_bind_payload(BP, lambda pkt: pkt.DATA_ClientServiceID == 1)
bind_layers(BP, BPBLOCK)
bind_layers(BPBLOCK, BPBLOCK)
