#! /usr/bin/env python

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

# scapy.contrib.description = HomePlugSG Layer
# scapy.contrib.status = loads

from __future__ import absolute_import

from scapy.packet import Packet, bind_layers
from scapy.fields import FieldLenField, StrFixedLenField, StrLenField

# Extends HomePlug AV and GP layer
from scapy.contrib.homeplugav import HomePlugAV, QualcommTypeList

#
#    Copyright (C) HomePlugSG Layer for Scapy by FlUxIuS (Sebastien Dudek)
#

# HomePlug GP extension for SG


HomePlugSGTypes = {0xA400: "VS_UART_CMD_Req",
                   0xA401: "VS_UART_CMD_Cnf"}


QualcommTypeList.update(HomePlugSGTypes)

# UART commands over HomePlugGP


class VS_UART_CMD_REQ(Packet):
    name = "VS_UART_CMD_REQ"
    fields_desc = [FieldLenField("UDataLen", None, count_of="UData", fmt="H"),
                   StrLenField("UData", "UartCommand\x00",
                               length_from=lambda pkt: pkt.UDataLen)]


class VS_UART_CMD_CNF(Packet):
    name = "VS_UART_CMD_CNF"
    fields_desc = [StrFixedLenField("reserved", b"\x00", 6),
                   FieldLenField("UDataLen", None, count_of="UData", fmt="H"),
                   StrLenField("UData", "UartCommand\x00",
                               length_from=lambda pkt: pkt.UDataLen)]


# END #

bind_layers(HomePlugAV, VS_UART_CMD_REQ, HPtype=0xA400)
bind_layers(HomePlugAV, VS_UART_CMD_CNF, HPtype=0xA401)
