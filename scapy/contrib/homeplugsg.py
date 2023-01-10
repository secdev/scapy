# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = HomePlugSG Layer
# scapy.contrib.status = loads


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
