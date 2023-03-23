# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Deniz Bingöl <deniz.bingol@technica-engineering.de>

# scapy.contrib.description = Protocol-Data-Unit (PDU) and n-PDU
# scapy.contrib.status = loads

from scapy.all import Packet, IntField, FieldLenField, StrLenField, bind_layers, PacketListField
from scapy.layers.inet import UDP

class PDU(Packet):
    """Protocol Data Unit Packet"""
    name = "PDU Packet"
    fields_desc = [
         IntField("pkg_id", 0),
         FieldLenField("data_length", None, "data", fmt="I"),
         StrLenField("data", b'', length_from=lambda pkt: pkt.data_length)
         ]
    
    def extract_padding(self, s):
        return "", s

class nPDU(Packet):
    """Container for n-PDU packets"""
    name = "nPDU Container"
    fields_desc = [
        PacketListField("pkgs", None, PDU)
    ]

bind_layers(UDP, nPDU, dport=6661, sport=5551)