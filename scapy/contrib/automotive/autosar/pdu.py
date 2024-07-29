#! /usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Damian Zaręba <damianzrb@zohomail.eu>

# scapy.contrib.description = AUTOSAR PDU packets handling package.
# scapy.contrib.status = loads
from typing import Tuple, Optional
from scapy.layers.inet import UDP
from scapy.fields import XIntField, PacketListField, LenField
from scapy.packet import Packet, bind_bottom_up


class PDU(Packet):
    """
    Single PDU Packet inside PDUTransport list.
    Contains ID and payload length, and later - raw load.
    It's free to interpret using bind_layers/bind_bottom_up method

    Based off this document:

    https://www.autosar.org/fileadmin/standards/classic/22-11/AUTOSAR_SWS_IPDUMultiplexer.pdf # noqa: E501
    """
    name = 'PDU'
    fields_desc = [
        XIntField('pdu_id', 0),
        LenField('pdu_payload_len', None, fmt="I")]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return s[:self.pdu_payload_len], s[self.pdu_payload_len:]


class PDUTransport(Packet):
    """
    Packet representing PDUTransport containing multiple PDUs
    """
    name = 'PDUTransport'
    fields_desc = [
        PacketListField("pdus", [PDU()], PDU)
    ]


bind_bottom_up(UDP, PDUTransport, dport=60000)
