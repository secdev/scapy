# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license


"""A minimal implementation of the CANopen protocol, based on
Wireshark dissectors. See https://wiki.wireshark.org/CANopen

"""


from scapy.config import conf
from scapy.data import DLT_CAN_SOCKETCAN
from scapy.fields import BitField, FieldLenField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import CookedLinux


class CAN(Packet):
    """A minimal implementation of the CANopen protocol, based on
    Wireshark dissectors. See https://wiki.wireshark.org/CANopen

    """
    fields_desc = [
        FlagsField('flags', 0, 3, ['error', 'remote_transmission_request', 'extended']),
        XBitField('identifier', 0, 29),
        FieldLenField('length', None, length_of='data', fmt='B'),
        ThreeBytesField('reserved', 0),
        StrLenField('data', '', length_from=lambda pkt: pkt.length),
        StrLenField('padding', '', length_from=lambda pkt: 8 - pkt.length),
    ]


conf.l2types.register(DLT_CAN_SOCKETCAN, CAN)
bind_layers(CookedLinux, CAN, proto=12)
