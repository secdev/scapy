#! /usr/bin/env python
#
# scapy.contrib.description = MACControl
# scapy.contrib.status = loads

"""
    MACControl
    ~~~~~~~~~~

    :author:    Thomas Tannhaeuser, hecke@naberius.de
    :license:   GPLv2

        This module is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This module is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

    :description:

        This module provides Scapy layers for the MACControl protocol messages:
            - Pause
            - Gate
            - Report
            - Register/REQ/ACK
            - Class Based Flow Control

        normative references:
            - IEEE 802.3x


    :NOTES:
        - this is based on the MACControl dissector used by Wireshark
          (https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-maccontrol.c)

"""

from scapy.compat import orb
from scapy.data import ETHER_TYPES
from scapy.error import Scapy_Exception
from scapy.fields import IntField, ByteField, ByteEnumField, ShortField, BitField  # noqa: E501
from scapy.layers.dot11 import Packet
from scapy.layers.l2 import Ether, Dot1Q, bind_layers

MAC_CONTROL_ETHER_TYPE = 0x8808
ETHER_TYPES['MAC_CONTROL'] = MAC_CONTROL_ETHER_TYPE

ETHER_SPEED_MBIT_10 = 0x01
ETHER_SPEED_MBIT_100 = 0x02
ETHER_SPEED_MBIT_1000 = 0x04


class MACControl(Packet):
    DEFAULT_DST_MAC = "01:80:c2:00:00:01"

    OP_CODE_PAUSE = 0x0001
    OP_CODE_GATE = 0x0002
    OP_CODE_REPORT = 0x0003
    OP_CODE_REGISTER_REQ = 0x0004
    OP_CODE_REGISTER = 0x0005
    OP_CODE_REGISTER_ACK = 0x0006
    OP_CODE_CLASS_BASED_FLOW_CONTROL = 0x0101

    OP_CODES = {
        OP_CODE_PAUSE: 'pause',
        OP_CODE_GATE: 'gate',
        OP_CODE_REPORT: 'report',
        OP_CODE_REGISTER_REQ: 'register req',
        OP_CODE_REGISTER: 'register',
        OP_CODE_REGISTER_ACK: 'register_ack',
        OP_CODE_CLASS_BASED_FLOW_CONTROL: 'class based flow control'
    }

    '''
    flags used by Register* messages
    '''
    FLAG_REGISTER = 0x01
    FLAG_DEREGISTER = 0x02
    FLAG_ACK = 0x03
    FLAG_NACK = 0x04

    REGISTER_FLAGS = {
        FLAG_REGISTER: 'register',
        FLAG_DEREGISTER: 'deregister',
        FLAG_ACK: 'ack',
        FLAG_NACK: 'nack'
    }

    def guess_payload_class(self, payload):

        try:
            op_code = (orb(payload[0]) << 8) + orb(payload[1])
            return MAC_CTRL_CLASSES[op_code]
        except KeyError:
            pass

        return Packet.guess_payload_class(self, payload)

    def _get_underlayers_size(self):
        """
        get the total size of all under layers
        :return: number of bytes
        """

        under_layer = self.underlayer

        under_layers_size = 0

        while under_layer and isinstance(under_layer, Dot1Q):
            under_layers_size += 4
            under_layer = under_layer.underlayer

        if under_layer and isinstance(under_layer, Ether):
            # ether header len + FCS len
            under_layers_size += 14 + 4

        return under_layers_size

    def post_build(self, pkt, pay):
        """
        add padding to the frame if required.

        note that padding is only added if pay is None/empty. this allows us to add  # noqa: E501
        any payload after the MACControl* PDU if needed (piggybacking).
        """

        if not pay:
            under_layers_size = self._get_underlayers_size()

            frame_size = (len(pkt) + under_layers_size)

            if frame_size < 64:
                return pkt + b'\x00' * (64 - frame_size)

        return pkt + pay


class MACControlInvalidSpeedException(Scapy_Exception):
    pass


class MACControlPause(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_PAUSE),
        ShortField("pause_time", 0),
    ]

    def get_pause_time(self, speed=ETHER_SPEED_MBIT_1000):
        """
        get pause time for given link speed in seconds

        :param speed: select link speed to get the pause time for, must be ETHER_SPEED_MBIT_[10,100,1000]  # noqa: E501
        :return: pause time in seconds
        :raises MACControlInvalidSpeedException: on invalid speed selector
        """

        try:
            return self.pause_time * {
                ETHER_SPEED_MBIT_10: (0.0000001 * 512),
                ETHER_SPEED_MBIT_100: (0.00000001 * 512),
                ETHER_SPEED_MBIT_1000: (0.000000001 * 512 * 2)
            }[speed]
        except KeyError:
            raise MACControlInvalidSpeedException('Invalid speed selector given. '  # noqa: E501
                                                  'Must be one of ETHER_SPEED_MBIT_[10,100,1000]')  # noqa: E501


class MACControlGate(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_GATE),
        IntField("timestamp", 0)
    ]


class MACControlReport(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_REPORT),
        IntField("timestamp", 0),
        ByteEnumField('flags', 0, MACControl.REGISTER_FLAGS),
        ByteField('pending_grants', 0)
    ]


class MACControlRegisterReq(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_REGISTER_REQ),
        IntField("timestamp", 0),
        ShortField('assigned_port', 0),
        ByteEnumField('flags', 0, MACControl.REGISTER_FLAGS),
        ShortField('sync_time', 0),
        ByteField('echoed_pending_grants', 0)
    ]


class MACControlRegister(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_REGISTER),
        IntField("timestamp", 0),
        ByteEnumField('flags', 0, MACControl.REGISTER_FLAGS),
        ShortField('echoed_assigned_port', 0),
        ShortField('echoed_sync_time', 0)
    ]


class MACControlRegisterAck(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_REGISTER_ACK),
        IntField("timestamp", 0),
        ByteEnumField('flags', 0, MACControl.REGISTER_FLAGS),
        ShortField('echoed_assigned_port', 0),
        ShortField('echoed_sync_time', 0)
    ]


class MACControlClassBasedFlowControl(MACControl):
    fields_desc = [
        ShortField("_op_code", MACControl.OP_CODE_CLASS_BASED_FLOW_CONTROL),
        ByteField("_reserved", 0),
        BitField('c7_enabled', 0, 1),
        BitField('c6_enabled', 0, 1),
        BitField('c5_enabled', 0, 1),
        BitField('c4_enabled', 0, 1),
        BitField('c3_enabled', 0, 1),
        BitField('c2_enabled', 0, 1),
        BitField('c1_enabled', 0, 1),
        BitField('c0_enabled', 0, 1),
        ShortField('c0_pause_time', 0),
        ShortField('c1_pause_time', 0),
        ShortField('c2_pause_time', 0),
        ShortField('c3_pause_time', 0),
        ShortField('c4_pause_time', 0),
        ShortField('c5_pause_time', 0),
        ShortField('c6_pause_time', 0),
        ShortField('c7_pause_time', 0)
    ]


MAC_CTRL_CLASSES = {
    MACControl.OP_CODE_PAUSE: MACControlPause,
    MACControl.OP_CODE_GATE: MACControlGate,
    MACControl.OP_CODE_REPORT: MACControlReport,
    MACControl.OP_CODE_REGISTER_REQ: MACControlRegisterReq,
    MACControl.OP_CODE_REGISTER: MACControlRegister,
    MACControl.OP_CODE_REGISTER_ACK: MACControlRegisterAck,
    MACControl.OP_CODE_CLASS_BASED_FLOW_CONTROL: MACControlClassBasedFlowControl  # noqa: E501
}

bind_layers(Ether, MACControl, type=MAC_CONTROL_ETHER_TYPE)
bind_layers(Dot1Q, MACControl, type=MAC_CONTROL_ETHER_TYPE)
