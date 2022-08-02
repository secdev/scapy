# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Freie Universitaet Berlin

"""
MQTT for Sensor Networks (MQTT-SN)

Specification:
http://www.mqtt.org/new/wp-content/uploads/2009/06/MQTT-SN_spec_v1.2.pdf
"""


# scapy.contrib.description = MQTT for Sensor Networks (MQTT-SN)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import BitField, BitEnumField, ByteField, ByteEnumField, \
    ConditionalField, FieldLenField, ShortField, StrFixedLenField, \
    StrLenField, XByteEnumField
from scapy.layers.inet import UDP
from scapy.error import Scapy_Exception
from scapy.compat import chb, orb
from scapy.volatile import RandNum
import struct


# Constants
ADVERTISE = 0x00
SEARCHGW = 0x01
GWINFO = 0x02
CONNECT = 0x04
CONNACK = 0x05
WILLTOPICREQ = 0x06
WILLTOPIC = 0x07
WILLMSGREQ = 0x08
WILLMSG = 0x09
REGISTER = 0x0a
REGACK = 0x0b
PUBLISH = 0x0c
PUBACK = 0x0d
PUBCOMP = 0x0e
PUBREC = 0x0f
PUBREL = 0x10
SUBSCRIBE = 0x12
SUBACK = 0x13
UNSUBSCRIBE = 0x14
UNSUBACK = 0x15
PINGREQ = 0x16
PINGRESP = 0x17
DISCONNECT = 0x18
WILLTOPICUPD = 0x1a
WILLTOPICRESP = 0x1b
WILLMSGUPD = 0x1c
WILLMSGRESP = 0x1d
ENCAPS_MSG = 0xfe

QOS_0 = 0b00
QOS_1 = 0b01
QOS_2 = 0b10
QOS_NEG1 = 0b11

TID_NORMAL = 0b00
TID_PREDEF = 0b01
TID_SHORT = 0b10
TID_RESVD = 0b11


ACCEPTED = 0x00
REJ_CONJ = 0x01
REJ_TID = 0x02
REJ_NOTSUP = 0x03


# Custom fields
class VariableFieldLenField(FieldLenField):
    """
    MQTT-SN length field either has 1 byte for values [0x02, 0xff] or 3 bytes
    for values [0x0100, 0xffff]. If the first byte is 0x01 the length value
    comes in network byte-order in the next 2 bytes. MQTT-SN packets are at
    least 2 bytes long (length field + type field).
    """
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        if (val < 2) or (val > 0xffff):
            raise Scapy_Exception("%s: invalid length field value" %
                                  self.__class__.__name__)
        elif val > 0xff:
            return s + b"\x01" + struct.pack("!H", val)
        else:
            return s + chb(val)

    def getfield(self, pkt, s):
        if orb(s[0]) == 0x01:
            if len(s) < 3:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)
            return s[3:], (orb(s[1]) << 8) | orb(s[2])
        else:
            return s[1:], orb(s[0])

    def randval(self):
        return RandVariableFieldLen()

    def __init__(self, *args, **kwargs):
        super(VariableFieldLenField, self).__init__(*args, **kwargs)


class RandVariableFieldLen(RandNum):
    def __init__(self):
        super(RandVariableFieldLen, self).__init__(0, 0xffff)


# Layers
PACKET_TYPE = {
    ADVERTISE: "ADVERTISE",
    SEARCHGW: "SEARCHGW",
    GWINFO: "GWINFO",
    CONNECT: "CONNECT",
    CONNACK: "CONNACK",
    WILLTOPICREQ: "WILLTOPICREQ",
    WILLTOPIC: "WILLTOPIC",
    WILLMSGREQ: "WILLMSGREQ",
    WILLMSG: "WILLMSG",
    REGISTER: "REGISTER",
    REGACK: "REGACK",
    PUBLISH: "PUBLISH",
    PUBACK: "PUBACK",
    PUBCOMP: "PUBCOMP",
    PUBREC: "PUBREC",
    PUBREL: "PUBREL",
    SUBSCRIBE: "SUBSCRIBE",
    SUBACK: "SUBACK",
    UNSUBSCRIBE: "UNSUBSCRIBE",
    UNSUBACK: "UNSUBACK",
    PINGREQ: "PINGREQ",
    PINGRESP: "PINGRESP",
    DISCONNECT: "DISCONNECT",
    WILLTOPICUPD: "WILLTOPICUPD",
    WILLTOPICRESP: "WILLTOPICRESP",
    WILLMSGUPD: "WILLMSGUPD",
    WILLMSGRESP: "WILLMSGRESP",
    ENCAPS_MSG: "Encapsulated message",
}


QOS_LEVELS = {
    QOS_0: 'Fire and Forget',
    QOS_1: 'Acknowledged deliver',
    QOS_2: 'Assured Delivery',
    QOS_NEG1: 'No Connection required',
}


TOPIC_ID_TYPES = {
    TID_NORMAL: 'Normal ID',
    TID_PREDEF: 'Pre-defined ID',
    TID_SHORT: 'Short Topic Name',
    TID_RESVD: 'Reserved',
}


RETURN_CODES = {
    ACCEPTED: "Accepted",
    REJ_CONJ: "Rejected: congestion",
    REJ_TID: "Rejected: invalid topic ID",
    REJ_NOTSUP: "Rejected: not supported",
}


FLAG_FIELDS = [
    BitField("dup", 0, 1),
    BitEnumField("qos", QOS_0, 2, QOS_LEVELS),
    BitField("retain", 0, 1),
    BitField("will", 0, 1),
    BitField("cleansess", 0, 1),
    BitEnumField("tid_type", TID_NORMAL, 2, TOPIC_ID_TYPES),
]


def _mqttsn_length_from(size_until):
    def fun(pkt):
        if (hasattr(pkt.underlayer, "len")):
            if pkt.underlayer.len > 0xff:
                return pkt.underlayer.len - size_until - 4
            elif (pkt.underlayer.len > 1) and (pkt.underlayer.len < 0xffff):
                return pkt.underlayer.len - size_until - 2
        # assume string to be of length 0
        return len(pkt.payload) - size_until + 1
    return fun


def _mqttsn_len_adjust(pkt, x):
    res = x + len(pkt.payload)
    if (pkt.type == DISCONNECT) and \
       (getattr(pkt.payload, "duration", None) is None):
        res -= 2    # duration is optional with DISCONNECT
    elif (pkt.type == ENCAPS_MSG) and \
         (getattr(pkt.payload, "w_node_id", None) is not None):
        res = x + len(pkt.payload.w_node_id) + 1
    if res > 0xff:
        res += 2
    return res


class MQTTSN(Packet):
    name = "MQTT-SN header"
    fields_desc = [
        # Since the size of the len field depends on the next layer, we
        # need to "cheat" with the length_of parameter and use adjust
        # parameter to calculate the value.
        VariableFieldLenField("len", None, length_of="len",
                              adjust=_mqttsn_len_adjust),
        XByteEnumField("type", 0, PACKET_TYPE),
    ]


class MQTTSNAdvertise(Packet):
    name = "MQTT-SN advertise gateway"
    fields_desc = [
        ByteField("gw_id", 0),
        ShortField("duration", 0),
    ]


class MQTTSNSearchGW(Packet):
    name = "MQTT-SN search gateway"
    fields_desc = [
        ByteField("radius", 0),
    ]


class MQTTSNGwInfo(Packet):
    name = "MQTT-SN gateway info"
    fields_desc = [
        ByteField("gw_id", 0),
        StrLenField("gw_addr", "", length_from=_mqttsn_length_from(1)),
    ]


class MQTTSNConnect(Packet):
    name = "MQTT-SN connect command"
    fields_desc = FLAG_FIELDS + [
        ByteField("prot_id", 1),
        ShortField("duration", 0),
        StrLenField("client_id", "", length_from=_mqttsn_length_from(4)),
    ]


class MQTTSNConnack(Packet):
    name = "MQTT-SN connect ACK"
    fields_desc = [
        ByteEnumField("return_code", ACCEPTED, RETURN_CODES),
    ]


class MQTTSNWillTopicReq(Packet):
    name = "MQTT-SN will topic request"


class MQTTSNWillTopic(Packet):
    name = "MQTT-SN will topic"
    fields_desc = FLAG_FIELDS + [
        StrLenField("will_topic", "", length_from=_mqttsn_length_from(1)),
    ]


class MQTTSNWillMsgReq(Packet):
    name = "MQTT-SN will message request"


class MQTTSNWillMsg(Packet):
    name = "MQTT-SN will message"
    fields_desc = [
        StrLenField("will_msg", "", length_from=_mqttsn_length_from(0))
    ]


class MQTTSNRegister(Packet):
    name = "MQTT-SN register"
    fields_desc = [
        ShortField("tid", 0),
        ShortField("mid", 0),
        StrLenField("topic_name", "", length_from=_mqttsn_length_from(4)),
    ]


class MQTTSNRegack(Packet):
    name = "MQTT-SN register ACK"
    fields_desc = [
        ShortField("tid", 0),
        ShortField("mid", 0),
        ByteEnumField("return_code", ACCEPTED, RETURN_CODES),
    ]


class MQTTSNPublish(Packet):
    name = "MQTT-SN publish message"
    fields_desc = FLAG_FIELDS + [
        ShortField("tid", 0),
        ShortField("mid", 0),
        StrLenField("data", "", length_from=_mqttsn_length_from(5)),
    ]


class MQTTSNPuback(Packet):
    name = "MQTT-SN publish ACK"
    fields_desc = [
        ShortField("tid", 0),
        ShortField("mid", 0),
        ByteEnumField("return_code", ACCEPTED, RETURN_CODES),
    ]


class MQTTSNPubcomp(Packet):
    name = "MQTT-SN publish complete"
    fields_desc = [
        ShortField("mid", 0),
    ]


class MQTTSNPubrec(Packet):
    name = "MQTT-SN publish received"
    fields_desc = [
        ShortField("mid", 0),
    ]


class MQTTSNPubrel(Packet):
    name = "MQTT-SN publish release"
    fields_desc = [
        ShortField("mid", 0),
    ]


class MQTTSNSubscribe(Packet):
    name = "MQTT-SN subscribe request"
    fields_desc = FLAG_FIELDS + [
        ShortField("mid", 0),
        ConditionalField(ShortField("tid", None),
                         lambda pkt: pkt.tid_type == 0b01),
        ConditionalField(StrFixedLenField("short_topic", None, length=2),
                         lambda pkt: pkt.tid_type == 0b10),
        ConditionalField(StrLenField("topic_name", None,
                                     length_from=_mqttsn_length_from(3)),
                         lambda pkt: pkt.tid_type not in [0b01, 0b10]),
    ]


class MQTTSNSuback(Packet):
    name = "MQTT-SN subscribe ACK"
    fields_desc = FLAG_FIELDS + [
        ShortField("tid", 0),
        ShortField("mid", 0),
        ByteEnumField("return_code", ACCEPTED, RETURN_CODES),
    ]


class MQTTSNUnsubscribe(Packet):
    name = "MQTT-SN unsubscribe request"
    fields_desc = FLAG_FIELDS + [
        ShortField("mid", 0),
        ConditionalField(ShortField("tid", None),
                         lambda pkt: pkt.tid_type == 0b01),
        ConditionalField(StrFixedLenField("short_topic", None, length=2),
                         lambda pkt: pkt.tid_type == 0b10),
        ConditionalField(StrLenField("topic_name", None,
                                     length_from=_mqttsn_length_from(3)),
                         lambda pkt: pkt.tid_type not in [0b01, 0b10]),
    ]


class MQTTSNUnsuback(Packet):
    name = "MQTT-SN unsubscribe ACK"
    fields_desc = [
        ShortField("mid", 0),
    ]


class MQTTSNPingReq(Packet):
    name = "MQTT-SN ping request"
    fields_desc = [
        StrLenField("client_id", "", length_from=_mqttsn_length_from(0)),
    ]


class MQTTSNPingResp(Packet):
    name = "MQTT-SN ping response"


class MQTTSNDisconnect(Packet):
    name = "MQTT-SN disconnect request"
    fields_desc = [
        ConditionalField(
            ShortField("duration", None),
            lambda pkt: hasattr(pkt.underlayer, "len") and
            ((pkt.underlayer.len is None) or (pkt.underlayer.len > 2))
        ),
    ]


class MQTTSNWillTopicUpd(Packet):
    name = "MQTT-SN will topic update"
    fields_desc = FLAG_FIELDS + [
        StrLenField("will_topic", "", length_from=_mqttsn_length_from(1)),
    ]


class MQTTSNWillTopicResp(Packet):
    name = "MQTT-SN will topic response"
    fields_desc = [
        ByteEnumField("return_code", ACCEPTED, RETURN_CODES),
    ]


class MQTTSNWillMsgUpd(Packet):
    name = "MQTT-SN will message update"
    fields_desc = [
        StrLenField("will_msg", "", length_from=_mqttsn_length_from(0))
    ]


class MQTTSNWillMsgResp(Packet):
    name = "MQTT-SN will message response"
    fields_desc = [
        ByteEnumField("return_code", ACCEPTED, RETURN_CODES),
    ]


class MQTTSNEncaps(Packet):
    name = "MQTT-SN encapsulated message"
    fields_desc = [
        BitField("resvd", 0, 6),
        BitField("radius", 0, 2),
        StrLenField(
            "w_node_id", "",
            length_from=_mqttsn_length_from(1)
        ),
    ]


# Layer bindings
bind_bottom_up(UDP, MQTTSN, sport=1883)
bind_bottom_up(UDP, MQTTSN, dport=1883)
bind_layers(UDP, MQTTSN, dport=1883, sport=1883)
bind_layers(MQTTSN, MQTTSNAdvertise, type=ADVERTISE)
bind_layers(MQTTSN, MQTTSNSearchGW, type=SEARCHGW)
bind_layers(MQTTSN, MQTTSNGwInfo, type=GWINFO)
bind_layers(MQTTSN, MQTTSNConnect, type=CONNECT)
bind_layers(MQTTSN, MQTTSNConnack, type=CONNACK)
bind_layers(MQTTSN, MQTTSNWillTopicReq, type=WILLTOPICREQ)
bind_layers(MQTTSN, MQTTSNWillTopic, type=WILLTOPIC)
bind_layers(MQTTSN, MQTTSNWillMsgReq, type=WILLMSGREQ)
bind_layers(MQTTSN, MQTTSNWillMsg, type=WILLMSG)
bind_layers(MQTTSN, MQTTSNRegister, type=REGISTER)
bind_layers(MQTTSN, MQTTSNRegack, type=REGACK)
bind_layers(MQTTSN, MQTTSNPublish, type=PUBLISH)
bind_layers(MQTTSN, MQTTSNPuback, type=PUBACK)
bind_layers(MQTTSN, MQTTSNPubcomp, type=PUBCOMP)
bind_layers(MQTTSN, MQTTSNPubrec, type=PUBREC)
bind_layers(MQTTSN, MQTTSNPubrel, type=PUBREL)
bind_layers(MQTTSN, MQTTSNSubscribe, type=SUBSCRIBE)
bind_layers(MQTTSN, MQTTSNSuback, type=SUBACK)
bind_layers(MQTTSN, MQTTSNUnsubscribe, type=UNSUBSCRIBE)
bind_layers(MQTTSN, MQTTSNUnsuback, type=UNSUBACK)
bind_layers(MQTTSN, MQTTSNPingReq, type=PINGREQ)
bind_layers(MQTTSN, MQTTSNPingResp, type=PINGRESP)
bind_layers(MQTTSN, MQTTSNDisconnect, type=DISCONNECT)
bind_layers(MQTTSN, MQTTSNWillTopicUpd, type=WILLTOPICUPD)
bind_layers(MQTTSN, MQTTSNWillTopicResp, type=WILLTOPICRESP)
bind_layers(MQTTSN, MQTTSNWillMsgUpd, type=WILLMSGUPD)
bind_layers(MQTTSN, MQTTSNWillMsgResp, type=WILLMSGRESP)
bind_layers(MQTTSN, MQTTSNEncaps, type=ENCAPS_MSG)
bind_layers(MQTTSNEncaps, MQTTSN)
