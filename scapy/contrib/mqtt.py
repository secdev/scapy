# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# This program is published under GPLv2 license


from scapy.packet import Packet, bind_layers
from scapy.fields import FieldLenField, BitEnumField, StrLenField, \
    ShortField, ConditionalField, ByteEnumField, ByteField, StrNullField
from scapy.layers.inet import TCP
from scapy.error import Scapy_Exception
from scapy.compat import orb, chb


# CUSTOM FIELDS

# source: http://stackoverflow.com/a/43717630
class VariableFieldLenField(FieldLenField):
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        data = []
        while val:
            if val > 127:
                data.append(val & 127)
                val /= 127
            else:
                data.append(val)
                lastoffset = len(data) - 1
                data = b"".join(chb(val | (0 if i == lastoffset else 128))
                               for i, val in enumerate(data))
                return s + data
            if len(data) > 3:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)

    def getfield(self, pkt, s):
        value = 0
        for offset, curbyte in enumerate(s):
            curbyte = orb(curbyte)
            value += (curbyte & 127) * (128 ** offset)
            if curbyte & 128 == 0:
                return s[offset + 1:], value
            if offset > 2:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)


# LAYERS

CONTROL_PACKET_TYPE = {1: 'CONNECT',
                       2: 'CONNACK',
                       3: 'PUBLISH',
                       4: 'PUBACK',
                       5: 'PUBREC',
                       6: 'PUBREL',
                       7: 'PUBCOMP',
                       8: 'SUBSCRIBE',
                       9: 'SUBACK',
                       10: 'UNSUBSCRIBE',
                       11: 'UNSUBACK',
                       12: 'PINGREQ',
                       13: 'PINGRESP',
                       14: 'DISCONNECT'}


QOS_LEVEL = {0: 'At most once delivery',
             1: 'At least once delivery',
             2: 'Exactly once delivery'}


# source: http://stackoverflow.com/a/43722441
class MQTT(Packet):
    name = "MQTT fixed header"
    fields_desc = [
        BitEnumField("type", 1, 4, CONTROL_PACKET_TYPE),
        BitEnumField("DUP", 0, 1, {0: 'Disabled',
                                   1: 'Enabled'}),
        BitEnumField("QOS", 0, 2, QOS_LEVEL),
        BitEnumField("RETAIN", 0, 1, {0: 'Disabled',
                                      1: 'Enabled'}),
        # Since the size of the len field depends on the next layer, we need
        # to "cheat" with the length_of parameter and use adjust parameter to
        # calculate the value.
        VariableFieldLenField("len", None, length_of="len",
                              adjust=lambda pkt, x: len(pkt.payload),),
    ]


class MQTTConnect(Packet):
    name = "MQTT connect"
    fields_desc = [
        FieldLenField("length", None, length_of="protoname"),
        StrLenField("protoname", "",
                    length_from=lambda pkt: pkt.length),
        ByteField("protolevel", 0),
        BitEnumField("usernameflag", 0, 1, {0: 'Disabled',
                                            1: 'Enabled'}),
        BitEnumField("passwordflag", 0, 1, {0: 'Disabled',
                                            1: 'Enabled'}),
        BitEnumField("willretainflag", 0, 1, {0: 'Disabled',
                                              1: 'Enabled'}),
        BitEnumField("willQOSflag", 0, 2, QOS_LEVEL),
        BitEnumField("willflag", 0, 1, {0: 'Disabled',
                                        1: 'Enabled'}),
        BitEnumField("cleansess", 0, 1, {0: 'Disabled',
                                         1: 'Enabled'}),
        BitEnumField("reserved", 0, 1, {0: 'Disabled',
                                        1: 'Enabled'}),
        ShortField("klive", 0),
        FieldLenField("clientIdlen", None, length_of="clientId"),
        StrLenField("clientId", "",
                    length_from=lambda pkt: pkt.clientIdlen),
        # Payload with optional fields depending on the flags
        ConditionalField(FieldLenField("wtoplen", None, length_of="willtopic"),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(StrLenField("willtopic", "",
                                     length_from=lambda pkt: pkt.wtoplen),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(FieldLenField("wmsglen", None, length_of="willmsg"),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(StrLenField("willmsg", "",
                                     length_from=lambda pkt: pkt.wmsglen),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(FieldLenField("userlen", None, length_of="username"),
                         lambda pkt: pkt.usernameflag == 1),
        ConditionalField(StrLenField("username", "",
                                     length_from=lambda pkt: pkt.userlen),
                         lambda pkt: pkt.usernameflag == 1),
        ConditionalField(FieldLenField("passlen", None, length_of="password"),
                         lambda pkt: pkt.passwordflag == 1),
        ConditionalField(StrLenField("password", "",
                                     length_from=lambda pkt: pkt.passlen),
                         lambda pkt: pkt.passwordflag == 1),
    ]


RETURN_CODE = {0: 'Connection Accepted',
               1: 'Unacceptable protocol version',
               2: 'Identifier rejected',
               3: 'Server unavailable',
               4: 'Bad username/password',
               5: 'Not authorized'}


class MQTTConnack(Packet):
    name = "MQTT connack"
    fields_desc = [
        ByteField("sessPresentFlag", 0),
        ByteEnumField("retcode", 0, RETURN_CODE),
        # this package has not payload
    ]


class MQTTPublish(Packet):
    name = "MQTT publish"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "",
                    length_from=lambda pkt: pkt.length),
        ConditionalField(ShortField("msgid", None),
                         lambda pkt: (pkt.underlayer.QOS == 1
                                      or pkt.underlayer.QOS == 2)),
        StrLenField("value", "",
                    length_from=lambda pkt: (pkt.underlayer.len -
                                             pkt.length - 2)),
    ]


class MQTTPuback(Packet):
    name = "MQTT puback"
    fields_desc = [
        ShortField("msgid", None),
        ]


class MQTTPubrec(Packet):
    name = "MQTT pubrec"
    fields_desc = [
        ShortField("msgid", None),
        ]


class MQTTPubrel(Packet):
    name = "MQTT pubrel"
    fields_desc = [
        ShortField("msgid", None),
        ]


class MQTTPubcomp(Packet):
    name = "MQTT pubcomp"
    fields_desc = [
        ShortField("msgid", None),
        ]


class MQTTSubscribe(Packet):
    name = "MQTT subscribe"
    fields_desc = [
        ShortField("msgid", None),
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "",
                    length_from=lambda pkt: pkt.length),
        ByteEnumField("QOS", 0, QOS_LEVEL),
        ]


ALLOWED_RETURN_CODE = {0: 'Success',
                       1: 'Success',
                       2: 'Success',
                       128: 'Failure'}


class MQTTSuback(Packet):
    name = "MQTT suback"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("retcode", None, ALLOWED_RETURN_CODE)
        ]


class MQTTUnsubscribe(Packet):
    name = "MQTT unsubscribe"
    fields_desc = [
        ShortField("msgid", None),
        StrNullField("payload", "")
        ]


class MQTTUnsuback(Packet):
    name = "MQTT unsuback"
    fields_desc = [
        ShortField("msgid", None)
        ]


# LAYERS BINDINGS

bind_layers(TCP, MQTT, sport=1883)
bind_layers(TCP, MQTT, dport=1883)
bind_layers(MQTT, MQTTConnect, type=1)
bind_layers(MQTT, MQTTConnack, type=2)
bind_layers(MQTT, MQTTPublish, type=3)
bind_layers(MQTT, MQTTPuback, type=4)
bind_layers(MQTT, MQTTPubrec, type=5)
bind_layers(MQTT, MQTTPubrel, type=6)
bind_layers(MQTT, MQTTPubcomp, type=7)
bind_layers(MQTT, MQTTSubscribe, type=8)
bind_layers(MQTT, MQTTSuback, type=9)
bind_layers(MQTT, MQTTUnsubscribe, type=10)
bind_layers(MQTT, MQTTUnsuback, type=11)
bind_layers(MQTTConnect, MQTT)
bind_layers(MQTTConnack, MQTT)
bind_layers(MQTTPublish, MQTT)
bind_layers(MQTTPuback, MQTT)
bind_layers(MQTTPubrec, MQTT)
bind_layers(MQTTPubrel, MQTT)
bind_layers(MQTTPubcomp, MQTT)
bind_layers(MQTTSubscribe, MQTT)
bind_layers(MQTTSuback, MQTT)
bind_layers(MQTTUnsubscribe, MQTT)
bind_layers(MQTTUnsuback, MQTT)
