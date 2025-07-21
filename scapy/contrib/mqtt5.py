# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# This program is published under GPLv2 license

# scapy.contrib.description = Message Queuing Telemetry Transport (MQTT) version 5.0
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import FieldLenField, BitEnumField, StrLenField, \
    ShortField, ConditionalField, ByteEnumField, ByteField, PacketListField
from scapy.layers.inet import TCP
from scapy.error import Scapy_Exception
from scapy.compat import orb, chb
from scapy.volatile import RandNum
from scapy.config import conf


# CUSTOM FIELDS
# source: http://stackoverflow.com/a/43717630
class VariableFieldLenField(FieldLenField):
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        data = []
        while val:
            if val > 127:
                data.append(val & 127)
                val //= 128
            else:
                data.append(val)
                lastoffset = len(data) - 1
                data = b"".join(chb(val | (0 if i == lastoffset else 128))
                                for i, val in enumerate(data))
                return s + data
            if len(data) > 3:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)
        # If val is None / 0
        return s + b"\x00"

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

    def randval(self):
        return RandVariableFieldLen()


class RandVariableFieldLen(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 268435455)


# LAYERS
CONTROL_PACKET_TYPE = {
    1: 'CONNECT',
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
    14: 'DISCONNECT',
    15: 'AUTH'  # Added in v5.0
}


QOS_LEVEL = {
    0: 'At most once delivery',
    1: 'At least once delivery',
    2: 'Exactly once delivery'
}

PROPERTY = {
        1: 'Payload Format Indicator', #Byte
        2: 'Message Expiry Interval', #Four Byte Integer
        3: 'Content Type', #UTF-8 Encoded String
        8: 'Response Topic', #UTF-8 Encoded String
        9: 'Correlation Data', #Binary Data
        11: 'Subscription Identifier', #Variable Byte Integer
        17: 'Session Expiry Interval', #Four Byte Integer
        18: 'Assigned Client Identifier', #UTF-8 Encoded String
        19: 'Server Keep Alive', #Two Byte Integer
        21: 'Authentication Method', #UTF-8 Encoded String
        22: 'Authentication Data', #Binary Data
        23: 'Request Problem Information', #Byte
        24: 'Will Delay Interval', #Four Byte Integer
        25: 'Request Response Information', #Byte
        26: 'Response Information', #UTF-8 Encoded String
        28: 'Server Reference', #UTF-8 Encoded String
        31: 'Reason String', #UTF-8 Encoded String
        33: 'Receive Maximum', #Two Byte Integer
        34: 'Topic Alias Maximum', #Two Byte Integer
        35: 'Topic Alias', #Two Byte Integer
        36: 'Maximum QoS', #Byte
        37: 'Retain Available', #Byte
        38: 'User Property', #UTF-8 String Pair
        39: 'Maximum Packet Size', #Four Byte Integer
        40: 'Wildcard Subscription Available', #Byte
        41: 'Subscription Identifier Available', #Byte
        42: 'Shared Subscription Available', #Byte
}


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


PROTOCOL_LEVEL = {
    #3: 'v3.1',
    #4: 'v3.1.1',
    5: 'v5.0'
}

class UTF8EncodedString(Packet):
    fields_desc = [
        FieldLenField("length", None, length_of="value"),
        StrLenField("value", "", length_from=lambda pkt:pkt.length)
    ]

class UTF8StringPair(Packet):
    fields_desc = [
                   FieldLenField("keylen", None, length_of="key"),
                   StrLenField("key", "", length_from=lambda pkt:pkt.keylen),
                   FieldLenField("valuelen", None, length_of="value"),
                   StrLenField("value", "", length_from=lambda pkt:pkt.valuelen)
                  ]

class MQTTProperty(Packet):
    name = "Property"
    fields_desc = [
            ByteEnumField("propid", None, PROPERTY),
            MultipleTypeField(
            [
                #2 BYTE INTEGER FIELDS
                (ShortField("propvalue", 0),
                            lambda pkt: (pkt.propid == 19 or 
                                         pkt.propid == 33 or 
                                         pkt.propid == 34 or 
                                         pkt.propid == 35)),

                #4 BYTE INTEGER FIELDS
                (IntField("propvalue", 0),
                          lambda pkt: (pkt.propid == 2 or
                                       pkt.propid == 11 or 
                                       pkt.propid == 17 or 
                                       pkt.propid == 24 or 
                                       pkt.propid == 39)),

                #1 BYTE FIELD
                (ByteEnumField("propvalue", 0, {0: 'Disabled',
                                                1: 'Enabled'}),
                               lambda pkt: (pkt.propid == 1 or
                                            pkt.propid == 23 or 
                                            pkt.propid == 25 or 
                                            pkt.propid == 36 or 
                                            pkt.propid == 37 or
                                            pkt.propid == 40 or
                                            pkt.propid == 41 or
                                            pkt.propid == 42)),

                #UTF8 STRING PAIR
                (PacketField("propvalue", None, pkt_cls=UTF8StringPair),
                                 lambda pkt: pkt.propid == 38),

                #UTF8 ENCODED STRING
                (PacketField("propvalue", None, pkt_cls=UTF8EncodedString),
                                 lambda pkt: (pkt.propid == 3 or
                                              pkt.propid == 8 or
                                              pkt.propid == 9 or
                                              pkt.propid == 18 or
                                              pkt.propid == 21 or
                                              pkt.propid == 22 or
                                              pkt.propid == 26 or
                                              pkt.propid == 28 or
                                              pkt.propid == 31)),
            ],

            #None
            StrLenField("propvalue", None)
        ),

    ] 

class MQTTWillProperty(MQTTProperty):
    name = "Will Properties"

class MQTTConnect(Packet):
    name = "MQTT connect"
    fields_desc = [
        FieldLenField("length", None, length_of="protoname"),
        StrLenField("protoname", "",
                    length_from=lambda pkt: pkt.length),
        ByteEnumField("protolevel", 5, PROTOCOL_LEVEL),
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

        #CONNECT PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

        FieldLenField("clientIdlen", None, length_of="clientId"),
        StrLenField("clientId", "",
                    length_from=lambda pkt: pkt.clientIdlen),
        # Payload with optional fields depending on the flags

        # WILL PROPERTIES
        ConditionalField(FieldLenField("willproplen", None, fmt='B', length_of="willproperties"),
                          lambda pkt: pkt.willflag == 1),
        ConditionalField(PacketListField("willproperties", [], pkt_cls=MQTTWillProperty, length_from=lambda pkt: pkt.willproplen),
                          lambda pkt: pkt.willflag == 1),

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


DISCONNECT_REASON_CODE = {
        0: 'Normal disconnection',
        4: 'Disconnect with Will Message',
        128: 'Unspecified error',
        129: 'Malformed Packet',
        130: 'Protocol Error',
        131: 'Implementation specific error',
        135: 'Not authorized',
        137: 'Server busy',
        139: 'Server shutting down',
        141: 'Keep Alive timeout',
        142: 'Session taken over',
        143: 'Topic Filter invalid',
        144: 'Topic Name invalid',
        147: 'Receive Maximum exceeded',
        148: 'Topic Alias invalid',
        149: 'Packet too large',
        150: 'Message rate too high',
        151: 'Quota exceeded',
        152: 'Administrative action',
        153: 'Payload format invalid',
        154: 'Retain not supported',
        155: 'QoS not supported',
        156: 'Use another server',
        157: 'Server moved',
        158: 'Shared Subscriptions not supported',
        159: 'Connection rate exceeded',
        160: 'Maximum connect time',
        161: 'Subscription identifiers not supported',
        162: 'Wildcard Subscriptions not supported'
}

class MQTTDisconnect(Packet):
    name = "MQTT disconnect"
    fields_desc = [
            ByteEnumField('reasoncode', 0, DISCONNECT_REASON_CODE),
            
            #DISCONNECT PROPERTIES
            FieldLenField("proplen", None, fmt='B', length_of="properties"),
            ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                             lambda pkt: pkt.proplen != 0),
            ]


RETURN_CODE = {
    0: 'Connection Accepted',
    128: 'Unspecified Error',
    129: 'Malformed Packet',
    130: 'Protocol Error',
    131: 'Implementation Specific Error',
    132: 'Unsupported Protocol Version',
    133: 'Client Identifier not valid',
    134: 'Bad User Name or Password',
    135: 'Not Authorized',
    136: 'Server Unavailable',
    137: 'Server Busy',
    138: 'Banned',
    140: 'Bad Authentication Method',
    144: 'Topic Name Invalid',
    149: 'Packet Too Large',
    151: 'Quota Exceeded',
    153: 'Payload Format Invalid',
    154: 'Retain Not Supported',
    155: 'QOS Not Supported',
    156: 'Use Another Server',
    157: 'Server Moved',
    159: 'Connection Rate Exceeded',
           
}


class MQTTConnack(Packet):
    name = "MQTT connack"
    fields_desc = [
        ByteField("sessPresentFlag", 0),
        ByteEnumField("retcode", 0, RETURN_CODE),
        
        #CONNACK PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),
    ]


class MQTTPublish(Packet):
    name = "MQTT publish"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "",
                    length_from=lambda pkt: pkt.length),
        ConditionalField(ShortField("msgid", None),
                         lambda pkt: (pkt.underlayer.QOS == 1 or
                                      pkt.underlayer.QOS == 2)),

        #PUBLISH PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

        StrLenField("value", "",
                    length_from=lambda pkt: (pkt.underlayer.len -
                                             pkt.length - 2)),
    ]

PUBLISH_QOS1_REASON_CODE = {
        0: 'Success',
        16: 'No matching subscribers',
        128: 'Unspecified error',
        131: 'Implementation specific error',
        135: 'Not authorized',
        144: 'Topic Name invalid',
        145: 'Packet identifier in use',
        151: 'Quota exceeded',
        153: 'Payload format invalid',
}


class MQTTPuback(Packet):
    name = "MQTT puback"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("reasoncode", 0, PUBLISH_QOS1_REASON_CODE),

        #PUBACK PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

    ]


class MQTTPubrec(Packet):
    name = "MQTT pubrec"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("reasoncode", 0, PUBLISH_QOS1_REASON_CODE),

        #PUBREC PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),
    ]

PUBLISH_QOS2_REASON_CODE = {
        0: 'Success',
        146: 'Packet Identifier not found',
}

class MQTTPubrel(Packet):
    name = "MQTT pubrel"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("reasoncode", 0, PUBLISH_QOS2_REASON_CODE),

        #PUBREL PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),
    ]


class MQTTPubcomp(Packet):
    name = "MQTT pubcomp"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("reasoncode", 0, PUBLISH_QOS2_REASON_CODE),

        #PUBCOMP PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),
    ]

RETAIN_VALUE = {
        0: 'Send retained messages at the time of subscribe',
        1: 'Send retained messages at subscribe only if the subscription does not currently exist',
        2: 'Do not send retained messages at the time of the subscribe'
}

class MQTTTopic(Packet):
    name = "MQTT topic"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "", length_from=lambda pkt:pkt.length)
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class MQTTTopicOptions(MQTTTopic):
    fields_desc = MQTTTopic.fields_desc + [
                                            BitEnumField("reserved", 0, 2, {0: 'Disabled',
                                                                            1: 'Enabled'}),
                                            BitEnumField("retainhandle", 0, 2, RETAIN_VALUE),
                                            BitEnumField("RAP", 0, 1, {0: 'Disabled',
                                                                       1: 'Enabled'}),
                                            BitEnumField("NL", 0, 1, {0: 'Disabled',
                                                                      1: 'Enabled'}),
                                            BitEnumField("QOS", 0, 2, QOS_LEVEL)
                                          ]

class MQTTSubscribe(Packet):
    name = "MQTT subscribe"
    fields_desc = [
        ShortField("msgid", None),

        #SUBSCRIBE PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

        PacketListField("topics", [], pkt_cls=MQTTTopicOptions),
    ]


SUBACK_REASON_CODE = {
        0: 'Granted QoS 0',
        1: 'Granted QoS 1',
        2: 'Granted QoS 2',
        128: 'Unspecified error',
        131: 'Implementation specific error',
        135: 'Not authorized',
        143: 'Topic Filter invalid',
        145: 'Packet Identifier in use',
        151: 'Quota exceeded',
        158: 'Shared Subscriptions not supported',
        161: 'Subscription identifiers not supported',
        162: 'Wildcard Subscriptions not supported'
}


class MQTTSuback(Packet):
    name = "MQTT suback"
    fields_desc = [
        ShortField("msgid", None),

        #SUBACK PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

        ByteEnumField("reasoncode", None, SUBACK_REASON_CODE)
    ]


class MQTTUnsubscribe(Packet):
    name = "MQTT unsubscribe"
    fields_desc = [
        ShortField("msgid", None),

        #UNSUBSCRIBE PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

        PacketListField("topics", [], pkt_cls=MQTTTopic)
    ]

UNSUBACK_REASON_CODE = {
        0: 'Sucess',
        17: 'No subscription existed',
        128: 'Unspecified error',
        131: 'Implementation specific error',
        135: 'Not authorized',
        143: 'Topic Filter invalid',
        145: 'Packet Identifier in use'
}


class MQTTUnsuback(Packet):
    name = "MQTT unsuback"
    fields_desc = [
        ShortField("msgid", None),

        #UNSUBACK PROPERTIES
        FieldLenField("proplen", None, fmt='B', length_of="properties"),
        ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),

        ByteEnumField('reasoncode', 0, UNSUBACK_REASON_CODE)
    ]

AUTHENTICATE_REASON_CODE = {
        0: 'Success',
        24: 'Continue authentication',
        25: 'Re-authenticate'
}

class MQTTAuth(Packet):
    fields_desc = [
            ByteEnumField('reasoncode', 0, AUTHENTICATE_REASON_CODE),

            #AUTH PROPERTIES
            FieldLenField("proplen", None, fmt='B', length_of="properties"),
            ConditionalField(PacketListField("properties", [], pkt_cls=MQTTProperty, length_from=lambda pkt: pkt.proplen),
                         lambda pkt: pkt.proplen != 0),
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
bind_layers(MQTT, MQTTDisconnect, type=14)
bind_layers(MQTT, MQTTAuth, type=15)
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
bind_layers(MQTTDisconnect, MQTT)
bind_layers(MQTTAuth, MQTT)
