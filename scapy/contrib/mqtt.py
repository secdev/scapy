## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
## This program is published under GPLv2 license


from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP


# CUSTOM FIELDS

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
                data = "".join(chr(val | (0 if i == lastoffset else 128))
                               for i, val in enumerate(data))
                return s + data
            if len(data) > 3:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)
    def getfield(self, pkt, s):
        value = 0
        for offset, curbyte in enumerate(s):
            curbyte = ord(curbyte)
            value += (curbyte & 127) * (128 ** offset)
            if curbyte & 128 == 0:
                return s[offset + 1:], value
            if offset > 2:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)



# LAYERS
            
control_packet_types = {1:'CONNECT (1)',
                        2:'CONNACK (2)',
                        3:'PUBLISH (3)',
                        4:'PUBACK (4)',
                        5:'PUBREC (5)',
                        6:'PUBREL (6)',
                        7:'PUBCOMP (7)',
                        8:'SUBSCRIBE (8)',
                        9:'SUBACK (9)',
                        10:'UNSUBSCRIBE (10)',
                        11:'UNSUBACK (11)',
                        12:'PINGREQ (12)',
                        13:'PINGRESP (13)',
                        14:'DISCONNECT (14)'}


QOS_level = {0:'0 (At most once delivery)',
             1:'1 (At least once delivery)',
             2:'2 (Exactly once delivery)'}


class MQTT(Packet):
    name = "MQTT fixed header"
    fields_desc = [
        BitEnumField("type", 1, 4, control_packet_types),
        BitEnumField("DUP", 0, 1, {0:'Disabled (0)',
                                   1:'Enabled (1)'}),
        BitEnumField("QOS", 0, 2, QOS_level),
        BitEnumField("RETAIN", 0, 1, {0:'Disabled (0)',
                                      1:'Enabled (1)'}),
        VariableFieldLenField("len", None, length_of="len",
                              adjust=lambda pkt, x: len(pkt.payload),),
    ]

    
class MQTT_CONNECT(Packet):
    name = "MQTT connect"
    fields_desc = [
        FieldLenField("length", None, length_of="protoname"),
        StrLenField("protoname","",
                    length_from=lambda pkt:pkt.length),
        ByteField("protolevel", 0),
        BitEnumField("usernameflag", 0, 1, {0:'Disabled (0)',
                                            1:'Enabled (1)'}),
        BitEnumField("passwordflag", 0, 1, {0:'Disabled (0)',
                                            1:'Enabled (1)'}),
        BitEnumField("willretainflag", 0, 1, {0:'Disabled (0)',
                                              1:'Enabled (1)'}),
        BitEnumField("willQOSflag", 0, 2, QOS_level),
        BitEnumField("willflag", 0, 1, {0:'Disabled (0)',
                                        1:'Enabled (1)'}),
        BitEnumField("cleansess", 0, 1, {0:'Disabled (0)',
                                         1:'Enabled (1)'}),
        BitEnumField("reserved", 0, 1, {0:'Disabled (0)',
                                        1:'Enabled (1)'}),
        ShortField("klive", 0),
        FieldLenField("clientIdlen", None, length_of="clientId"),
        StrLenField("clientId", "",
                    length_from = lambda pkt:pkt.clientIdlen),
        ## Payload with optional fields depending on the flags ##
        ConditionalField(FieldLenField("wtoplen", None, length_of = "willtopic"),
                         lambda pkt:pkt.willflag == 1),
        ConditionalField(StrLenField("willtopic", "",
                                     length_from = lambda pkt:pkt.wtoplen),
                         lambda pkt:pkt.willflag == 1),
        ConditionalField(FieldLenField("wmsglen", None, length_of = "willmsg"),
                         lambda pkt:pkt.willflag == 1),
        ConditionalField(StrLenField("willmsg","",
                                     length_from = lambda pkt:pkt.wmsglen),
                         lambda pkt:pkt.willflag == 1),
        ConditionalField(FieldLenField("userlen", None, length_of = "username"),
                         lambda pkt:pkt.usernameflag == 1),
        ConditionalField(StrLenField("username", "",
                                     length_from = lambda pkt:pkt.userlen),
                         lambda pkt:pkt.usernameflag == 1),
        ConditionalField(FieldLenField("passlen", None, length_of = "password"),
                         lambda pkt:pkt.passwordflag == 1),
        ConditionalField(StrLenField("password", "",
                                     length_from = lambda pkt:pkt.passlen),
                         lambda pkt:pkt.passwordflag == 1),
    ]


return_code = {0: '0 (Connection Accepted)',
               1: '1 (Unacceptable protocol version)',
               2: '2 (Identifier rejected)',
               3: '3 (Server unavailable)',
               4: '4 (Bad username/password)',
               5: '5 (Not authorized)'}


class MQTT_CONNACK(Packet):
    name = "MQTT connack"
    fields_desc = [
        ByteField("sessPresentFlag", 0),
        ByteEnumField("retcode", 0, return_code),
        ## this package has not payload ##
    ]


class MQTT_PUBLISH(Packet):
    name = "MQTT publish"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic","",
                    length_from=lambda pkt:pkt.length),
        ConditionalField(ShortField("msgid", None),
                         lambda pkt:(pkt.underlayer.QOS == 1 or pkt.underlayer.QOS == 2)),
        StrLenField("value", "",
                    length_from=lambda pkt:(pkt.underlayer.len - pkt.length - 2)),
    ]


class MQTT_PUBACK(Packet):
    name = "MQTT puback"
    fields_desc = [
        ShortField("msgid", None),
        ]

    
class MQTT_PUBREC(Packet):
    name = "MQTT pubrec"
    fields_desc = [
        ShortField("msgid", None),
        ]

    
class MQTT_PUBREL(Packet):
    name = "MQTT pubrel"
    fields_desc = [
        ShortField("msgid", None),
        ]

class MQTT_PUBCOMP(Packet):
    name = "MQTT pubcomp"
    fields_desc = [
        ShortField("msgid", None),
        ]

    
class MQTT_SUBSCRIBE(Packet):
    name = "MQTT subscribe"
    fields_desc = [
        ShortField("msgid", None),
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic","",
                    length_from=lambda pkt:pkt.length),
        ByteEnumField("QOS" ,0 ,QOS_level),
        ]

    
allowed_return_codes = {0:'0 (Success)',
                        1:'1 (Success)',
                        2:'2 (Success)',
                        128:'128 (Failure)'}


class MQTT_SUBACK(Packet):
    name = "MQTT suback"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("retcode", None, allowed_return_codes)
        ]


class MQTT_UNSUBSCRIBE(Packet):
    name = "MQTT unsubscribe"
    fields_desc = [
        ShortField("msgid", None),
        StrNullField("payload", "")
        ]

class MQTT_UNSUBACK(Packet):
    name = "MQTT unsuback"
    fields_desc = [
        ShortField("msgid", None)
        ]


## LAYERS BINDINGS

bind_layers(TCP,MQTT, sport=1883)
bind_layers(TCP,MQTT, dport=1883)
bind_layers(MQTT, MQTT_CONNECT, type=1)
bind_layers(MQTT, MQTT_CONNACK, type=2)
bind_layers(MQTT, MQTT_PUBLISH, type=3)
bind_layers(MQTT, MQTT_PUBACK, type =4)
bind_layers(MQTT, MQTT_PUBREC, type = 5)
bind_layers(MQTT, MQTT_PUBREL, type =6)
bind_layers(MQTT, MQTT_PUBCOMP, type =7)
bind_layers(MQTT, MQTT_SUBSCRIBE, type=8)
bind_layers(MQTT, MQTT_SUBACK, type=9)
bind_layers(MQTT, MQTT_UNSUBSCRIBE, type=10)
bind_layers(MQTT, MQTT_UNSUBACK, type=11)
bind_layers(MQTT_PUBLISH, MQTT) 
bind_layers(MQTT_CONNECT, MQTT)
bind_layers(MQTT_CONNACK, MQTT)
bind_layers(MQTT_PUBLISH, MQTT)
bind_layers(MQTT_PUBACK, MQTT)
bind_layers(MQTT_PUBREC, MQTT)
bind_layers(MQTT_PUBREL, MQTT)
bind_layers(MQTT_PUBCOMP, MQTT)
bind_layers(MQTT_SUBSCRIBE, MQTT)
bind_layers(MQTT_SUBACK, MQTT)
bind_layers(MQTT_UNSUBSCRIBE, MQTT)
bind_layers(MQTT_UNSUBACK, MQTT)
