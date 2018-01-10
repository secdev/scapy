"""
This module implements all networking structures required for OPC UA TCP communication.
For SecureConversation messages refer to secureConversation.py

If all OPC UA basic data types are needed load the uaTypes module
"""
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.contrib.opcua.helpers import *


class UaTcpMessageHeader(UaTypePacket):
    fields_desc = [UaBytesField("MessageType", None, 3),
                   UaByteField("Reserved", b'F'),
                   UaUInt32Field("MessageSize", None)]


class UaTcpHelloMessage(UaTypePacket):
    fields_desc = [UaUInt32Field("ProtocolVersion", 0),
                   UaUInt32Field("ReceiveBufferSize", 1 << 12),
                   UaUInt32Field("SendBufferSize", 1 << 12),
                   UaUInt32Field("MaxMessageSize", 1 << 12),
                   UaUInt32Field("MaxChunkCount", 1),
                   PacketField("EndpointUrl", UaString(), UaString)]


class UaTcpAcknowledgeMessage(UaTypePacket):
    fields_desc = [UaUInt32Field("ProtocolVersion", 0),
                   UaUInt32Field("ReceiveBufferSize", 0),
                   UaUInt32Field("SendBufferSize", 0),
                   UaUInt32Field("MaxMessageSize", 0),
                   UaUInt32Field("MaxChunkCount", 0)]


class UaTcpErrorMessage(UaTypePacket):
    fields_desc = [UaUInt32Field("Error", 0),
                   PacketField("Reason", UaString(), UaString)]


def isHEL(p):
    messageType = p.TcpMessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.Message, UaTcpHelloMessage)
    return p.TcpMessageHeader.MessageType == b'HEL' or isinstance(p.Message, UaTcpHelloMessage)


def isACK(p):
    messageType = p.TcpMessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.Message, UaTcpAcknowledgeMessage)
    return p.TcpMessageHeader.MessageType == b'ACK'


def isERR(p):
    messageType = p.TcpMessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.Message, UaTcpErrorMessage)
    return p.TcpMessageHeader.MessageType == b'ERR'


class UaTcp(UaTypePacket):
    fields_desc = [PacketField("TcpMessageHeader", UaTcpMessageHeader(), UaTcpMessageHeader),
                   ConditionalField(PacketField("Message",
                                                UaTcpErrorMessage(),
                                                UaTcpErrorMessage),
                                    isERR),
                   ConditionalField(PacketField("Message",
                                                UaTcpAcknowledgeMessage(),
                                                UaTcpAcknowledgeMessage),
                                    isACK),
                   ConditionalField(PacketField("Message",
                                                UaTcpHelloMessage(),
                                                UaTcpHelloMessage),
                                    isHEL)
                   ]

    message_types = [b'HEL', b'ACK', b'ERR']

    def post_build(self, pkt, pay):
        messageTypeField, messageType = self.TcpMessageHeader.getfield_and_val("MessageType")
        messageSizeField, messageSize = self.TcpMessageHeader.getfield_and_val("MessageSize")

        typeBinary = pkt[:messageTypeField.sz]
        restString = pkt[messageTypeField.sz:]

        if messageType is None:
            if isinstance(self.Message, UaTcpHelloMessage):
                typeBinary = b'HEL'
            elif isinstance(self.Message, UaTcpAcknowledgeMessage):
                typeBinary = b'ACK'
            elif isinstance(self.Message, UaTcpErrorMessage):
                typeBinary = b'ERR'
            else:
                typeBinary = b'\x00\x00\x00'

        completePkt = typeBinary + restString + pay

        if messageSize is None:
            messageSize = len(completePkt)

        return messageSizeField.addfield(completePkt,
                                         completePkt[:len(self.TcpMessageHeader)][:-messageSizeField.sz],
                                         messageSize) + completePkt[len(self.TcpMessageHeader):]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Determines whether we are dealing with UA TCP messages or with SecureConversation messages
        """
        if _pkt is None:
            return cls

        messageTypeField = UaBytesField("", None, 3)

        rest, val = messageTypeField.getfield(None, _pkt)
        from scapy.contrib.opcua.binary.secureConversation import UaSecureConversationAsymmetric, \
            UaSecureConversationSymmetric

        val = bytes(bytearray(val))
        if val in UaSecureConversationAsymmetric.message_types:
            return UaSecureConversationAsymmetric
        elif val in UaSecureConversationSymmetric.message_types:
            return UaSecureConversationSymmetric
        elif val in cls.message_types:
            return cls

        return cls
