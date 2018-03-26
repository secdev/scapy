# coding=utf-8
"""
This module implements all networking structures required for OPC UA TCP communication.
For SecureConversation messages refer to secureConversation.py

If all OPC UA basic data types are needed load the uaTypes module
"""
from scapy.contrib.opcua.binary.builtinTypes import UaUInt32Field, UaByteField, UaBytesField, UaString
from scapy.contrib.opcua.helpers import UaTypePacket, UaPacketField
from scapy.fields import ConditionalField


class UaTcpMessageHeader(UaTypePacket):
    """
    This class represents the TcpMessageHeader of UA TCP messages in the binary encoding according to the specification.
    See part 6 v1.03 Table 34.
    """
    fields_desc = [UaBytesField("MessageType", None, 3),
                   UaByteField("Reserved", b'F'),
                   UaUInt32Field("MessageSize", None)]


class UaTcpHelloMessage(UaTypePacket):
    """
    This class represents a TcpHelloMessage in the OPC UA binary encoding according to the specification.
    See part 6 v1.03 Table 35.
    """
    fields_desc = [UaUInt32Field("ProtocolVersion", 0),
                   UaUInt32Field("ReceiveBufferSize", 1 << 12),
                   UaUInt32Field("SendBufferSize", 1 << 12),
                   UaUInt32Field("MaxMessageSize", 1 << 14),
                   UaUInt32Field("MaxChunkCount", 0),
                   UaPacketField("EndpointUrl", UaString(), UaString)]

    def post_build(self, pkt, pay):
        """
        Replaces all fields except for the EndpointUrl with values specified in the ConnectionContext.
        If a field was modified manually it is not changed automatically.
        If no ConnectionContext is set, the fields remain untouched.
        """
        if self.connectionContext is not None:
            # Just build completely new packet, since we replace a lot
            newPkt = UaTcpHelloMessage()
            
            protocolVersion = self.connectionContext.protocolVersion
            newPkt.ProtocolVersion = self.ProtocolVersion
            if protocolVersion is not None and self.ProtocolVersion == 0:
                newPkt.ProtocolVersion = protocolVersion
            
            receiveBufferSize = self.connectionContext.localBufferSizes.receiveBufferSize
            newPkt.ReceiveBufferSize = self.ReceiveBufferSize
            if receiveBufferSize is not None and self.ReceiveBufferSize == 1 << 12:
                newPkt.ReceiveBufferSize = receiveBufferSize
            
            sendBufferSize = self.connectionContext.localBufferSizes.sendBufferSize
            newPkt.SendBufferSize = self.SendBufferSize
            if sendBufferSize is not None and self.SendBufferSize == 1 << 12:
                newPkt.SendBufferSize = sendBufferSize
            
            maxMessageSize = self.connectionContext.localBufferSizes.maxMessageSize
            newPkt.MaxMessageSize = self.MaxMessageSize
            if maxMessageSize is not None and self.MaxMessageSize == 1 << 14:
                newPkt.MaxMessageSize = maxMessageSize
            
            maxChunkCount = self.connectionContext.localBufferSizes.maxChunkCount
            newPkt.MaxChunkCount = self.MaxChunkCount
            if maxChunkCount is not None and self.MaxChunkCount == 0:
                newPkt.MaxChunkCount = maxChunkCount
            
            newPkt.EndpointUrl = self.EndpointUrl
            
            return bytes(newPkt)
        
        return pkt + pay


class UaTcpAcknowledgeMessage(UaTypePacket):
    """
    This class represents a TcpAcknowledgeMessage in the OPC UA binary encoding according to the specification.
    See part 6 v1.03 Table 36.
    """
    fields_desc = [UaUInt32Field("ProtocolVersion", 0),
                   UaUInt32Field("ReceiveBufferSize", 0),
                   UaUInt32Field("SendBufferSize", 0),
                   UaUInt32Field("MaxMessageSize", 0),
                   UaUInt32Field("MaxChunkCount", 0)]


class UaTcpErrorMessage(UaTypePacket):
    """
    This class represents a TcpErrorMessage in the OPC UA binary encoding according to the specification.
    See part 6 v1.03 Table 37.
    """
    fields_desc = [UaUInt32Field("Error", 0),
                   UaPacketField("Reason", UaString(), UaString)]


def _is_hel(p):
    """
    Determines whether the supplied packet contains a TcpHelloMessage
    
    :param p: the packet bytes starting at the UA TCP layer.
    :return: True if the packet contains a TcpHelloMessage and False otherwise.
    """
    messageType = p.TcpMessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.Message, UaTcpHelloMessage)
    return p.TcpMessageHeader.MessageType == b'HEL' or isinstance(p.Message, UaTcpHelloMessage)


def _is_ack(p):
    """
    Determines whether the supplied packet contains a TcpAcknowledgeMessage
    
    :param p: the packet bytes starting at the UA TCP layer.
    :return: True if the packet contains a TcpAcknowledgeMessage and False otherwise.
    """
    messageType = p.TcpMessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.Message, UaTcpAcknowledgeMessage)
    return p.TcpMessageHeader.MessageType == b'ACK'


def _is_err(p):
    """
    Determines whether the supplied packet contains a TcpErrorMessage
    
    :param p: the packet bytes starting at the UA TCP layer.
    :return: True if the packet contains a TcpErrorMessage and False otherwise.
    """
    messageType = p.TcpMessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.Message, UaTcpErrorMessage)
    return p.TcpMessageHeader.MessageType == b'ERR'


class UaTcp(UaTypePacket):
    """
    This class models a packet on the UA TCP layer.
    
    It is the entry point to any OPC UA binary communication.
    This means that every OPC UA packet encoded with the binary encoding can be decoded by binding the normal
    tcp layer to this packet class.
    
    A TCP message in OPC UA consists of the TcpMessageHeader (see :class:`UaTcpMessageHeader`)
    and one of the three possible Messages (see :class:`UaTcpHelloMessage`, :class:`UaTcpAcknowledgeMessage` and
    :class:`UaTcpErrorMessage`).
    
    One of the three messages can be set in the Message attribute.
    The default is TcpHelloMessage.
    """
    __slots__ = []
    fields_desc = [UaPacketField("TcpMessageHeader", UaTcpMessageHeader(), UaTcpMessageHeader),
                   ConditionalField(UaPacketField("Message",
                                                  UaTcpErrorMessage(),
                                                  UaTcpErrorMessage),
                                    _is_err),
                   ConditionalField(UaPacketField("Message",
                                                  UaTcpAcknowledgeMessage(),
                                                  UaTcpAcknowledgeMessage),
                                    _is_ack),
                   ConditionalField(UaPacketField("Message",
                                                  UaTcpHelloMessage(),
                                                  UaTcpHelloMessage),
                                    _is_hel)
                   ]
    
    message_types = [b'HEL', b'ACK', b'ERR']
    
    def post_build(self, pkt, pay):
        """
        Automatically calculates the MessageType depending on the contained message if it was not manually set.
        The message size of the packet is also calculated automatically if not set manually.
        
        See overridden method for more.
        """
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
        Determines whether we are dealing with UA TCP messages or with SecureConversation messages.
        
        :return the correct class with which the packet will be decoded
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
