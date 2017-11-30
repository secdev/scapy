# coding=utf-8

from scapy.packet import Raw
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.contrib.opcua.helpers import *
from scapy.fields import PacketField, ConditionalField


class UaSecureConversationMessageHeader(UaTypePacket):
    fields_desc = [UaBytesField("MessageType", None, 3),
                   UaByteField("IsFinal", b'F'),
                   UaUInt32Field("MessageSize", None),
                   UaUInt32Field("SecureChannelId", 0)]


class UaAsymmetricAlgorithmSecurityHeader(UaTypePacket):
    fields_desc = [PacketField("SecurityPolicyUri",
                               UaByteString(length=None, data=b'http://opcfoundation.org/UA/SecurityPolicy#None'),
                               UaByteString),
                   PacketField("SenderCertificate", UaByteString(), UaByteString),
                   PacketField("ReceiverCertificateThumbprint", UaByteString(), UaByteString)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] <= 1500:
                return UaSymmetricAlgorithmSecurityHeader
        return cls


class UaSymmetricAlgorithmSecurityHeader(UaTypePacket):
    fields_desc = [UaUInt32Field("TokenId", 0)]


class UaSequenceHeader(UaTypePacket):
    fields_desc = [UaUInt32Field("SequenceNumber", 0),
                   UaUInt32Field("RequestId", 0)]


def isMSG(p):
    messageType = p.MessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.SymmetricSecurityHeader, UaSymmetricAlgorithmSecurityHeader)
    return p.MessageHeader.MessageType == b'MSG'


def isOPN(p):
    messageType = p.MessageHeader.getfieldval("MessageType")
    if messageType is None:
        return isinstance(p.AsymmetricSecurityHeader, UaAsymmetricAlgorithmSecurityHeader)
    return p.MessageHeader.MessageType == b'OPN'


class UaSecureConversation(Packet):
    fields_desc = [PacketField("MessageHeader", UaSecureConversationMessageHeader(), UaSecureConversationMessageHeader),
                   # ConditionalField(PacketField("AsymmetricSecurityHeader",
                   #                             UaAsymmetricAlgorithmSecurityHeader(),
                   #                             UaAsymmetricAlgorithmSecurityHeader),
                   #                 isOPN),
                   # ConditionalField(PacketField("SymmetricSecurityHeader",
                   #                             UaSymmetricAlgorithmSecurityHeader(),
                   #                             UaSymmetricAlgorithmSecurityHeader),
                   #                 isMSG),
                   ConditionalField(PacketField("SecurityHeader", UaAsymmetricAlgorithmSecurityHeader(),
                                                UaAsymmetricAlgorithmSecurityHeader), lambda p: True),
                   PacketField("SequenceHeader", UaSequenceHeader(), UaSequenceHeader),
                   PacketField("Payload", Raw(), Raw)]

    message_types = [b'OPN', b'MSG', b'CLO']

    def post_build(self, pkt, pay):
        messageTypeField, messageType = self.MessageHeader.getfield_and_val("MessageType")
        messageSizeField, messageSize = self.MessageHeader.getfield_and_val("MessageSize")

        typeBinary = pkt[:messageTypeField.sz]
        restString = pkt[messageTypeField.sz:]

        """
        if messageType is None:
            if isinstance(self.AsymmetricSecurityHeader, UaAsymmetricAlgorithmSecurityHeader):
                self.MessageHeader.MessageType = b'OPN'
                typeBinary = b'OPN'
            elif isinstance(self.SymmetricSecurityHeader, UaSymmetricAlgorithmSecurityHeader):
                self.MessageHeader.MessageType = b'MSG'  # TODO: Differentiate between MSG and CLO???
                typeBinary = b'MSG'
            else:
                self.MessageHeader.MessageType = b'\x00\x00\x00'
                typeBinary = b'\x00\x00\x00'
        """

        if messageSize is None:
            completePkt = typeBinary + restString + pay
            messageSize = len(completePkt)
            self.MessageHeader.MessageSize = messageSize
            return messageSizeField.addfield(self,
                                             completePkt[:len(self.MessageHeader)][:-2 * messageSizeField.sz],
                                             messageSize) + completePkt[len(self.MessageHeader) - messageSizeField.sz:]

        return pkt + pay

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Determines whether we are dealing with UA TCP messages or with SecureConversation messages
        """
        messageTypeField = UaBytesField("", None, 3)

        rest, val = messageTypeField.getfield(None, _pkt)
        from scapy.contrib.opcua.binary.tcp import UaTcp

        if bytes(val) in UaTcp.message_types:
            return UaTcp
        return cls
