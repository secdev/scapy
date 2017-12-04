# coding=utf-8

from scapy.packet import Raw
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.contrib.opcua.helpers import *
from scapy.fields import PacketField
from scapy.contrib.opcua.binary.tcp import UaTcp
from scapy.contrib.opcua.binary.schemaTypes import *


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


class UaSymmetricAlgorithmSecurityHeader(UaTypePacket):
    fields_desc = [UaUInt32Field("TokenId", 0)]


class UaSequenceHeader(UaTypePacket):
    fields_desc = [UaUInt32Field("SequenceNumber", 0),
                   UaUInt32Field("RequestId", 0)]


class UaSecureConversationAsymmetric(UaTcp):
    fields_desc = [PacketField("MessageHeader", UaSecureConversationMessageHeader(), UaSecureConversationMessageHeader),
                   PacketField("SecurityHeader",
                               UaAsymmetricAlgorithmSecurityHeader(),
                               UaAsymmetricAlgorithmSecurityHeader),
                   PacketField("SequenceHeader", UaSequenceHeader(), UaSequenceHeader),
                   PacketField("DataTypeEncoding", UaNodeId(), UaNodeId),
                   PacketField("Payload", Raw(), Raw)]

    message_types = [b'OPN']

    def post_build(self, pkt, pay):
        messageTypeField, messageType = self.MessageHeader.getfield_and_val("MessageType")
        messageSizeField, messageSize = self.MessageHeader.getfield_and_val("MessageSize")

        typeBinary = pkt[:messageTypeField.sz]
        restString = pkt[messageTypeField.sz:]

        if messageType is None:
            if isinstance(self.SecurityHeader, UaAsymmetricAlgorithmSecurityHeader):
                self.MessageHeader.MessageType = b'OPN'
                typeBinary = b'OPN'
            elif isinstance(self.SecurityHeader, UaSymmetricAlgorithmSecurityHeader):
                self.MessageHeader.MessageType = b'MSG'  # TODO: Differentiate between MSG and CLO???
                typeBinary = b'MSG'
            else:
                self.MessageHeader.MessageType = b'\x00\x00\x00'
                typeBinary = b'\x00\x00\x00'

        if messageSize is None:
            completePkt = typeBinary + restString + pay
            messageSize = len(completePkt)
            self.MessageHeader.MessageSize = messageSize
            return messageSizeField.addfield(self,
                                             completePkt[:len(self.MessageHeader)][:-2 * messageSizeField.sz],
                                             messageSize) + completePkt[len(self.MessageHeader) - messageSizeField.sz:]

        return pkt + pay

    def pre_dissect(self, s):
        # TODO: Implement decryption of asymmetric messages?
        return s

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(UaSecureConversationAsymmetric, cls).dispatch_hook(_pkt, args, kargs)


class UaSecureConversationSymmetric(UaSecureConversationAsymmetric):
    fields_desc = [PacketField("MessageHeader", UaSecureConversationMessageHeader(), UaSecureConversationMessageHeader),
                   PacketField("SecurityHeader",
                               UaSymmetricAlgorithmSecurityHeader(),
                               UaSymmetricAlgorithmSecurityHeader),
                   PacketField("SequenceHeader", UaSequenceHeader(), UaSequenceHeader),
                   PacketField("DataTypeEncoding", UaExpandedNodeId(), UaExpandedNodeId),
                   PacketField("Payload", Raw(), Raw)]

    message_types = [b'MSG', b'CLO']

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(UaSecureConversationSymmetric, cls).dispatch_hook(_pkt, args, kargs)
