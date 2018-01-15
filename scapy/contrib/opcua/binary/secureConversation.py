# coding=utf-8
"""
This module implements all networking structures required for OPC UA secure conversation communication.
For SecureConversation messages refer to secureConversation.py

If all OPC UA basic data types are needed load the uaTypes module
"""
import six

from cryptography.exceptions import InvalidSignature
from scapy.compat import raw
from scapy.fields import ConditionalField, FieldListField
from scapy.contrib.opcua.helpers import UaTypePacket, UaPacketField, ByteListField
from scapy.contrib.opcua.binary.builtinTypes import UaBytesField, UaByteField, UaUInt32Field, UaByteString, \
    UaExpandedNodeId, UaNodeId
from scapy.contrib.opcua.binary.tcp import UaTcp
from scapy.contrib.opcua.binary.schemaTypes import UaOpenSecureChannelRequest, UaCloseSecureChannelRequest, \
    UaCloseSecureChannelResponse, nodeIdMappings, UaMessageSecurityMode
import hashlib
import logging


class UaSecureConversationMessageHeader(UaTypePacket):
    fields_desc = [UaBytesField("MessageType", None, 3),
                   UaByteField("IsFinal", b'F', displayAsChar=True),
                   UaUInt32Field("MessageSize", None),
                   UaUInt32Field("SecureChannelId", None)]
    
    def post_build(self, pkt, pay):
        idField, id = self.getfield_and_val("SecureChannelId")
        
        if id is None and self.connectionContext is not None:
            pkt = idField.addfield(self, pkt[:-idField.sz], self.connectionContext.securityToken.ChannelId)
        
        return pkt + pay


def _has_padding(pkt):
    if pkt.connectionContext is None:
        return False
    hasPadding = pkt.connectionContext.securityPolicy is not None
    if not hasPadding:
        return hasPadding
    
    try:
        if pkt.underlayer.MessageHeader.MessageType == b'OPN':
            return hasPadding
    except AttributeError:
        return False
    
    hasPadding = pkt.connectionContext.securityPolicy.Mode == UaMessageSecurityMode.SignAndEncrypt
    return hasPadding


def _has_signature(pkt):
    return pkt.connectionContext is not None and \
           pkt.connectionContext.securityPolicy is not None and \
           pkt.connectionContext.securityPolicy.Mode > getattr(UaMessageSecurityMode, "None")


class UaSecureConversationMessageFooter(UaTypePacket):
    fields_desc = [ConditionalField(UaByteField("PaddingSize", None, count_of="Padding"), _has_padding),
                   ConditionalField(FieldListField("Padding", None, UaByteField("", None, False),
                                                   count_from=lambda p: p.PaddingSize), _has_padding),
                   ConditionalField(ByteListField("Signature", None, UaByteField("", None, True), length_from=lambda
                       p: p.connectionContext.securityPolicy.asymmetric_cryptography.vsignature_size()),
                                    _has_signature)]
    
    # We override this method because we don't want to add anything that is set to none
    def do_build(self, field_pos_list=None):
        if self.raw_packet_cache is not None:
            for fname, fval in six.iteritems(self.raw_packet_cache_fields):
                if self.getfieldval(fname) != fval:
                    self.raw_packet_cache = None
                    self.raw_packet_cache_fields = None
                    break
            if self.raw_packet_cache is not None:
                return self.raw_packet_cache
        p = b""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if val is None or val == []:
                continue
            from packet import RawVal
            if isinstance(val, RawVal):
                sval = raw(val)
                p += sval
                if field_pos_list is not None:
                    field_pos_list.append((f.name, sval.encode("string_escape"), len(p), len(sval)))
            else:
                p = f.addfield(self, p, val)
        return p


class UaAsymmetricAlgorithmSecurityHeader(UaTypePacket):
    fields_desc = [UaPacketField("SecurityPolicyUri",
                                 UaByteString(),
                                 UaByteString),
                   UaPacketField("SenderCertificate", UaByteString(), UaByteString),
                   UaPacketField("ReceiverCertificateThumbprint", UaByteString(), UaByteString)]
    
    def post_build(self, pkt, pay):
        policyField, policy = self.getfield_and_val("SecurityPolicyUri")
        policyLen = len(policy)
        
        if self.connectionContext is None or self.connectionContext.securityPolicy is None and policy.data is None:
            policy = UaByteString(data=b'http://opcfoundation.org/UA/SecurityPolicy#None')
            return bytes(policy) + pkt[policyLen:] + pay
        
        if self.connectionContext.securityPolicy is not None:
            result = b''
            policy = UaByteString(data=self.connectionContext.securityPolicy.URI)
            result += bytes(policy)
            
            certField, cert = self.getfield_and_val("SenderCertificate")
            certLen = len(cert)
            if cert.data is None:
                cert = UaByteString(data=self.connectionContext.securityPolicy.client_certificate)
                result += bytes(cert)
            else:
                result += pkt[policyLen:][:certLen]
            
            thumbPrintField, thumbPrint = self.getfield_and_val("ReceiverCertificateThumbprint")
            if thumbPrint.data is None and self.connectionContext.securityPolicy.client_certificate is not None:
                thumbPrintBytes = hashlib.sha1(self.connectionContext.securityPolicy.server_certificate).digest()
                thumbPrint = UaByteString(data=thumbPrintBytes)
                result += bytes(thumbPrint)
            else:
                result += pkt[policyLen + certLen:]
            
            return result + pay
        
        return pkt + pay


class UaSymmetricAlgorithmSecurityHeader(UaTypePacket):
    fields_desc = [UaUInt32Field("TokenId", None)]
    
    def post_build(self, pkt, pay):
        tokenIdField, tokenId = self.getfield_and_val("TokenId")
        
        if tokenId is None and self.connectionContext is not None:
            pkt = tokenIdField.addfield(self, b'', self.connectionContext.securityToken.TokenId)
        return pkt + pay


class UaSequenceHeader(UaTypePacket):
    fields_desc = [UaUInt32Field("SequenceNumber", None),
                   UaUInt32Field("RequestId", None)]
    
    def post_build(self, pkt, pay):
        sequenceNumberField, sequenceNumber = self.getfield_and_val("SequenceNumber")
        
        if sequenceNumber is None and self.connectionContext is not None:
            # Set the send sequence number. The receive sequence number is only used for checking messages that
            # are received from a remote.
            pkt = sequenceNumberField.addfield(self, b'', self.connectionContext.sendSequenceNumber) + \
                  pkt[sequenceNumberField.sz:]
            
        # TODO: use connectionContext to replace request id?
        return pkt + pay


class UaMessage(UaTypePacket):
    fields_desc = [UaPacketField("DataTypeEncoding", UaNodeId(), UaNodeId),
                   UaPacketField("Message", None, UaTypePacket)]
    
    _cache = {}
    
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt is not None:
            nodeId = UaExpandedNodeId(_pkt)
            
            if nodeId.Identifier in nodeIdMappings:
                if nodeId.Identifier not in UaMessage._cache:
                    dispatchedClass = nodeIdMappings[nodeId.Identifier]
                    fields_desc = [UaPacketField("DataTypeEncoding", UaNodeId(), UaNodeId),
                                   UaPacketField("Message", dispatchedClass(), dispatchedClass)]
                    newDict = dict(cls.__dict__)
                    newDict["fields_desc"] = fields_desc
                    UaMessage._cache[nodeId.Identifier] = type(cls.__name__, cls.__bases__, newDict)
                return UaMessage._cache[nodeId.Identifier]
        
        return cls
    
    def post_build(self, pkt, pay):
        identifierField, identifier = self.DataTypeEncoding.getfield_and_val("Identifier")
        removeUpTo = len(self.DataTypeEncoding)
        
        if identifier is None:
            if self.Message is not None and self.Message.binaryEncodingId is not None:
                identifier = self.Message.binaryEncodingId
                encoding = self.DataTypeEncoding.getfieldval("Encoding")
                namespace = self.DataTypeEncoding.getfieldval("Namespace")
                
                pkt = UaNodeId(Encoding=encoding, Namespace=namespace, Identifier=identifier).build() + pkt[removeUpTo:]
        
        return pkt + pay


class UaSecureConversationAsymmetric(UaTcp):
    fields_desc = [
        UaPacketField("MessageHeader", UaSecureConversationMessageHeader(), UaSecureConversationMessageHeader),
        UaPacketField("SecurityHeader",
                      UaAsymmetricAlgorithmSecurityHeader(),
                      UaAsymmetricAlgorithmSecurityHeader),
        UaPacketField("SequenceHeader", UaSequenceHeader(), UaSequenceHeader),
        UaPacketField("Payload", UaMessage(Message=UaOpenSecureChannelRequest()), UaMessage),
        UaPacketField("MessageFooter", UaSecureConversationMessageFooter(), UaSecureConversationMessageFooter)]
    
    message_types = [b'OPN']
    
    _logger = logging.getLogger(__name__)
    
    def _get_type_binary(self):
        if isinstance(self.SecurityHeader, UaAsymmetricAlgorithmSecurityHeader):
            typeBinary = b'OPN'
        elif isinstance(self.SecurityHeader, UaSymmetricAlgorithmSecurityHeader):
            if isinstance(self.Payload.Message, (UaCloseSecureChannelRequest, UaCloseSecureChannelResponse)):
                typeBinary = B'CLO'
            else:
                typeBinary = b'MSG'
        else:
            typeBinary = b'\x00\x00\x00'
        
        return typeBinary
    
    def _get_num_encryption_blocks_and_padding(self, body, crypto_module):
        padding = b''
        if self.MessageFooter.getfieldval("PaddingSize") is None:
            padding = crypto_module.padding(len(body))
        sigLen = crypto_module.signature_size()
        blockSize = crypto_module.plain_block_size()
        return (len(body) + len(padding) + sigLen) // blockSize, padding
    
    def post_build(self, pkt, pay, cryptoModule=None):
        messageTypeField, messageType = self.MessageHeader.getfield_and_val("MessageType")
        messageSizeField, messageSize = self.MessageHeader.getfield_and_val("MessageSize")
        
        if cryptoModule is None and \
                self.connectionContext is not None and \
                self.connectionContext.securityPolicy is not None:
            cryptoModule = self.connectionContext.securityPolicy.asymmetric_cryptography
        
        typeBinary = pkt[:messageTypeField.sz]
        restString = pkt[messageTypeField.sz:]
        
        if messageType is None:
            typeBinary = self._get_type_binary()
        
        completePkt = typeBinary + restString + pay
        unencryptedSize = len(self.MessageHeader) + len(self.SecurityHeader)
        padding = b''
        numEncryptionBlocks = 0
        
        # If we are encrypting the final size of the chunk has to be known in advance, since the signature includes
        # the messageSize and the signature needs to be encrypted. Here we only calculate the number of blocks.
        # Later we can multiply the number of blocks by the encrypted block size to get the actual size.
        if cryptoModule is not None:
            body = completePkt[unencryptedSize:]
            numEncryptionBlocks, padding = self._get_num_encryption_blocks_and_padding(body, cryptoModule)
        
        if messageSize is None:
            if cryptoModule is not None:
                messageSize = unencryptedSize
                messageSize += numEncryptionBlocks * cryptoModule.encrypted_block_size()
            else:
                messageSize = len(completePkt)
            completePkt = messageSizeField.addfield(self,
                                                    completePkt[:len(self.MessageHeader)][:-2 * messageSizeField.sz],
                                                    messageSize) + completePkt[
                                                                   len(self.MessageHeader) - messageSizeField.sz:]
        
        if cryptoModule is not None:
            completePkt += padding
            completePkt += cryptoModule.signature(completePkt)
            dataToEncrypt = completePkt[unencryptedSize:]
            encrypted = cryptoModule.encrypt(dataToEncrypt)
            completePkt = completePkt[:unencryptedSize] + encrypted
        
        return completePkt
    
    def pre_dissect(self, s, cryptoModule=None, securityHeader=UaAsymmetricAlgorithmSecurityHeader):
        if cryptoModule is None and \
                self.connectionContext is not None and \
                self.connectionContext.securityPolicy is not None:
            cryptoModule = self.connectionContext.securityPolicy.asymmetric_cryptography
        if cryptoModule is not None:
            header = UaSecureConversationMessageHeader(s)
            securityHeader = securityHeader(header.payload)
            header.remove_payload()
            securityHeader.remove_payload()
    
            unencryptedLength = len(header) + len(securityHeader)
    
            if self.connectionContext.decodeRemote:
                decrypted = cryptoModule.decrypt_remote(s[unencryptedLength:])
            else:
                decrypted = cryptoModule.decrypt(s[unencryptedLength:])
    
            s = s[:unencryptedLength] + decrypted

            try:
                if self.connectionContext.decodeRemote:
                    sigLen = cryptoModule.signature_size()
                    cryptoModule.verify_remote(s[:-sigLen], s[-sigLen:])
                else:
                    sigLen = cryptoModule.vsignature_size()
                    cryptoModule.verify(s[:-sigLen], s[-sigLen:])
            except InvalidSignature:
                self._logger.warning("Failed to verify signature")
                # TODO: Make this configurable, so that the user can decide if an exception is thrown, or
                # TODO: if only a log message is created. (Replace print with log)

        
        return s
    
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaSecureConversationAsymmetric, cls).dispatch_hook(_pkt, args, kwargs)


class UaSecureConversationSymmetric(UaSecureConversationAsymmetric):
    fields_desc = [
        UaPacketField("MessageHeader", UaSecureConversationMessageHeader(), UaSecureConversationMessageHeader),
        UaPacketField("SecurityHeader",
                      UaSymmetricAlgorithmSecurityHeader(),
                      UaSymmetricAlgorithmSecurityHeader),
        UaPacketField("SequenceHeader", UaSequenceHeader(), UaSequenceHeader),
        UaPacketField("Payload", UaMessage(), UaMessage),
        UaPacketField("MessageFooter", UaSecureConversationMessageFooter(), UaSecureConversationMessageFooter)]
    
    message_types = [b'MSG', b'CLO']
    
    def post_build(self, pkt, pay, cryptoModule=None):
        if self.connectionContext is not None and self.connectionContext.securityPolicy is not None:
            cryptoModule = self.connectionContext.securityPolicy.symmetric_cryptography
        return super(UaSecureConversationSymmetric, self).post_build(pkt, pay, cryptoModule)
    
    def pre_dissect(self, s, cryptoModule=None, securityHeader=UaSymmetricAlgorithmSecurityHeader):
        if self.connectionContext is not None and self.connectionContext.securityPolicy is not None:
            cryptoModule = self.connectionContext.securityPolicy.symmetric_cryptography
        return super(UaSecureConversationSymmetric, self).pre_dissect(s, cryptoModule, securityHeader)
    
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaSecureConversationSymmetric, cls).dispatch_hook(_pkt, args, kwargs)
