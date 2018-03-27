# coding=utf-8
"""
This module implements all networking structures required for OPC UA secure conversation communication.
For SecureConversation messages refer to secureConversation.py

If all OPC UA basic data types are needed load the uaTypes module
"""
import hashlib
import logging
from cryptography.exceptions import InvalidSignature

from scapy.compat import raw
from scapy.fields import ConditionalField, FieldListField
from scapy.contrib.opcua.helpers import UaTypePacket, UaPacketField, ByteListField
from scapy.contrib.opcua.binary.builtinTypes import UaBytesField, UaByteField, UaUInt32Field, UaByteString, \
    UaExpandedNodeId, UaNodeId
from scapy.contrib.opcua.binary.tcp import UaTcp
from scapy.contrib.opcua.binary.schemaTypes import UaOpenSecureChannelRequest, UaCloseSecureChannelRequest, \
    UaCloseSecureChannelResponse, nodeIdMappings, UaMessageSecurityMode
from scapy.modules import six


class UaSecureConversationMessageHeader(UaTypePacket):
    """
    This class represents the SecureConversationMessageHeader of SecureConversation messages in the binary encoding
    according to the specification.
    See part 6 v1.03 Table 26.
    """
    fields_desc = [UaBytesField("MessageType", None, 3),
                   UaByteField("IsFinal", b'F', displayAsChar=True),
                   UaUInt32Field("MessageSize", None),
                   UaUInt32Field("SecureChannelId", None)]
    
    def post_build(self, pkt, pay):
        """
        Replaces the SecureChannelId with the value in the ConnectionContext
        if it is supplied and it was not set manually.
        """
        idField, id = self.getfield_and_val("SecureChannelId")
        
        if id is None and self.connectionContext is not None:
            pkt = idField.addfield(self, pkt[:-idField.sz], self.connectionContext.securityToken.ChannelId)
        
        return pkt + pay


def _has_padding(pkt):
    """
    Determines whether the supplied SecureConversationMessageFooter packet has a padding.
    
    :param pkt: the SecureConversationMessageFooter packet to check for padding.
    :return: True if the packet has padding and False otherwise.
    """
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
    """
    Determines whether the supplied SecureConversationMessageFooter packet has a signature.
    :param pkt: the SecureConversationMessageFooter packet to check for a signature.
    :return: True if the packet has a signature and False otherwise.
    """
    return pkt.connectionContext is not None and \
           pkt.connectionContext.securityPolicy is not None and \
           pkt.connectionContext.securityPolicy.Mode > getattr(UaMessageSecurityMode, "None")


class UaSecureConversationMessageFooter(UaTypePacket):
    """
    This class represents the SecureConversationMessageFooter of SecureConversation messages
    in the binary encoding according to the specification.
    See part 6 v1.03 Table 30.
    """
    fields_desc = [ConditionalField(UaByteField("PaddingSize", None, count_of="Padding"), _has_padding),
                   ConditionalField(FieldListField("Padding", None, UaByteField("", None, False),
                                                   count_from=lambda p: p.PaddingSize), _has_padding),
                   ConditionalField(ByteListField("Signature", None, UaByteField("", None, True), length_from=lambda
                       p: p.connectionContext.securityPolicy.asymmetric_cryptography.vsignature_size()),
                                    _has_signature)]
    
    # We override this method because we don't want to add anything that is set to none
    # The function is copied from the parent class and slightly changed.
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
    """
    This class represents the AsymmetricAlgorithmSecurityHeader of SecureConversation messages
    in the binary encoding according to the specification.
    See part 6 v1.03 Table 27.
    """
    fields_desc = [UaPacketField("SecurityPolicyUri",
                                 UaByteString(),
                                 UaByteString),
                   UaPacketField("SenderCertificate", UaByteString(), UaByteString),
                   UaPacketField("ReceiverCertificateThumbprint", UaByteString(), UaByteString)]
    
    def post_build(self, pkt, pay):
        """
        The fields are automatically replaced if a ConnectionContext is set.
        The Thumbprint will be automatically calculated from the data present in the SecurityPolicy.
        If any field has been manually set it will remain unchanged.
        """
        policyField, policy = self.getfield_and_val("SecurityPolicyUri")
        policyLen = len(policy)
        
        if self.connectionContext is None or self.connectionContext.securityPolicy is None and policy.data is None:
            policy = UaByteString(data=b'http://opcfoundation.org/UA/SecurityPolicy#None')
            return bytes(policy) + pkt[policyLen:] + pay
        
        if self.connectionContext.securityPolicy is not None:
            result = b''
            if policy.data is None:
                policyUri = self.connectionContext.securityPolicy.URI
                policy = UaByteString(data=policyUri)
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
    """
    This class represents the SymmetricAlgorithmSecurityHeader of SecureConversation messages
    in the binary encoding according to the specification.
    See part 6 v1.03 Table 28.
    """
    fields_desc = [UaUInt32Field("TokenId", None)]
    
    def post_build(self, pkt, pay):
        """
        Automatically replaces the TokenId if it is present in the ConnectionContext and was not set manually.
        """
        tokenIdField, tokenId = self.getfield_and_val("TokenId")
        
        if tokenId is None and self.connectionContext is not None:
            pkt = tokenIdField.addfield(self, b'', self.connectionContext.securityToken.TokenId)
        return pkt + pay


class UaSequenceHeader(UaTypePacket):
    """
    This class represents the SequenceHeader of SecureConversation messages
    in the binary encoding according to the specification.
    See part 6 v1.03 Table 29.
    """
    fields_desc = [UaUInt32Field("SequenceNumber", None),
                   UaUInt32Field("RequestId", None)]
    
    def post_build(self, pkt, pay):
        """
        Automatically replaces SequenceNumber and RequestId if they are present in the ConnectionContext
        and were not set manually.
        """
        sequenceNumberField, sequenceNumber = self.getfield_and_val("SequenceNumber")
        
        if sequenceNumber is None and self.connectionContext is not None:
            # Set the send sequence number. The receive sequence number is only used for checking messages that
            # are received from a remote.
            pkt = sequenceNumberField.addfield(self, b'', self.connectionContext.sendSequenceNumber) + \
                  pkt[sequenceNumberField.sz:]
        
        requestIdField, requestId = self.getfield_and_val("RequestId")
        
        if requestId is None and self.connectionContext is not None:
            pkt = requestIdField.addfield(self, pkt[:requestIdField.sz], self.connectionContext.requestId)
        
        return pkt + pay


def _chunked_data_length(pkt):
    """
    Determines the length of a :class:`UaChunkedData` Message.
    
    :param pkt: the packet that contains the chunked data.
    :return: the length of the data.
    """
    reduceBy = 0
    
    if pkt.connectionContext is not None and pkt.connectionContext.securityPolicy is not None:
        signatureSize = pkt.connectionContext.securityPolicy.symmetric_cryptography.vsignature_size()
        reduceBy += signatureSize
        if pkt.connectionContext.securityPolicy.symmetric_cryptography.is_encrypted:
            paddingSize = int(pkt.original[-signatureSize - 1])  # TODO: calculate correctly for keys > 2048 bit
            reduceBy += paddingSize + 1  # no padding bytes and no PaddingSize byte
    
    if reduceBy == 0:
        return len(pkt.original)
    
    return len(pkt.original[:-reduceBy])


class UaChunkedData(UaTypePacket):
    """
    This helper class is used to decode message chunks that have the intermediate flag 'C' set.
    The data is interpreted as byte string and as soon as a final chunk 'F' is decoded it will be reassembled.
    """
    __slots__ = ["isCLO"]
    fields_desc = [ByteListField("Message", None, UaByteField("", None, True), count_from=_chunked_data_length)]
    
    def __init__(self, _pkt=b"", connectionContext=None, post_transform=None, _internal=0, _underlayer=None, **fields):
        super(UaChunkedData, self).__init__(_pkt, connectionContext, post_transform, _internal, _underlayer, **fields)
        self.isCLO = False
    
    def post_dissection(self, s):
        """
        Appends the decoded intermediate chunk to a list of chunks in the ConnectionContext.
        They will be automatically reassembled once a final chunk is decoded.
        """
        requestId = self.underlayer.SequenceHeader.RequestId
        if self.connectionContext is not None:
            self.connectionContext.chunks[requestId].append(self.underlayer)
        return s


class UaMessage(UaTypePacket):
    """
    This class is used to decode OPC UA messages.
    It represents a complete message that is not split into chunks.
    The DataTypeEncoding determines how the Message field is decoded.
    For each different DataTypeEncoding a new UaMessage class is created which is cached in a dictionary.
    To a user this is not visible.
    """
    fields_desc = [UaPacketField("DataTypeEncoding", UaNodeId(), UaNodeId),
                   UaPacketField("Message", None, UaTypePacket)]
    
    _cache = {}
    _intermediate = UaChunkedData
    
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        """
        This dispatch_hook method looks up the UaMessage cache for an appropriate class and returns it.
        If none exists, a new one is created, added to the cache and then returned.
        
        If the Data is an intermediate chunk, the :class:`UaChunkedData` class is returned for decoding.
        """
        if _pkt is not None:
            if "_underlayer" in kwargs:
                underlayer = kwargs["_underlayer"]
                if underlayer.MessageHeader.IsFinal == b'C':
                    return UaMessage._intermediate
                if underlayer.connectionContext is not None:
                    if underlayer.SequenceHeader.RequestId in underlayer.connectionContext.chunks:
                        return UaMessage._intermediate
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
        """
        Automatically replaces the DataTypeEncoding with the appropriate value if it was not manually set.
        """
        dataTypeEncoding = self.DataTypeEncoding
        try:
            identifier = dataTypeEncoding.getfieldval("Identifier")
        except AttributeError:
            identifier = dataTypeEncoding.NodeId.getfieldval("Identifier")
        removeUpTo = len(self.DataTypeEncoding)
        
        if identifier is None:
            if self.Message is not None and self.Message.binaryEncodingId is not None and \
                    type(dataTypeEncoding) is UaNodeId:
                identifier = self.Message.binaryEncodingId
                encoding = dataTypeEncoding.getfieldval("Encoding")
                namespace = dataTypeEncoding.getfieldval("Namespace")
                pkt = UaNodeId(Encoding=encoding, Namespace=namespace, Identifier=identifier).build() + pkt[removeUpTo:]
        
        return pkt + pay
    
    def post_dissection(self, pkt):
        """
        If the packet is not chunked set it as its own reassembled packet.
        """
        try:
            self.underlayer.reassembled = self
        except AttributeError:
            pass
        return pkt


class UaSecureConversationAsymmetric(UaTcp):
    """
    This class represents all SecureConversation chunks that may be asymmetrically secured.
    See specification part 6 v1.03 §6.7.2 for the chunk structure.
    
    Intermediate chunks are automatically reassembled if the final chunk is decoded.
    After decoding and reassembling the complete message is available in the reassembled attribute.
    """
    __slots__ = ["original_decrypted", "reassembled"]
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
    
    def __init__(self, _pkt=b"", connectionContext=None, post_transform=None, _internal=0, _underlayer=None, **fields):
        self.original_decrypted = None
        self.reassembled = None
        super(UaSecureConversationAsymmetric, self).__init__(_pkt, connectionContext, post_transform, _internal,
                                                             _underlayer, **fields)
    
    def copy(self):
        pkt = super(UaSecureConversationAsymmetric, self).copy()
        pkt.original_decrypted = self.original_decrypted
        pkt.reassembled = self.reassembled
        return pkt
    
    def clone_with(self, payload=None, **kargs):
        pkt = super(UaSecureConversationAsymmetric, self).clone_with(payload, **kargs)
        pkt.original_decrypted = self.original_decrypted
        pkt.reassembled = self.reassembled
        return pkt
    
    def _get_type_binary(self):
        if isinstance(self.SecurityHeader, UaAsymmetricAlgorithmSecurityHeader):
            typeBinary = b'OPN'
        elif isinstance(self.SecurityHeader, UaSymmetricAlgorithmSecurityHeader):
            if isinstance(self.Payload.Message, (UaCloseSecureChannelRequest, UaCloseSecureChannelResponse)):
                typeBinary = b'CLO'
            elif isinstance(self.Payload, UaChunkedData) and self.Payload.isCLO:
                typeBinary = b'CLO'
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
        """
        If not manually set the MessageType and MessageSize are automatically calculated.
        Afterwards the message is signed and encrypted according to the supplied cryptoModule.
        If no cryptoModule is supplied and the ConnectionContext is set, the chunk is secured
        with asymmetric algorithms
        
        :param str pkt: the current packet (built by self_build function)
        :param str pay: the packet payload (built by do_build_payload function)
        :param cryptoModule: the cryptoModule that is used to secure the chunk
        :return: a string of the packet with the payload
        """
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
        """
        Decrypts the message before it is decoded.
        If no cryptoModule is supplied and the ConnectionContext is set, the asymmetric cryptoModule is used.
        By default the security header is interpreted as the asymmetric header.
        If called by the symmetric class, the symmetric header needs to be passed.
        
        :param s: the raw packet.
        :param cryptoModule: the cryptoModule to use to decrypt the message.
        :param securityHeader: the asymmetric header of the message.
        :return: the decrypted packet.
        """
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
        
        self.original_decrypted = s
        return s
    
    def post_dissection(self, pkt):
        """
        After dissecting the packet and if it was a final chunk, it is reassembled and made available in the
        reassembled attribute.
        """
        if self.MessageHeader.IsFinal == b'F' and self.reassembled is None and self.connectionContext is not None:
            from scapy.contrib.opcua.binary.chunking import dechunkify
            self.reassembled = dechunkify(self.connectionContext.chunks[self.SequenceHeader.RequestId])
            del self.connectionContext.chunks[self.SequenceHeader.RequestId]
        return pkt
    
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaSecureConversationAsymmetric, cls).dispatch_hook(_pkt, args, kwargs)


class UaSecureConversationSymmetric(UaSecureConversationAsymmetric):
    """
    This class represents all SecureConversation chunks that may be symmetrically secured.
    See specification part 6 v1.03 §6.7.2 for the chunk structure.
    Intermediate chunks are automatically reassembled if the final chunk is decoded.
    After decoding and reassembling the complete message is available in the reassembled attribute.
    """
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
