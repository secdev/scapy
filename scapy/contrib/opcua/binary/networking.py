# coding=utf-8
import copy

from contrib.opcua.crypto.securityPolicies import CryptographyNone
from scapy.contrib.opcua.binary.tcp import *
from scapy.contrib.opcua.binary.secureConversation import *


def max_body_size(crypto, max_chunk_size, headerSize, sequenceHeaderSize):
    max_encrypted_size = max_chunk_size - headerSize
    max_plain_size = (max_encrypted_size // crypto.encrypted_block_size()) * crypto.plain_block_size()
    return max_plain_size - sequenceHeaderSize - crypto.signature_size() - crypto.min_padding_size()


def chunkify(packet, maxChunkSize=2048):
    if not isinstance(packet, UaSecureConversationSymmetric):
        raise TypeError("Invalid type to chunkify: {} "
                        "Only UaSecureConversationSymmetric can be chunked".format(type(packet)))
    
    if packet.connectionContext is not None and packet.connectionContext.localBufferSizes.maxMessageSize is not None:
        maxChunkSize = packet.connectionContext.localBufferSizes.sendBufferSize
    
    # Create carrier prototype which will be used for all chunks
    carrier = copy.deepcopy(packet)
    carrier.Payload = UaChunkedData()
    carrier.MessageHeader.IsFinal = b'C'
    headerSize = len(carrier.MessageHeader) + len(carrier.SecurityHeader)
    sequenceHeaderSize = len(carrier.SequenceHeader)
    
    try:
        crypto = packet.connectionContext.securityPolicy.symmetric_cryptography
    except AttributeError:
        crypto = CryptographyNone()
    maxBodySize = max_body_size(crypto, maxChunkSize, headerSize, sequenceHeaderSize)
    
    data = bytes(packet.Payload)
    while len(data) > maxBodySize:
        pkt = copy.deepcopy(carrier)
        pkt.Payload.Message = data[:maxBodySize]
        data = data[maxBodySize:]
        if carrier.SequenceHeader.SequenceNumber is not None:
            carrier.SequenceHeader.SequenceNumber += 1
        if not data:
            pkt.MessageHeader.IsFinal = b'F'
        yield pkt
    
    if data:
        pkt = copy.deepcopy(carrier)
        pkt.Payload.Message = data
        pkt.MessageHeader.IsFinal = b'F'
        yield pkt


def dechunkify(packets):
    pass
