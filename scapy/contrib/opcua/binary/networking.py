# coding=utf-8
import copy

from scapy.contrib.opcua.crypto.securityPolicies import CryptographyNone
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
    
    if packet.connectionContext is not None \
            and packet.connectionContext.remoteBufferSizes.receiveBufferSize is not None:
        maxChunkSize = packet.connectionContext.remoteBufferSizes.receiveBufferSize
    
    headerSize = len(packet.MessageHeader) + len(packet.SecurityHeader)
    sequenceHeaderSize = len(packet.SequenceHeader)
    
    try:
        crypto = packet.connectionContext.securityPolicy.symmetric_cryptography
    except AttributeError:
        crypto = CryptographyNone()
    maxBodySize = max_body_size(crypto, maxChunkSize, headerSize, sequenceHeaderSize)

    if len(packet.Payload) < maxBodySize:
        yield packet
        return

    # Create carrier prototype which will be used for all chunks
    carrier = copy.deepcopy(packet)
    carrier.Payload = UaChunkedData()
    carrier.Payload.isCLO = isinstance(packet.Payload.Message, UaCloseSecureChannelRequest) or \
                            isinstance(packet.Payload.Message, UaCloseSecureChannelResponse)
    carrier.MessageHeader.IsFinal = b'C'
    
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
    """
    Reassembles the packets of one request. All supplied packets have to belong to the same request
    :param packets:
    :return:
    """
    if not packets:
        return None
    
    carrier = copy.deepcopy(packets[0])
    carrier.MessageHeader.IsFinal = b'F'
    data = b''
    requestId = carrier.SequenceHeader.RequestId
    
    for packet in packets:
        assert (requestId == packet.SequenceHeader.RequestId)
        data += packet.Payload.Message
    
    carrier.Payload = UaMessage(data)
    return carrier


def dechunkify_all(packets):
    """
    Tries to reassemble all supplied packets. The packet list may contain chunks from different requests.
    The reassembled packets are sorted by sequence number.
    :param packets:
    :return:
    """
    
    requests = defaultdict(list)
    
    for packet in packets:
        requestId = packet.SequenceHeader.RequestId
        
        if requestId not in requests:
            requests[requestId].append([])
        requests[requestId][-1].append(packet)
        if packet.MessageHeader.IsFinal == b'F':
            requests[requestId].append([])
    
    dechunked = [dechunkify(plist) for request in requests.values() for plist in request if plist]
    dechunked.sort(key=lambda pkt: pkt.SequenceHeader.SequenceNumber if pkt.SequenceHeader.SequenceNumber else 0)
    
    return dechunked
