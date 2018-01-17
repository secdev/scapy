# coding=utf-8
import copy

from scapy.contrib.opcua.binary.tcp import *
from scapy.contrib.opcua.binary.secureConversation import *


def chunkify(packet, maxMessageSize=2048):
    if not isinstance(packet, UaSecureConversationSymmetric):
        raise TypeError("Invalid type to chunkify: {} "
                        "Only UaSecureConversationSymmetric can be chunked".format(type(packet)))
    
    if packet.connectionContext is not None and packet.connectionContext.localBufferSizes.maxMessageSize is not None:
        maxMessageSize = packet.connectionContext.localBufferSizes.maxMessageSize
    
    # Create carrier prototype which will be used for all chunks
    carrier = copy.deepcopy(packet)
    carrier.Payload = UaChunkedData()
    carrier.MessageHeader.IsFinal = b'C'
    
    chunks = []
    data = bytes(packet.Payload)
    while len(data) > maxMessageSize:
        pkt = copy.deepcopy(carrier)
        pkt.Payload.Message = data[:maxMessageSize]
        chunks.append(pkt)
        data = data[maxMessageSize:]
    if data:
        pkt = copy.deepcopy(carrier)
        pkt.Payload.Message = data
        chunks.append(pkt)
    
    chunks[-1].MessageHeader.IsFinal = b'F'
    return chunks


def dechunkify(packets):
    pass
