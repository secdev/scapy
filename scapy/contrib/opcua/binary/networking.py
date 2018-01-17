# coding=utf-8
from scapy.contrib.opcua.binary.tcp import *
from scapy.contrib.opcua.binary.secureConversation import *


def chunkify(packet, maxChunkSize=2048):
    if not isinstance(packet, UaSecureConversationSymmetric):
        raise TypeError("Invalid type to chunkify: {} "
                        "Only UaSecureConversationSymmetric can be chunked".format(type(packet)))
    return [packet]


def dechunkify(packets):
    pass
