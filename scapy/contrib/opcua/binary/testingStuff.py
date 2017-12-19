# coding=utf-8
import functools
import logging
import timeit

logging.getLogger("scapy").setLevel(logging.INFO)
from scapy.contrib.opcua.binary.bindings import *
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.layers.inet import *
from scapy.layers.all import *
from scapy.contrib.opcua.binary.secureConversation import *
from scapy.contrib.opcua.binary.schemaTypes import *


def read_pcap():
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng", 57)
    return pc


if __name__ == '__main__':
    conf.debug_dissector = True
    test = UaSecureConversationSymmetric()

    # pc2 = rdpcap("/home/infinity/bachelor/pcaps/ipfragmented2.pcapng")

    #pc = read_pcap()
    #test = pc[56]

    test.show()
    test.show2()
    print(repr(test.build()))
