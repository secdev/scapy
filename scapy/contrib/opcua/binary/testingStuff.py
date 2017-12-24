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
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    return pc


if __name__ == '__main__':
    conf.debug_dissector = True

    # pc2 = rdpcap("/home/infinity/bachelor/pcaps/ipfragmented2.pcapng")

    pc = read_pcap()
    test = pc[56]

    #b = bytearray.fromhex(
    #    "c70c0000000100000002000000030000000400000005000000060000000700000008000000090000000a0000000b0000000c00000003000000020000000200000003000000")
    #test = UaVariant(b)
    test.show()
    test.show2()
    print(repr(test.build()))
