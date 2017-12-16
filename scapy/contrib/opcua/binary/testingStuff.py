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
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng", 40)
    return pc


if __name__ == '__main__':
    conf.debug_dissector = True
    # test = UaBinary()/UaSecureConversation()

    # pc2 = rdpcap("/home/infinity/bachelor/pcaps/ipfragmented2.pcapng")

    #pc = read_pcap()
    #test = pc[39]

    # test = UaSecureConversationSymmetric(DataTypeEncoding=UaExpandedNodeId(NamespaceUri=UaString(data="asdf")))
    # test = UaSecureConversationSymmetric(b"MSGF'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x82\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00asdf")
    # test = UaMethodNode()
    # test.show()
    # test.show2()
    # hexdump(test)
    # print("\n" + repr(test.__str__()))
    # print(repr(test))
    # msg = b'MSGFH\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00\n\x00\x00\x00\x01\x00\x16\x03\xf4\x11\x89\xfb\xd9H\xd3\x01\t\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00@\x7f@\x10\'\x00\x00\x01\x00\x00\x00'
    # print(msg[28:])
    # UaResponseHeader(msg[28:]).show2()
    # test = UaMessage(msg[24:])
    #bstr = bytearray.fromhex("525dd5fbd948d3010b0000000000000000ffffffff0000000100000001000000010000000001000000525dd5fbd948d3010100000001002b03011a000000010000000100000005062a000000ec1489fbd948d301ffffffffffffffffffffffff")
    #test = UaPublishResponse()
    #test.show()
    #test.show2()
    #print(repr(test.build()))
    testmsg = bytearray.fromhex("01003d03525dd5fbd948d3010b0000000000000000ffffffff0000000100000001000000010000000001000000525dd5fbd948d3010100000001002b03011a000000010000000100000005062a000000ec1489fbd948d301ffffffffffffffffffffffff")
    def to_time():
        UaMessage.dispatch_hook(testmsg)

    print(timeit.timeit(to_time, number=10000))
