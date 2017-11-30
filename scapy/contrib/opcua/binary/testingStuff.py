# coding=utf-8

from scapy.layers.inet import *
from scapy.contrib.opcua.binary.bindings import *

class TestPacket(Packet):
    fields_desc = [IntField("mask", None),
                   ConditionalField(IntField("myFld", 42), lambda p: p.mask == 3)]

if __name__ == '__main__':
    conf.debug_dissector = True
    #test = UaBinary()/UaSecureConversation()

    #pc2 = rdpcap("/home/infinity/bachelor/pcaps/ipfragmented2.pcapng")
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    test = pc[7]

    #test = UaLocalizedText()
    test.show()
    test.show2()
    hexdump(test)
    print("\n" + repr(test.__str__()))
    print(repr(test))
