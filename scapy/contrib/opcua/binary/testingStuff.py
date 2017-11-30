# coding=utf-8

from scapy.contrib.opcua.binary.bindings import *
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.layers.inet import *
from scapy.contrib.opcua.binary.secureConversation import *

if __name__ == '__main__':
    conf.debug_dissector = True
    #test = UaBinary()/UaSecureConversation()

    #pc2 = rdpcap("/home/infinity/bachelor/pcaps/ipfragmented2.pcapng")
    #pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    #test = pc[9]

    test = UaSecureConversationSymmetric(DataTypeEncoding=UaFourByteNodeId(Identifier=42))
    test.show()
    test.show2()
    hexdump(test)
    print("\n" + repr(test.__str__()))
    print(repr(test))
