# coding=utf-8
import logging

logging.getLogger("scapy").setLevel(logging.INFO)
from scapy.contrib.opcua.binary.bindings import *
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.layers.inet import *
from scapy.contrib.opcua.binary.secureConversation import *
from scapy.contrib.opcua.binary.schemaTypes import *


class TestPLF(Packet):
    fields_desc = [UaUInt32Field("len", None, count_of="plist"),
                   PacketListField("plist", None, UaExpandedNodeId, count_from=lambda pkt: pkt.len)]


if __name__ == '__main__':
    conf.debug_dissector = True
    # test = UaBinary()/UaSecureConversation()

    # pc2 = rdpcap("/home/infinity/bachelor/pcaps/ipfragmented2.pcapng")
    # pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    # test = pc[7]

    # test = UaSecureConversationSymmetric(DataTypeEncoding=UaExpandedNodeId(NamespaceUri=UaString(data="asdf")))
    # test = UaSecureConversationSymmetric(b"MSGF'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x82\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00asdf")
    # test = UaMethodNode()
    # test.show()
    # test.show2()
    # hexdump(test)
    # print("\n" + repr(test.__str__()))
    # print(repr(test))

    test = TestPLF(plist=[UaNodeId(), UaTwoByteNodeId(),
                          UaExpandedNodeId(NodeId=UaTwoByteNodeId(), NamespaceUri=UaString(data="lol"),
                                           ServerIndex=10)])
    test.show2()

    test2 = UaModifySubscriptionResponse()
    test2.show2()
