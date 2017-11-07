from scapy.layers.opcua.types import UaBytesField, UaByteField, UaUInt32Field
from scapy.packet import Packet, Raw
from scapy.layers.inet import TCP, Ether, IP
from scapy.fields import *
from scapy.packet import bind_layers
from scapy.main import interact


class UaTcpMessageHeader(Packet):
    name = "OPC UA TCP MessageHeader"
    fields_desc = [UaBytesField("MessageType", 'HEL', 3),
                   UaByteField("Reserved", 'F'),
                   UaUInt32Field("MessageSize", 8)]


"""Wrapper class that looks at MessageType but doesn't modify the packet string while dissecting"""
class UaBinary(Packet):
    name = "UaBinary"

    fields_desc = []
    """
    def dissect(self, s):
        typeField = UaBytesField("MessageType", 'HEL', 3)
        self.message_type = typeField.m2i(self, s)

        self.do_dissect_payload(s)
    """

    def guess_payload_class(self, payload):
        typeField = UaBytesField("MessageType", 'HEL', 3)
        rest, val = typeField.getfield(self, payload)
        message_type = typeField.i2h(self, val)

        if message_type == 'HEL' or message_type == 'ACK' or message_type == 'ERR':
            return UaTcp
        elif message_type == 'OPN' or message_type == 'CLO' or message_type == 'MSG':
            return UaSecureConversation
        else:
            return self.default_payload_class(payload)


class UaTcp(Packet):
    name = "UaTcp"
    fields_desc = [PacketField("TcpMessageHeader", UaTcpMessageHeader(), UaTcpMessageHeader)]


class UaSecureConversation(Packet):
    name = "UaSecureConversation"
    fields_desc = [PacketField("MessageHeader", UaTcpMessageHeader(), UaTcpMessageHeader)]


# Bind standard ports
# TODO: Make better layer bindings that do not depend on port numbers.
# TODO: investigate if possible to determine from MessageType
bind_layers(TCP, UaBinary, dport=4840)
bind_layers(TCP, UaBinary, sport=4840)

if __name__ == '__main__':
    test = Ether()/IP()/TCP()/UaBinary()/UaTcp()

    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    pc[5].show()