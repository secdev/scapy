# coding=utf-8
import timeit

from scapy.contrib.opcua.binary.bindings import *
from scapy.layers.inet import *
from scapy.contrib.opcua.binary.secureConversation import *
from scapy.contrib.opcua.binary.clientAutomaton import UaClient


def read_pcap():
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    return pc


if __name__ == '__main__':
    conf.debug_dissector = True

    client = UaClient()
    client.run()
