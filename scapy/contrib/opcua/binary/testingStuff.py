# coding=utf-8
import timeit

from scapy.contrib.opcua.binary.bindings import *
from scapy.layers.inet import *
from scapy.contrib.opcua.binary.secureConversation import *
from scapy.contrib.opcua.binary.clientAutomaton import UaClient
from scapy.contrib.opcua.binary.uaTypes import *
from scapy.contrib.opcua.crypto.securityPolicies import *
from scapy.contrib.opcua.crypto.uacrypto import *


def read_pcap():
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    return pc


if __name__ == '__main__':
    conf.debug_dissector = True
    
    server_cert = load_certificate("../crypto/server_cert.der")
    server_pk = load_private_key("../crypto/server_key.pem")
    # server_cert = load_certificate("../crypto/server_cert4096.der")
    # server_pk = load_private_key("../crypto/server_key4096.der")
    client_cert = load_certificate("../crypto/uaexpert.der")
    client_pk = load_private_key("../crypto/uaexpert_key.pem")
    
    policy = SecurityPolicyBasic128Rsa15(server_cert, server_pk, client_cert, client_pk, UaMessageSecurityMode.Sign)
    # policy = SecurityPolicy()
    
    # test = UaSecureConversationAsymmetric(securityPolicy=policy)
    # test = UaSecureConversationAsymmetric()
    # test = UaSecureConversationSymmetric()
    # print(bytes(test))
    #
    # test.show()
    # test.show2()
    
    # print(bytes(test))
    client = UaClient(securityPolicy=policy)
    client.run()
