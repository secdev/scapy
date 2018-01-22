# coding=utf-8

# import logging
# import sys
#
#
# root = logging.getLogger()
# root.setLevel(logging.DEBUG)
# ch = logging.StreamHandler(sys.stdout)
# ch.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# ch.setFormatter(formatter)
# root.addHandler(ch)

from scapy.config import conf
conf.debug_dissector = True
# from scapy.contrib.opcua.binary.bindings import *
import scapy.contrib.opcua.binary.bindings
from scapy.layers.inet import rdpcap
# from scapy.contrib.opcua.binary.uaTypes import *
# from scapy.contrib.opcua.crypto.securityPolicies import *
# from scapy.contrib.opcua.crypto.uacrypto import *



def read_pcap():
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    return pc


if __name__ == '__main__':
    
    # server_cert = load_certificate("../crypto/server_cert.der")
    # server_pk = load_private_key("../crypto/server_key.pem")
    # server_cert = load_certificate("../crypto/server_cert4096.der")
    # server_pk = load_private_key("../crypto/server_key4096.der")
    # client_cert = load_certificate("../crypto/uaexpert.der")
    # client_pk = load_private_key("../crypto/uaexpert_key.pem")
    
    # policy = SecurityPolicyBasic128Rsa15(server_cert, server_pk, client_cert, client_pk, UaMessageSecurityMode.SignAndEncrypt)
    # policy.make_symmetric_key(b'aaa', b'bbb')
    # connectionContext = UaConnectionContext()
    # connectionContext.securityPolicy = policy
    
    pc = read_pcap()
    
    pc[23].show()
    
    # policy = SecurityPolicy()
    
    # test = UaSecureConversationAsymmetric(connectionContext=connectionContext)
    # test = UaSecureConversationAsymmetric()
    # msg = UaCreateSessionRequest()
    # msg.ClientCertificate = UaByteString(data="A"*10000)
    # test = UaSecureConversationSymmetric(Payload=UaMessage(Message=msg), connectionContext=connectionContext)
    # test2 = UaSecureConversationSymmetric(Payload=UaMessage(Message=msg))
    # test2.SequenceHeader.RequestId = 2
    # test2.SequenceHeader.SequenceNumber = 1
    # pkts = list(chunkify(test))
    # pkts += list(chunkify(test2))
    
    # for pkt in pkts:
    #     print(bytes(pkt))
    #     pkt.show2()
    
    # dechunked = dechunkify_all(pkts)
    #
    # for pkt in dechunked:
    #     pkt.show2()
    
    # test.show()
    # test.show2()
    
    # print(bytes(test))
    # client = UaClient(securityPolicy=policy)
    # client.run()
