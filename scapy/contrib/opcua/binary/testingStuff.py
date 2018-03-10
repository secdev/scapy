# coding=utf-8

import logging
import sys
import timeit

import gc

from scapy.contrib.opcua.binary.sessionClient import UaSessionSocket
from scapy.contrib.opcua.binary.secureConversationClient import UaSecureConversationSocket
from scapy.contrib.opcua.helpers import UaConnectionContext

root = logging.getLogger()
root.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

from scapy.contrib.opcua.binary.tcpClient import UaTcpSocket
from scapy.config import conf
from scapy.main import interact

conf.debug_dissector = True
import scapy.contrib.opcua.binary.bindings
from scapy.layers.inet import rdpcap, TCP_client

from scapy.contrib.opcua.binary.uaTypes import *
from scapy.contrib.opcua.crypto.securityPolicies import *
from scapy.contrib.opcua.crypto.uacrypto import *


def read_pcap():
    pc = rdpcap("/home/infinity/bachelor/pcaps/open62541_example_client_server_policy_none.pcapng")
    return pc


hel = UaTcp(Message=UaTcpHelloMessage())
opn = UaSecureConversationAsymmetric()
# opn.Payload.Message.SecurityMode = 1

msg = UaSecureConversationSymmetric()
ep = UaGetEndpointsRequest()
msg.Payload.Message = ep
msg.Payload.Message.RequestHeader.AuditEntryId = UaString(data="A" * 4017)


def getContext():
    server_cert = load_certificate("./crypto/server_cert.der")
    server_pk = load_private_key("./crypto/server_key.pem")
    # server_cert = load_certificate("./crypto/server_cert4096.der")
    # server_pk = load_private_key("./crypto/server_key4096.der")
    client_cert = load_certificate("./crypto/uaexpert.der")
    client_pk = load_private_key("./crypto/uaexpert_key.pem")
    
    policy = SecurityPolicyBasic128Rsa15(server_cert, None, client_cert, client_pk,
                                         UaMessageSecurityMode.SignAndEncrypt)
    # policy.make_symmetric_key(b'aaa', b'bbb')
    connectionContext = UaConnectionContext()
    # connectionContext.securityPolicy = policy
    
    return connectionContext


def testTcpAutomaton():
    connectionContext = getContext()
    for i in range(0, 1000):
        s = UaTcpSocket(connectionContext)
        connectionContext.localNonce = create_nonce(connectionContext.securityPolicy.symmetric_key_size)
        opn.Payload.Message.ClientNonce = UaByteString(data=connectionContext.localNonce)
        s.connect()
        s.send(opn)
        rec = s.recv()
        # rec.show()
        serverNonce = rec.Payload.Message.ServerNonce.data
        connectionContext.securityToken = rec.Payload.Message.SecurityToken
        connectionContext.securityPolicy.make_symmetric_key(connectionContext.localNonce, serverNonce)
        s.send(msg)
        resp = s.recv()
        # resp.show()
        resp = s.recv()
        # print(repr(resp.reassembled))
        
        # print("\n\n\nRECEIVED")
        
        s.close()


def testSecureConvAutomaton():
    for _ in range(0, 1):
        connectionContext = getContext()
        s = UaSecureConversationSocket(connectionContext=connectionContext, target="172.16.101.41", targetPort=48010)
        s.connect()
        s.send(msg)
        resp = s.recv()
        print(resp.reassembled)
        # resp.show()
        resp = s.recv()
        # resp.show()
        resp.reassembled.show2()
        
        s.close()


def testReadRequest():
    connectionContext = getContext()
    s = UaSessionSocket(connectionContext=connectionContext, target="172.16.101.41", targetPort=48010)
    s.connect()
    
    idToRead = UaStringNodeId(Namespace=4,
                              Identifier=UaString(
                                  data="S7-1200-Station_1.isutest3-mark-sps.Programs.Referenzsignal.Signal"))
    
    rvId = UaReadValueId()
    rvId.NodeId = idToRead
    rvId.AttributeId = 0xd
    
    rr = UaReadRequest()
    rr.NodesToRead = [rvId]
    msg = UaSecureConversationSymmetric(Payload=UaMessage(Message=rr))
    
    s.send(msg)
    resp = s.recv()
    resp.reassembled.show()
    # resp.show()
    
    s.close()


if __name__ == '__main__':
    # pc = read_pcap()
    # pc[23].show()
    
    # policy = SecurityPolicy()
    
    # test = UaSecureConversationAsymmetric(connectionContext=connectionContext)
    # test = UaSecureConversationAsymmetric()
    # msg = UaCreateSessionRequest()
    # msg.ClientCertificate = UaByteString(data="A"*10000)
    # test = UaSecureConversationSymmetric(Payload=UaMessage(Message=msg), connectionContext=connectionContext)
    # test2 = UaSecureConversationSymmetric(Payload=UaMessage(Message=msg))
    
    # test.show()
    # test.show2()
    
    # testTcpAutomaton()
    # testSecureConvAutomaton()
    # testReadRequest()
    
    test = UaExpandedNodeId()
    test.NamespaceUri = UaString(data="test")
    test.show2()
    
    # input("Press key")
    # interact(globals())
    pass
