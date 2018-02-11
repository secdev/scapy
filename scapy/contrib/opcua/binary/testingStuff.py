# coding=utf-8

import logging
import sys

from scapy.contrib.opcua.helpers import UaConnectionContext

root = logging.getLogger()
root.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

from scapy.contrib.opcua.binary.tcpClient import ClientAutomaton, UaTcpSocket
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


client = ClientAutomaton(debug=5)
opn = UaSecureConversationAsymmetric()
# opn.Payload.Message.SecurityMode = 1

msg = UaSecureConversationSymmetric()
ep = UaGetEndpointsRequest()
msg.Payload.Message = ep
msg.Payload.Message.RequestHeader.AuditEntryId = UaString(data="A"*4017)

if __name__ == '__main__':
    server_cert = load_certificate("./crypto/server_cert.der")
    server_pk = load_private_key("./crypto/server_key.der")
    # server_cert = load_certificate("./crypto/server_cert4096.der")
    # server_pk = load_private_key("./crypto/server_key4096.der")
    client_cert = load_certificate("./crypto/uaexpert.der")
    client_pk = load_private_key("./crypto/uaexpert_key.pem")
    
    policy = SecurityPolicyBasic128Rsa15(server_cert, None, client_cert, client_pk, UaMessageSecurityMode.SignAndEncrypt)
    # policy.make_symmetric_key(b'aaa', b'bbb')
    connectionContext = UaConnectionContext()
    connectionContext.securityPolicy = policy
    
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
    
    # print(bytes(test))
    
    # client.runbg()
    # client.io.uatcp.send(opn)
    # client.io.uatcp.recv().show()
    
    s = UaTcpSocket(connectionContext)
    connectionContext.localNonce = create_nonce(connectionContext.securityPolicy.symmetric_key_size)
    opn.Payload.Message.ClientNonce = UaByteString(data=connectionContext.localNonce)
    for i in range(1, 3):
        s.connect()
        s.send(opn)
        rec = s.recv()
        rec.show()
        serverNonce = rec.Payload.Message.ServerNonce.data
        connectionContext.securityToken = rec.Payload.Message.SecurityToken
        connectionContext.securityPolicy.make_symmetric_key(connectionContext.localNonce, serverNonce)
        s.send(msg)
        resp = s.recv()
        resp.show()
        resp = s.recv()
        print(repr(resp.reassembled))
        
        print("\n\n\nRECEIVED")
        
        s.close()

    input("Press key")
    # interact(globals())
