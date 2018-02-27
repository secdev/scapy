# coding=utf-8
import socket

import os

from scapy.contrib.opcua.crypto.uacrypto import create_nonce
from scapy.contrib.opcua.binary.tcpClient import UaTcpSocket
from scapy.contrib.opcua.helpers import UaConnectionContext
from scapy.automaton import ATMT, Automaton
from scapy.contrib.opcua.binary.uaTypes import *
from scapy.supersocket import SuperSocket
import scapy.contrib.opcua.binary.uaTypes as UA


class SecureConversationAutomaton(Automaton):
    """
    This Automaton implements the ua tcp layer functionality.
    It can be used as part of an automaton that implements the SecureChannel layer.
    """
    
    def parse_args(self, connectionContext=UaConnectionContext(), target="localhost",
                   targetPort=4840, debug=0, store=1, **kwargs):
        super(SecureConversationAutomaton, self).parse_args(debug, store, **kwargs)
        self.target = target
        self.targetPort = targetPort
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.connectionContext = connectionContext
    
    @ATMT.state(initial=1)
    def START(self):
        pass
    
    @ATMT.state()
    def CONNECTED(self):
        pass
    
    @ATMT.state()
    def ESTABLISHING_SECURECHANNEL(self):
        pass
    
    @ATMT.state()
    def SECURECHANNEL_ESTABLISHED(self):
        pass
    
    @ATMT.state()
    def DISCONNECTING(self):
        pass
    
    @ATMT.state()
    def DISCONNECTED(self):
        pass
    
    @ATMT.state(final=1)
    def END(self):
        # Send None to signal that the socket is closed
        self.oi.uatcp.send(None)
    
    @ATMT.condition(START)
    def connect(self):
        self.send_sock = UaTcpSocket(connectionContext=self.connectionContext, target=self.target,
                                     targetPort=self.targetPort)
        self.listen_sock = self.send_sock
        
        try:
            self.send_sock.connect()
            self.logger.debug("Connected")
        except socket.error as e:
            self.logger.warning("TCP connection refused: {}".format(e))
            raise self.END()
        raise self.CONNECTED()
    
    @ATMT.condition(CONNECTED)
    def open_secure_channel(self):
        self.logger.debug("Sending OPN")
        
        opn = UaSecureConversationAsymmetric()
        self.connectionContext.localNonce = create_nonce(self.connectionContext.securityPolicy.symmetric_key_size)
        opn.Payload.Message.ClientNonce = UaByteString(data=self.connectionContext.localNonce)
        # TODO: Make configurable if nonce is randomly generated or not.
        
        self.send(opn)
        raise self.ESTABLISHING_SECURECHANNEL()
    
    @ATMT.receive_condition(ESTABLISHING_SECURECHANNEL)
    def receive_ack(self, pkt):
        if isinstance(pkt, UaSecureConversationAsymmetric) and \
                isinstance(pkt.Payload.Message, UaOpenSecureChannelResponse):
            self.logger.debug("Received OpenSecureChannelResponse")
            
            # pkt.Payload.Message.show()
            
            self.connectionContext.securityToken = pkt.Payload.Message.SecurityToken
            self.connectionContext.remoteNonce = pkt.Payload.Message.ServerNonce.data
            self.connectionContext.securityPolicy.make_symmetric_key(self.connectionContext.localNonce,
                                                                     self.connectionContext.remoteNonce)
            
            raise self.SECURECHANNEL_ESTABLISHED()
        if isinstance(pkt, UaSecureConversationAsymmetric) and \
                isinstance(pkt.Payload.Message, UaServiceFault):
            self.logger.debug("Received ServiceFault: {}".format(pkt.Payload.Message))
            raise self.DISCONNECTING()
        elif isinstance(pkt, UaTcp) and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.debug("Received ERR: {}".format(statusCodes[pkt.Message.Error]))
            raise self.DISCONNECTING()
        else:
            self.logger.debug("Unexpected message received")
            raise self.DISCONNECTING()
    
    """
    @ATMT.condition(TCP_DISCONNECTING)
    def tcp_disconnect(self):
        self.send_sock.close()
        self.logger.debug("TCP socket disconnected")
        raise self.TCP_DISCONNECTED()
    
    @ATMT.condition(TCP_DISCONNECTED)
    def end(self):
        raise self.END()
    
    """
    
    @ATMT.receive_condition(SECURECHANNEL_ESTABLISHED, prio=1)
    def receive_response(self, pkt):
        print("Receiving")
        self.oi.uasc.send(pkt)
        raise self.SECURECHANNEL_ESTABLISHED()
    
    @ATMT.receive_condition(SECURECHANNEL_ESTABLISHED, prio=0)
    def error_received(self, pkt):
        if type(pkt) is UaTcp and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.warning("ERR received: {} ... Closing connection".format(statusCodes[pkt.Message.Error]))
            raise self.DISCONNECTING()
        elif type(pkt) is UaSecureConversationSymmetric and \
                isinstance(pkt.Payload.Message, UaServiceFault):
            self.logger.warning("Received service fault. Ignoring... {}".format(pkt.Payload.Message))
        
        elif not isinstance(pkt, UaTcp):
            self.logger.warning("Unexpected message received... Closing connection")
            raise self.DISCONNECTING()
    
    @ATMT.ioevent(SECURECHANNEL_ESTABLISHED, "uasc")
    def socket_send(self, fd):
        raise self.SECURECHANNEL_ESTABLISHED().action_parameters(fd.recv())
    
    @ATMT.ioevent(CONNECTED, "shutdown")
    def shutdown(self, fd):
        raise self.DISCONNECTING()
    
    @ATMT.action(socket_send)
    def send_data(self, data):
        self.send(data)


class UaSecureConversationSocket(SuperSocket):
    
    def __init__(self, connectionContext, target="localhost", targetPort=4840, endpoint="TODO"):
        self.atmt = SecureConversationAutomaton(connectionContext=connectionContext, target=target,
                                                targetPort=targetPort)
        self.atmt.runbg()
        self.open = True
        self.logger = logging.getLogger(__name__)
    
    def send(self, data):
        if not self.open:
            self.logger.warning("Socket not open. No data sent.")
            return
        self.atmt.io.uasc.send(data)
    
    def recv(self, x=0):
        if not self.open:
            self.logger.warning("Socket not open. Cannot receive any data.")
            return None
        data = self.atmt.io.uasc.recv()
        if data is None:
            self.close()
        return data
    
    def fileno(self):
        raise NotImplementedError()
    
    def connect(self):
        if not self.open:
            self.atmt.start()
            self.atmt.runbg()
            self.open = True
    
    def close(self):
        # TODO: Stop gracefully
        if self.open:
            self.atmt.io.shutdown.send(None)
            self.atmt.stop()
            self.open = False
    
    def sr(self, *args, **kargs):
        raise NotImplementedError()
    
    def sr1(self, *args, **kargs):
        raise NotImplementedError()
    
    def sniff(self, *args, **kargs):
        raise NotImplementedError()
