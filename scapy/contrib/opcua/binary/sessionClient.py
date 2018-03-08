# coding=utf-8
import copy
import socket

import os
import threading
from time import sleep

from scapy.contrib.opcua.binary.secureConversationClient import UaSecureConversationSocket
from scapy.contrib.opcua.binary.automaton import _UaAutomaton
from scapy.automaton import ATMT, Automaton
from scapy.contrib.opcua.binary.uaTypes import *
from scapy.supersocket import SuperSocket
import scapy.contrib.opcua.binary.uaTypes as UA


class SessionAutomaton(_UaAutomaton):
    """
    This Automaton implements the ua secure conversation functionality.
    It can be used as part of an automaton that implements the Session layer.
    """
    
    def __init__(self, *args, **kwargs):
        super(SessionAutomaton, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)
    
    @ATMT.state(initial=1)
    def START(self):
        pass
    
    @ATMT.state()
    def CONNECTED(self):
        pass
    
    @ATMT.state()
    def ESTABLISHING_SESSION(self):
        pass
    
    @ATMT.state()
    def SESSION_ESTABLISHED(self):
        pass
    
    @ATMT.state()
    def ACTIVATING_SESSION(self):
        pass
    
    @ATMT.state()
    def SESSION_ACTIVATED(self):
        pass
    
    @ATMT.state()
    def CLOSING_SESSION(self):
        pass
    
    @ATMT.state()
    def SESSION_CLOSED(self):
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
        self.oi.uasess.send(None)
        self.oi.shutdown.send(None)
    
    @ATMT.condition(START)
    def connect(self):
        if self.send_sock is not None:
            self.send_sock.close()
        if self.send_sock is None:
            self.send_sock = UaSecureConversationSocket(connectionContext=self._connectionContext, target=self.target,
                                                        targetPort=self.targetPort, timeout=self._timeout)
        else:
            with self.send_sock.atmt.send_sock._openLock:
                self.send_sock = UaSecureConversationSocket(connectionContext=self._connectionContext,
                                                            target=self.target,
                                                            targetPort=self.targetPort, timeout=self._timeout)
        
        self.listen_sock = self.send_sock
        
        try:
            self.send_sock.connect()
            self.logger.debug("Connected")
        except socket.error and TimeoutError as e:
            self.logger.warning("TCP connection refused: {}".format(e))
            raise self.END()
        self.oi.shutdown.send("started")
        raise self.CONNECTED()
    
    @ATMT.condition(CONNECTED)
    def create_session(self):
        self.logger.debug("Sending CreateSession")
        
        createSession = UaCreateSessionRequest()
        msg = UaSecureConversationSymmetric(Payload=UaMessage(Message=createSession))
        
        self.send(msg)
        raise self.ESTABLISHING_SESSION()
    
    @ATMT.receive_condition(ESTABLISHING_SESSION)
    def receive_create_session_response(self, pkt):
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                pkt.MessageHeader.IsFinal != b'F':
            # Wait for final chunk
            raise self.ESTABLISHING_SESSION()
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                isinstance(pkt.reassembled.Message, UaCreateSessionResponse):
            self.logger.debug("Received CreateSessionResponse")
            
            self._connectionContext.authenticationToken = pkt.reassembled.Message.AuthenticationToken
            
            raise self.SESSION_ESTABLISHED()
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                isinstance(pkt.Payload.Message, UaServiceFault):
            self.logger.debug("Received ServiceFault: {}".format(pkt.Payload.Message))
            raise self.DISCONNECTING()
        elif type(pkt) is UaTcp and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.debug("Received ERR: {}".format(statusCodes[pkt.Message.Error]))
            raise self.DISCONNECTING()
        else:
            self.logger.debug("Unexpected message received")
            raise self.DISCONNECTING()
    
    @ATMT.condition(SESSION_ESTABLISHED)
    def activate_session(self):
        self.logger.debug("Sending ActivateSession")
        
        activateSession = UaActivateSessionRequest()
        msg = UaSecureConversationSymmetric(Payload=UaMessage(Message=activateSession))
        
        self.send(msg)
        raise self.ACTIVATING_SESSION()
    
    @ATMT.receive_condition(ACTIVATING_SESSION)
    def receive_activate_session_response(self, pkt):
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                pkt.MessageHeader.IsFinal != b'F':
            # Wait for final chunk
            raise self.ACTIVATING_SESSION()
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                isinstance(pkt.reassembled.Message, UaActivateSessionResponse):
            self.logger.debug("Received ActivateSessionResponse")
            
            raise self.SESSION_ACTIVATED()
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                isinstance(pkt.Payload.Message, UaServiceFault):
            self.logger.debug("Received ServiceFault: {}".format(pkt.Payload.Message))
            raise self.DISCONNECTING()
        elif type(pkt) is UaTcp and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.debug("Received ERR: {}".format(statusCodes[pkt.Message.Error]))
            raise self.DISCONNECTING()
        else:
            self.logger.debug("Unexpected message received")
            raise self.DISCONNECTING()
    
    @ATMT.condition(DISCONNECTING)
    def disconnect(self):
        self.send_sock.close()
        self.logger.debug("SecureConversation socket disconnected")
        raise self.DISCONNECTED()
    
    @ATMT.condition(DISCONNECTED)
    def end(self):
        raise self.END()
    
    @ATMT.receive_condition(SESSION_ACTIVATED, prio=1)
    def receive_response(self, pkt):
        self.oi.uasess.send(pkt)
        raise self.SESSION_ACTIVATED()
    
    @ATMT.receive_condition(SESSION_ACTIVATED, prio=0)
    def error_received(self, pkt):
        if type(pkt) is UaTcp and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.warning("ERR received: {}".format(statusCodes[pkt.Message.Error]))
        elif type(pkt) is UaSecureConversationSymmetric and \
                isinstance(pkt.Payload.Message, UaServiceFault):
            self.logger.warning("Received service fault. Ignoring... {}".format(pkt.Payload.Message))
        elif not isinstance(pkt, UaTcp):
            self.logger.warning("Unexpected message received... Closing connection")
    
    @ATMT.ioevent(SESSION_ACTIVATED, "uasess")
    def socket_send(self, fd):
        raise self.SESSION_ACTIVATED().action_parameters(fd.recv())
    
    @ATMT.ioevent(SESSION_ACTIVATED, "shutdown")
    def shutdown(self, fd):
        closeSession = UaCloseSessionRequest(DeleteSubscriptions=True)
        msg = UaSecureConversationSymmetric(Payload=UaMessage(Message=closeSession))
        self.send(msg)
        raise self.CLOSING_SESSION()
    
    @ATMT.receive_condition(CLOSING_SESSION)
    def receive_close_response(self, pkt):
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                pkt.MessageHeader.IsFinal != b'F':
            # Wait for final chunk
            raise self.CLOSING_SESSION()
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                isinstance(pkt.reassembled.Message, UaCloseSessionResponse):
            self.logger.debug("Received CloseSessionResponse")
        
            raise self.SESSION_CLOSED()
        if isinstance(pkt, UaSecureConversationSymmetric) and \
                isinstance(pkt.Payload.Message, UaServiceFault):
            self.logger.debug("Received ServiceFault: {}".format(pkt.Payload.Message))
        elif type(pkt) is UaTcp and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.debug("Received ERR: {}".format(statusCodes[pkt.Message.Error]))
        else:
            self.logger.debug("Unexpected message received")
        
        raise self.DISCONNECTING()
    
    @ATMT.condition(SESSION_CLOSED)
    def close(self):
        self.logger.debug("Disconnecting")
        raise self.DISCONNECTING()
    
    @ATMT.action(socket_send)
    def send_data(self, data):
        self.send(data)
    
    def my_send(self, pkt):
        try:
            pkt.Payload.Message.RequestHeader.AuthenticationToken = self._connectionContext.authenticationToken
        except AttributeError:
            pass
        self.send_sock.send(pkt)


class UaSessionSocket(SuperSocket):
    
    def __init__(self, connectionContext, target="localhost", targetPort=4840, endpoint="TODO", timeout=None):
        self.atmt = SessionAutomaton(connectionContext=connectionContext, target=target,
                                     targetPort=targetPort, timeout=timeout)
        self.open = False
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
    
    def send(self, data):
        if not self.open:
            self.logger.warning("Socket not open. No data sent.")
            return
        
        # HACK :-(
        self.atmt.send_sock.atmt.send_sock.atmt.send_sock._pending_sess_jobs.put(None)
        self.atmt.io.uasess.send(copy.deepcopy(data))
        self.atmt.send_sock.atmt.send_sock.atmt.send_sock._pending_sess_jobs.join()
        
    def recv(self, x=0):
        if not self.open:
            self.logger.warning("Socket not open. Cannot receive any data.")
            return None
        data = self.atmt.io.uasess.recv()
        if data is None:
            self.close()
        return data
    
    def fileno(self):
        return self.atmt.io.uasess.fileno()
    
    def connect(self):
        if not self.open:
            self.atmt.start()
            self.atmt.runbg()
            if self.atmt.io.shutdown.recv() is None:
                self.atmt.stop()
                raise TimeoutError()
            self.open = True
    
    def close(self):
        if self.open:
            self.atmt.stop()
            self.open = False
    
    def sr(self, *args, **kargs):
        raise NotImplementedError()
    
    def sr1(self, *args, **kargs):
        raise NotImplementedError()
    
    def sniff(self, *args, **kargs):
        raise NotImplementedError()
