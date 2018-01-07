# coding=utf-8
import socket

from contrib.opcua.binary.automaton import _UaAutomaton
from scapy.automaton import ATMT
from scapy.contrib.opcua.binary.uaTypes import *


class UaClient(_UaAutomaton):
    """
    This Automaton implements basic client functionality
    """
    def __init__(self, *args, **kargs):
        super(UaClient, self).__init__(*args, **kargs)
        self.pkt = None

    def parse_args(self, target="localhost", targetPort=4840, debug=0, store=1, **kwargs):
        super(UaClient, self).parse_args(debug, store, **kwargs)
        self.target = target
        self.targetPort = targetPort

    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def TCP_CONNECTED(self):
        pass

    @ATMT.state()
    def CONNECTING(self):
        pass

    @ATMT.state()
    def CONNECTED(self):
        pass

    @ATMT.state()
    def SECURE_CHANNEL_ESTABLISHING(self):
        pass

    @ATMT.state()
    def SECURE_CHANNEL_ESTABLISHED(self):
        pass

    @ATMT.state()
    def TCP_DISCONNECTING(self):
        pass

    @ATMT.state()
    def TCP_DISCONNECTED(self):
        pass

    @ATMT.state(final=1)
    def END(self):
        pass

    @ATMT.condition(START)
    def connectTCP(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.target, self.targetPort))
        self.start_receiving()
        raise self.TCP_CONNECTED()

    @ATMT.condition(TCP_CONNECTED)
    def connect(self):
        self.send(UaTcp(Message=UaTcpHelloMessage()))
        print("attempting to connect")
        raise self.CONNECTING()

    @ATMT.condition(CONNECTING)
    def receive_ack(self):
        pkt = self.recv()
        if isinstance(pkt, UaTcp) and isinstance(pkt.Message, UaTcpAcknowledgeMessage):
            raise self.CONNECTED()
        else:
            raise self.END()

    @ATMT.condition(CONNECTED)
    def open_secure_channel(self):
        message = UaMessage(Message=UaOpenSecureChannelRequest(SecurityMode=1))
        self.send(UaSecureConversationAsymmetric(Payload=message))
        print("attempting to open SecureChannel")
        raise self.SECURE_CHANNEL_ESTABLISHING()

    @ATMT.condition(SECURE_CHANNEL_ESTABLISHING)
    def receive_open_secure_channel_response(self):
        pkt = self.recv()
        if isinstance(pkt, UaSecureConversationAsymmetric) and \
                isinstance(pkt.Payload.Message, UaOpenSecureChannelResponse):
            print("securechannel established")
            raise self.SECURE_CHANNEL_ESTABLISHED()
        else:
            raise self.END()

    @ATMT.condition(TCP_DISCONNECTING)
    def tcp_disconnect(self):
        self.socket.close()
        raise self.TCP_DISCONNECTED()

    @ATMT.condition(TCP_DISCONNECTED)
    def end(self):
        raise self.END()

    def my_send(self, pkt):
        data = pkt.build()
        print(data)
        sent = 0
        while sent < len(data):
            part = self.socket.send(data[sent:])
            if part == 0:
                raise RuntimeError("Connection broke")
            sent += part
