# coding=utf-8
import socket

from contrib.opcua.binary.automaton import _UaAutomaton
from scapy.contrib.opcua.binary.tcp import UaTcpHelloMessage, UaTcp
from scapy.all import ATMT


class UaClient(_UaAutomaton):
    """
    This Automaton implements basic client functionality
    """
    def __init__(self, *args, **kargs):
        super(UaClient, self).__init__(*args, **kargs)
        self.target = "localhost"
        self.targetPort = 4840

    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def TCP_CONNECTED(self):
        pass

    @ATMT.state()
    def CONNECTED(self):
        pass

    @ATMT.state()
    def CONNECTING(self):
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
        raise self.TCP_CONNECTED()

    @ATMT.condition(TCP_CONNECTED)
    def connect(self):
        self.send(UaTcp(Message=UaTcpHelloMessage()))
        print("attempting to connect")
        raise self.CONNECTING()

    @ATMT.condition(CONNECTED)
    def disconnect(self):
        self.socket.close()
        raise self.TCP_DISCONNECTED()

    @ATMT.condition(TCP_DISCONNECTED)
    def end(self):
        raise self.END()

    def my_send(self, pkt):
        print(pkt)
        data = pkt.build()
        sent = 0
        while sent < len(data):
            part = self.socket.send(data[sent:])
            if part == 0:
                raise RuntimeError("Connection broke")
            sent += part
        self.socket.close()
        raise self.START()
