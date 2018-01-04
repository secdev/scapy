# coding=utf-8

from scapy.all import Automaton, ATMT
from scapy.contrib.opcua.binary.tcp import UaTcpHelloMessage, UaTcp
import socket


class UaClient(Automaton):
    """
    This Automaton implements basic client functionality
    """
    def __init__(self, *args, **kargs):
        super(UaClient, self).__init__(*args, **kargs)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    def TCP_DISCONNECTED(self):
        pass

    @ATMT.state(final=1)
    def END(self):
        pass

    @ATMT.condition(START)
    def connectTCP(self):
        self.socket.connect((self.target, self.targetPort))
        raise self.TCP_CONNECTED()

    @ATMT.condition(TCP_CONNECTED)
    def connect(self):
        self.send(UaTcp(Message=UaTcpHelloMessage()))
        print("attempting to connect")
        raise self.CONNECTED()

    @ATMT.condition(CONNECTED)
    def disconnect(self):
        self.socket.close()
        raise self.TCP_DISCONNECTED()

    @ATMT.condition(TCP_DISCONNECTED)
    def end(self):
        raise self.END()

    def my_send(self, pkt):
        print(pkt)
        self.socket.send(pkt.build())
