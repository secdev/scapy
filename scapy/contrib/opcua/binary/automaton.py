# coding=utf-8
import socket

from scapy.automaton import Automaton
import scapy.contrib.opcua.binary.types as UA


class _UaAutomaton(Automaton):

    def __init__(self, *args, **kargs):
        super(_UaAutomaton, self).__init__(*args, **kargs)
        self.socket = None

    def parse_args(self, debug=0, store=1, **kwargs):
        super(_UaAutomaton, self).parse_args(debug, store, **kwargs)

    def recv(self):
        len(UA.UaTcpMessageHeader())
        self.socket.recv()
        pass
