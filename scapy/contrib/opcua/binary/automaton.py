# coding=utf-8
"""
This module contains an automaton prototype with methods that are used by both the client and server automaton.
"""
import logging
import threading

import select
from time import sleep
from six.moves import queue
from scapy.automaton import Automaton
import scapy.contrib.opcua.binary.uaTypes as UA
from scapy.contrib.opcua.helpers import UaConnectionContext


class _UaAutomaton(Automaton):
    
    def parse_args(self, connectionContext=UaConnectionContext(), target="localhost",
                   targetPort=4840, debug=0, store=1, **kwargs):
        super(_UaAutomaton, self).parse_args(debug, store, **kwargs)
        self.target = target
        self.targetPort = targetPort
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.connectionContext = connectionContext
