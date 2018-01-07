# coding=utf-8
"""
This module contains an automaton prototype with methods that are used by both the client and server automaton.
"""
import logging
import threading

from six.moves import queue
from scapy.automaton import Automaton
import scapy.contrib.opcua.binary.uaTypes as UA


class _UaAutomaton(Automaton):

    def __init__(self, *args, **kargs):
        super(_UaAutomaton, self).__init__(*args, **kargs)
        self.socket = None
        self.receivedPackets = queue.Queue()
        self.receiverThread = None
        self.logger = logging.getLogger(__name__)

    def parse_args(self, debug=0, store=1, **kwargs):
        super(_UaAutomaton, self).parse_args(debug, store, **kwargs)

    def recv(self):
        return self.receivedPackets.get()

    def start_receiving(self):
        self.receiverThread = threading.Thread(target=self._message_poll_thread)
        self.receiverThread.start()

    def _message_poll_thread(self):
        headerLen = len(UA.UaTcpMessageHeader())
        while True:
            header = self.socket.recv(headerLen)
            if not header:
                self.logger.warning("TCP socket got disconnected")
                return

            decodedHeader = UA.UaTcpMessageHeader(header)
            size = decodedHeader.MessageSize - headerLen

            body = self.socket.recv(size)
            if not body:
                self.logger.error("Could net receive body. expected {} bytes".format(size))
                return
            pkt = UA.UaTcp(header + body)
            self.receivedPackets.put(pkt)

