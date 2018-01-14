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


class _UaAutomaton(Automaton):

    def __init__(self, *args, **kargs):
        super(_UaAutomaton, self).__init__(*args, **kargs)
        self.socket = None
        self.receivedPackets = queue.Queue()
        self.receiverThread = None
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.pktcount = 0

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
            read_sockets, _, _ = select.select([self.socket], [], [])
            if self.socket not in read_sockets:
                continue
            self.lock.acquire()
            header = self.socket.recv(headerLen)
            if not header:
                self.socket.close()
                self.socket = None
                self.logger.warning("TCP socket got disconnected")
                self.lock.release()
                return

            decodedHeader = UA.UaTcpMessageHeader(header)
            size = decodedHeader.MessageSize - headerLen

            body = self.socket.recv(size)
            if not body:
                self.logger.error("Could net receive body. expected {} bytes".format(size))
                self.lock.release()
                return
            pkt = UA.UaTcp(header + body)
            self.receivedPackets.put(pkt)
            self.lock.release()

    def my_send(self, pkt):
        self.pktcount += 1
        if not self.pktcount % 100:
            print(self.pktcount)
        self.lock.acquire()
        if self.socket is None:
            self.lock.release()
            raise self.START()
        data = bytes(pkt)
        #print(data)
        sent = 0
        try:
            while sent < len(data):
                part = self.socket.send(data[sent:])
                if part == 0:
                    raise RuntimeError("Connection broke")
                sent += part
        except BrokenPipeError as e:
            print(e)
            #self.lock.release()
            #raise self.START()
        self.lock.release()
