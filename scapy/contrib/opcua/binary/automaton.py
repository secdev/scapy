# coding=utf-8
"""
This module contains an automaton prototype with methods that are used by both the client and server automaton.
"""
import logging
from scapy.automaton import Automaton, Message, _ATMT_Command, select_objects
from scapy.contrib.opcua.helpers import UaConnectionContext
import os


class _UaAutomaton(Automaton):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stopped = False
    
    def parse_args(self, connectionContext=UaConnectionContext(), target="localhost",
                   targetPort=4840, debug=0, store=False, **kwargs):
        super().parse_args(debug, store, **kwargs)
        self.target = target
        self.targetPort = targetPort
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.connectionContext = connectionContext
        self.send_sock_class = lambda **x: None
        self.recv_sock_class = lambda **x: None
    
    def __del__(self):
        if not self._stopped:
            super().__del__()
    
    def stop(self):
        """
        Stops the automaton.
        This method is overridden to make sure the automaton is ended in a graceful manner.
        This requires sending a message on the shutdown socket so that the automaton can
        perform the necessary steps to correctly close the connection.
        """
        self.io.shutdown.send(None)
        with self.started:
            # Flush command pipes
            while True:
                r = select_objects([self.cmdin, self.cmdout], 0)
                if not r:
                    break
                for fd in r:
                    fd.recv()
            self._close_sockets()
        self._stopped = True
    
    def _close_sockets(self):
        """
        Closes all sockets used by the automaton.
        The network sockets shall be closed by the automaton itself upon receiving the shutdown message.
        """
        for name in self.ionames:
            try:
                os.close(self.ioin[name].rd)
            except OSError:
                pass
            try:
                os.close(self.ioin[name].wr)
            except OSError:
                pass
            try:
                os.close(self.ioout[name].rd)
            except OSError:
                pass
            try:
                os.close(self.ioout[name].wr)
            except OSError:
                pass
        try:
            os.close(self.cmdin.wr)
        except OSError:
            pass
        try:
            os.close(self.cmdin.rd)
        except OSError:
            pass
        try:
            os.close(self.cmdout.wr)
        except OSError:
            pass
        try:
            os.close(self.cmdout.rd)
        except OSError:
            pass
