# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = TestSocket library for unit tests
# scapy.contrib.status = library

import time
import random

from socket import socket
from threading import Lock

from scapy.config import conf
from scapy.automaton import ObjectPipe, select_objects
from scapy.data import MTU
from scapy.packet import Packet
from scapy.error import Scapy_Exception
from scapy.compat import Optional, Type, Tuple, Any, List, cast
from scapy.supersocket import SuperSocket


open_test_sockets = list()  # type: List[TestSocket]


class TestSocket(SuperSocket):

    test_socket_mutex = Lock()

    def __init__(self,
                 basecls=None,  # type: Optional[Type[Packet]]
                 external_obj_pipe=None  # type: Optional[ObjectPipe[bytes]]
                 ):
        # type: (...) -> None
        global open_test_sockets
        self.basecls = basecls
        self.paired_sockets = list()  # type: List[TestSocket]
        self.ins = external_obj_pipe or ObjectPipe(name="TestSocket")  # type: ignore
        self._has_external_obj_pip = external_obj_pipe is not None
        self.outs = None
        open_test_sockets.append(self)

    def __enter__(self):
        # type: () -> TestSocket
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # type: (Optional[Type[BaseException]], Optional[BaseException], Optional[Any]) -> None  # noqa: E501
        """Close the socket"""
        self.close()

    def close(self):
        # type: () -> None
        global open_test_sockets

        if self.closed:
            return

        for s in self.paired_sockets:
            try:
                s.paired_sockets.remove(self)
            except (ValueError, AttributeError, TypeError):
                pass

        if not self._has_external_obj_pip:
            super(TestSocket, self).close()
        else:
            # We don't close external object pipes
            self.closed = True

        try:
            open_test_sockets.remove(self)
        except (ValueError, AttributeError, TypeError):
            pass

    def pair(self, sock):
        # type: (TestSocket) -> None
        self.paired_sockets += [sock]
        sock.paired_sockets += [self]

    def send(self, x):
        # type: (Packet) -> int
        sx = bytes(x)
        for r in self.paired_sockets:
            r.ins.send(sx)
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        return len(sx)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        return self.basecls, self.ins.recv(0), time.time()

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        return select_objects(sockets, remain)


class UnstableSocket(TestSocket):
    """
    This is an unstable socket which randomly fires exceptions or loses
    packets on recv.
    """

    def __init__(self,
                 basecls=None,  # type: Optional[Type[Packet]]
                 external_obj_pipe=None  # type: Optional[ObjectPipe[bytes]]
                 ):
        # type: (...) -> None
        super(UnstableSocket, self).__init__(basecls, external_obj_pipe)
        self.no_error_for_x_rx_pkts = 10
        self.no_error_for_x_tx_pkts = 10

    def send(self, x):
        # type: (Packet) -> int
        if self.no_error_for_x_tx_pkts == 0:
            if random.randint(0, 1000) == 42:
                self.no_error_for_x_tx_pkts = 10
                print("SOCKET CLOSED")
                raise OSError("Socket closed")
        if self.no_error_for_x_tx_pkts > 0:
            self.no_error_for_x_tx_pkts -= 1
        return super(UnstableSocket, self).send(x)

    def recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        if self.no_error_for_x_tx_pkts == 0:
            if random.randint(0, 1000) == 42:
                self.no_error_for_x_tx_pkts = 10
                raise OSError("Socket closed")
            if random.randint(0, 1000) == 13:
                self.no_error_for_x_tx_pkts = 10
                raise Scapy_Exception("Socket closed")
            if random.randint(0, 1000) == 7:
                self.no_error_for_x_tx_pkts = 10
                raise ValueError("Socket closed")
            if random.randint(0, 1000) == 113:
                self.no_error_for_x_tx_pkts = 10
                return None
        if self.no_error_for_x_tx_pkts > 0:
            self.no_error_for_x_tx_pkts -= 1
        return super(UnstableSocket, self).recv(x)


def cleanup_testsockets():
    # type: () -> None
    """
    Helper function to remove TestSocket objects after a test
    """
    count = max(len(open_test_sockets), 1)
    while len(open_test_sockets) and count:
        sock = open_test_sockets[0]
        sock.close()
        count -= 1
