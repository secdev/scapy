# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = TestSocket library for unit tests
# scapy.contrib.status = library

import time
import random
from socket import socket

from scapy.config import conf
from scapy.automaton import ObjectPipe, select_objects
from scapy.data import MTU
from scapy.packet import Packet
from scapy.error import Scapy_Exception
from scapy.compat import Optional, Type, Tuple, Any, List, cast
from scapy.supersocket import SuperSocket


open_test_sockets = list()  # type: List[TestSocket]


class TestSocket(SuperSocket):
    def __init__(self, basecls=None):
        # type: (Optional[Type[Packet]]) -> None
        global open_test_sockets
        super(TestSocket, self).__init__()
        self.basecls = basecls
        self.paired_sockets = list()  # type: List[TestSocket]
        self.closed = False
        self.ins = self.outs = cast(socket, ObjectPipe(name="TestSocket"))
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
        for s in self.paired_sockets:
            try:
                s.paired_sockets.remove(self)
            except (ValueError, AttributeError, TypeError):
                pass
        self.closed = True
        super(TestSocket, self).close()
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

    def __del__(self):
        # type: () -> None
        self.close()

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        return select_objects(sockets, remain)


class UnstableSocket(TestSocket):
    """
    This is an unstable socket which randomly fires exceptions or loses
    packets on recv.
    """

    def __init__(self, basecls=None):
        # type: (Optional[Type[Packet]]) -> None
        super(UnstableSocket, self).__init__(basecls)
        self.last_rx_was_error = False
        self.last_tx_was_error = False

    def send(self, x):
        # type: (Packet) -> int
        if not self.last_tx_was_error:
            if random.randint(0, 1000) == 42:
                self.last_tx_was_error = True
                print("SOCKET CLOSED")
                raise OSError("Socket closed")
        self.last_tx_was_error = False
        return super(UnstableSocket, self).send(x)

    def recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        if not self.last_rx_was_error:
            if random.randint(0, 1000) == 42:
                self.last_rx_was_error = True
                raise OSError("Socket closed")
            if random.randint(0, 1000) == 13:
                self.last_rx_was_error = True
                raise Scapy_Exception("Socket closed")
            if random.randint(0, 1000) == 7:
                self.last_rx_was_error = True
                raise ValueError("Socket closed")
            if random.randint(0, 1000) == 113:
                self.last_rx_was_error = True
                return None
        self.last_rx_was_error = False
        return super(UnstableSocket, self).recv(x)


def cleanup_testsockets():
    # type: () -> None
    """
    Helper function to remove TestSocket objects after a test
    """
    for sock in open_test_sockets:
        sock.close()
