# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = TestSocket library for unit tests
# scapy.contrib.status = library

import time
import random

from scapy.config import conf
from scapy.automaton import ObjectPipe, select_objects
from scapy.data import MTU
from scapy.packet import Packet
from scapy.error import Scapy_Exception
from scapy.compat import Optional, Type, Tuple, Any, List, cast
from scapy.supersocket import SuperSocket


open_test_sockets = list()  # type: List[TestSocket]


class TestSocket(ObjectPipe[Packet], SuperSocket):
    nonblocking_socket = False  # type: bool

    def __init__(self, basecls=None):
        # type: (Optional[Type[Packet]]) -> None
        global open_test_sockets
        super(TestSocket, self).__init__()
        self.basecls = basecls
        self.paired_sockets = list()  # type: List[TestSocket]
        self.closed = False
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
        for s in self.paired_sockets:
            try:
                s.paired_sockets.remove(self)
            except ValueError:
                pass
        self.closed = True
        super(TestSocket, self).close()

    def pair(self, sock):
        # type: (TestSocket) -> None
        self.paired_sockets += [sock]
        sock.paired_sockets += [self]

    def send(self, x):
        # type: (Packet) -> int
        sx = bytes(x)
        for r in self.paired_sockets:
            super(TestSocket, r).send(sx)  # type: ignore
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        return len(sx)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        return self.basecls, \
            super(TestSocket, self).recv(), \
            time.time()

    def recv(self, x=MTU):  # type: ignore
        # type: (int) -> Optional[Packet]
        return SuperSocket.recv(self, x=x)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        sock = [s for s in sockets if isinstance(s, ObjectPipe) and
                not s._closed]
        return cast(List[SuperSocket], select_objects(sock, remain))


class UnstableSocket(TestSocket):
    """
    This is an unstable socket which randomly fires exceptions or loses
    packets on recv.
    """

    def recv(self, x=MTU):  # type: ignore
        # type: (int) -> Optional[Packet]
        if random.randint(0, 1000) == 42:
            raise OSError("Socket closed")
        if random.randint(0, 1000) == 13:
            raise Scapy_Exception("Socket closed")
        if random.randint(0, 1000) == 7:
            raise ValueError("Socket closed")
        if random.randint(0, 1000) == 113:
            return None
        return super(UnstableSocket, self).recv(x)


def cleanup_testsockets():
    # type: () -> None
    """
    Helper function to remove TestSocket objects after a test
    """
    global open_test_sockets
    for sock in open_test_sockets:
        sock.close()
        del sock
