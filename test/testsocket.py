# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = TestSocket library for unit tests
# scapy.contrib.status = library

import time

from scapy.config import conf
import scapy.modules.six as six
from scapy.automaton import ObjectPipe, select_objects
from scapy.data import MTU
from scapy.packet import Packet
from scapy.plist import PacketList, SndRcvList
from scapy.compat import Optional, Type, Tuple, Any, List, cast
from scapy.supersocket import SuperSocket


open_test_sockets = list()  # type: List[TestSocket]


class TestSocket(ObjectPipe, object):
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
            super(TestSocket, r).send(sx)
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

    def recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        if six.PY3:
            return SuperSocket.recv(self, x)
        else:
            return SuperSocket.recv.im_func(self, x)

    def sr1(self, *args, **kargs):
        # type: (Any, Any) -> Optional[Packet]
        if six.PY3:
            return SuperSocket.sr1(self, *args, **kargs)
        else:
            return SuperSocket.sr1.im_func(self, *args, **kargs)

    def sr(self, *args, **kargs):
        # type: (Any, Any) -> Tuple[SndRcvList, PacketList]
        if six.PY3:
            return SuperSocket.sr(self, *args, **kargs)
        else:
            return SuperSocket.sr.im_func(self, *args, **kargs)

    def sniff(self, *args, **kargs):
        # type: (Any, Any) -> PacketList
        if six.PY3:
            return SuperSocket.sniff(self, *args, **kargs)
        else:
            return SuperSocket.sniff.im_func(self, *args, **kargs)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        sock = [s for s in sockets if isinstance(s, ObjectPipe) and
                not s._closed]
        return cast(List[SuperSocket], select_objects(sock, remain))


def cleanup_testsockets():
    # type: () -> None
    """
    Helper function to remove TestSocket objects after a test
    """
    global open_test_sockets
    for sock in open_test_sockets:
        sock.close()
        del sock
