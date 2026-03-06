# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = TestSocket library for unit tests
# scapy.contrib.status = library

import time
import random

from threading import Lock

from scapy.config import conf
from scapy.automaton import ObjectPipe, select_objects
from scapy.data import MTU
from scapy.packet import Packet
from scapy.error import Scapy_Exception

# Typing imports
from typing import (
    Optional,
    Type,
    Tuple,
    Any,
    List,
)
from scapy.supersocket import SuperSocket

from scapy.plist import (
    PacketList,
    SndRcvList,
)


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

    def sr(self, *args, **kargs):
        # type: (Any, Any) -> Tuple[SndRcvList, PacketList]
        """Send and Receive multiple packets
        """
        from scapy import sendrecv
        return sendrecv.sndrcv(self, *args, threaded=False, **kargs)

    def sr1(self, *args, **kargs):
        # type: (Any, Any) -> Optional[Packet]
        """Send one packet and receive one answer
        """
        from scapy import sendrecv
        ans = sendrecv.sndrcv(self, *args, threaded=False, **kargs)[0]  # type: SndRcvList
        if len(ans) > 0:
            pkt = ans[0][1]  # type: Packet
            return pkt
        else:
            return None

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

    def recv(self, x=MTU, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
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
        return super(UnstableSocket, self).recv(x, **kwargs)


class SlowTestSocket(TestSocket):
    """A TestSocket that simulates the mux/throttle behavior of
    PythonCANSocket on a slow serial interface (like slcan).

    Frames sent to this socket go into an intermediate serial buffer.
    They only become visible to recv()/select() after mux() moves
    them to the rx ObjectPipe.

    Key parameters model the real slcan timing bottleneck:
    - frame_delay: per-frame serial read time (~2-3ms on real slcan)
    - serial_timeout: blocking wait when serial buffer is empty.
      Real python-can slcan uses serial.Serial(timeout=0.1), so
      bus.recv(timeout=0) blocks for 100ms when buffer is empty.
    - read_time_limit: max time spent reading per mux call, matching
      SocketMapper.READ_BUS_TIME_LIMIT in production code.

    can_filters: Optional list of CAN identifiers for per-socket
    filtering.  When set, mux reads all frames but only delivers
    matching ones, like SocketMapper.distribute() + _matches_filters.
    """

    def __init__(self, basecls=None, frame_delay=0.0002,
                 mux_throttle=0.001, can_filters=None,
                 serial_timeout=0.0, read_time_limit=0.0,
                 interface_name="slcan"):
        # type: (Optional[Type[Packet]], float, float, Optional[List[int]], float, float, str) -> None  # noqa: E501
        """
        :param frame_delay: Simulated per-frame serial read time (seconds).
        :param mux_throttle: Minimum time between mux calls (default 1ms).
        :param can_filters: Optional list of CAN identifiers for filtering.
        :param serial_timeout: Time to block when serial buffer is empty
            (models python-can slcan serial.Serial(timeout=0.1)).
            Set to 0.1 to reproduce real slcan behavior.
        :param read_time_limit: Max time per mux read pass (seconds).
            Set to 0.02 to match SocketMapper.READ_BUS_TIME_LIMIT.
            When 0 (default), no time limit is applied.
        :param interface_name: Simulated interface name (default "slcan").
            Used in test descriptions to identify the adapter type.
        """
        super(SlowTestSocket, self).__init__(basecls)
        self.interface_name = interface_name
        from collections import deque
        self._serial_buffer = deque()  # type: deque[bytes]
        self._serial_lock = Lock()
        self._last_mux = 0.0
        self._frame_delay = frame_delay
        self._mux_throttle = mux_throttle
        self._can_filters = can_filters
        self._serial_timeout = serial_timeout
        self._read_time_limit = read_time_limit
        self._real_ins = self.ins
        self.ins = _SlowPipeWrapper(self)  # type: ignore[assignment]

    @staticmethod
    def _extract_can_id(frame):
        # type: (bytes) -> int
        """Extract CAN identifier from raw CAN frame bytes."""
        import struct
        if len(frame) < 4:
            return -1
        return int(struct.unpack('!I', frame[:4])[0] & 0x1FFFFFFF)

    def _mux(self):
        # type: () -> None
        """Move frames from serial buffer to rx ObjectPipe.

        Models the real PythonCANSocket read path:
        1. read_bus(): loop calling bus.recv(timeout=0) — each call
           takes frame_delay when data is available, or serial_timeout
           when the buffer is empty (modeling slcan serial timeout).
        2. distribute(): deliver matching frames to the ObjectPipe.

        With read_time_limit > 0, the read loop stops after that many
        seconds (matching SocketMapper.READ_BUS_TIME_LIMIT).
        """
        now = time.monotonic()
        if now - self._last_mux < self._mux_throttle:
            return

        # Phase 1: read_bus — read frames from serial buffer
        msgs = []
        deadline = time.monotonic() + self._read_time_limit \
            if self._read_time_limit > 0 else None
        while True:
            if self.closed:
                break
            with self._serial_lock:
                if self._serial_buffer:
                    frame = self._serial_buffer.popleft()
                else:
                    frame = None
            if frame is None:
                # Empty buffer: model the serial timeout blocking
                if self._serial_timeout > 0:
                    time.sleep(self._serial_timeout)
                break
            if self._frame_delay > 0:
                time.sleep(self._frame_delay)
            msgs.append(frame)
            if deadline and time.monotonic() >= deadline:
                break

        # Phase 2: distribute — apply per-socket filtering
        for frame in msgs:
            if self._can_filters is not None:
                can_id = self._extract_can_id(frame)
                if can_id not in self._can_filters:
                    continue
            self._real_ins.send(frame)

        self._last_mux = time.monotonic()

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Read from the rx ObjectPipe (populated by mux via select)."""
        return self.basecls, self._real_ins.recv(0), time.time()

    def send(self, x):
        # type: (Packet) -> int
        if self._frame_delay > 0:
            time.sleep(self._frame_delay)
        return super(SlowTestSocket, self).send(x)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        for s in sockets:
            if isinstance(s, SlowTestSocket):
                s._mux()
        return select_objects(sockets, remain)

    def close(self):
        # type: () -> None
        self.ins = self._real_ins
        super(SlowTestSocket, self).close()


class _SlowPipeWrapper:
    """Wrapper that intercepts send() to route into serial buffer."""
    def __init__(self, owner):
        # type: (SlowTestSocket) -> None
        self._owner = owner

    def send(self, data):
        # type: (bytes) -> None
        with self._owner._serial_lock:
            self._owner._serial_buffer.append(data)

    def recv(self, timeout=0):
        # type: (int) -> Optional[bytes]
        return self._owner._real_ins.recv(timeout)

    def fileno(self):
        # type: () -> int
        return self._owner._real_ins.fileno()

    def close(self):
        # type: () -> None
        self._owner._real_ins.close()

    @property
    def closed(self):
        # type: () -> bool
        return bool(self._owner._real_ins.closed)  # type: ignore[attr-defined]


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
