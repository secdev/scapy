# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license

from __future__ import absolute_import

import abc
from threading import Lock
import time
from scapy.modules.six.moves.queue import Queue, Empty

from scapy.compat import ABC, raw
from scapy.config import conf
from scapy.supersocket import SimpleSocket, SuperSocket


class Packetizer(ABC):
    """
    Packetizer defines an interface for the implementation of data-link layers.

    It contains some buffering semantics for handling incomplete data.

    """
    def __init__(self):
        self.buffer = bytearray()
        self.buffer_lock = Lock()

    def clear_buffer(self):
        """
        Clears the buffer.

        This will cause any partial packets to be discarded.

        If ``start`` is not set and a packet is in progress, a corrupted packet
        will be returned in the next callback.

        This method blocks while acquiring the buffer lock.
        """
        with self.buffer_lock:
            self.buffer = bytearray()

    def data_received(self, data):
        """
        Adds data to the decoding buffer, and starts processing it.

        This method blocks while acquiring the buffer lock.

        This method yields tuples of (frame_bytes, time) for every frame
        available.

        :param data: (bytes) data to append to the buffer.
        """
        with self.buffer_lock:
            self.buffer.extend(data)

            frame_length = self.find_end()
            while frame_length > -1:
                p = self.decode_frame(frame_length)
                del self.buffer[:frame_length]

                if p:
                    yield p, time.time()

                frame_length = self.find_end()

    @abc.abstractmethod
    def find_end(self):
        """Find the end of the first packet in the buffer (``self.buffer``).

        In the event of desynchronisation (a packet has been unexpectedly
        terminated), the partial packet must be counted.

        The returned value must include the length of any end-of-packet marker.

        :return: The length of the packet in the buffer (in bytes), or -1 if
                 there is no completed packet available.
        """
        return -1

    @abc.abstractmethod
    def decode_frame(self, length):
        """Gets the bytes for a single frame in the buffer (``self.buffer``).

        Any start or ending makers must be removed, and bytes must be
        unescaped.

        If the frame is invalid and should be skipped, return None.

        This is an internal method, and only be called by ``data_received``.

        :param length: The length of the frame.
        :return: The bytes of the frame.
        """
        pass

    @abc.abstractmethod
    def encode_frame(self, pkt):
        """Encodes frame bytes (or a Packet) for transmission on the stream.

        By default, this uses ``raw``.

        :param pkt: frame bytes, or a Packet
        :return: bytes that can be transmitted on the stream.
        """
        return raw(pkt)

    def make_socket(self, fd, packet_class=None, default_read_size=None):
        return PacketizerSocket(fd, self, packet_class, default_read_size)


class PacketizerSocket(SimpleSocket):
    """Wrapper for Packetizer that turns a file-like object into a SuperSocket.

    :param fd: The file-like object to wrap.
    :param packetizer: An implementation of Packetizer
    :param default_read_size: The default read size for recv, defaults to
                              256 bytes
    """
    def __init__(self, fd, packetizer, packet_class=None,
                 default_read_size=None):
        # This allows subclasses to pass "None" to accept our default.
        default_read_size = (default_read_size if default_read_size is not None
                             else 256)

        super(PacketizerSocket, self).__init__(fd, default_read_size)
        if not isinstance(packetizer, Packetizer):
            raise TypeError('packetizer must implement Packetizer interface')

        self.packet_class = packet_class or conf.raw_layer
        self.packetizer = packetizer
        self._packet_queue = Queue()

        self.promisc = True

    def recv_raw(self, x=None):
        try:
            pkt, ts = self._packet_queue.get_nowait()
            return self.packet_class, pkt, ts
        except Empty:
            # Well, looks like we need to do some work...
            pass

        # read some bytes
        for p in self.packetizer.data_received(self.ins.read(x)):
            self._packet_queue.put(p)

        # Do we have some packets now?
        try:
            pkt, ts = self._packet_queue.get_nowait()
            return self.packet_class, pkt, ts
        except Empty:
            return None, None, None

    def send(self, x):
        if not isinstance(x, self.packet_class):
            x = self.packet_class()/x

        sx = raw(x)
        if hasattr(x, 'sent_time'):
            x.sent_time = time.time()
        self.ins.write(self.packetizer.encode_frame(sx))

    def has_packets(self):
        """Returns True if there are packets already in the queue."""
        return not self._packet_queue.empty()

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # Before passing off to base select, see if we have anything ready in
        # a queue
        queued = [s for s in sockets
                  if isinstance(s, PacketizerSocket) and s.has_packets()]
        if queued:
            return queued, None

        return SuperSocket.select(sockets, remain)
