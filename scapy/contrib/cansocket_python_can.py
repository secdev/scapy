# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = python-can CANSocket
# scapy.contrib.status = loads

"""
Python-CAN CANSocket Wrapper.
"""

import time
import struct
import threading

from functools import reduce
from operator import add

from scapy.config import conf
from scapy.supersocket import SuperSocket
from scapy.layers.can import CAN
from scapy.packet import Packet
from scapy.error import warning
from scapy.compat import List, Type, Tuple, Dict, Any, Optional, cast
from scapy.modules.six.moves import queue

from can import Message as can_Message
from can import CanError as can_CanError
from can import BusABC as can_BusABC
from can.interface import Bus as can_Bus

__all__ = ["CANSocket", "PythonCANSocket"]


class PriotizedCanMessage(object):
    """Helper object for comparison of CAN messages. If the timestamps of two
    messages are equal, the counter value of a priority counter, is used
    for comparison. It's only important that this priority counter always
    get increased for every CAN message in the receive heapq. This compensates
    a low resolution of `time.time()` on some operating systems.
    """
    def __init__(self, msg, count):
        # type: (can_Message, int) -> None
        self.msg = msg
        self.count = count

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, PriotizedCanMessage):
            return False
        return self.msg.timestamp == other.msg.timestamp and \
            self.count == other.count

    def __lt__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, PriotizedCanMessage):
            return False
        return self.msg.timestamp < other.msg.timestamp or \
            (self.msg.timestamp == other.msg.timestamp and
             self.count < other.count)

    def __le__(self, other):
        # type: (Any) -> bool
        return self == other or self < other

    def __gt__(self, other):
        # type: (Any) -> bool
        return not self <= other

    def __ge__(self, other):
        # type: (Any) -> bool
        return not self < other


class SocketMapper:
    """Internal Helper class to map a python-can bus object to
    a list of SocketWrapper instances
    """
    def __init__(self, bus, sockets):
        # type: (can_BusABC, List[SocketWrapper]) -> None
        """Initializes the SocketMapper helper class

        :param bus: A python-can Bus object
        :param sockets: A list of SocketWrapper objects which want to receive
                        messages from the provided python-can Bus object.
        """
        self.bus = bus
        self.sockets = sockets

    def mux(self):
        # type: () -> None
        """Multiplexer function. Tries to receive from its python-can bus
        object. If a message is received, this message gets forwarded to
        all receive queues of the SocketWrapper objects.
        """
        while True:
            prio_count = 0
            try:
                msg = self.bus.recv(timeout=0)
                if msg is None:
                    return
                for sock in self.sockets:
                    if sock._matches_filters(msg):
                        prio_count += 1
                        sock.rx_queue.put(PriotizedCanMessage(msg, prio_count))
            except Exception as e:
                warning("[MUX] python-can exception caught: %s" % e)


class _SocketsPool(object):
    """Helper class to organize all SocketWrapper and SocketMapper objects"""
    def __init__(self):
        # type: () -> None
        self.pool = dict()  # type: Dict[str, SocketMapper]
        self.pool_mutex = threading.Lock()

    def internal_send(self, sender, msg, prio=0):
        # type: (SocketWrapper, can_Message, int) -> None
        """Internal send function.

        A given SocketWrapper wants to send a CAN message. The python-can
        Bus object is obtained from an internal pool of SocketMapper objects.
        The given message is sent on the python-can Bus object and also
        inserted into the message queues of all other SocketWrapper objects
        which are connected to the same python-can bus object
        by the SocketMapper.

        :param sender: SocketWrapper which initiated a send of a CAN message
        :param msg: CAN message to be sent
        :param prio: Priority count for internal heapq
        """
        if sender.name is None:
            raise TypeError("SocketWrapper.name should never be None")

        with self.pool_mutex:
            try:
                mapper = self.pool[sender.name]
                mapper.bus.send(msg)
                for sock in mapper.sockets:
                    if sock == sender:
                        continue
                    if not sock._matches_filters(msg):
                        continue

                    sock.rx_queue.put(PriotizedCanMessage(msg, prio))
            except KeyError:
                warning("[SND] Socket %s not found in pool" % sender.name)
            except can_CanError as e:
                warning("[SND] python-can exception caught: %s" % e)

    def multiplex_rx_packets(self):
        # type: () -> None
        """This calls the mux() function of all SocketMapper
        objects in this SocketPool
        """
        with self.pool_mutex:
            for _, t in self.pool.items():
                t.mux()

    def register(self, socket, *args, **kwargs):
        # type: (SocketWrapper, Tuple[Any, ...], Dict[str, Any]) -> None
        """Registers a SocketWrapper object. Every SocketWrapper describes to
        a python-can bus object. This python-can bus object can only exist
        once. In case this object already exists in this SocketsPool, organized
        by a SocketMapper object, the new SocketWrapper is inserted in the
        list of subscribers of the SocketMapper. Otherwise a new python-can
        Bus object is created from the provided args and kwargs and inserted,
        encapsulated in a SocketMapper, into this SocketsPool.

        :param socket: SocketWrapper object which needs to be registered.
        :param args: Arguments for the python-can Bus object
        :param kwargs: Keyword arguments for the python-can Bus object
        """
        k = str(kwargs.get("bustype", "unknown_bustype")) + "_" + \
            str(kwargs.get("channel", "unknown_channel"))
        with self.pool_mutex:
            if k in self.pool:
                t = self.pool[k]
                t.sockets.append(socket)
                filters = [s.filters for s in t.sockets
                           if s.filters is not None]
                if filters:
                    t.bus.set_filters(reduce(add, filters))
                socket.name = k
            else:
                bus = can_Bus(*args, **kwargs)
                socket.name = k
                self.pool[k] = SocketMapper(bus, [socket])

    def unregister(self, socket):
        # type: (SocketWrapper) -> None
        """Unregisters a SocketWrapper from its subscription to a SocketMapper.

        If a SocketMapper doesn't have any subscribers, the python-can Bus
        get shutdown.

        :param socket: SocketWrapper to be unregistered
        """
        if socket.name is None:
            raise TypeError("SocketWrapper.name should never be None")

        with self.pool_mutex:
            try:
                t = self.pool[socket.name]
                t.sockets.remove(socket)
                if not t.sockets:
                    t.bus.shutdown()
                    del self.pool[socket.name]
            except KeyError:
                warning("Socket %s already removed from pool" % socket.name)


SocketsPool = _SocketsPool()


class SocketWrapper(can_BusABC):
    """Helper class to wrap a python-can Bus object as socket"""

    def __init__(self, *args, **kwargs):
        # type: (Tuple[Any, ...], Dict[str, Any]) -> None
        """Initializes a new python-can based socket, described by the provided
        arguments and keyword arguments. This SocketWrapper gets automatically
        registered in the SocketsPool.

        :param args: Arguments for the python-can Bus object
        :param kwargs: Keyword arguments for the python-can Bus object
        """
        super(SocketWrapper, self).__init__(*args, **kwargs)
        self.rx_queue = queue.PriorityQueue()  # type: queue.PriorityQueue[PriotizedCanMessage]  # noqa: E501
        self.name = None  # type: Optional[str]
        self.prio_counter = 0
        SocketsPool.register(self, *args, **kwargs)

    def _recv_internal(self, timeout):
        # type: (int) -> Tuple[Optional[can_Message], bool]
        """Internal blocking receive method,
        following the ``can_BusABC`` interface of python-can.

        This triggers the multiplex function of the general SocketsPool.

        :param timeout: Time to wait for a packet
        :return: Returns a tuple of either a can_Message or None and a bool to
                 indicate if filtering was already applied.
        """
        SocketsPool.multiplex_rx_packets()
        try:
            pm = self.rx_queue.get(block=True, timeout=timeout)
            return pm.msg, True
        except queue.Empty:
            return None, True

    def send(self, msg, timeout=None):
        # type: (can_Message, Optional[int]) -> None
        """Send function, following the ``can_BusABC`` interface of python-can.

        :param msg: Message to be sent.
        :param timeout: Not used.
        """
        self.prio_counter += 1
        SocketsPool.internal_send(self, msg, self.prio_counter)

    def shutdown(self):
        # type: () -> None
        """Shutdown function, following the ``can_BusABC`` interface of
        python-can.
        """
        SocketsPool.unregister(self)


class PythonCANSocket(SuperSocket):
    """Initializes a python-can bus object as Scapy PythonCANSocket.

    All provided keyword arguments, except *basecls* are forwarded to
    the python-can can_Bus init function. For further details on python-can
    check: https://python-can.readthedocs.io/

    Example:
        >>> socket = PythonCANSocket(bustype='socketcan', channel='vcan0', bitrate=250000)
    """  # noqa: E501
    desc = "read/write packets at a given CAN interface " \
           "using a python-can bus object"
    nonblocking_socket = True

    def __init__(self, **kwargs):
        # type: (Dict[str, Any]) -> None

        self.basecls = None  # type: Optional[Type[Packet]]
        try:
            self.basecls = cast(Type[Packet], kwargs.pop("basecls"))
        except KeyError:
            self.basecls = CAN

        self.can_iface = SocketWrapper(**kwargs)

    def recv_raw(self, x=0xffff):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        msg = self.can_iface.recv()

        hdr = msg.is_extended_id << 31 | msg.is_remote_frame << 30 | \
            msg.is_error_frame << 29 | msg.arbitration_id

        if conf.contribs['CAN']['swap-bytes']:
            hdr = struct.unpack("<I", struct.pack(">I", hdr))[0]

        dlc = msg.dlc << 24
        pkt_data = struct.pack("!II", hdr, dlc) + bytes(msg.data)
        return self.basecls, pkt_data, msg.timestamp

    def send(self, x):
        # type: (Packet) -> int
        msg = can_Message(is_remote_frame=x.flags == 0x2,
                          is_extended_id=x.flags == 0x4,
                          is_error_frame=x.flags == 0x1,
                          arbitration_id=x.identifier,
                          dlc=x.length,
                          data=bytes(x)[8:])
        msg.timestamp = time.time()
        try:
            x.sent_time = msg.timestamp
        except AttributeError:
            pass
        self.can_iface.send(msg)
        return len(x)

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        """This function is called during sendrecv() routine to select
        the available sockets.

        :param sockets: an array of sockets that need to be selected
        :returns: an array of sockets that were selected and
            the function to be called next to get the packets (i.g. recv)
        """
        SocketsPool.multiplex_rx_packets()
        return [s for s in sockets if isinstance(s, PythonCANSocket) and
                not s.can_iface.rx_queue.empty()]

    def close(self):
        # type: () -> None
        """Closes this socket"""
        if self.closed:
            return
        super(PythonCANSocket, self).close()
        self.can_iface.shutdown()


CANSocket = PythonCANSocket
