# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

from __future__ import print_function
import socket
import subprocess

from scapy.libs.six.moves.queue import Queue, Empty
from scapy.automaton import ObjectPipe
from scapy.config import conf
from scapy.compat import raw
from scapy.interfaces import _GlobInterfaceType
from scapy.packet import Packet
from scapy.pipetool import Source, Drain, Sink
from scapy.utils import ContextManagerSubprocess, PcapReader, PcapWriter

from scapy.supersocket import SuperSocket
from scapy.compat import (
    Any,
    Callable,
    List,
    Optional,
    cast,
)


class SniffSource(Source):
    """Read packets from an interface and send them to low exit.

    .. code::

             +-----------+
          >>-|           |->>
             |           |
           >-|  [iface]--|->
             +-----------+

    If neither of the ``iface`` or ``socket`` parameters are specified, then
    Scapy will capture from the first network interface.

    :param iface: A layer 2 interface to sniff packets from. Mutually
                  exclusive with the ``socket`` parameter.
    :param filter: Packet filter to use while capturing. See ``L2listen``.
                   Not used with ``socket`` parameter.
    :param socket: A ``SuperSocket`` to sniff packets from.
    """

    def __init__(self,
                 iface=None,  # type: Optional[str]
                 filter=None,  # type: Optional[Any]
                 socket=None,  # type: Optional[SuperSocket]
                 name=None,  # type: Optional[Any]
                 ):
        # type: (...) -> None
        Source.__init__(self, name=name)

        if (iface or filter) and socket:
            raise ValueError("iface and filter options are mutually exclusive "
                             "with socket")

        self.s = cast(SuperSocket, socket)
        self.iface = iface
        self.filter = filter

    def start(self):
        # type: () -> None
        if not self.s:
            self.s = conf.L2listen(iface=self.iface, filter=self.filter)

    def stop(self):
        # type: () -> None
        if self.s:
            self.s.close()

    def fileno(self):
        # type: () -> int
        return self.s.fileno()

    def deliver(self):
        # type: () -> None
        try:
            pkt = self.s.recv()
            if pkt is not None:
                self._send(pkt)
        except EOFError:
            self.is_exhausted = True


class RdpcapSource(Source):
    """Read packets from a PCAP file send them to low exit.

    .. code::

         +----------+
      >>-|          |->>
         |          |
       >-|  [pcap]--|->
         +----------+
    """

    def __init__(self, fname, name=None):
        # type: (str, Optional[Any]) -> None
        Source.__init__(self, name=name)
        self.fname = fname
        self.f = PcapReader(self.fname)

    def start(self):
        # type: () -> None
        self.f = PcapReader(self.fname)
        self.is_exhausted = False

    def stop(self):
        # type: () -> None
        self.f.close()

    def fileno(self):
        # type: () -> int
        return self.f.fileno()

    def deliver(self):
        # type: () -> None
        try:
            p = self.f.recv()
            self._send(p)
        except EOFError:
            self.is_exhausted = True


class InjectSink(Sink):
    """Packets received on low input are injected to an interface

    .. code::

         +-----------+
      >>-|           |->>
         |           |
       >-|--[iface]  |->
         +-----------+
    """

    def __init__(self, iface=None, name=None):
        # type: (Optional[_GlobInterfaceType], Optional[str]) -> None
        Sink.__init__(self, name=name)
        if iface is None:
            iface = conf.iface
        self.iface = iface

    def start(self):
        # type: () -> None
        self.s = conf.L2socket(iface=self.iface)

    def stop(self):
        # type: () -> None
        self.s.close()

    def push(self, msg):
        # type: (Packet) -> None
        self.s.send(msg)


class Inject3Sink(InjectSink):
    def start(self):
        # type: () -> None
        self.s = conf.L3socket(iface=self.iface)


class WrpcapSink(Sink):
    """
    Writes :py:class:`Packet` on the low entry to a ``pcap`` file.
    Ignores all messages on the high entry.

    .. note::

        Due to limitations of the ``pcap`` format, all packets **must** be of
        the same link type. This class will not mutate packets to conform with
        the expected link type.

    .. code::

         +----------+
      >>-|          |->>
         |          |
       >-|--[pcap]  |->
         +----------+

    :param fname: Filename to write packets to.
    :type fname: str
    :param linktype: See :py:attr:`linktype`.
    :type linktype: None or int

    .. py:attribute:: linktype

        Set an explicit link-type (``DLT_``) for packets.  This must be an
        ``int`` or ``None``.

        This is the same as the :py:func:`wrpcap` ``linktype`` parameter.

        If ``None`` (the default), the linktype will be auto-detected on the
        first packet. This field will *not* be updated with the result of this
        auto-detection.

        This attribute has no effect after calling :py:meth:`PipeEngine.start`.
    """

    def __init__(self, fname, name=None, linktype=None):
        # type: (str, Optional[str], Optional[int]) -> None
        Sink.__init__(self, name=name)
        self.fname = fname
        self.f = None  # type: Optional[PcapWriter]
        self.linktype = linktype

    def start(self):
        # type: () -> None
        self.f = PcapWriter(self.fname, linktype=self.linktype)

    def stop(self):
        # type: () -> None
        if self.f:
            self.f.flush()
            self.f.close()

    def push(self, msg):
        # type: (Packet) -> None
        if msg and self.f:
            self.f.write(msg)


class WiresharkSink(WrpcapSink):
    """
    Streams :py:class:`Packet` from the low entry to Wireshark.

    Packets are written into a ``pcap`` stream (like :py:class:`WrpcapSink`),
    and streamed to a new Wireshark process on its ``stdin``.

    Wireshark is run with the ``-ki -`` arguments, which cause it to treat
    ``stdin`` as a capture device.  Arguments in :py:attr:`args` will be
    appended after this.

    Extends :py:mod:`WrpcapSink`.

    .. code::

         +----------+
      >>-|          |->>
         |          |
       >-|--[pcap]  |->
         +----------+

    :param linktype: See :py:attr:`WrpcapSink.linktype`.
    :type linktype: None or int
    :param args: See :py:attr:`args`.
    :type args: None or list[str]

    .. py:attribute:: args

        Additional arguments for the Wireshark process.

        This must be either ``None`` (the default), or a ``list`` of ``str``.

        This attribute has no effect after calling :py:meth:`PipeEngine.start`.

        See :manpage:`wireshark(1)` for more details.
    """

    def __init__(self, name=None, linktype=None, args=None):
        # type: (Optional[Any], Optional[int], Optional[List[str]]) -> None
        WrpcapSink.__init__(self, fname="", name=name, linktype=linktype)
        self.args = args

    def start(self):
        # type: () -> None
        # Wireshark must be running first, because PcapWriter will block until
        # data has been read!
        with ContextManagerSubprocess(conf.prog.wireshark):
            args = [conf.prog.wireshark, "-Slki", "-"]
            if self.args:
                args.extend(self.args)

            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=None,
                stderr=None,
            )

        self.fname = proc.stdin  # type: ignore
        WrpcapSink.start(self)


class UDPDrain(Drain):
    """UDP payloads received on high entry are sent over UDP

    .. code::

         +-------------+
      >>-|--[payload]--|->>
         |      X      |
       >-|----[UDP]----|->
         +-------------+
    """

    def __init__(self, ip="127.0.0.1", port=1234):
        # type: (str, int) -> None
        Drain.__init__(self)
        self.ip = ip
        self.port = port

    def push(self, msg):
        # type: (Packet) -> None
        from scapy.layers.inet import IP, UDP
        if IP in msg and msg[IP].proto == 17 and UDP in msg:
            payload = msg[UDP].payload
            self._high_send(raw(payload))

    def high_push(self, msg):
        # type: (Packet) -> None
        from scapy.layers.inet import IP, UDP
        p = IP(dst=self.ip) / UDP(sport=1234, dport=self.port) / msg
        self._send(p)


class FDSourceSink(Source):
    """Use a file descriptor as source and sink

    .. code::

         +-------------+
      >>-|             |->>
         |             |
       >-|-[file desc]-|->
         +-------------+
    """

    def __init__(self, fd, name=None):
        # type: (ObjectPipe[Any], Optional[Any]) -> None
        Source.__init__(self, name=name)
        self.fd = fd

    def push(self, msg):
        # type: (str) -> None
        self.fd.write(msg)

    def fileno(self):
        # type: () -> int
        return self.fd.fileno()

    def deliver(self):
        # type: () -> None
        self._send(self.fd.read())


class TCPConnectPipe(Source):
    """TCP connect to addr:port and use it as source and sink

    .. code::

         +-------------+
      >>-|             |->>
         |             |
       >-|-[addr:port]-|->
         +-------------+
    """
    __selectable_force_select__ = True

    def __init__(self, addr="", port=0, name=None):
        # type: (str, int, Optional[str]) -> None
        Source.__init__(self, name=name)
        self.addr = addr
        self.port = port
        self.fd = cast(socket.socket, None)

    def start(self):
        # type: () -> None
        self.fd = socket.socket()
        self.fd.connect((self.addr, self.port))

    def stop(self):
        # type: () -> None
        if self.fd:
            self.fd.close()

    def push(self, msg):
        # type: (Packet) -> None
        self.fd.send(msg)

    def fileno(self):
        # type: () -> int
        return self.fd.fileno()

    def deliver(self):
        # type: () -> None
        try:
            msg = self.fd.recv(65536)
        except socket.error:
            self.stop()
            raise
        if msg:
            self._send(msg)


class TCPListenPipe(TCPConnectPipe):
    """TCP listen on [addr:]port and use first connection as source and sink;
    send peer address to high output

    .. code::

         +------^------+
      >>-|    +-[peer]-|->>
         |   /         |
       >-|-[addr:port]-|->
         +-------------+
    """
    __selectable_force_select__ = True

    def __init__(self, addr="", port=0, name=None):
        # type: (str, int, Optional[str]) -> None
        TCPConnectPipe.__init__(self, addr, port, name)
        self.connected = False
        self.q = Queue()

    def start(self):
        # type: () -> None
        self.connected = False
        self.fd = socket.socket()
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.fd.bind((self.addr, self.port))
        self.fd.listen(1)

    def push(self, msg):
        # type: (Packet) -> None
        if self.connected:
            self.fd.send(msg)
        else:
            self.q.put(msg)

    def deliver(self):
        # type: () -> None
        if self.connected:
            try:
                msg = self.fd.recv(65536)
            except socket.error:
                self.stop()
                raise
            if msg:
                self._send(msg)
        else:
            fd, frm = self.fd.accept()
            self._high_send(frm)
            self.fd.close()
            self.fd = fd
            self.connected = True
            self._trigger(frm)
            while True:
                try:
                    self.fd.send(self.q.get(block=False))
                except Empty:
                    break


class UDPClientPipe(TCPConnectPipe):
    """UDP send packets to addr:port and use it as source and sink
    Start trying to receive only once a packet has been send

    .. code::

         +-------------+
      >>-|             |->>
         |             |
       >-|-[addr:port]-|->
         +-------------+
    """

    def __init__(self, addr="", port=0, name=None):
        # type: (str, int, Optional[str]) -> None
        TCPConnectPipe.__init__(self, addr, port, name)
        self.connected = False

    def start(self):
        # type: () -> None
        self.fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.fd.connect((self.addr, self.port))
        self.connected = True

    def push(self, msg):
        # type: (Packet) -> None
        self.fd.send(msg)

    def deliver(self):
        # type: () -> None
        if not self.connected:
            return
        try:
            msg = self.fd.recv(65536)
        except socket.error:
            self.stop()
            raise
        if msg:
            self._send(msg)


class UDPServerPipe(TCPListenPipe):
    """UDP bind to [addr:]port and use as source and sink
    Use (ip, port) from first received IP packet as destination for all data

    .. code::

         +------^------+
      >>-|    +-[peer]-|->>
         |   /         |
       >-|-[addr:port]-|->
         +-------------+
    """

    def __init__(self, addr="", port=0, name=None):
        # type: (str, int, Optional[str]) -> None
        TCPListenPipe.__init__(self, addr, port, name)
        self._destination = None  # type: Any

    def start(self):
        # type: () -> None
        self.fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.fd.bind((self.addr, self.port))

    def push(self, msg):
        # type: (Packet) -> None
        if self._destination:
            self.fd.sendto(msg, self._destination)
        else:
            self.q.put(msg)

    def deliver(self):
        # type: () -> None
        if self._destination:
            try:
                msg = self.fd.recv(65536)
            except socket.error:
                self.stop()
                raise
            if msg:
                self._send(msg)
        else:
            msg, dest = self.fd.recvfrom(65536)
            if msg:
                self._send(msg)
            self._destination = dest
            self._trigger(dest)
            self._high_send(dest)
            while True:
                try:
                    msg = self.q.get(block=False)
                    self.fd.sendto(msg, self._destination)
                except Empty:
                    break


class TriggeredMessage(Drain):
    """Send a preloaded message when triggered and trigger in chain

    .. code::

         +------^------+
      >>-|      | /----|->>
         |      |/     |
       >-|-[ message ]-|->
         +------^------+
    """

    def __init__(self, msg, name=None):
        # type: (str, Optional[Any]) -> None
        Drain.__init__(self, name=name)
        self.msg = msg

    def on_trigger(self, trigmsg):
        # type: (bool) -> None
        self._send(self.msg)
        self._high_send(self.msg)
        self._trigger(trigmsg)


class TriggerDrain(Drain):
    """Pass messages and trigger when a condition is met

    .. code::

         +------^------+
      >>-|-[condition]-|->>
         |      |      |
       >-|-[condition]-|->
         +-------------+
    """

    def __init__(self, f, name=None):
        # type: (Callable[..., None], Optional[str]) -> None
        Drain.__init__(self, name=name)
        self.f = f

    def push(self, msg):
        # type: (str) -> None
        v = self.f(msg)
        if v:
            self._trigger(v)
        self._send(msg)

    def high_push(self, msg):
        # type: (str) -> None
        v = self.f(msg)
        if v:
            self._trigger(v)
        self._high_send(msg)


class TriggeredValve(Drain):
    """Let messages alternatively pass or not, changing on trigger

.. code::

         +------^------+
      >>-|-[pass/stop]-|->>
         |      |      |
       >-|-[pass/stop]-|->
         +------^------+
    """

    def __init__(self, start_state=True, name=None):
        # type: (bool, Optional[Any]) -> None
        Drain.__init__(self, name=name)
        self.opened = start_state

    def push(self, msg):
        # type: (str) -> None
        if self.opened:
            self._send(msg)

    def high_push(self, msg):
        # type: (str) -> None
        if self.opened:
            self._high_send(msg)

    def on_trigger(self, msg):
        # type: (bool) -> None
        self.opened ^= True
        self._trigger(msg)


class TriggeredQueueingValve(Drain):
    """Let messages alternatively pass or queued, changing on trigger

    .. code::

         +------^-------+
      >>-|-[pass/queue]-|->>
         |      |       |
       >-|-[pass/queue]-|->
         +------^-------+
    """

    def __init__(self, start_state=True, name=None):
        # type: (bool, Optional[Any]) -> None
        Drain.__init__(self, name=name)
        self.opened = start_state
        self.q = Queue()

    def start(self):
        # type: () -> None
        self.q = Queue()

    def push(self, msg):
        # type: (str) -> None
        if self.opened:
            self._send(msg)
        else:
            self.q.put((True, msg))

    def high_push(self, msg):
        # type: (str) -> None
        if self.opened:
            self._send(msg)
        else:
            self.q.put((False, msg))

    def on_trigger(self, msg):
        # type: (bool) -> None
        self.opened ^= True
        self._trigger(msg)
        while True:
            try:
                low, msg = self.q.get(block=False)
            except Empty:
                break
            else:
                if low:
                    self._send(msg)
                else:
                    self._high_send(msg)


class TriggeredSwitch(Drain):
    r"""Let messages alternatively high or low, changing on trigger

    .. code::

         +------^------+
      >>-|-\    |    /-|->>
         |  [up/down]  |
       >-|-/    |    \-|->
         +------^------+
    """

    def __init__(self, start_state=True, name=None):
        # type: (bool, Optional[Any]) -> None
        Drain.__init__(self, name=name)
        self.low = start_state

    def push(self, msg):
        # type: (str) -> None
        if self.low:
            self._send(msg)
        else:
            self._high_send(msg)
    high_push = push

    def on_trigger(self, msg):
        # type: (bool) -> None
        self.low ^= True
        self._trigger(msg)
