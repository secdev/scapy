# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Sessions: decode flow of packets when sniffing
"""

from collections import defaultdict
import socket
import struct

from scapy.compat import raw, orb
from scapy.config import conf
from scapy.packet import NoPayload, Packet
from scapy.plist import PacketList
from scapy.pton_ntop import inet_pton

# Typing imports
from scapy.compat import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    List,
    Optional,
    Tuple,
    cast
)


class DefaultSession(object):
    """Default session: no stream decoding"""

    def __init__(
            self,
            prn=None,  # type: Optional[Callable[[Packet], Any]]
            store=False,  # type: bool
            supersession=None,  # type: Optional[DefaultSession]
            *args,  # type: Any
            **karg  # type: Any
    ):
        # type: (...) -> None
        self.__prn = prn
        self.__store = store
        self.lst = []  # type: List[Packet]
        self.__count = 0
        self._supersession = supersession
        if self._supersession:
            self._supersession.prn = self.__prn
            self._supersession.store = self.__store
            self.__store = False
            self.__prn = None

    @property
    def store(self):
        # type: () -> bool
        return self.__store

    @store.setter
    def store(self, val):
        # type: (bool) -> None
        if self._supersession:
            self._supersession.store = val
        else:
            self.__store = val

    @property
    def prn(self):
        # type: () -> Optional[Callable[[Packet], Any]]
        return self.__prn

    @prn.setter
    def prn(self, f):
        # type: (Optional[Any]) -> None
        if self._supersession:
            self._supersession.prn = f
        else:
            self.__prn = f

    @property
    def count(self):
        # type: () -> int
        if self._supersession:
            return self._supersession.count
        else:
            return self.__count

    def toPacketList(self):
        # type: () -> PacketList
        if self._supersession:
            return PacketList(self._supersession.lst, "Sniffed")
        else:
            return PacketList(self.lst, "Sniffed")

    def on_packet_received(self, pkt):
        # type: (Optional[Packet]) -> None
        """DEV: entry point. Will be called by sniff() for each
        received packet (that passes the filters).
        """
        if not pkt:
            return
        if not isinstance(pkt, Packet):
            raise TypeError("Only provide a Packet.")
        self.__count += 1
        if self.store:
            self.lst.append(pkt)
        if self.prn:
            result = self.prn(pkt)
            if result is not None:
                print(result)


class IPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.

    Usage:
    >>> sniff(session=IPSession)
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        DefaultSession.__init__(self, *args, **kwargs)
        self.fragments = defaultdict(list)  # type: DefaultDict[Tuple[Any, ...], List[Packet]]  # noqa: E501

    def _ip_process_packet(self, packet):
        # type: (Packet) -> Optional[Packet]
        from scapy.layers.inet import _defrag_list, IP
        if IP not in packet:
            return packet
        ip = packet[IP]
        packet._defrag_pos = 0
        if ip.frag != 0 or ip.flags.MF:
            uniq = (ip.id, ip.src, ip.dst, ip.proto)
            self.fragments[uniq].append(packet)
            if not ip.flags.MF:  # end of frag
                try:
                    if self.fragments[uniq][0].frag == 0:
                        # Has first fragment (otherwise ignore)
                        defrag = []  # type: List[Packet]
                        _defrag_list(self.fragments[uniq], defrag, [])
                        defragmented_packet = defrag[0]
                        defragmented_packet = defragmented_packet.__class__(
                            raw(defragmented_packet)
                        )
                        defragmented_packet.time = packet.time
                        return defragmented_packet
                finally:
                    del self.fragments[uniq]
            return None
        else:
            return packet

    def on_packet_received(self, pkt):
        # type: (Optional[Packet]) -> None
        if not pkt:
            return None
        super(IPSession, self).on_packet_received(self._ip_process_packet(pkt))


class StringBuffer(object):
    """StringBuffer is an object used to re-order data received during
    a TCP transmission.

    Each TCP fragment contains a sequence number, which marks
    (relatively to the first sequence number) the index of the data contained
    in the fragment.

    If a TCP fragment is missed, this class will fill the missing space with
    zeros.
    """

    def __init__(self):
        # type: () -> None
        self.content = bytearray(b"")
        self.content_len = 0
        self.incomplete = []  # type: List[Tuple[int, int]]

    def append(self, data, seq):
        # type: (bytes, int) -> None
        data_len = len(data)
        seq = seq - 1
        if seq + data_len > self.content_len:
            self.content += b"\x00" * (seq - self.content_len + data_len)
            # If data was missing, mark it.
            self.incomplete.append((self.content_len, seq))
            self.content_len = seq + data_len
            assert len(self.content) == self.content_len
        # XXX removes empty space marker.
        # for ifrag in self.incomplete:
        #     if [???]:
        #         self.incomplete.remove([???])
        memoryview(self.content)[seq:seq + data_len] = data

    def full(self):
        # type: () -> bool
        # Should only be true when all missing data was filled up,
        # (or there never was missing data)
        return True  # XXX

    def clear(self):
        # type: () -> None
        self.__init__()  # type: ignore

    def __bool__(self):
        # type: () -> bool
        return bool(self.content_len)
    __nonzero__ = __bool__

    def __len__(self):
        # type: () -> int
        return self.content_len

    def __bytes__(self):
        # type: () -> bytes
        return bytes(self.content)

    def __str__(self):
        # type: () -> str
        return cast(str, self.__bytes__())


class TCPSession(IPSession):
    """A Session that matches seq/ack packets together to dissect
    special protocols, such as HTTP.

    DEV: implement a class-function `tcp_reassemble` in your Packet class::

        @classmethod
        def tcp_reassemble(cls, data, metadata, session):
            # data = the reassembled data from the same request/flow
            # metadata = empty dictionary, that can be used to store data
            #            during TCP reassembly
            # session = a dictionary proper to the bidirectional TCP session,
            #           that can be used to store anything
            [...]
            # If the packet is available, return it. Otherwise don't.
            # Whenever you return a packet, the buffer will be discarded.
            return pkt
            # Otherwise, maybe store stuff in metadata, and return None,
            # as you need additional data.
            return None

    For more details and a real example, see:
    https://scapy.readthedocs.io/en/latest/usage.html#how-to-use-tcpsession-to-defragment-tcp-packets

    :param app: Whether the socket is on application layer = has no TCP
                layer. This is used for instance if you are using a native
                TCP socket. Default to False
    """

    def __init__(self, app=False, *args, **kwargs):
        # type: (bool, *Any, **Any) -> None
        super(TCPSession, self).__init__(*args, **kwargs)
        self.app = app
        if app:
            self.data = b""
            self.metadata = {}  # type: Dict[str, Any]
            self.session = {}  # type: Dict[str, Any]
        else:
            # The StringBuffer() is used to build a global
            # string from fragments and their seq nulber
            self.tcp_frags = defaultdict(
                lambda: (StringBuffer(), {})
            )  # type: DefaultDict[bytes, Tuple[StringBuffer, Dict[str, Any]]]
            self.tcp_sessions = defaultdict(
                dict
            )  # type: DefaultDict[bytes, Dict[str, Any]]

    def _get_ident(self, pkt, session=False):
        # type: (Packet, bool) -> bytes
        underlayer = pkt["TCP"].underlayer
        af = socket.AF_INET6 if "IPv6" in pkt else socket.AF_INET
        src = underlayer and inet_pton(af, underlayer.src) or b""
        dst = underlayer and inet_pton(af, underlayer.dst) or b""
        if session:
            # Bidirectional
            def xor(x, y):
                # type: (bytes, bytes) -> bytes
                return bytes(orb(a) ^ orb(b) for a, b in zip(x, y))
            return struct.pack("!4sH", xor(src, dst), pkt.dport ^ pkt.sport)
        else:
            # Uni-directional
            return src + dst + struct.pack("!HH", pkt.dport, pkt.sport)

    def _process_packet(self, pkt):
        # type: (Packet) -> Optional[Packet]
        """Process each packet: matches the TCP seq/ack numbers
        to follow the TCP streams, and orders the fragments.
        """
        if self.app:
            # Special mode: Application layer. Use on top of TCP
            pay_class = pkt.__class__
            if not hasattr(pay_class, "tcp_reassemble"):
                # Being on top of TCP, we have no way of knowing
                # when a packet ends.
                return pkt
            self.data += bytes(pkt)
            pkt = pay_class.tcp_reassemble(self.data, self.metadata, self.session)
            if pkt:
                self.data = b""
                self.metadata = {}
                return pkt
            return None

        from scapy.layers.inet import IP, TCP
        if not pkt or TCP not in pkt:
            return pkt
        pay = pkt[TCP].payload
        if isinstance(pay, (NoPayload, conf.padding_layer)):
            return pkt
        new_data = pay.original
        # Match packets by a unique TCP identifier
        seq = pkt[TCP].seq
        ident = self._get_ident(pkt)
        data, metadata = self.tcp_frags[ident]
        tcp_session = self.tcp_sessions[self._get_ident(pkt, True)]
        # Let's guess which class is going to be used
        if "pay_class" not in metadata:
            pay_class = pay.__class__
            if hasattr(pay_class, "tcp_reassemble"):
                tcp_reassemble = pay_class.tcp_reassemble
            else:
                # We can't know for sure when a packet ends.
                # Ignore.
                return pkt
            metadata["pay_class"] = pay_class
            metadata["tcp_reassemble"] = tcp_reassemble
        else:
            tcp_reassemble = metadata["tcp_reassemble"]
        if "seq" not in metadata:
            metadata["seq"] = seq
        # Get a relative sequence number for a storage purpose
        relative_seq = metadata.get("relative_seq", None)
        if relative_seq is None:
            relative_seq = metadata["relative_seq"] = seq - 1
        seq = seq - relative_seq
        # Add the data to the buffer
        # Note that this take care of retransmission packets.
        data.append(new_data, seq)
        # Check TCP FIN or TCP RESET
        if pkt[TCP].flags.F or pkt[TCP].flags.R:
            metadata["tcp_end"] = True

        # In case any app layer protocol requires it,
        # allow the parser to inspect TCP PSH flag
        if pkt[TCP].flags.P:
            metadata["tcp_psh"] = True
        # XXX TODO: check that no empty space is missing in the buffer.
        # XXX Currently, if a TCP fragment was missing, we won't notice it.
        packet = None  # type: Optional[Packet]
        if data.full():
            # Reassemble using all previous packets
            packet = tcp_reassemble(bytes(data), metadata, tcp_session)
        # Stack the result on top of the previous frames
        if packet:
            if "seq" in metadata:
                pkt[TCP].seq = metadata["seq"]
            # Clear buffer
            data.clear()
            # Clear TCP reassembly metadata
            metadata.clear()
            del self.tcp_frags[ident]
            # Rebuild resulting packet
            pay.underlayer.remove_payload()
            if IP in pkt:
                pkt[IP].len = None
                pkt[IP].chksum = None
            pkt = pkt / packet
            pkt.wirelen = None
            return pkt
        return None

    def on_packet_received(self, pkt):
        # type: (Optional[Packet]) -> None
        """Hook to the Sessions API: entry point of the dissection.
        This will defragment IP if necessary, then process to
        TCP reassembly.
        """
        if not pkt:
            return None
        # First, defragment IP if necessary
        pkt = self._ip_process_packet(pkt)
        if not pkt:
            return None
        # Now handle TCP reassembly
        pkt = self._process_packet(pkt)
        DefaultSession.on_packet_received(self, pkt)
