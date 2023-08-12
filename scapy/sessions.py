# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Sessions: decode flow of packets when sniffing
"""

from collections import defaultdict
import socket
import struct

from scapy.compat import orb
from scapy.config import conf
from scapy.packet import NoPayload, Packet
from scapy.pton_ntop import inet_pton

# Typing imports
from typing import (
    Any,
    DefaultDict,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    cast,
    TYPE_CHECKING,
)
from scapy.compat import Self
if TYPE_CHECKING:
    from scapy.supersocket import SuperSocket


class DefaultSession(object):
    """Default session: no stream decoding"""

    def __init__(self, supersession: Optional[Self] = None):
        if supersession and not isinstance(supersession, DefaultSession):
            supersession = supersession()
        self.supersession = supersession

    def process(self, pkt: Packet) -> Optional[Packet]:
        """
        Called to pre-process the packet
        """
        # Optionally handle supersession
        if self.supersession:
            return self.supersession.process(pkt)
        return pkt

    def recv(self, sock: 'SuperSocket') -> Iterator[Packet]:
        """
        Will be called by sniff() to ask for a packet
        """
        pkt = sock.recv()
        if not pkt:
            return
        pkt = self.process(pkt)
        if pkt:
            yield pkt


class IPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.

    Usage:
    >>> sniff(session=IPSession)
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        DefaultSession.__init__(self, *args, **kwargs)
        self.fragments = defaultdict(list)  # type: DefaultDict[Tuple[Any, ...], List[Packet]]  # noqa: E501

    def process(self, packet: Packet) -> Optional[Packet]:
        from scapy.layers.inet import IP, _defrag_ip_pkt
        if IP not in packet:
            return packet
        return _defrag_ip_pkt(packet, self.fragments)[1]  # type: ignore


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
        self.noff = 0  # negative offset
        self.incomplete = []  # type: List[Tuple[int, int]]

    def append(self, data: bytes, seq: Optional[int] = None) -> None:
        data_len = len(data)
        if seq is None:
            seq = self.content_len
        seq = seq - 1 - self.noff
        if seq < 0:
            # Data is located before the start of the current buffer
            # (e.g. the first fragment was missing)
            self.content = bytearray(b"\x00" * (-seq)) + self.content
            self.content_len += (-seq)
            self.noff += seq
            seq = 0
        if seq + data_len > self.content_len:
            # Data is located after the end of the current buffer
            self.content += b"\x00" * (seq - self.content_len + data_len)
            # As data was missing, mark it.
            # self.incomplete.append((self.content_len, seq))
            self.content_len = seq + data_len
            assert len(self.content) == self.content_len
        # XXX removes empty space marker.
        # for ifrag in self.incomplete:
        #     if [???]:
        #         self.incomplete.remove([???])
        memoryview(self.content)[seq:seq + data_len] = data

    def shiftleft(self, i: int) -> None:
        self.content = self.content[i:]
        self.content_len -= i

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
            self.data = StringBuffer()
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
        # Setup stopping dissection condition
        from scapy.layers.inet import TCP
        self.stop_dissection_after = TCP

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

    def _strip_padding(self, pkt: Packet) -> Optional[bytes]:
        """Strip the packet of any padding, and return the padding.
        """
        pad = pkt.getlayer(conf.padding_layer)
        if pad is not None and pad.underlayer is not None:
            # strip padding
            del pad.underlayer.payload
            return cast(bytes, pad.load)
        return None

    def process(self, pkt: Packet) -> Optional[Packet]:
        """Process each packet: matches the TCP seq/ack numbers
        to follow the TCP streams, and orders the fragments.
        """
        _pkt = super(TCPSession, self).process(pkt)
        if pkt is None:
            return None
        else:  # Python 3.8 := would be nice
            pkt = cast(Packet, _pkt)
        packet = None  # type: Optional[Packet]
        if self.app:
            # Special mode: Application layer. Use on top of TCP
            pay_class = pkt.__class__
            if hasattr(pay_class, "tcp_reassemble"):
                tcp_reassemble = pay_class.tcp_reassemble
            else:
                # There is no tcp_reassemble. Just dissect the packet
                tcp_reassemble = lambda data, *_: pay_class(data)
            self.data.append(bytes(pkt))
            packet = tcp_reassemble(
                bytes(self.data),
                self.metadata,
                self.session
            )
            if packet:
                padding = self._strip_padding(packet)
                if padding:
                    # There is remaining data for the next payload.
                    self.data.shiftleft(len(self.data) - len(padding))
                else:
                    # No padding (data) left. Clear
                    self.data.clear()
                self.metadata.clear()
                return packet
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
            pay_class = pkt[TCP].guess_payload_class(new_data)
            if hasattr(pay_class, "tcp_reassemble"):
                tcp_reassemble = pay_class.tcp_reassemble
            else:
                # There is no tcp_reassemble. Just dissect the packet
                tcp_reassemble = lambda data, *_: pay_class(data)
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
        if data.full():
            # Reassemble using all previous packets
            metadata["original"] = pkt
            packet = tcp_reassemble(
                bytes(data),
                metadata,
                tcp_session
            )
        # Stack the result on top of the previous frames
        if packet:
            if "seq" in metadata:
                pkt[TCP].seq = metadata["seq"]
            # Clear TCP reassembly metadata
            metadata.clear()
            # Check for padding
            padding = self._strip_padding(packet)
            if padding:
                # There is remaining data for the next payload.
                full_length = data.content_len - len(padding)
                metadata["relative_seq"] = relative_seq + full_length
                data.shiftleft(full_length)
            else:
                # No padding (data) left. Clear
                data.clear()
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

    def recv(self, sock: 'SuperSocket') -> Iterator[Packet]:
        """
        Will be called by sniff() to ask for a packet
        """
        pkt = sock.recv(stop_dissection_after=self.stop_dissection_after)
        if not pkt:
            return None
        # Now handle TCP reassembly
        pkt = self.process(pkt)
        if pkt:
            yield pkt
