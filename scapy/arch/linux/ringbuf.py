# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Layer 2 sockets that carry their packets through a PACKET_MMAP ring buffer.

The kernel and the process share a ring of fixed size frames, mapped once, so
receiving a packet is a read out of memory rather than a recvfrom(), and
sending one a write followed by a send() that hands the filled frames over.

Only the creation of a packet socket asks for CAP_NET_RAW; mapping its rings,
binding, receiving and sending do not. A privileged program can therefore set
one up and pass it to an unprivileged Scapy over a UNIX socket, which then
sniffs and sends on it as if it had opened it itself::

    # in the privileged program
    sock = L2RingSocket(iface="eth0")
    sock.share(unix_socket)

    # in Scapy, without privileges
    sock = L2RingSocket.from_unix(unix_socket)
    sniff(opened_socket=sock, count=10)
    srp1(Ether() / IP(dst="1.1.1.1") / ICMP(), opened_socket=sock)

The privileged side is also available from the command line::

    python -m scapy.arch.linux.ringbuf eth0 /run/scapy-eth0.sock --owner scapy
"""

import array
import json
import mmap
import os
import select
import socket
import struct
import time

from scapy.arch.linux import L2Socket
from scapy.compat import raw
from scapy.config import conf
from scapy.data import ETH_P_ALL, MTU, SOL_PACKET
from scapy.error import Scapy_Exception, warning
from scapy.packet import Packet
from scapy.supersocket import ETH_P_8021Q

# Typing imports
from scapy.compat import Self
from scapy.interfaces import _GlobInterfaceType
from typing import (
    Any,
    Dict,
    NoReturn,
    Optional,
    Tuple,
    Type,
)

__all__ = ["RingSpec", "L2RingSocket", "L2ListenRingSocket"]

# From <linux/if_packet.h>
PACKET_STATISTICS = 6
PACKET_VERSION = 10
PACKET_RX_RING = 5
PACKET_TX_RING = 13

TPACKET_V2 = 1
TPACKET_ALIGNMENT = 16

# Status of a frame of the receive ring
TP_STATUS_KERNEL = 0
TP_STATUS_USER = 1 << 0
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6

# Status of a frame of the transmit ring
TP_STATUS_AVAILABLE = 0
TP_STATUS_SEND_REQUEST = 1 << 0
TP_STATUS_WRONG_FORMAT = 1 << 2

# struct tpacket2_hdr, at the head of every frame
_TPACKET2 = struct.Struct("=IIIHHIIHH4x")
# tp_status alone, the field the kernel and the process pass a frame with
_TP_STATUS = struct.Struct("=I")
# struct tpacket_req, the geometry a ring is created with
_TPACKET_REQ = struct.Struct("=IIII")
# struct tpacket_stats
_TPACKET_STATS = struct.Struct("=II")

# TPACKET_ALIGN(sizeof(struct tpacket2_hdr)), where the sockaddr_ll of a
# received frame sits, and where the kernel reads the data of one to transmit
# (TPACKET2_HDRLEN - sizeof(struct sockaddr_ll))
_SLL_OFFSET = 32
_TX_DATA_OFFSET = 32
# sll_pkttype within a struct sockaddr_ll
_SLL_PKTTYPE = _SLL_OFFSET + 10
# TPACKET2_HDRLEN, the smallest frame the kernel accepts
_TPACKET2_HDRLEN = 52

# 2 MiB of 2 KiB frames, which holds a packet of any usual MTU
DEFAULT_FRAME_SIZE = 2048
DEFAULT_BLOCK_SIZE = 8 * 4096
DEFAULT_BLOCK_NR = 64


class RingSpec(object):
    """
    Geometry of one PACKET_MMAP ring.

    The kernel allocates a ring as a number of blocks of contiguous pages, each
    holding a whole number of equally sized frames. A frame takes one packet,
    behind its header, so its size is the largest packet the ring carries.

    :param frame_size: size of a frame, header included
    :param block_size: size of a block, a multiple of the page and frame sizes
    :param block_nr: number of blocks
    """

    __slots__ = ["frame_size", "block_size", "block_nr"]

    def __init__(self,
                 frame_size=DEFAULT_FRAME_SIZE,  # type: int
                 block_size=DEFAULT_BLOCK_SIZE,  # type: int
                 block_nr=DEFAULT_BLOCK_NR,  # type: int
                 ):
        # type: (...) -> None
        if frame_size <= _TPACKET2_HDRLEN or frame_size % TPACKET_ALIGNMENT:
            raise ValueError(
                "frame_size must be over %d and a multiple of %d" % (
                    _TPACKET2_HDRLEN, TPACKET_ALIGNMENT
                )
            )
        if block_size % mmap.PAGESIZE or block_size % frame_size:
            raise ValueError(
                "block_size must be a multiple of the page size (%d) and of "
                "frame_size" % mmap.PAGESIZE
            )
        if block_nr <= 0:
            raise ValueError("block_nr must be positive")
        self.frame_size = frame_size
        self.block_size = block_size
        self.block_nr = block_nr

    @property
    def frames_per_block(self):
        # type: () -> int
        return self.block_size // self.frame_size

    @property
    def frame_nr(self):
        # type: () -> int
        return self.frames_per_block * self.block_nr

    @property
    def size(self):
        # type: () -> int
        """Bytes the ring takes in the mapping."""
        return self.block_size * self.block_nr

    @property
    def payload_size(self):
        # type: () -> int
        """Largest packet a frame carries."""
        return self.frame_size - _TX_DATA_OFFSET

    def to_req(self):
        # type: () -> bytes
        """The struct tpacket_req that creates this ring."""
        return _TPACKET_REQ.pack(
            self.block_size, self.block_nr, self.frame_size, self.frame_nr
        )

    def to_dict(self):
        # type: () -> Dict[str, int]
        return {
            "frame_size": self.frame_size,
            "block_size": self.block_size,
            "block_nr": self.block_nr,
        }

    @classmethod
    def from_dict(cls, data):
        # type: (Dict[str, int]) -> RingSpec
        return cls(**data)

    def __repr__(self):
        # type: () -> str
        return "<RingSpec %d frames of %d bytes>" % (
            self.frame_nr, self.frame_size
        )


class L2RingSocket(L2Socket):
    desc = "read/write packets at layer 2 through a PACKET_MMAP ring buffer"

    def __init__(self,
                 iface=None,  # type: Optional[_GlobInterfaceType]
                 type=ETH_P_ALL,  # type: int
                 promisc=None,  # type: Optional[bool]
                 filter=None,  # type: Optional[str]
                 nofilter=0,  # type: int
                 monitor=None,  # type: Optional[Any]
                 ring=None,  # type: Optional[RingSpec]
                 tx=True,  # type: bool
                 ):
        # type: (...) -> None
        """
        :param ring: geometry of the rings, a default one if left out
        :param tx: also set a transmit ring up, to send through the mapping
        """
        super(L2RingSocket, self).__init__(
            iface=iface,
            type=type,
            promisc=promisc,
            filter=filter,
            nofilter=nofilter,
            monitor=monitor,
        )
        spec = ring or RingSpec()
        self.ins.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V2)
        self.ins.setsockopt(SOL_PACKET, PACKET_RX_RING, spec.to_req())
        if tx:
            self.ins.setsockopt(SOL_PACKET, PACKET_TX_RING, spec.to_req())
        self._map(spec, spec if tx else None)

    # Setup

    def _map(self, rx, tx):
        # type: (RingSpec, Optional[RingSpec]) -> None
        """Map the rings of the socket, which the kernel lays receive first."""
        self.rx = rx
        self.tx = tx
        self.ring = mmap.mmap(
            self.ins.fileno(),
            rx.size + (tx.size if tx else 0),
            mmap.MAP_SHARED,
            mmap.PROT_READ | mmap.PROT_WRITE,
        )
        self._rx_index = 0
        self._tx_index = 0

    @classmethod
    def from_fd(cls,
                fd,  # type: int
                rx,  # type: RingSpec
                tx=None,  # type: Optional[RingSpec]
                ):
        # type: (...) -> Self
        """
        Take a packet socket someone else created the rings of over.

        The rings are only mapped, as they cannot be created twice, so their
        geometry must be the one they were created with.

        :param fd: descriptor of a bound packet socket, which this socket owns
            from now on and closes with itself
        :param rx: geometry of its receive ring
        :param tx: geometry of its transmit ring, if it has one
        """
        self = cls.__new__(cls)
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, 0, fileno=fd
        )
        self.outs = self.ins
        # Whoever created the socket put the interface in promiscuous mode and
        # takes it back out of it.
        self.promisc = False
        name, proto, _, hatype, _ = self.ins.getsockname()
        self.iface = name
        self.type = proto
        # As in L2Socket, the link type comes from what the socket is bound to
        if hatype in conf.l2types:
            self.LL = conf.l2types.num2layer[hatype]
            self.lvl = 2
        elif proto in conf.l3types:
            self.LL = conf.l3types.num2layer[proto]
            self.lvl = 3
        else:
            self.LL = conf.default_l2
            self.lvl = 2
            warning(
                "Unable to guess type (interface=%s protocol=%#x hatype=%i). "
                "Using %s", name, proto, hatype, self.LL.name
            )
        self._map(rx, tx)
        return self

    # Passing the socket on

    def geometry(self):
        # type: () -> Dict[str, Any]
        """What a process needs to map the rings of this socket."""
        return {
            "version": TPACKET_V2,
            "rx": self.rx.to_dict(),
            "tx": self.tx.to_dict() if self.tx else None,
        }

    def share(self, sock):
        # type: (socket.socket) -> None
        """
        Pass this socket, rings and all, over a UNIX socket.

        The receiving process needs no privileges of its own, as the kernel
        only asks for CAP_NET_RAW when a packet socket is created.

        :param sock: a connected UNIX socket, whose peer reads the packet
            socket back with :func:`from_unix`
        """
        sock.sendmsg(
            [json.dumps(self.geometry()).encode()],
            [(
                socket.SOL_SOCKET,
                socket.SCM_RIGHTS,
                array.array("i", [self.ins.fileno()]),
            )],
        )

    @classmethod
    def from_unix(cls, sock):
        # type: (socket.socket) -> Self
        """
        Take over the packet socket a peer sent with :func:`share`.

        :param sock: a connected UNIX socket
        """
        fds = array.array("i")
        payload, ancdata, _, _ = sock.recvmsg(
            4096, socket.CMSG_SPACE(fds.itemsize)
        )
        for level, kind, data in ancdata:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
        if not fds:
            raise Scapy_Exception("No packet socket came with the message")
        for extra in fds[1:]:
            os.close(extra)
        try:
            geometry = json.loads(payload.decode())
            version = geometry["version"]
            if version != TPACKET_V2:
                raise ValueError("unsupported TPACKET version %r" % version)
            rx = RingSpec.from_dict(geometry["rx"])
            tx = geometry.get("tx")
            tx_spec = RingSpec.from_dict(tx) if tx else None
        except (KeyError, TypeError, ValueError) as ex:
            os.close(fds[0])
            raise Scapy_Exception("The message describes no ring: %s" % ex)
        return cls.from_fd(fds[0], rx, tx_spec)

    # Frames

    @staticmethod
    def _frame_offset(spec, index, base=0):
        # type: (RingSpec, int, int) -> int
        """Offset of a frame in the mapping."""
        block, frame = divmod(index, spec.frames_per_block)
        return base + block * spec.block_size + frame * spec.frame_size

    def _status(self, offset):
        # type: (int) -> int
        return int(_TP_STATUS.unpack_from(self.ring, offset)[0])

    def _wait(self, events, deadline):
        # type: (int, Optional[float]) -> bool
        """Wait for the kernel to hand a frame over, honouring the timeout."""
        poller = select.poll()
        poller.register(self.ins.fileno(), events)
        timeout = None  # type: Optional[float]
        if deadline is not None:
            timeout = max(0.0, deadline - time.monotonic()) * 1000
        return bool(poller.poll(timeout))

    def _deadline(self):
        # type: () -> Optional[float]
        """When to give up, from the timeout of the socket."""
        timeout = self.ins.gettimeout()
        if timeout is None:
            return None
        return time.monotonic() + timeout

    def _resync(self):
        # type: () -> bool
        """
        Move the read position to the oldest frame the kernel has filled.

        The position only follows the one the kernel writes at as long as it
        started with it, which a ring taken over while it was already running
        does not. Their timestamps tell which of its frames comes first.
        """
        oldest = None  # type: Optional[Tuple[Tuple[int, int], int]]
        for index in range(self.rx.frame_nr):
            offset = self._frame_offset(self.rx, index)
            status, _, _, _, _, sec, nsec, _, _ = _TPACKET2.unpack_from(
                self.ring, offset
            )
            if not status & TP_STATUS_USER:
                continue
            if oldest is None or (sec, nsec) < oldest[0]:
                oldest = ((sec, nsec), index)
        if oldest is None:
            return False
        self._rx_index = oldest[1]
        return True

    def _rx_frame(self):
        # type: () -> Optional[int]
        """Offset of the next frame to read, waiting for one if needed."""
        deadline = self._deadline()
        while True:
            offset = self._frame_offset(self.rx, self._rx_index)
            if self._status(offset) & TP_STATUS_USER:
                return offset
            if not self._wait(select.POLLIN, deadline):
                return None
            if self._status(offset) & TP_STATUS_USER:
                return offset
            if not self._resync():
                return None

    def _tx_frame(self, tx):
        # type: (RingSpec) -> Optional[int]
        """Offset of a frame to write to, waiting for one if needed."""
        deadline = self._deadline()
        while True:
            offset = self._frame_offset(tx, self._tx_index, self.rx.size)
            status = self._status(offset)
            if status == TP_STATUS_AVAILABLE:
                return offset
            if status & TP_STATUS_WRONG_FORMAT:
                # The kernel refused what sat here and left it to us to clear
                _TP_STATUS.pack_into(self.ring, offset, TP_STATUS_AVAILABLE)
                return offset
            if not self._wait(select.POLLOUT, deadline):
                return None
            # Ours is still being sent while another frame came free
            for index in range(tx.frame_nr):
                offset = self._frame_offset(tx, index, self.rx.size)
                if self._status(offset) == TP_STATUS_AVAILABLE:
                    self._tx_index = index
                    return offset

    # Reading and writing

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        offset = self._rx_frame()
        if offset is None:
            return None, None, None
        (
            status, _, snaplen, mac, _, sec, nsec, vlan_tci, vlan_tpid
        ) = _TPACKET2.unpack_from(self.ring, offset)
        pkttype = self.ring[offset + _SLL_PKTTYPE]
        pkt = self.ring[offset + mac:offset + mac + min(snaplen, x)]
        if status & TP_STATUS_VLAN_VALID:
            # The kernel keeps the tag out of the frame, next to it
            tpid = ETH_P_8021Q
            if status & TP_STATUS_VLAN_TPID_VALID:
                tpid = vlan_tpid
            pkt = pkt[:12] + struct.pack("!HH", tpid, vlan_tci) + pkt[12:]
        _TP_STATUS.pack_into(self.ring, offset, TP_STATUS_KERNEL)
        self._rx_index = (self._rx_index + 1) % self.rx.frame_nr
        if self.outs is not None and pkttype == socket.PACKET_OUTGOING:
            return None, None, None
        return self.LL, pkt, sec + nsec * 1e-9

    def send(self, x):
        # type: (Packet) -> int
        sx = raw(x)
        if len(sx) < conf.min_pkt_size:
            # The kernel takes no frame shorter than a hardware header, and
            # reports one bad frame as an error on the whole ring, so pad
            sx += b"\x00" * (conf.min_pkt_size - len(sx))
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        tx = self.tx
        if tx is None:
            if self.outs is None:
                raise Scapy_Exception("Socket not opened for sending")
            return self.outs.send(sx)
        if len(sx) > tx.payload_size:
            raise Scapy_Exception(
                "Packet of %d bytes over the %d bytes a frame holds" % (
                    len(sx), tx.payload_size
                )
            )
        offset = self._tx_frame(tx)
        if offset is None:
            raise socket.timeout("The transmit ring stayed full")
        end = offset + _TX_DATA_OFFSET + len(sx)
        self.ring[offset + _TX_DATA_OFFSET:end] = sx
        _TPACKET2.pack_into(
            self.ring, offset,
            TP_STATUS_AVAILABLE, len(sx), len(sx), 0, 0, 0, 0, 0, 0
        )
        # The kernel reads the frame as soon as it is asked to, so its length
        # goes in before the status that hands it over
        _TP_STATUS.pack_into(self.ring, offset, TP_STATUS_SEND_REQUEST)
        self._tx_index = (self._tx_index + 1) % tx.frame_nr
        try:
            # An empty send() carries nothing itself, it tells the kernel to
            # walk the ring and send what it finds handed over
            self.ins.send(b"")
        except OSError:
            _TP_STATUS.pack_into(self.ring, offset, TP_STATUS_AVAILABLE)
            raise
        return len(sx)

    # Housekeeping

    def stats(self):
        # type: () -> Tuple[int, int]
        """Packets the kernel put in the receive ring, and packets it dropped.

        The counters are those of the socket and reset on every read.
        """
        data = self.ins.getsockopt(
            SOL_PACKET, PACKET_STATISTICS, _TPACKET_STATS.size
        )
        packets, drops = _TPACKET_STATS.unpack(data)
        return packets, drops

    def close(self):
        # type: () -> None
        if self.closed:
            return
        ring = getattr(self, "ring", None)
        if ring is not None:
            # The kernel holds the rings until the last mapping of them goes
            ring.close()
        super(L2RingSocket, self).close()


class L2ListenRingSocket(L2RingSocket):
    desc = "read packets at layer 2 through a PACKET_MMAP ring buffer. Also receives the packets going OUT"  # noqa: E501

    def __init__(self,
                 iface=None,  # type: Optional[_GlobInterfaceType]
                 type=ETH_P_ALL,  # type: int
                 promisc=None,  # type: Optional[bool]
                 filter=None,  # type: Optional[str]
                 nofilter=0,  # type: int
                 monitor=None,  # type: Optional[Any]
                 ring=None,  # type: Optional[RingSpec]
                 ):
        # type: (...) -> None
        super(L2ListenRingSocket, self).__init__(
            iface=iface,
            type=type,
            promisc=promisc,
            filter=filter,
            nofilter=nofilter,
            monitor=monitor,
            ring=ring,
            tx=False,
        )
        self.outs = None  # type: ignore

    def send(self, x):
        # type: (Packet) -> NoReturn
        raise Scapy_Exception("Can't send anything with L2ListenRingSocket")


def main():
    # type: () -> None
    """Serve a ring socket to unprivileged processes over a UNIX socket."""
    import argparse
    # Registers the link types a socket reads what it is bound to from
    import scapy.layers.l2  # noqa: F401
    parser = argparse.ArgumentParser(
        description="Set a PACKET_MMAP ring socket up and pass it to whoever "
                    "connects, so that an unprivileged Scapy can sniff and "
                    "send on it. Anyone allowed to connect gets raw access to "
                    "the interface."
    )
    parser.add_argument("iface", help="interface to bind the socket to")
    parser.add_argument("path", help="UNIX socket to serve it on")
    parser.add_argument("--filter", help="BPF filter to attach to it")
    parser.add_argument(
        "--owner",
        help="user to give the UNIX socket to, the one running Scapy",
    )
    parser.add_argument(
        "--mode", default="0600", help="mode of the UNIX socket"
    )
    parser.add_argument(
        "--frame-size", type=int, default=DEFAULT_FRAME_SIZE,
        help="largest packet a frame of the rings holds",
    )
    parser.add_argument(
        "--block-nr", type=int, default=DEFAULT_BLOCK_NR,
        help="number of blocks in each ring",
    )
    parser.add_argument(
        "--no-tx", action="store_true", help="only set a receive ring up"
    )
    args = parser.parse_args()

    ring = RingSpec(frame_size=args.frame_size, block_nr=args.block_nr)

    def open_socket():
        # type: () -> L2RingSocket
        return L2RingSocket(
            iface=args.iface,
            filter=args.filter,
            ring=ring,
            tx=not args.no_tx,
        )

    # Report a bad interface or filter now rather than when a client turns up
    open_socket().close()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(args.path)
    except OSError:
        pass
    server.bind(args.path)
    os.chmod(args.path, int(args.mode, 8))
    if args.owner:
        import pwd
        entry = pwd.getpwnam(args.owner)
        os.chown(args.path, entry.pw_uid, entry.pw_gid)
    server.listen(1)
    print("Serving %s on %s, %r" % (args.iface, args.path, ring))
    try:
        while True:
            client, _ = server.accept()
            with client:
                # A socket of its own, so that two clients do not read the
                # same ring and take each other's packets out of it
                sock = open_socket()
                sock.share(client)
                # The client holds it now: let go of it without taking the
                # interface out of promiscuous mode under it
                sock.promisc = False
                sock.close()
            print("Passed a socket on")
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        os.unlink(args.path)


if __name__ == "__main__":
    main()
