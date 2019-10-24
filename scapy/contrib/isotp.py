#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Enrico Pozzobon <enricopozzobon@gmail.com>
# Copyright (C) Alexander Schroeder <alexander1.schroeder@st.othr.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = ISO-TP (ISO 15765-2)
# scapy.contrib.status = loads

"""
ISOTPSocket.
"""


import ctypes
from ctypes.util import find_library
import struct
import socket
import time
from threading import Thread, Event, Lock, Semaphore

from scapy.packet import Packet
from scapy.fields import BitField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField, ConditionalField, \
    BitEnumField, ByteField, XByteField, BitFieldLenField, StrField
from scapy.compat import chb, orb
from scapy.layers.can import CAN
import scapy.modules.six as six
import scapy.automaton as automaton
import six.moves.queue as queue
from scapy.error import Scapy_Exception, warning, log_loading
from scapy.supersocket import SuperSocket
from scapy.config import conf
from scapy.consts import LINUX
from scapy.contrib.cansocket import PYTHON_CAN
from scapy.sendrecv import sniff
from scapy.sessions import DefaultSession

__all__ = ["ISOTP", "ISOTPHeader", "ISOTPHeaderEA", "ISOTP_SF", "ISOTP_FF",
           "ISOTP_CF", "ISOTP_FC", "ISOTPSoftSocket", "ISOTPSession",
           "ISOTPSocket", "ISOTPSocketImplementation", "ISOTPMessageBuilder",
           "ISOTPScan"]

USE_CAN_ISOTP_KERNEL_MODULE = False
if six.PY3 and LINUX:
    LIBC = ctypes.cdll.LoadLibrary(find_library("c"))
    try:
        if conf.contribs['ISOTP']['use-can-isotp-kernel-module']:
            USE_CAN_ISOTP_KERNEL_MODULE = True
    except KeyError:
        log_loading.info("Specify 'conf.contribs['ISOTP'] = "
                         "{'use-can-isotp-kernel-module': True}' to enable "
                         "usage of can-isotp kernel module.")

CAN_MAX_IDENTIFIER = (1 << 29) - 1  # Maximum 29-bit identifier
CAN_MTU = 16
CAN_MAX_DLEN = 8
ISOTP_MAX_DLEN_2015 = (1 << 32) - 1  # Maximum for 32-bit FF_DL
ISOTP_MAX_DLEN = (1 << 12) - 1  # Maximum for 12-bit FF_DL

N_PCI_SF = 0x00  # /* single frame */
N_PCI_FF = 0x10  # /* first frame */
N_PCI_CF = 0x20  # /* consecutive frame */
N_PCI_FC = 0x30  # /* flow control */


class ISOTP(Packet):
    name = 'ISOTP'
    fields_desc = [
        StrField('data', B"")
    ]
    __slots__ = Packet.__slots__ + ["src", "dst", "exsrc", "exdst"]

    def answers(self, other):
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def __init__(self, *args, **kwargs):
        self.src = None
        self.dst = None
        self.exsrc = None
        self.exdst = None
        if "src" in kwargs:
            self.src = kwargs["src"]
            del kwargs["src"]
        if "dst" in kwargs:
            self.dst = kwargs["dst"]
            del kwargs["dst"]
        if "exsrc" in kwargs:
            self.exsrc = kwargs["exsrc"]
            del kwargs["exsrc"]
        if "exdst" in kwargs:
            self.exdst = kwargs["exdst"]
            del kwargs["exdst"]
        Packet.__init__(self, *args, **kwargs)
        self.validate_fields()

    def validate_fields(self):
        if self.src is not None:
            if not 0 <= self.src <= CAN_MAX_IDENTIFIER:
                raise Scapy_Exception("src is not a valid CAN identifier")
        if self.dst is not None:
            if not 0 <= self.dst <= CAN_MAX_IDENTIFIER:
                raise Scapy_Exception("dst is not a valid CAN identifier")
        if self.exsrc is not None:
            if not 0 <= self.exsrc <= 0xff:
                raise Scapy_Exception("exsrc is not a byte")
        if self.exdst is not None:
            if not 0 <= self.exdst <= 0xff:
                raise Scapy_Exception("exdst is not a byte")

    def fragment(self):
        data_bytes_in_frame = 7
        if self.exdst is not None:
            data_bytes_in_frame = 6

        if len(self.data) > ISOTP_MAX_DLEN_2015:
            raise Scapy_Exception("Too much data in ISOTP message")

        if len(self.data) <= data_bytes_in_frame:
            # We can do this in a single frame
            frame_data = struct.pack('B', len(self.data)) + self.data
            if self.exdst:
                frame_data = struct.pack('B', self.exdst) + frame_data
            pkt = CAN(identifier=self.dst, data=frame_data)
            return [pkt]

        # Construct the first frame
        if len(self.data) <= ISOTP_MAX_DLEN:
            frame_header = struct.pack(">H", len(self.data) + 0x1000)
        else:
            frame_header = struct.pack(">HI", 0x1000, len(self.data))
        if self.exdst:
            frame_header = struct.pack('B', self.exdst) + frame_header
        idx = 8 - len(frame_header)
        frame_data = self.data[0:idx]
        frame = CAN(identifier=self.dst, data=frame_header + frame_data)

        # Construct consecutive frames
        n = 1
        pkts = [frame]
        while idx < len(self.data):
            frame_data = self.data[idx:idx + data_bytes_in_frame]
            frame_header = struct.pack("b", (n % 16) + N_PCI_CF)

            n += 1
            idx += len(frame_data)

            if self.exdst:
                frame_header = struct.pack('B', self.exdst) + frame_header
            pkt = CAN(identifier=self.dst, data=frame_header + frame_data)
            pkts.append(pkt)
        return pkts

    @staticmethod
    def defragment(can_frames, use_extended_addressing=None):
        if len(can_frames) == 0:
            raise Scapy_Exception("ISOTP.defragment called with 0 frames")

        dst = can_frames[0].identifier
        for frame in can_frames:
            if frame.identifier != dst:
                warning("Not all CAN frames have the same identifier")

        parser = ISOTPMessageBuilder(use_extended_addressing)
        for c in can_frames:
            parser.feed(c)

        results = []
        while parser.count > 0:
            p = parser.pop()
            if (use_extended_addressing is True and p.exdst is not None) \
                    or (use_extended_addressing is False and p.exdst is None) \
                    or (use_extended_addressing is None):
                results.append(p)

        if len(results) == 0:
            return None

        if len(results) > 0:
            warning("More than one ISOTP frame could be defragmented from the "
                    "provided CAN frames, returning the first one.")

        return results[0]


class ISOTPHeader(CAN):
    name = 'ISOTPHeader'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', None),
        ThreeBytesField('reserved', 0),
    ]

    def extract_padding(self, p):
        return p, None

    def post_build(self, pkt, pay):
        """
        This will set the ByteField 'length' to the correct value.
        """
        if self.length is None:
            pkt = pkt[:4] + chb(len(pay)) + pkt[5:]
        return pkt + pay

    def guess_payload_class(self, payload):
        """
        ISOTP encodes the frame type in the first nibble of a frame.
        """
        t = (orb(payload[0]) & 0xf0) >> 4
        if t == 0:
            return ISOTP_SF
        elif t == 1:
            return ISOTP_FF
        elif t == 2:
            return ISOTP_CF
        else:
            return ISOTP_FC


class ISOTPHeaderEA(ISOTPHeader):
    name = 'ISOTPHeaderExtendedAddress'
    fields_desc = ISOTPHeader.fields_desc + [
        XByteField('extended_address', 0),
    ]

    def post_build(self, p, pay):
        """
        This will set the ByteField 'length' to the correct value.
        'chb(len(pay) + 1)' is required, because the field 'extended_address'
        is counted as payload on the CAN layer
        """
        if self.length is None:
            p = p[:4] + chb(len(pay) + 1) + p[5:]
        return p + pay


ISOTP_TYPE = {0: 'single',
              1: 'first',
              2: 'consecutive',
              3: 'flow_control'}


class ISOTP_SF(Packet):
    name = 'ISOTPSingleFrame'
    fields_desc = [
        BitEnumField('type', 0, 4, ISOTP_TYPE),
        BitFieldLenField('message_size', None, 4, length_of='data'),
        StrLenField('data', '', length_from=lambda pkt: pkt.message_size)
    ]


class ISOTP_FF(Packet):
    name = 'ISOTPFirstFrame'
    fields_desc = [
        BitEnumField('type', 1, 4, ISOTP_TYPE),
        BitField('message_size', 0, 12),
        ConditionalField(BitField('extended_message_size', 0, 32),
                         lambda pkt: pkt.message_size == 0),
        StrField('data', '', fmt="B")
    ]


class ISOTP_CF(Packet):
    name = 'ISOTPConsecutiveFrame'
    fields_desc = [
        BitEnumField('type', 2, 4, ISOTP_TYPE),
        BitField('index', 0, 4),
        StrField('data', '', fmt="B")
    ]


class ISOTP_FC(Packet):
    name = 'ISOTPFlowControlFrame'
    fields_desc = [
        BitEnumField('type', 3, 4, ISOTP_TYPE),
        BitEnumField('fc_flag', 0, 4, {0: 'continue',
                                       1: 'wait',
                                       2: 'abort'}),
        ByteField('block_size', 0),
        ByteField('separation_time', 0),
    ]


class ISOTPMessageBuilderIter(object):
    slots = ["builder"]

    def __init__(self, builder):
        self.builder = builder

    def __iter__(self):
        return self

    def __next__(self):
        while self.builder.count:
            return self.builder.pop()
        raise StopIteration

    next = __next__


class ISOTPMessageBuilder:
    """
    Utility class to build ISOTP messages out of CAN frames, used by both
    ISOTP.defragment() and ISOTPSession.

    This class attempts to interpret some CAN frames as ISOTP frames, both with
    and without extended addressing at the same time. For example, if an
    extended address of 07 is being used, all frames will also be interpreted
    as ISOTP single-frame messages.

    CAN frames are fed to an ISOTPMessageBuilder object with the feed() method
    and the resulting ISOTP frames can be extracted using the pop() method.
    """

    class Bucket:
        def __init__(self, total_len, first_piece, ts=None):
            self.pieces = list()
            self.total_len = total_len
            self.current_len = 0
            self.ready = None
            self.src = None
            self.exsrc = None
            self.time = ts
            self.push(first_piece)

        def push(self, piece):
            self.pieces.append(piece)
            self.current_len += len(piece)
            if self.current_len >= self.total_len:
                if six.PY3:
                    isotp_data = b"".join(self.pieces)
                else:
                    isotp_data = "".join(map(str, self.pieces))
                self.ready = isotp_data[:self.total_len]

    def __init__(self, use_ext_addr=None, did=None, basecls=None):
        """
        Initialize a ISOTPMessageBuilder object

        :param use_ext_addr:    True for only attempting to defragment with
                                extended addressing, False for only attempting
                                to defragment without extended addressing,
                                or None for both
        :param basecls:         the class of packets that will be returned,
                                defaults to ISOTP

        """
        self.ready = []
        self.buckets = {}
        self.use_ext_addr = use_ext_addr
        self.basecls = basecls or ISOTP
        self.dst_ids = None
        self.last_ff = None
        self.last_ff_ex = None
        if did is not None:
            if hasattr(did, "__iter__"):
                self.dst_ids = did
            else:
                self.dst_ids = [did]

    def feed(self, can):
        """Attempt to feed an incoming CAN frame into the state machine"""
        if not isinstance(can, Packet) and hasattr(can, "__iter__"):
            for p in can:
                self.feed(p)
            return
        identifier = can.identifier

        if self.dst_ids is not None and identifier not in self.dst_ids:
            return

        data = bytes(can.data)

        if len(data) > 1 and self.use_ext_addr is not True:
            self._try_feed(identifier, None, data, can.time)
        if len(data) > 2 and self.use_ext_addr is not False:
            ea = six.indexbytes(data, 0)
            self._try_feed(identifier, ea, data[1:], can.time)

    @property
    def count(self):
        """Returns the number of ready ISOTP messages built from the provided
        can frames"""
        return len(self.ready)

    def __len__(self):
        return self.count

    def pop(self, identifier=None, ext_addr=None):
        """
        Returns a built ISOTP message

        :param identifier: if not None, only return isotp messages with this
                           destination
        :param ext_addr: if identifier is not None, only return isotp messages
                         with this extended address for destination
        :returns: an ISOTP packet, or None if no message is ready
        """

        if identifier is not None:
            for i in range(len(self.ready)):
                b = self.ready[i]
                iden = b[0]
                ea = b[1]
                if iden == identifier and ext_addr == ea:
                    return ISOTPMessageBuilder._build(self.ready.pop(i),
                                                      self.basecls)
            return None

        if len(self.ready) > 0:
            return ISOTPMessageBuilder._build(self.ready.pop(0), self.basecls)
        return None

    def __iter__(self):
        return ISOTPMessageBuilderIter(self)

    @staticmethod
    def _build(t, basecls=ISOTP):
        bucket = t[2]
        p = basecls(bucket.ready)
        if hasattr(p, "dst"):
            p.dst = t[0]
        if hasattr(p, "exdst"):
            p.exdst = t[1]
        if hasattr(p, "src"):
            p.src = bucket.src
        if hasattr(p, "exsrc"):
            p.exsrc = bucket.exsrc
        if hasattr(p, "time"):
            p.time = bucket.time
        return p

    def _feed_first_frame(self, identifier, ea, data, ts):
        if len(data) < 3:
            # At least 3 bytes are necessary: 2 for length and 1 for data
            return False

        header = struct.unpack('>H', bytes(data[:2]))[0]
        expected_length = header & 0x0fff
        isotp_data = data[2:]
        if expected_length == 0 and len(data) >= 6:
            expected_length = struct.unpack('>I', bytes(data[2:6]))[0]
            isotp_data = data[6:]

        key = (ea, identifier, 1)
        if ea is None:
            self.last_ff = key
        else:
            self.last_ff_ex = key
        self.buckets[key] = self.Bucket(expected_length, isotp_data, ts)
        return True

    def _feed_single_frame(self, identifier, ea, data, ts):
        if len(data) < 2:
            # At least 2 bytes are necessary: 1 for length and 1 for data
            return False

        length = six.indexbytes(data, 0) & 0x0f
        isotp_data = data[1:length + 1]

        if length > len(isotp_data):
            # CAN frame has less data than expected
            return False

        self.ready.append((identifier, ea,
                           self.Bucket(length, isotp_data, ts)))
        return True

    def _feed_consecutive_frame(self, identifier, ea, data):
        if len(data) < 2:
            # At least 2 bytes are necessary: 1 for sequence number and
            # 1 for data
            return False

        first_byte = six.indexbytes(data, 0)
        seq_no = first_byte & 0x0f
        isotp_data = data[1:]

        key = (ea, identifier, seq_no)
        bucket = self.buckets.pop(key, None)

        if bucket is None:
            # There is no message constructor waiting for this frame
            return False

        bucket.push(isotp_data)
        if bucket.ready is None:
            # full ISOTP message is not ready yet, put it back in
            # buckets list
            next_seq = (seq_no + 1) % 16
            key = (ea, identifier, next_seq)
            self.buckets[key] = bucket
        else:
            self.ready.append((identifier, ea, bucket))

        return True

    def _feed_flow_control_frame(self, identifier, ea, data):
        if len(data) < 3:
            # At least 2 bytes are necessary: 1 for sequence number and
            # 1 for data
            return False

        keys = [self.last_ff, self.last_ff_ex]
        if not any(keys):
            return False

        buckets = [self.buckets.pop(k, None) for k in keys]

        self.last_ff = None
        self.last_ff_ex = None

        if not any(buckets):
            # There is no message constructor waiting for this frame
            return False

        for key, bucket in zip(keys, buckets):
            if bucket is None:
                continue
            bucket.src = identifier
            bucket.exsrc = ea
            self.buckets[key] = bucket
        return True

    def _try_feed(self, identifier, ea, data, ts):
        first_byte = six.indexbytes(data, 0)
        if len(data) > 1 and first_byte & 0xf0 == N_PCI_SF:
            self._feed_single_frame(identifier, ea, data, ts)
        if len(data) > 2 and first_byte & 0xf0 == N_PCI_FF:
            self._feed_first_frame(identifier, ea, data, ts)
        if len(data) > 1 and first_byte & 0xf0 == N_PCI_CF:
            self._feed_consecutive_frame(identifier, ea, data)
        if len(data) > 1 and first_byte & 0xf0 == N_PCI_FC:
            self._feed_flow_control_frame(identifier, ea, data)


class ISOTPSession(DefaultSession):
    """Defragment ISOTP packets 'on-the-flow'.

    Usage:
    >>> sniff(session=ISOTPSession)
    """

    def __init__(self, *args, **kwargs):
        DefaultSession.__init__(self, *args, **kwargs)
        self.m = ISOTPMessageBuilder(
            use_ext_addr=kwargs.pop("use_ext_addr", None),
            did=kwargs.pop("did", None),
            basecls=kwargs.pop("basecls", None))

    def on_packet_received(self, pkt):
        if not pkt:
            return
        if isinstance(pkt, list):
            for p in pkt:
                ISOTPSession.on_packet_received(self, p)
            return
        self.m.feed(pkt)
        while len(self.m) > 0:
            rcvd = self.m.pop()
            if self._supersession:
                self._supersession.on_packet_received(rcvd)
            else:
                DefaultSession.on_packet_received(self, rcvd)


class ISOTPSoftSocket(SuperSocket):
    """
    This class is a wrapper around the ISOTPSocketImplementation, for the
    reasons described below.

    The ISOTPSoftSocket aims to be fully compatible with the Linux ISOTP
    sockets provided by the can-isotp kernel module, while being usable on any
    operating system.
    Therefore, this socket needs to be able to respond to an incoming FF frame
    with a FC frame even before the recv() method is called.
    A thread is needed for receiving CAN frames in the background, and since
    the lower layer CAN implementation is not guaranteed to have a functioning
    POSIX select(), each ISOTP socket needs its own CAN receiver thread.
    Additionally, 2 timers are necessary to keep track of the timeouts and
    frame separation times, and each timer is implemented in its own thread.
    In total, each ISOTPSoftSocket spawns 3 background threads when
    constructed, which must be terminated afterwards by calling the close()
    method.
    SuperSocket automatically calls the close() method when the GC destroys an
    ISOTPSoftSocket. However, note that if any thread holds a reference to
    an ISOTPSoftSocket object, it will not be collected by the GC.

    The implementation of the ISOTP protocol, along with the necessary
    threads, are stored in the ISOTPSocketImplementation class, and therefore:

    * There no reference from ISOTPSocketImplementation to ISOTPSoftSocket
    * ISOTPSoftSocket can be normally garbage collected
    * Upon destruction, ISOTPSoftSocket.close() will be called
    * ISOTPSoftSocket.close() will call ISOTPSocketImplementation.close()
    * All background threads can be stopped by the garbage collector
    """

    nonblocking_socket = True

    def __init__(self,
                 can_socket=None,
                 sid=0,
                 did=0,
                 extended_addr=None,
                 extended_rx_addr=None,
                 rx_block_size=0,
                 rx_separation_time_min=0,
                 padding=False,
                 listen_only=False,
                 basecls=ISOTP):
        """
        Initialize an ISOTPSoftSocket using the provided underlying can socket

        :param can_socket: a CANSocket instance, preferably filtering only can
                           frames with identifier equal to did
        :param sid: the CAN identifier of the sent CAN frames
        :param did: the CAN identifier of the received CAN frames
        :param extended_addr: the extended address of the sent ISOTP frames
                              (can be None)
        :param extended_rx_addr: the extended address of the received ISOTP
                                 frames (can be None)
        :param rx_block_size: block size sent in Flow Control ISOTP frames
        :param rx_separation_time_min: minimum desired separation time sent in
                                       Flow Control ISOTP frames
        :param padding: If True, pads sending packets with 0x00 which not
                        count to the payload.
                        Does not affect receiving packets.
        :param basecls: base class of the packets emitted by this socket
        """

        if six.PY3 and LINUX and isinstance(can_socket, six.string_types):
            from scapy.contrib.cansocket import CANSocket
            can_socket = CANSocket(can_socket)
        elif isinstance(can_socket, six.string_types):
            raise Scapy_Exception("Provide a CANSocket object instead")

        self.exsrc = extended_addr
        self.exdst = extended_rx_addr
        self.src = sid
        self.dst = did

        impl = ISOTPSocketImplementation(
            can_socket,
            src_id=sid,
            dst_id=did,
            padding=padding,
            extended_addr=extended_addr,
            extended_rx_addr=extended_rx_addr,
            rx_block_size=rx_block_size,
            rx_separation_time_min=rx_separation_time_min,
            listen_only=listen_only
        )

        self.ins = impl
        self.outs = impl
        self.impl = impl

        if basecls is None:
            warning('Provide a basecls ')
        self.basecls = basecls

    def close(self):
        if not self.closed:
            self.impl.close()
            self.outs = None
            self.ins = None
            SuperSocket.close(self)

    def begin_send(self, p):
        """Begin the transmission of message p. This method returns after
        sending the first frame. If multiple frames are necessary to send the
        message, this socket will unable to send other messages until either
        the transmission of this frame succeeds or it fails."""
        if hasattr(p, "sent_time"):
            p.sent_time = time.time()

        return self.outs.begin_send(bytes(p))

    def recv_raw(self, x=0xffff):
        """Receive a complete ISOTP message, blocking until a message is
        received or the specified timeout is reached.
        If self.timeout is 0, then this function doesn't block and returns the
        first frame in the receive buffer or None if there isn't any."""
        msg = self.ins.recv()
        t = time.time()
        return self.basecls, msg, t

    def recv(self, x=0xffff):
        msg = SuperSocket.recv(self, x)

        if hasattr(msg, "src"):
            msg.src = self.src
        if hasattr(msg, "dst"):
            msg.dst = self.dst
        if hasattr(msg, "exsrc"):
            msg.exsrc = self.exsrc
        if hasattr(msg, "exdst"):
            msg.exdst = self.exdst
        return msg

    @staticmethod
    def select(sockets, remain=None):
        """This function is called during sendrecv() routine to wait for
        sockets to be ready to receive
        """
        blocking = remain is None or remain > 0

        def find_ready_sockets():
            return list(filter(lambda x: not x.ins.rx_queue.empty(), sockets))

        ready_sockets = find_ready_sockets()
        if len(ready_sockets) > 0 or not blocking:
            return ready_sockets, None

        exit_select = Event()

        def my_cb(msg):
            exit_select.set()

        try:
            for s in sockets:
                s.ins.rx_callbacks.append(my_cb)

            exit_select.wait(remain)

        finally:
            for s in sockets:
                try:
                    s.ins.rx_callbacks.remove(my_cb)
                except ValueError:
                    pass

        ready_sockets = find_ready_sockets()
        return ready_sockets, None


ISOTPSocket = ISOTPSoftSocket


class CANReceiverThread(Thread):
    """
    Helper class that receives CAN frames and feeds them to the provided
    callback. It relies on CAN frames being enqueued in the CANSocket object
    and not being lost if they come before the sniff method is called. This is
    true in general since sniff is usually implemented as repeated recv(), but
    might be false in some implementation of CANSocket
    """

    def __init__(self, can_socket, callback):
        """
        Initialize the thread. In order for this thread to be able to be
        stopped by the destructor of another object, it is important to not
        keep a reference to the object in the callback function.

        :param socket: the CANSocket upon which this class will call the
                       sniff() method
        :param callback: function to call whenever a CAN frame is received
        """
        self.socket = can_socket
        self.callback = callback
        self.exiting = False
        self._thread_started = Event()
        self.exception = None

        Thread.__init__(self)
        self.name = "CANReceiver" + self.name

    def start(self):
        Thread.start(self)
        self._thread_started.wait()

    def run(self):
        self._thread_started.set()
        try:
            def prn(msg):
                if not self.exiting:
                    self.callback(msg)

            while 1:
                try:
                    sniff(store=False, timeout=1, count=1,
                          stop_filter=lambda x: self.exiting,
                          prn=prn, opened_socket=self.socket)
                except ValueError as ex:
                    if not self.exiting:
                        raise ex
                if self.exiting:
                    return
        except Exception as ex:
            self.exception = ex

    def stop(self):
        self.exiting = True


class TimeoutThread(Thread):
    """
    Utility class implementing a timer, useful for both timeouts and
    waiting between sent CAN frames.
    Contrary to the threading.Timer implementation, this timer thread can be
    reused for multiple timeouts. This avoids the overhead of creating a new
    pthread every time a timeout is planned.
    """

    def __init__(self):
        Thread.__init__(self)

        self._thread_started = Event()
        self._cancelled = Event()
        self._ready_sem = Semaphore(1)
        self._busy_sem = Semaphore(0)
        self._timeout = 1
        self._callback = None
        self._exception = None
        self._killed = False
        self._dead = False

        self.name = "ISOTP Timer " + self.name

    def run(self):
        self._thread_started.set()

        try:
            while not self._killed:
                self._busy_sem.acquire()
                f = self._cancelled.wait(self._timeout)
                self._ready_sem.release()
                if f is False:
                    if self._callback is not None:
                        self._callback()

        except Exception as ex:
            self._exception = ex
            warning(self.name + " is now stopped")
            raise ex

        finally:
            self._dead = True

    def start(self):
        """Start the thread, and make sure it is running"""
        Thread.start(self)
        self._thread_started.wait()

    def set_timeout(self, timeout, callback):
        """Call 'callback' in 'timeout' seconds, unless cancelled."""
        if not self._ready_sem.acquire(False):
            raise Scapy_Exception("Timer was already started")

        self._callback = callback
        self._timeout = timeout
        self._cancelled.clear()
        self._busy_sem.release()

    def cancel(self):
        """Stop the timer without executing the callback."""
        self._cancelled.set()
        if not self._dead:
            self._ready_sem.acquire()
            self._ready_sem.release()

    def stop(self):
        """Stop the thread, making this object unusable."""
        if not self._dead:
            self._killed = True
            self._cancelled.set()
            self._busy_sem.release()
            self.join()
            if not self._ready_sem.acquire(False):
                warning("ISOTP Timer thread may not have stopped "
                        "correctly")


"""ISOTPSoftSocket definitions."""

# Enum states
ISOTP_IDLE = 0
ISOTP_WAIT_FIRST_FC = 1
ISOTP_WAIT_FC = 2
ISOTP_WAIT_DATA = 3
ISOTP_SENDING = 4

# /* Flow Status given in FC frame */
ISOTP_FC_CTS = 0  # /* clear to send */
ISOTP_FC_WT = 1  # /* wait */
ISOTP_FC_OVFLW = 2  # /* overflow */


class ISOTPSocketImplementation(automaton.SelectableObject):
    """
    Implementation of an ISOTP "state machine".

    Most of the ISOTP logic was taken from
    https://github.com/hartkopp/can-isotp/blob/master/net/can/isotp.c

    This class is separated from ISOTPSoftSocket to make sure the background
    threads can't hold a reference to ISOTPSoftSocket, allowing it to be
    collected by the GC.
    """

    def __init__(self,
                 can_socket,
                 src_id,
                 dst_id,
                 padding=False,
                 extended_addr=None,
                 extended_rx_addr=None,
                 rx_block_size=0,
                 rx_separation_time_min=0,
                 listen_only=False):
        """
        :param can_socket: a CANSocket instance, preferably filtering only can
                           frames with identifier equal to did
        :param src_id: the CAN identifier of the sent CAN frames
        :param dst_id: the CAN identifier of the received CAN frames
        :param padding: If True, pads sending packets with 0x00 which not
                        count to the payload.
                        Does not affect receiving packets.
        :param extended_addr: Extended Address byte to be added at the
                beginning of every CAN frame _sent_ by this object. Can be None
                in order to disable extended addressing on sent frames.
        :param extended_rx_addr: Extended Address byte expected to be found at
                the beginning of every CAN frame _received_ by this object. Can
                be None in order to disable extended addressing on received
                frames.
        :param rx_block_size: Block Size byte to be included in every Control
                Flow Frame sent by this object. The default value of 0 means
                that all the data will be received in a single block.
        :param rx_separation_time_min: Time Minimum Separation byte to be
                included in every Control Flow Frame sent by this object. The
                default value of 0 indicates that the peer will not wait any
                time between sending frames.
        :param listen_only: Disables send of flow control frames
        """

        automaton.SelectableObject.__init__(self)

        self.can_socket = can_socket
        self.dst_id = dst_id
        self.src_id = src_id
        self.padding = padding
        self.fc_timeout = 1
        self.cf_timeout = 1

        self.filter_warning_emitted = False

        self.extended_rx_addr = extended_rx_addr
        self.ea_hdr = b""
        if extended_addr is not None:
            self.ea_hdr = struct.pack("B", extended_addr)
        self.listen_only = listen_only

        self.rxfc_bs = rx_block_size
        self.rxfc_stmin = rx_separation_time_min

        self.rx_queue = queue.Queue()
        self.rx_len = -1
        self.rx_buf = None
        self.rx_sn = 0
        self.rx_bs = 0
        self.rx_idx = 0
        self.rx_state = ISOTP_IDLE

        self.txfc_bs = 0
        self.txfc_stmin = 0
        self.tx_gap = 0

        self.tx_buf = None
        self.tx_sn = 0
        self.tx_bs = 0
        self.tx_idx = 0
        self.rx_ll_dl = 0
        self.tx_state = ISOTP_IDLE

        self.tx_timer = TimeoutThread()
        self.rx_timer = TimeoutThread()
        self.rx_thread = CANReceiverThread(can_socket, self.on_can_recv)

        self.tx_mutex = Lock()
        self.rx_mutex = Lock()
        self.send_mutex = Lock()

        self.tx_done = Event()
        self.tx_exception = None

        self.tx_callbacks = []
        self.rx_callbacks = []

        self.tx_timer.start()
        self.rx_timer.start()
        self.rx_thread.start()

    def __del__(self):
        self.close()

    def can_send(self, load):
        if self.padding:
            load += bytearray(CAN_MAX_DLEN - len(load))
        self.can_socket.send(CAN(identifier=self.src_id, data=load))

    def on_can_recv(self, p):
        if not isinstance(p, CAN):
            raise Scapy_Exception("argument is not a CAN frame")
        if p.identifier != self.dst_id:
            if not self.filter_warning_emitted:
                warning("You should put a filter for identifier=%x on your"
                        "CAN socket" % self.dst_id)
                self.filter_warning_emitted = True
        else:
            self.on_recv(p)

    def close(self):
        self.rx_timer.stop()
        self.tx_timer.stop()
        self.rx_thread.stop()

    def _rx_timer_handler(self):
        """Method called every time the rx_timer times out, due to the peer not
        sending a consecutive frame within the expected time window"""

        with self.rx_mutex:
            if self.rx_state == ISOTP_WAIT_DATA:
                # we did not get new data frames in time.
                # reset rx state
                self.rx_state = ISOTP_IDLE
                warning("RX state was reset due to timeout")

    def _tx_timer_handler(self):
        """Method called every time the tx_timer times out, which can happen in
        two situations: either a Flow Control frame was not received in time,
        or the Separation Time Min is expired and a new frame must be sent."""

        with self.tx_mutex:
            if (self.tx_state == ISOTP_WAIT_FC or
                    self.tx_state == ISOTP_WAIT_FIRST_FC):
                # we did not get any flow control frame in time
                # reset tx state
                self.tx_state = ISOTP_IDLE
                self.tx_exception = "TX state was reset due to timeout"
                self.tx_done.set()
                raise Scapy_Exception(self.tx_exception)
            elif self.tx_state == ISOTP_SENDING:
                # push out the next segmented pdu
                src_off = len(self.ea_hdr)
                max_bytes = 7 - src_off

                while 1:
                    load = self.ea_hdr
                    load += struct.pack("B", N_PCI_CF + self.tx_sn)
                    load += self.tx_buf[self.tx_idx:self.tx_idx + max_bytes]
                    self.can_send(load)

                    self.tx_sn = (self.tx_sn + 1) % 16
                    self.tx_bs += 1
                    self.tx_idx += max_bytes

                    if len(self.tx_buf) <= self.tx_idx:
                        # we are done
                        self.tx_state = ISOTP_IDLE
                        self.tx_done.set()
                        for cb in self.tx_callbacks:
                            cb()
                        return

                    if self.txfc_bs != 0 and self.tx_bs >= self.txfc_bs:
                        # stop and wait for FC
                        self.tx_state = ISOTP_WAIT_FC
                        self.tx_timer.set_timeout(self.fc_timeout,
                                                  self._tx_timer_handler)
                        return

                    if self.tx_gap == 0:
                        continue
                    else:
                        self.tx_timer.set_timeout(self.tx_gap,
                                                  self._tx_timer_handler)

    def on_recv(self, cf):
        """Function that must be called every time a CAN frame is received, to
        advance the state machine."""

        data = bytes(cf.data)

        if len(data) < 2:
            return

        ae = 0
        if self.extended_rx_addr is not None:
            ae = 1
            if len(data) < 3:
                return
            if six.indexbytes(data, 0) != self.extended_rx_addr:
                return

        n_pci = six.indexbytes(data, ae) & 0xf0

        if n_pci == N_PCI_FC:
            with self.tx_mutex:
                self._recv_fc(data[ae:])
        elif n_pci == N_PCI_SF:
            with self.rx_mutex:
                self._recv_sf(data[ae:])
        elif n_pci == N_PCI_FF:
            with self.rx_mutex:
                self._recv_ff(data[ae:])
        elif n_pci == N_PCI_CF:
            with self.rx_mutex:
                self._recv_cf(data[ae:])

    def _recv_fc(self, data):
        """Process a received 'Flow Control' frame"""
        if (self.tx_state != ISOTP_WAIT_FC and
                self.tx_state != ISOTP_WAIT_FIRST_FC):
            return 0

        self.tx_timer.cancel()

        if len(data) < 3:
            self.tx_state = ISOTP_IDLE
            self.tx_exception = "CF frame discarded because it was too short"
            self.tx_done.set()
            raise Scapy_Exception(self.tx_exception)

        # get communication parameters only from the first FC frame
        if self.tx_state == ISOTP_WAIT_FIRST_FC:
            self.txfc_bs = six.indexbytes(data, 1)
            self.txfc_stmin = six.indexbytes(data, 2)

        if ((self.txfc_stmin > 0x7F) and
                ((self.txfc_stmin < 0xF1) or (self.txfc_stmin > 0xF9))):
            self.txfc_stmin = 0x7F

        if six.indexbytes(data, 2) <= 127:
            tx_gap = six.indexbytes(data, 2) / 1000.0
        elif 0xf1 <= six.indexbytes(data, 2) <= 0xf9:
            tx_gap = (six.indexbytes(data, 2) & 0x0f) / 10000.0
        else:
            tx_gap = 0
        self.tx_gap = tx_gap

        self.tx_state = ISOTP_WAIT_FC

        isotp_fc = six.indexbytes(data, 0) & 0x0f

        if isotp_fc == ISOTP_FC_CTS:
            self.tx_bs = 0
            self.tx_state = ISOTP_SENDING
            # start cyclic timer for sending CF frame
            self.tx_timer.set_timeout(self.tx_gap, self._tx_timer_handler)
        elif isotp_fc == ISOTP_FC_WT:
            # start timer to wait for next FC frame
            self.tx_state = ISOTP_WAIT_FC
            self.tx_timer.set_timeout(self.fc_timeout, self._tx_timer_handler)
        elif isotp_fc == ISOTP_FC_OVFLW:
            # overflow in receiver side
            self.tx_state = ISOTP_IDLE
            self.tx_exception = "Overflow happened at the receiver side"
            self.tx_done.set()
            raise Scapy_Exception(self.tx_exception)
        else:
            self.tx_state = ISOTP_IDLE
            self.tx_exception = "Unknown FC frame type"
            self.tx_done.set()
            raise Scapy_Exception(self.tx_exception)

        return 0

    def _recv_sf(self, data):
        """Process a received 'Single Frame' frame"""
        self.rx_timer.cancel()
        if self.rx_state != ISOTP_IDLE:
            warning("RX state was reset because single frame was received")
            self.rx_state = ISOTP_IDLE

        length = six.indexbytes(data, 0) & 0xf
        if len(data) - 1 < length:
            return 1

        msg = data[1:1 + length]
        self.rx_queue.put(msg)
        for cb in self.rx_callbacks:
            cb(msg)
        self.call_release()
        return 0

    def _recv_ff(self, data):
        """Process a received 'First Frame' frame"""
        self.rx_timer.cancel()
        if self.rx_state != ISOTP_IDLE:
            warning("RX state was reset because first frame was received")
            self.rx_state = ISOTP_IDLE

        if len(data) < 7:
            return 1
        self.rx_ll_dl = len(data)

        # get the FF_DL
        self.rx_len = (six.indexbytes(data, 0) & 0x0f) * 256 + six.indexbytes(
            data, 1)
        ff_pci_sz = 2

        # Check for FF_DL escape sequence supporting 32 bit PDU length
        if self.rx_len == 0:
            # FF_DL = 0 => get real length from next 4 bytes
            self.rx_len = six.indexbytes(data, 2) << 24
            self.rx_len += six.indexbytes(data, 3) << 16
            self.rx_len += six.indexbytes(data, 4) << 8
            self.rx_len += six.indexbytes(data, 5)
            ff_pci_sz = 6

        # copy the first received data bytes
        data_bytes = data[ff_pci_sz:]
        self.rx_idx = len(data_bytes)
        self.rx_buf = data_bytes

        # initial setup for this pdu reception
        self.rx_sn = 1
        self.rx_state = ISOTP_WAIT_DATA

        # no creation of flow control frames
        if not self.listen_only:
            # send our first FC frame
            load = self.ea_hdr
            load += struct.pack("BBB", N_PCI_FC, self.rxfc_bs, self.rxfc_stmin)
            self.can_send(load)

        # wait for a CF
        self.rx_bs = 0
        self.rx_timer.set_timeout(self.cf_timeout, self._rx_timer_handler)

        return 0

    def _recv_cf(self, data):
        """Process a received 'Consecutive Frame' frame"""
        if self.rx_state != ISOTP_WAIT_DATA:
            return 0

        self.rx_timer.cancel()

        # CFs are never longer than the FF
        if len(data) > self.rx_ll_dl:
            return 1

        # CFs have usually the LL_DL length
        if len(data) < self.rx_ll_dl:
            # this is only allowed for the last CF
            if self.rx_len - self.rx_idx > self.rx_ll_dl:
                warning("Received a CF with insuffifient length")
                return 1

        if six.indexbytes(data, 0) & 0x0f != self.rx_sn:
            # Wrong sequence number
            warning("RX state was reset because wrong sequence number was "
                    "received")
            self.rx_state = ISOTP_IDLE
            return 1

        self.rx_sn = (self.rx_sn + 1) % 16
        self.rx_buf += data[1:]
        self.rx_idx = len(self.rx_buf)

        if self.rx_idx >= self.rx_len:
            # we are done
            self.rx_buf = self.rx_buf[0:self.rx_len]
            self.rx_state = ISOTP_IDLE
            self.rx_queue.put(self.rx_buf)
            for cb in self.rx_callbacks:
                cb(self.rx_buf)
            self.call_release()
            self.rx_buf = None
            return 0

        # perform blocksize handling, if enabled
        if self.rxfc_bs != 0:
            self.rx_bs += 1

            # check if we reached the end of the block
            if self.rx_bs >= self.rxfc_bs and not self.listen_only:
                # send our FC frame
                load = self.ea_hdr
                load += struct.pack("BBB", N_PCI_FC, self.rxfc_bs,
                                    self.rxfc_stmin)
                self.can_send(load)

        # wait for another CF
        self.rx_timer.set_timeout(self.cf_timeout, self._rx_timer_handler)
        return 0

    def begin_send(self, x):
        """Begins sending an ISOTP message. This method does not block."""
        with self.tx_mutex:
            if self.tx_state != ISOTP_IDLE:
                raise Scapy_Exception("Socket is already sending, retry later")

            self.tx_done.clear()
            self.tx_exception = None
            self.tx_state = ISOTP_SENDING

            length = len(x)
            if length > ISOTP_MAX_DLEN_2015:
                raise Scapy_Exception("Too much data for ISOTP message")

            if len(self.ea_hdr) + length <= 7:
                # send a single frame
                data = self.ea_hdr
                data += struct.pack("B", length)
                data += x
                self.tx_state = ISOTP_IDLE
                self.can_send(data)
                self.tx_done.set()
                for cb in self.tx_callbacks:
                    cb()
                return

            # send the first frame
            data = self.ea_hdr
            if length > ISOTP_MAX_DLEN:
                data += struct.pack(">HI", 0x1000, length)
            else:
                data += struct.pack(">H", 0x1000 | length)
            load = x[0:8 - len(data)]
            data += load
            self.can_send(data)

            self.tx_buf = x
            self.tx_sn = 1
            self.tx_bs = 0
            self.tx_idx = len(load)

            self.tx_state = ISOTP_WAIT_FIRST_FC
            self.tx_timer.set_timeout(self.fc_timeout, self._tx_timer_handler)

    def send(self, p):
        """Send an ISOTP frame and block until the message is sent or an error
        happens."""
        with self.send_mutex:
            self.begin_send(p)

            # Wait until the tx callback is called
            self.tx_done.wait()
            if self.tx_exception is not None:
                raise Scapy_Exception(self.tx_exception)
            return

    def recv(self, timeout=None):
        """Receive an ISOTP frame, blocking if none is available in the buffer
        for at most 'timeout' seconds."""

        try:
            return self.rx_queue.get(timeout is None or timeout > 0, timeout)
        except queue.Empty:
            return None

    def check_recv(self):
        """Implementation for SelectableObject"""
        return not self.rx_queue.empty()


if six.PY3 and LINUX:

    from scapy.arch.linux import get_last_packet_timestamp, SIOCGIFINDEX

    """ISOTPNativeSocket definitions:"""

    CAN_ISOTP = 6  # ISO 15765-2 Transport Protocol

    SOL_CAN_BASE = 100  # from can.h
    SOL_CAN_ISOTP = SOL_CAN_BASE + CAN_ISOTP
    # /* for socket options affecting the socket (not the global system) */
    CAN_ISOTP_OPTS = 1  # /* pass struct can_isotp_options */
    CAN_ISOTP_RECV_FC = 2  # /* pass struct can_isotp_fc_options */

    # /* sockopts to force stmin timer values for protocol regression tests */
    CAN_ISOTP_TX_STMIN = 3  # /* pass __u32 value in nano secs    */
    CAN_ISOTP_RX_STMIN = 4  # /* pass __u32 value in nano secs   */
    CAN_ISOTP_LL_OPTS = 5  # /* pass struct can_isotp_ll_options */

    CAN_ISOTP_LISTEN_MODE = 0x001  # /* listen only (do not send FC) */
    CAN_ISOTP_EXTEND_ADDR = 0x002  # /* enable extended addressing */
    CAN_ISOTP_TX_PADDING = 0x004  # /* enable CAN frame padding tx path */
    CAN_ISOTP_RX_PADDING = 0x008  # /* enable CAN frame padding rx path */
    CAN_ISOTP_CHK_PAD_LEN = 0x010  # /* check received CAN frame padding */
    CAN_ISOTP_CHK_PAD_DATA = 0x020  # /* check received CAN frame padding */
    CAN_ISOTP_HALF_DUPLEX = 0x040  # /* half duplex error state handling */
    CAN_ISOTP_FORCE_TXSTMIN = 0x080  # /* ignore stmin from received FC */
    CAN_ISOTP_FORCE_RXSTMIN = 0x100  # /* ignore CFs depending on rx stmin */
    CAN_ISOTP_RX_EXT_ADDR = 0x200  # /* different rx extended addressing */

    # /* default values */
    CAN_ISOTP_DEFAULT_FLAGS = 0
    CAN_ISOTP_DEFAULT_EXT_ADDRESS = 0x00
    CAN_ISOTP_DEFAULT_PAD_CONTENT = 0xCC  # /* prevent bit-stuffing */
    CAN_ISOTP_DEFAULT_FRAME_TXTIME = 0
    CAN_ISOTP_DEFAULT_RECV_BS = 0
    CAN_ISOTP_DEFAULT_RECV_STMIN = 0x00
    CAN_ISOTP_DEFAULT_RECV_WFTMAX = 0
    CAN_ISOTP_DEFAULT_LL_MTU = CAN_MTU
    CAN_ISOTP_DEFAULT_LL_TX_DL = CAN_MAX_DLEN
    CAN_ISOTP_DEFAULT_LL_TX_FLAGS = 0

    class SOCKADDR(ctypes.Structure):
        # See /usr/include/i386-linux-gnu/bits/socket.h for original struct
        _fields_ = [("sa_family", ctypes.c_uint16),
                    ("sa_data", ctypes.c_char * 14)]

    class TP(ctypes.Structure):
        # This struct is only used within the SOCKADDR_CAN struct
        _fields_ = [("rx_id", ctypes.c_uint32),
                    ("tx_id", ctypes.c_uint32)]

    class ADDR_INFO(ctypes.Union):
        # This struct is only used within the SOCKADDR_CAN struct
        # This union is to future proof for future can address information
        _fields_ = [("tp", TP)]

    class SOCKADDR_CAN(ctypes.Structure):
        # See /usr/include/linux/can.h for original struct
        _fields_ = [("can_family", ctypes.c_uint16),
                    ("can_ifindex", ctypes.c_int),
                    ("can_addr", ADDR_INFO)]

    class IFREQ(ctypes.Structure):
        # The two fields in this struct were originally unions.
        # See /usr/include/net/if.h for original struct
        _fields_ = [("ifr_name", ctypes.c_char * 16),
                    ("ifr_ifindex", ctypes.c_int)]

    class ISOTPNativeSocket(SuperSocket):
        desc = "read/write packets at a given CAN interface using CAN_ISOTP " \
               "socket "
        can_isotp_options_fmt = "@2I4B"
        can_isotp_fc_options_fmt = "@3B"
        can_isotp_ll_options_fmt = "@3B"
        sockaddr_can_fmt = "@H3I"

        def __build_can_isotp_options(
                self,
                flags=CAN_ISOTP_DEFAULT_FLAGS,
                frame_txtime=0,
                ext_address=CAN_ISOTP_DEFAULT_EXT_ADDRESS,
                txpad_content=0,
                rxpad_content=0,
                rx_ext_address=CAN_ISOTP_DEFAULT_EXT_ADDRESS):
            return struct.pack(self.can_isotp_options_fmt,
                               flags,
                               frame_txtime,
                               ext_address,
                               txpad_content,
                               rxpad_content,
                               rx_ext_address)

        # == Must use native not standard types for packing ==
        # struct can_isotp_options {
        # __u32 flags;            /* set flags for isotp behaviour.       */
        #                         /* __u32 value : flags see below        */
        #
        # __u32 frame_txtime;     /* frame transmission time (N_As/N_Ar)  */
        #                       /* __u32 value : time in nano secs      */
        #
        # __u8  ext_address;      /* set address for extended addressing  */
        #                         /* __u8 value : extended address        */
        #
        # __u8  txpad_content;    /* set content of padding byte (tx)     */
        #                         /* __u8 value : content on tx path      */
        #
        # __u8  rxpad_content;    /* set content of padding byte (rx)     */
        #                         /* __u8 value : content on rx path      */
        #
        # __u8  rx_ext_address;   /* set address for extended addressing  */
        #                         /* __u8 value : extended address (rx)   */
        # };

        def __build_can_isotp_fc_options(self,
                                         bs=CAN_ISOTP_DEFAULT_RECV_BS,
                                         stmin=CAN_ISOTP_DEFAULT_RECV_STMIN,
                                         wftmax=CAN_ISOTP_DEFAULT_RECV_WFTMAX):
            return struct.pack(self.can_isotp_fc_options_fmt,
                               bs,
                               stmin,
                               wftmax)

        # == Must use native not standard types for packing ==
        # struct can_isotp_fc_options {
        #
        # __u8  bs;               /* blocksize provided in FC frame       */
        #                         /* __u8 value : blocksize. 0 = off      */
        #
        # __u8  stmin;            /* separation time provided in FC frame */
        #                         /* __u8 value :                         */
        #                         /* 0x00 - 0x7F : 0 - 127 ms             */
        #                         /* 0x80 - 0xF0 : reserved               */
        #                         /* 0xF1 - 0xF9 : 100 us - 900 us        */
        #                         /* 0xFA - 0xFF : reserved               */
        #
        # __u8  wftmax;           /* max. number of wait frame transmiss. */
        #                         /* __u8 value : 0 = omit FC N_PDU WT    */
        # };

        def __build_can_isotp_ll_options(self,
                                         mtu=CAN_ISOTP_DEFAULT_LL_MTU,
                                         tx_dl=CAN_ISOTP_DEFAULT_LL_TX_DL,
                                         tx_flags=CAN_ISOTP_DEFAULT_LL_TX_FLAGS
                                         ):
            return struct.pack(self.can_isotp_ll_options_fmt,
                               mtu,
                               tx_dl,
                               tx_flags)

        # == Must use native not standard types for packing ==
        # struct can_isotp_ll_options {
        #
        # __u8  mtu;              /* generated & accepted CAN frame type  */
        #                         /* __u8 value :                         */
        #                         /* CAN_MTU   (16) -> standard CAN 2.0   */
        #                         /* CANFD_MTU (72) -> CAN FD frame       */
        #
        # __u8  tx_dl;            /* tx link layer data length in bytes   */
        #                         /* (configured maximum payload length)  */
        #                         /* __u8 value : 8,12,16,20,24,32,48,64  */
        #                         /* => rx path supports all LL_DL values */
        #
        # __u8  tx_flags;         /* set into struct canfd_frame.flags    */
        #                         /* at frame creation: e.g. CANFD_BRS    */
        #                         /* Obsolete when the BRS flag is fixed  */
        #                         /* by the CAN netdriver configuration   */
        # };

        def __get_sock_ifreq(self, sock, iface):
            socket_id = ctypes.c_int(sock.fileno())
            ifr = IFREQ()
            ifr.ifr_name = iface.encode('ascii')
            ret = LIBC.ioctl(socket_id, SIOCGIFINDEX, ctypes.byref(ifr))

            if ret < 0:
                m = u'Failure while getting "{}" interface index.'.format(
                    iface)
                raise Scapy_Exception(m)
            return ifr

        def __bind_socket(self, sock, iface, sid, did):
            socket_id = ctypes.c_int(sock.fileno())
            ifr = self.__get_sock_ifreq(sock, iface)

            if sid > 0x7ff:
                sid = sid | socket.CAN_EFF_FLAG
            if did > 0x7ff:
                did = did | socket.CAN_EFF_FLAG

            # select the CAN interface and bind the socket to it
            addr = SOCKADDR_CAN(ctypes.c_uint16(socket.PF_CAN),
                                ifr.ifr_ifindex,
                                ADDR_INFO(TP(ctypes.c_uint32(did),
                                             ctypes.c_uint32(sid))))

            error = LIBC.bind(socket_id, ctypes.byref(addr),
                              ctypes.sizeof(addr))

            if error < 0:
                warning("Couldn't bind socket")

        def __set_option_flags(self, sock, extended_addr=None,
                               extended_rx_addr=None,
                               listen_only=False,
                               padding=False,
                               transmit_time=100):
            option_flags = CAN_ISOTP_DEFAULT_FLAGS
            if extended_addr is not None:
                option_flags = option_flags | CAN_ISOTP_EXTEND_ADDR
            else:
                extended_addr = CAN_ISOTP_DEFAULT_EXT_ADDRESS

            if extended_rx_addr is not None:
                option_flags = option_flags | CAN_ISOTP_RX_EXT_ADDR
            else:
                extended_rx_addr = CAN_ISOTP_DEFAULT_EXT_ADDRESS

            if listen_only:
                option_flags = option_flags | CAN_ISOTP_LISTEN_MODE

            if padding:
                option_flags = option_flags | CAN_ISOTP_TX_PADDING \
                                            | CAN_ISOTP_RX_PADDING

            sock.setsockopt(SOL_CAN_ISOTP,
                            CAN_ISOTP_OPTS,
                            self.__build_can_isotp_options(
                                frame_txtime=transmit_time,
                                flags=option_flags,
                                ext_address=extended_addr,
                                rx_ext_address=extended_rx_addr))

        def __init__(self,
                     iface=None,
                     sid=0,
                     did=0,
                     extended_addr=None,
                     extended_rx_addr=None,
                     listen_only=False,
                     padding=False,
                     transmit_time=100,
                     basecls=ISOTP):
            self.iface = conf.contribs['NativeCANSocket']['iface'] \
                if iface is None else iface
            self.can_socket = socket.socket(socket.PF_CAN, socket.SOCK_DGRAM,
                                            CAN_ISOTP)
            self.__set_option_flags(self.can_socket,
                                    extended_addr,
                                    extended_rx_addr,
                                    listen_only,
                                    padding,
                                    transmit_time)

            self.src = sid
            self.dst = did
            self.exsrc = extended_addr
            self.exdst = extended_rx_addr

            self.can_socket.setsockopt(SOL_CAN_ISOTP,
                                       CAN_ISOTP_RECV_FC,
                                       self.__build_can_isotp_fc_options())
            self.can_socket.setsockopt(SOL_CAN_ISOTP,
                                       CAN_ISOTP_LL_OPTS,
                                       self.__build_can_isotp_ll_options())

            self.__bind_socket(self.can_socket, iface, sid, did)
            self.ins = self.can_socket
            self.outs = self.can_socket
            if basecls is None:
                warning('Provide a basecls ')
            self.basecls = basecls

        def recv_raw(self, x=0xffff):
            """
            Receives a packet, then returns a tuple containing
            (cls, pkt_data, time)
            """  # noqa: E501
            try:
                pkt = self.can_socket.recvfrom(x)[0]
            except BlockingIOError:  # noqa: F821
                warning('Captured no data, socket in non-blocking mode.')
                return None
            except socket.timeout:
                warning('Captured no data, socket read timed out.')
                return None
            except OSError:
                # something bad happened (e.g. the interface went down)
                warning("Captured no data.")
                return None

            ts = get_last_packet_timestamp(self.can_socket)
            return self.basecls, pkt, ts

        def recv(self, x=0xffff):
            msg = SuperSocket.recv(self, x)

            if hasattr(msg, "src"):
                msg.src = self.src
            if hasattr(msg, "dst"):
                msg.dst = self.dst
            if hasattr(msg, "exsrc"):
                msg.exsrc = self.exsrc
            if hasattr(msg, "exdst"):
                msg.exdst = self.exdst
            return msg

    __all__.append("ISOTPNativeSocket")

if USE_CAN_ISOTP_KERNEL_MODULE:
    ISOTPSocket = ISOTPNativeSocket


# ###################################################################
# #################### ISOTPSCAN ####################################
# ###################################################################
def send_multiple_ext(sock, ext_id, packet, number_of_packets):
    """ Send multiple packets with extended addresses at once

    Args:
        sock: socket for can interface
        ext_id: extended id. First id to send.
        packet: packet to send
        number_of_packets: number of packets send

    This function is used for scanning with extended addresses.
    It sends multiple packets at once. The number of packets
    is defined in the number_of_packets variable.
    It only iterates the extended ID, NOT the actual ID of the packet.
    This method is used in extended scan function.
    """
    end_id = min(ext_id + number_of_packets, 255)
    for i in range(ext_id, end_id + 1):
        packet.extended_address = i
        sock.send(packet)


def get_isotp_packet(identifier=0x0, extended=False, extended_can_id=False):
    """ Craft ISO TP packet
    Args:
        identifier: identifier of crafted packet
        extended: boolean if packet uses extended address
        extended_can_id: boolean if CAN should use extended Ids
    """

    if extended:
        pkt = ISOTPHeaderEA() / ISOTP_FF()
        pkt.extended_address = 0
        pkt.data = b'\x00\x00\x00\x00\x00'
    else:
        pkt = ISOTPHeader() / ISOTP_FF()
        pkt.data = b'\x00\x00\x00\x00\x00\x00'
    if extended_can_id:
        pkt.flags = "extended"

    pkt.identifier = identifier
    pkt.message_size = 100
    return pkt


def filter_periodic_packets(packet_dict, verbose=False):
    """ Filter for periodic packets

    Args:
        packet_dict: Dictionary with Send-to-ID as key and a tuple
                     (received packet, Recv_ID)
        verbose: Displays further information

    ISOTP-Filter for periodic packets (same ID, always same timegap)
    Deletes periodic packets in packet_dict
    """
    filter_dict = {}

    for key, value in packet_dict.items():
        pkt = value[0]
        idn = value[1]
        if idn not in filter_dict:
            filter_dict[idn] = ([key], [pkt])
        else:
            key_lst, pkt_lst = filter_dict[idn]
            filter_dict[idn] = (key_lst + [key], pkt_lst + [pkt])

    for idn in filter_dict:
        key_lst = filter_dict[idn][0]
        pkt_lst = filter_dict[idn][1]
        if len(pkt_lst) < 3:
            continue

        tg = [p1.time - p2.time for p1, p2 in zip(pkt_lst[1:], pkt_lst[:-1])]
        if all(abs(t1 - t2) < 0.001 for t1, t2 in zip(tg[1:], tg[:-1])):
            if verbose:
                print("[i] Identifier 0x%03x seems to be periodic. "
                      "Filtered.")
            for k in key_lst:
                del packet_dict[k]


def get_isotp_fc(id_value, id_list, noise_ids, extended, packet,
                 verbose=False):
    """Callback for sniff function when packet received

    Args:
            id_value: packet id of send packet
            id_list: list of received IDs
            noise_ids: list of packet IDs which will not be considered when
                       received during scan
            extended: boolean if extended scan
            packet: received packet
            verbose: displays information during scan

    If received packet is a FlowControl
    and not in noise_ids
    append it to id_list
    """
    if packet.flags and packet.flags != "extended":
        return

    if noise_ids is not None and packet.identifier in noise_ids:
        return

    try:
        index = 1 if extended else 0
        isotp_pci = orb(packet.data[index]) >> 4
        isotp_fc = orb(packet.data[index]) & 0x0f
        if isotp_pci == 3 and 0 <= isotp_fc <= 2:
            if verbose:
                print("[+] Found flow-control frame from identifier 0x%03x"
                      " when testing identifier 0x%03x" %
                      (packet.identifier, id_value))
            if isinstance(id_list, dict):
                id_list[id_value] = (packet, packet.identifier)
            elif isinstance(id_list, list):
                id_list.append(id_value)
            else:
                raise TypeError("Unknown type of id_list")
        else:
            noise_ids.append(packet.identifier)
    except Exception as e:
        print("[!] Unknown message Exception: %s on packet: %s" %
              (e, repr(packet)))


def scan(sock, scan_range=range(0x800), noise_ids=None, sniff_time=0.1,extended_can_id=False,
         verbose=False):
    """Scan and return dictionary of detections

    Args:
            sock: socket for can interface
            scan_range: hexadecimal range of IDs to scan.
                        Default is 0x0 - 0x7ff
            noise_ids: list of packet IDs which will not be considered when
                       received during scan
            sniff_time: time the scan waits for isotp flow control responses
                        after sending a first frame
            verbose: displays information during scan

    ISOTP-Scan - NO extended IDs
    found_packets = Dictionary with Send-to-ID as
    key and a tuple (received packet, Recv_ID)
    """
    return_values = dict()
    for value in scan_range:
        sock.sniff(prn=lambda pkt: get_isotp_fc(value, return_values,
                                                noise_ids, False, pkt,
                                                verbose),
                   timeout=sniff_time,
                   started_callback=lambda: sock.send(
                       get_isotp_packet(value, extended_can_id=extended_can_id)))
    return return_values


def scan_extended(sock, scan_range=range(0x800), scan_block_size=100,
                  noise_ids=None, sniff_time=0.1, extended_can_id=False, verbose=False):
    """Scan with extended addresses and return dictionary of detections

    Args:
            sock: socket for can interface
            scan_range: hexadecimal range of IDs to scan.
                        Default is 0x0 - 0x7ff
            scan_block_size: count of packets send at once
            noise_ids: list of packet IDs which will not be considered when
                       received during scan
            sniff_time: time the scan waits for isotp flow control responses
                        after sending a first frame
            extended_can_id: Send extended can frames
            verbose: displays information during scan

    If an answer-packet found -> slow scan with
    single packages with extended ID 0 - 255
    found_packets = Dictionary with Send-to-ID
    as key and a tuple (received packet, Recv_ID)
    """

    return_values = dict()
    scan_block_size = scan_block_size or 1

    for value in scan_range:
        pkt = get_isotp_packet(value, extended=True)
        if extended_can_id:
            pkt.flags = "extended"
        id_list = []

        for extended_id in range(0, 256, scan_block_size):
            sock.sniff(prn=lambda p: get_isotp_fc(extended_id, id_list,
                                                  noise_ids, True, p,
                                                  verbose),
                       timeout=sniff_time * 3,
                       started_callback=send_multiple_ext(sock, extended_id,
                                                          pkt,
                                                          scan_block_size))
            # sleep to prevent flooding
            time.sleep(1)

        # remove duplicate IDs
        id_list = list(set(id_list))
        for extended_id in id_list:
            for ext_id in range(extended_id, min(extended_id +
                                                 scan_block_size, 256)):
                pkt.extended_address = ext_id
                full_id = (value << 8) + ext_id
                sock.sniff(prn=lambda pkt: get_isotp_fc(full_id,
                                                        return_values,
                                                        noise_ids, True,
                                                        pkt, verbose),
                           timeout=sniff_time,
                           started_callback=lambda: sock.send(pkt))
    return return_values


def ISOTPScan(sock, scan_range=range(0x7ff + 1), extended_addressing=False,
              noise_listen_time=2,
              sniff_time=0.1,
              output_format=None,
              can_interface="can0",
              extended_can_id=False,
              verbose=False):

    """Scan for ISOTP Sockets on a bus and return findings

    Args:
        sock: CANSocket object to communicate with the bus under scan
        scan_range: hexadecimal range of CAN-Identifiers to scan.
                    Default is 0x0 - 0x7ff
        extended_addressing: scan with ISOTP extended addressing
        noise_listen_time: seconds to listen for default
                           communication on the bus
        sniff_time: time the scan waits for isotp flow control responses
                    after sending a first frame
        output_format: defines the format of the returned
                       results (text, code or sockets). Provide a string
                       e.g. "text". Default is "socket".
        can_interface: interface used to create the returned code/sockets
        extended_can_ids: Use Extended CAN-Frames
        verbose: displays information during scan

    Scan for ISOTP Sockets in the defined range and returns found sockets
    in a specified format. The format can be:

    - text: human readable output
    - code: python code for copy&paste
    - sockets: if output format is not specified, ISOTPSockets will be
      created and returned in a list
    """

    if verbose:
        print("Filtering background noise...")

    # Send dummy packet. In most cases, this triggers activity on the bus.

    dummy_pkt = CAN(identifier=0x123,
                data=b'\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb')
    if extended_can_id:
        dummy_pkt.flags = "extended"

    background_pkts = sock.sniff(timeout=noise_listen_time,
                                 started_callback=lambda:
                                 sock.send(dummy_pkt))

    noise_ids = list(set(pkt.identifier for pkt in background_pkts))

    if extended_addressing:
        found_packets = scan_extended(sock, scan_range, noise_ids=noise_ids,
                                      sniff_time=sniff_time, extended_can_id=extended_can_id, verbose=verbose)
    else:
        found_packets = scan(sock, scan_range, noise_ids=noise_ids,
                             sniff_time=sniff_time, extended_can_id=extended_can_id, verbose=verbose)

    filter_periodic_packets(found_packets, verbose)

    if output_format == "text":
        return generate_text_output(found_packets)
    if output_format == "code":
        return generate_code_output(found_packets, can_interface)
    return generate_isotp_list(found_packets, can_interface)


def generate_text_output(found_packets):
    """Generate a human readable output from the result of the `scan` or
        the `scan_extended` function.

        Args:
                found_packets: result of the `scan` or `scan_extended` function
    """
    if not found_packets:
        return "No packets found."

    text = "\nFound %s ISOTP-FlowControl Packet(s):" % len(found_packets)
    for pack in found_packets:
        extended_id = pack > 0x7ff
        if extended_id:
            send_id = pack // 256
            send_ext = pack - (send_id * 256)
            ext_id = hex(orb(found_packets[pack][0].data[0]))
            text += "\nSend to ID:             %s" \
                    "\nSend to extended ID:    %s" \
                    "\nReceived ID:            %s" \
                    "\nReceived extended ID:   %s" \
                    "\nMessage:                %s" % \
                    (hex(send_id), hex(send_ext),
                     hex(found_packets[pack][0].identifier), ext_id,
                     repr(found_packets[pack][0]))
        else:
            text += "\nSend to ID:             %s" \
                    "\nReceived ID:            %s" \
                    "\nMessage:                %s" % \
                    (hex(pack),
                     hex(found_packets[pack][0].identifier),
                     repr(found_packets[pack][0]))

        padding = found_packets[pack][0].length == 8
        if padding:
            text += "\nPadding enabled"
        else:
            text += "\nNo Padding"

        text += "\n"
    return text


def generate_code_output(found_packets, can_interface):
    """Generate a copy&past-able output from the result of the `scan` or
        the `scan_extended` function.

        Args:
                found_packets: result of the `scan` or `scan_extended` function
                can_interface: description string for a CAN interface to be
                                used for the creation of the output.
    """
    result = ""
    if not found_packets:
        return result

    header = "\n\nimport can\n" \
             "conf.contribs['CANSocket'] = {'use-python-can': %s}\n" \
             "load_contrib('cansocket')\n" \
             "load_contrib('isotp')\n\n" % PYTHON_CAN

    for pack in found_packets:
        extended_id = pack > 0x7ff
        if extended_id:
            send_id = pack // 256
            send_ext = pack - (send_id * 256)
            ext_id = orb(found_packets[pack][0].data[0])
            result += "ISOTPSocket(%s, sid=%s, did=%s, padding=%s, " \
                      "extended_addr=%s, extended_rx_addr=%s, " \
                      "basecls=ISOTP)\n" % \
                      (can_interface, hex(send_id),
                       hex(int(found_packets[pack][0].identifier)),
                       found_packets[pack][0].length == 8,
                       hex(send_ext),
                       hex(ext_id))

        else:
            result += "ISOTPSocket(%s, sid=%s, did=%s, padding=%s, " \
                      "basecls=ISOTP)\n" % \
                      (can_interface, hex(pack),
                       hex(int(found_packets[pack][0].identifier)),
                       found_packets[pack][0].length == 8)
    return header + result


def generate_isotp_list(found_packets, can_interface):
    """Generate a list of ISOTPSocket objects from the result of the `scan` or
        the `scan_extended` function.

        Args:
            found_packets: result of the `scan` or `scan_extended` function
            can_interface: description string for a CAN interface to be
                            used for the creation of the output.
    """
    socket_list = []
    for pack in found_packets:
        extended_id = pack > 0x7ff
        pkt = found_packets[pack][0]

        dest_id = pkt.identifier
        pad = True if pkt.length == 8 else False

        if extended_id:
            source_id = pack >> 8
            source_ext = int(pack - (source_id * 256))
            dest_ext = orb(pkt.data[0])
            socket_list.append(ISOTPSocket(can_interface, sid=source_id,
                                           extended_addr=source_ext,
                                           did=dest_id,
                                           extended_rx_addr=dest_ext,
                                           padding=pad,
                                           basecls=ISOTP))
        else:
            source_id = pack
            socket_list.append(ISOTPSocket(can_interface, sid=source_id,
                                           did=dest_id, padding=pad,
                                           basecls=ISOTP))
    return socket_list
