#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Enrico Pozzobon <enricopozzobon@gmail.com>
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
from threading import Thread, Event, RLock

from scapy.packet import Packet
from scapy.fields import BitField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField, ConditionalField, \
    BitEnumField, ByteField, XByteField, BitFieldLenField, StrField
from scapy.compat import chb, orb
from scapy.layers.can import CAN
import scapy.modules.six as six
from scapy.error import Scapy_Exception, warning, log_loading
from scapy.supersocket import SuperSocket
from scapy.config import conf
from scapy.consts import LINUX

__all__ = ["ISOTP", "ISOTPHeader", "ISOTPHeaderEA", "ISOTP_SF", "ISOTP_FF",
           "ISOTP_CF", "ISOTP_FC", "ISOTPSniffer", "ISOTPSoftSocket",
           "ISOTPSocket", "ISOTPSocketImplementation", "ISOTPMessageBuilder"]

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
        assert (len(can_frames) > 0)

        dst = can_frames[0].identifier
        for frame in can_frames:
            if frame.identifier != dst:
                warning("Not all CAN frames have the same identifier")

        parser = ISOTPMessageBuilder(use_extended_addressing)
        for c in can_frames:
            parser.feed(c)

        results = []
        while parser.count() > 0:
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

    def post_build(self, p, pay):
        """
        This will set the ByteField 'length' to the correct value.
        """
        if self.length is None:
            p = p[:4] + chb(len(pay)) + p[5:]
        return p + pay

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


class ISOTPMessageBuilder:
    """
    Utility class to build ISOTP messages out of CAN frames, used by both
    ISOTP.defragment() and ISOTPSniffer.sniff().

    This class attempts to interpret some CAN frames as ISOTP frames, both with
    and without extended addressing at the same time. For example, if an
    extended address of 07 is being used, all frames will also be interpreted
    as ISOTP single-frame messages.

    CAN frames are fed to an ISOTPMessageBuilder object with the feed() method
    and the resulting ISOTP frames can be extracted using the pop() method.
    """

    class Bucket:
        def __init__(self, total_len, first_piece):
            self.pieces = [first_piece]
            self.total_len = total_len
            self.current_len = len(first_piece)
            self.ready = None

        def push(self, piece):
            self.pieces.append(piece)
            self.current_len += len(piece)
            if self.current_len >= self.total_len:
                if six.PY3:
                    isotp_data = b"".join(self.pieces)
                else:
                    isotp_data = "".join(map(str, self.pieces))
                self.ready = isotp_data[:self.total_len]

    def __init__(self, use_ext_addr=None):
        """
        Initialize a ISOTPMessageBuilder object
        :param use_ext_addr: True for only attempting to defragment with
        extended addressing, False for only attempting to defragment without
        extended addressing, or None for both
        """
        self.ready = []
        self.buckets = {}
        self.use_ext_addr = use_ext_addr

    def feed(self, can):
        """Attempt to feed an incoming CAN frame into the state machine"""
        assert(isinstance(can, CAN))
        identifier = can.identifier
        data = bytes(can.data)

        if len(data) > 1 and self.use_ext_addr is not True:
            self._try_feed(identifier, None, data)
        if len(data) > 2 and self.use_ext_addr is not False:
            ea = six.indexbytes(data, 0)
            self._try_feed(identifier, ea, data[1:])

    def count(self):
        """Returns the number of ready ISOTP messages built from the provided
        can frames"""
        return len(self.ready)

    def pop(self, identifier=None, ext_addr=None, basecls=ISOTP):
        """
        Returns a built ISOTP message
        :param identifier: if not None, only return isotp messages with this
                           destination
        :param ext_addr: if identifier is not None, only return isotp messages
                         with this extended address for destination
        :param basecls: the class of packets that will be returned, defautls to
                        ISOTP
        :return: an ISOTP packet, or None if no message is ready
        """

        if identifier is not None:
            for i in range(len(self.ready)):
                b = self.ready[i]
                identifier = b[0]
                ea = b[1]
                if identifier == identifier and ext_addr == ea:
                    return ISOTPMessageBuilder._build(self.ready.pop(i))
            return None

        if len(self.ready) > 0:
            return ISOTPMessageBuilder._build(self.ready.pop(0))
        return None

    @staticmethod
    def _build(t, basecls=ISOTP):
        return basecls(dst=t[0], exdst=t[1], data=t[2])

    def _feed_first_frame(self, identifier, ea, data):
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
        self.buckets[key] = self.Bucket(expected_length, isotp_data)
        return True

    def _feed_single_frame(self, identifier, ea, data):
        if len(data) < 2:
            # At least 2 bytes are necessary: 1 for length and 1 for data
            return False

        length = six.indexbytes(data, 0) & 0x0f
        isotp_data = data[1:length + 1]

        if length > len(isotp_data):
            # CAN frame has less data than expected
            return False

        self.ready.append((identifier, ea, isotp_data))
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
            self.ready.append((identifier, ea, bucket.ready))

        return True

    def _try_feed(self, identifier, ea, data):
        first_byte = six.indexbytes(data, 0)
        if len(data) > 1 and first_byte & 0xf0 == N_PCI_SF:
            self._feed_single_frame(identifier, ea, data)
        if len(data) > 2 and first_byte & 0xf0 == N_PCI_FF:
            self._feed_first_frame(identifier, ea, data)
        if len(data) > 1 and first_byte & 0xf0 == N_PCI_CF:
            self._feed_consecutive_frame(identifier, ea, data)


class ISOTPSniffer:
    """
    ISOTPSniffer - convenience class for sniffing any ISOTP message out of a
    CAN socket.

    Since an ISOTPSocket requires source and destination CAN identifiers and
    extended addresses in order to sniff messages, it is unsuitable for
    sniffing all ISOTP on a CAN socket without knowledge of such information.
    """

    class Closure:
        def __init__(self):
            self.count = 0
            self.stop = False
            self.max_count = 0
            self.lst = []

    @staticmethod
    def sniff(opened_socket, count=0, store=True, timeout=None,
              prn=None, stop_filter=None, lfilter=None, started_callback=None):
        from scapy import plist
        m = ISOTPMessageBuilder()
        c = ISOTPSniffer.Closure()
        c.max_count = count

        def internal_prn(p):
            m.feed(p)
            while not c.stop and m.count() > 0:
                rcvd = m.pop()
                on_pkt(rcvd)

        def internal_stop_filter(p):
            return c.stop

        def on_pkt(p):
            if lfilter and not lfilter(p):
                return
            p.sniffed_on = opened_socket
            if store:
                c.lst.append(p)
            c.count += 1
            if prn is not None:
                r = prn(p)
                if r is not None:
                    print(r)
            if stop_filter and stop_filter(p):
                c.stop = True
                return
            if 0 < c.max_count <= c.count:
                c.stop = True
                return

        opened_socket.sniff(timeout=timeout, prn=internal_prn,
                            stop_filter=internal_stop_filter,
                            started_callback=started_callback)
        return plist.PacketList(c.lst, "Sniffed")


class ISOTPSoftSocket(SuperSocket):
    """
    Implements an ISOTP socket using a CAN socket. A thread is used to
    receive CAN frames and send Flow Control frames. The thread is stopped
    when calling the close() function or when this object is destructed.
    """

    def __init__(self,
                 can_socket=None,
                 sid=0,
                 did=0,
                 extended_addr=None,
                 extended_rx_addr=None,
                 timeout=1,
                 rx_block_size=0,
                 rx_separation_time_min=0,
                 padding=False,
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
        :param timeout: maximum time to wait for a packet when calling recv()
                        (can be None for infinite time)
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

        self.src = sid
        self.dst = did
        self.exsrc = extended_addr
        self.exdst = extended_rx_addr
        self.timeout = timeout
        self.filter_warning_emitted = False

        def can_send(load):
            if padding:
                load += bytearray(CAN_MAX_DLEN - len(load))
            can_socket.send(CAN(identifier=sid, data=load))

        def can_on_recv(p):
            assert(isinstance(p, CAN))
            if p.identifier != did:
                if not self.filter_warning_emitted:
                    warning("You should put a filter for identifier=%x on your"
                            "CAN socket" % did)
                    self.filter_warning_emitted = True
            else:
                self.ins.on_recv(p)

        self.ins = ISOTPSocketImplementation(
            can_send,
            extended_addr=extended_addr,
            extended_rx_addr=extended_rx_addr,
            rx_block_size=rx_block_size,
            rx_separation_time_min=rx_separation_time_min
        )

        self.outs = self.ins

        self.can_socket = can_socket
        self.rx_thread = CANReceiverThread(can_socket, can_on_recv)
        self.rx_thread.start()

        if basecls is None:
            warning('Provide a basecls ')
        self.basecls = basecls

    def close(self):
        """Close the socket and stop the receiving thread"""
        self.can_socket.close()
        self.rx_thread.stop()
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
        return self.basecls, self.ins.recv(self.timeout), time.time()

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
        """This function is called during sendrecv() routine to select
        the available sockets.
        """
        # ISOTPSoftSockets aren't selectable, so we return all of them
        # sockets, None (means use the socket's recv() )
        return sockets, None


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

        Thread.__init__(self)
        self.name = "CANReceiver" + self.name

    def run(self):
        ins = self.socket

        while 1:
            ins.sniff(store=False, timeout=1,
                      stop_filter=lambda x: self.exiting,
                      prn=self.callback)
            if self.exiting:
                return

    def stop(self):
        self.exiting = True


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


class ISOTPSocketImplementation:
    """
    Implementation of an ISOTP "state machine".

    Most of the ISOTP logic was taken from
    https://github.com/hartkopp/can-isotp/blob/master/net/can/isotp.c

    This class only contains logic and timing for receiving and sending ISOTP
    messages, but doesn't implement the actual CAN input/output.

    Received CAN frames should be provided to this object using the on_recv()
    method.
    A provided callback function will be called every time a CAN frame should
    be sent for both data frames and flow control (e.g. ACK) frames.
    """

    class Timer:
        """
        Utility class implementing a timer, useful for both timeouts and
        waiting between sent CAN frames.
        A timer is initialized with a callback function to call when the timer
        expires.
        """

        def __init__(self, callback):
            self._thread = None
            self._event = Event()
            self._callback = callback
            self._completed = True

        @staticmethod
        def _wait(self, event, timeout, callback):
            f = None
            try:
                f = event.wait(timeout)

            finally:
                self._completed = True
                if f is False:
                    # A timeout happened
                    callback()

        def start(self, timeout):
            """Starts the timer with the provided timeout, in seconds."""
            if not self._completed:
                raise Scapy_Exception("Timer was already started")

            self._event.clear()
            self._thread = Thread(target=ISOTPSocketImplementation.Timer._wait,
                                  args=(
                                      self, self._event, timeout,
                                      self._callback))
            self._completed = False
            self._thread.name = "ISOTP Timer " + self._thread.name
            self._thread.start()

        def cancel(self):
            """This method can be used to stop the timer without executing the
            callback."""
            self._event.set()
            if self._thread is not None:
                self._thread.join()

    class BlockingCallback:
        """
        Utility class to create callback objects that can be waited on until
        they are executed on another thread.
        """

        def __init__(self):
            self._event = Event()
            self.args = None
            self.kwargs = None

        def wait(self, timeout=None):
            """Wait until this object is called."""
            return self._event.wait(timeout)

        def callback(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self._event.set()

    def __init__(self,
                 sendfunc,
                 extended_addr=None,
                 extended_rx_addr=None,
                 rx_block_size=0,
                 rx_separation_time_min=0):
        """

        :param sendfunc: Function that will be called whenever this object
                decides that a CAN frame should be sent.
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
        """

        self.sendfunc = sendfunc

        self.extended_rx_addr = extended_rx_addr
        self.ea_hdr = b""
        if extended_addr is not None:
            self.ea_hdr = struct.pack("B", extended_addr)
        self.listen_mode = False

        self.rxfc_bs = rx_block_size
        self.rxfc_stmin = rx_separation_time_min

        self.rx_messages = []
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

        self.rx_timer = ISOTPSocketImplementation.Timer(self._rx_timer_handler)
        self.tx_timer = ISOTPSocketImplementation.Timer(self._tx_timer_handler)

        self.mutex = RLock()
        self.send_mutex = RLock()

        self.tx_callback = None
        self.rx_callback = None

    def _rx_timer_handler(self):
        """Method called every time the rx_timer times out, due to the peer not
        sending a consecutive frame within the expected time window"""

        self.mutex.acquire()
        try:
            if self.rx_state == ISOTP_WAIT_DATA:
                # we did not get new data frames in time.
                # reset rx state
                self.rx_state = ISOTP_IDLE
                warning("RX state was reset due to timeout")
                if self.rx_callback:
                    self.rx_callback(None)
        finally:
            self.mutex.release()

    def _tx_timer_handler(self):
        """Method called every time the tx_timer times out, which can happen in
        two situations: either a Flow Control frame was not received in time,
        or the Separation Time Min is expired and a new frame must be sent."""

        self.mutex.acquire()
        try:
            if (self.tx_state == ISOTP_WAIT_FC or
                    self.tx_state == ISOTP_WAIT_FIRST_FC):
                # we did not get any flow control frame in time
                # reset tx state
                self.tx_state = ISOTP_IDLE
                warning("TX state was reset due to timeout")
                if self.tx_callback:
                    self.tx_callback(None)
            elif self.tx_state == ISOTP_SENDING:
                # push out the next segmented pdu
                src_off = len(self.ea_hdr)
                max_bytes = 7 - src_off

                while 1:
                    load = self.ea_hdr
                    load += struct.pack("B", N_PCI_CF + self.tx_sn)
                    load += self.tx_buf[self.tx_idx:self.tx_idx + max_bytes]
                    assert (len(load) <= 8)
                    self.sendfunc(load)

                    self.tx_sn = (self.tx_sn + 1) % 16
                    self.tx_bs += 1
                    self.tx_idx += max_bytes

                    if len(self.tx_buf) <= self.tx_idx:
                        # we are done
                        self.tx_state = ISOTP_IDLE
                        if self.tx_callback:
                            self.tx_callback(self.tx_idx)
                        return

                    if self.txfc_bs != 0 and self.tx_bs >= self.txfc_bs:
                        # stop and wait for FC
                        self.tx_state = ISOTP_WAIT_FC
                        self.tx_timer.start(1)
                        return

                    if self.tx_gap == 0:
                        continue
                    else:
                        self.tx_timer.start(self.tx_gap)
        finally:
            self.mutex.release()

    def on_recv(self, cf):
        """Function that must be called every time a CAN frame is received, to
        advance the state machine."""

        self.mutex.acquire()
        try:
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
                self._recv_fc(data[ae:])
            elif n_pci == N_PCI_SF:
                if len(cf.data) > 8:
                    raise Scapy_Exception("CANFD not implemented")
                self._recv_sf(data[ae:])
            elif n_pci == N_PCI_FF:
                self._recv_ff(data[ae:])
            elif n_pci == N_PCI_CF:
                self._recv_cf(data[ae:])

        finally:
            self.mutex.release()

    def _recv_fc(self, data):
        """Process a received 'Flow Control' frame"""
        if (self.tx_state != ISOTP_WAIT_FC and
                self.tx_state != ISOTP_WAIT_FIRST_FC):
            return 0

        self.tx_timer.cancel()

        if len(data) < 3:
            warning("CF frame discarded because it was too short")
            self.tx_state = ISOTP_IDLE
            if self.tx_callback:
                self.tx_callback(None)
            return 1

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
            self.tx_timer.start(self.tx_gap)
        elif isotp_fc == ISOTP_FC_WT:
            # start timer to wait for next FC frame
            self.tx_state = ISOTP_WAIT_FC
            self.tx_timer.start(1)
        elif isotp_fc == ISOTP_FC_OVFLW:
            # overflow in receiver side
            warning("Overflow happened at the receiver side")
            self.tx_state = ISOTP_IDLE
            if self.tx_callback:
                self.tx_callback(None)
        else:
            warning("Unknown CF frame type")
            self.tx_state = ISOTP_IDLE
            if self.tx_callback:
                self.tx_callback(None)

        return 0

    def _recv_sf(self, data):
        """Process a received 'Single Frame' frame"""
        self.rx_timer.cancel()
        if self.rx_state != ISOTP_IDLE:
            warning("RX state was reset because single frame was received")
            self.rx_state = ISOTP_IDLE
            if self.rx_callback:
                self.rx_callback(None)

        length = six.indexbytes(data, 0) & 0xf
        if len(data) - 1 < length:
            return 1

        msg = data[1:1 + length]
        assert (len(msg) == length)
        self.rx_messages.append(msg)
        if self.rx_callback:
            self.rx_callback(msg)
        return 0

    def _recv_ff(self, data):
        """Process a received 'First Frame' frame"""
        self.rx_timer.cancel()
        if self.rx_state != ISOTP_IDLE:
            warning("RX state was reset because first frame was received")
            self.rx_state = ISOTP_IDLE
            if self.rx_callback:
                self.rx_callback(None)

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
        if self.listen_mode:
            return 0

        # send our first FC frame
        load = self.ea_hdr
        load += struct.pack("BBB", N_PCI_FC, self.rxfc_bs, self.rxfc_stmin)
        self.sendfunc(load)

        self.rx_bs = 0
        self.rx_timer.start(1)

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
            if self.rx_callback:
                self.rx_callback(None)
            return 1

        self.rx_sn = (self.rx_sn + 1) % 16
        self.rx_buf += data[1:]
        self.rx_idx = len(self.rx_buf)

        if self.rx_idx >= self.rx_len:
            # we are done
            self.rx_buf = self.rx_buf[0:self.rx_len]
            self.rx_state = ISOTP_IDLE
            self.rx_messages.append(self.rx_buf)
            if self.rx_callback:
                self.rx_callback(self.rx_buf)
            self.rx_buf = None
            return 0

        # no creation of flow control frames
        if self.listen_mode:
            return 0

        # perform blocksize handling, if enabled
        if self.rxfc_bs != 0:
            self.rx_bs += 1
        if self.rxfc_bs == 0 or self.rx_bs < self.rxfc_bs:
            self.rx_timer.start(1)
            return 0

        # we reached the specified blocksize self.rxfc_bs
        # send our FC frame
        load = self.ea_hdr
        load += struct.pack("BBB", N_PCI_FC, self.rxfc_bs, self.rxfc_stmin)
        self.sendfunc(load)
        return 0

    def begin_send(self, x):
        """Begins sending an ISOTP message. This method does not block."""
        self.mutex.acquire()
        try:
            if self.tx_state != ISOTP_IDLE:
                raise Scapy_Exception("Socket is already sending, retry later")

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
                r = self.sendfunc(data)
                if self.tx_callback:
                    self.tx_callback(length)
                return r

            # send the first frame
            data = self.ea_hdr
            if length > ISOTP_MAX_DLEN:
                data += struct.pack(">HI", 0x1000, length)
            else:
                data += struct.pack(">H", 0x1000 | length)
            load = x[0:8 - len(data)]
            data += load
            self.sendfunc(data)

            self.tx_buf = x
            self.tx_sn = 1
            self.tx_bs = 0
            self.tx_idx = len(load)

            self.tx_state = ISOTP_WAIT_FIRST_FC
            self.tx_timer.start(1)

        finally:
            self.mutex.release()

    def deque(self):
        """Extract a received ISOTP message from the receive buffer."""
        self.mutex.acquire()
        try:
            if len(self.rx_messages) > 0:
                return self.rx_messages.pop(0)
            else:
                return None
        finally:
            self.mutex.release()

    def send(self, p):
        """Send an ISOTP frame and block until the message is sent or an error
        happens."""
        self.send_mutex.acquire()
        try:
            block = ISOTPSocketImplementation.BlockingCallback()
            self.tx_callback = block.callback
            self.begin_send(p)
            # Wait until the tx callback is called
            block.wait()
            return block.args[0]
        finally:
            self.send_mutex.release()

    def recv(self, timeout=1):
        """Receive an ISOTP frame, blocking if none is available in the buffer
        for at most 'timeout' seconds."""
        block = ISOTPSocketImplementation.BlockingCallback()

        if timeout <= 0:
            # Non-blocking receive: return a message that was already received
            return self.deque()

        self.mutex.acquire()
        try:
            if len(self.rx_messages) > 0:
                return self.rx_messages.pop(0)
            self.rx_callback = block.callback
        finally:
            self.mutex.release()

        if block.wait(timeout):
            return self.deque()
        else:
            return None


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
