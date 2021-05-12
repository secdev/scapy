# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Enrico Pozzobon <enricopozzobon@gmail.com>
# This program is published under a GPLv2 license

# scapy.contrib.description = ISO-TP (ISO 15765-2) Soft Socket Library
# scapy.contrib.status = library

import struct
import time
import traceback
import heapq
import socket

from threading import Thread, Event, Lock

from scapy.compat import Optional, Union, List, Tuple, Any, Type, cast, \
    Callable, TYPE_CHECKING
from scapy.packet import Packet
from scapy.layers.can import CAN
import scapy.modules.six as six
from scapy.modules.six.moves import queue
from scapy.error import Scapy_Exception, warning, log_runtime
from scapy.supersocket import SuperSocket
from scapy.config import conf
from scapy.consts import LINUX
from scapy.sendrecv import sniff
from scapy.utils import EDecimal
from scapy.contrib.isotp.isotp_packet import ISOTP, CAN_MAX_DLEN, N_PCI_SF, \
    N_PCI_CF, N_PCI_FC, N_PCI_FF, ISOTP_MAX_DLEN, ISOTP_MAX_DLEN_2015

if TYPE_CHECKING:
    from scapy.contrib.cansocket import CANSocket


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
    SuperSocket automatically calls the close() method when the GC destroys an
    ISOTPSoftSocket. However, note that if any thread holds a reference to
    an ISOTPSoftSocket object, it will not be collected by the GC.

    The implementation of the ISOTP protocol, along with the necessary
    thread, are stored in the ISOTPSocketImplementation class, and therefore:

    * There no reference from ISOTPSocketImplementation to ISOTPSoftSocket
    * ISOTPSoftSocket can be normally garbage collected
    * Upon destruction, ISOTPSoftSocket.close() will be called
    * ISOTPSoftSocket.close() will call ISOTPSocketImplementation.close()
    * RX background thread can be stopped by the garbage collector

    Initialize an ISOTPSoftSocket using the provided underlying can socket.

    Example (with NativeCANSocket underneath):
        >>> conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': False}
        >>> load_contrib('isotp')
        >>> with ISOTPSocket("can0", sid=0x641, did=0x241) as sock:
        >>>     sock.send(...)

    Example (with PythonCANSocket underneath):
        >>> conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': False}
        >>> conf.contribs['CANSocket'] = {'use-python-can': True}
        >>> load_contrib('isotp')
        >>> with ISOTPSocket(CANSocket(bustype='socketcan', channel="can0"), sid=0x641, did=0x241) as sock:
        >>>     sock.send(...)

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
    """  # noqa: E501

    nonblocking_socket = True

    def __init__(self,
                 can_socket=None,  # type: Optional["CANSocket"]
                 sid=0,  # type: int
                 did=0,  # type: int
                 extended_addr=None,  # type: Optional[int]
                 extended_rx_addr=None,  # type: Optional[int]
                 rx_block_size=0,  # type: int
                 rx_separation_time_min=0,  # type: int
                 padding=False,  # type: bool
                 listen_only=False,  # type: bool
                 basecls=ISOTP  # type: Type[Packet]
                 ):
        # type: (...) -> None

        if six.PY3 and LINUX and isinstance(can_socket, six.string_types):
            from scapy.contrib.cansocket_native import NativeCANSocket
            can_socket = NativeCANSocket(can_socket)
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

        # Cast for compatibility to functions from SuperSocket.
        self.ins = cast(socket.socket, impl)
        self.outs = cast(socket.socket, impl)
        self.impl = impl
        self.basecls = basecls
        if basecls is None:
            warning('Provide a basecls ')

    def close(self):
        # type: () -> None
        if not self.closed:
            self.impl.close()
            self.closed = True

    def begin_send(self, p):
        # type: (Packet) -> int
        """Begin the transmission of message p. This method returns after
        sending the first frame. If multiple frames are necessary to send the
        message, this socket will unable to send other messages until either
        the transmission of this frame succeeds or it fails."""

        if not self.closed:
            if hasattr(p, "sent_time"):
                p.sent_time = time.time()
            self.impl.begin_send(bytes(p))
            return len(p)
        else:
            return 0

    def recv_raw(self, x=0xffff):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Receive a complete ISOTP message, blocking until a message is
        received or the specified timeout is reached.
        If self.timeout is 0, then this function doesn't block and returns the
        first frame in the receive buffer or None if there isn't any."""
        if not self.closed:
            tup = self.impl.recv()
            if tup is not None:
                return self.basecls, tup[0], float(tup[1])
        return self.basecls, None, None

    def recv(self, x=0xffff):
        # type: (int) -> Optional[Packet]
        msg = super(ISOTPSoftSocket, self).recv(x)
        if msg is None:
            return None

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
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        """This function is called during sendrecv() routine to wait for
        sockets to be ready to receive
        """

        def find_ready_sockets(socks):
            # type: (List[SuperSocket]) -> List[SuperSocket]
            return [x for x in socks if isinstance(x, ISOTPSoftSocket) and
                    not x.closed and not x.impl.rx_queue.empty()]

        ready_sockets = find_ready_sockets(sockets)

        blocking = remain != 0
        if len(ready_sockets) > 0 or not blocking:
            return ready_sockets

        exit_select = Event()

        def my_cb(msg):
            # type: (Any) -> None
            exit_select.set()

        try:
            for s in sockets:
                if not s.closed and isinstance(s, ISOTPSoftSocket):
                    s.impl.rx_callbacks.append(my_cb)

            exit_select.wait(remain)

        finally:
            for s in sockets:
                if isinstance(s, ISOTPSoftSocket):
                    try:
                        s.impl.rx_callbacks.remove(my_cb)
                    except (ValueError, AttributeError):
                        pass

        ready_sockets = find_ready_sockets(sockets)
        return ready_sockets


class CANReceiverThread(Thread):
    """
    Helper class that receives CAN frames and feeds them to the provided
    callback. It relies on CAN frames being enqueued in the CANSocket object
    and not being lost if they come before the sniff method is called. This is
    true in general since sniff is usually implemented as repeated recv(), but
    might be false in some implementation of CANSocket

    Initialize the thread. In order for this thread to be able to be
    stopped by the destructor of another object, it is important to not
    keep a reference to the object in the callback function.

    :param socket: the CANSocket upon which this class will call the
                   sniff() method
    :param callback: function to call whenever a CAN frame is received
    """

    def __init__(self, can_socket, callback):
        # type: ("CANSocket", Callable[[Packet], None]) -> None
        super(CANReceiverThread, self).__init__()
        self.socket = can_socket
        self.callback = callback
        self.exiting = False
        self._thread_started = Event()
        self.exception = None  # type: Optional[Exception]
        self.name = "CANReceiver" + self.name

    def start(self):
        # type: () -> None
        super(CANReceiverThread, self).start()
        if not self._thread_started.wait(5):
            raise Scapy_Exception("CAN RX thread not started in 5s.")

    def run(self):
        # type: () -> None
        self._thread_started.set()
        try:
            def prn(msg):
                # type: (Packet) -> None
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
        except Exception as e:
            self.exception = e

    def stop(self):
        # type: () -> None
        self.exiting = True


class TimeoutScheduler:
    """A timeout scheduler which uses a single thread for all timeouts, unlike
    python's own Timer objects which use a thread each."""
    VERBOSE = False
    GRACE = .1
    _mutex = Lock()
    _event = Event()
    _thread = None  # type: Optional[Thread]

    # use heapq functions on _handles!
    _handles = []  # type: List[TimeoutScheduler.Handle]

    @staticmethod
    def schedule(timeout, callback):
        # type: (float, Callable[[], None]) -> TimeoutScheduler.Handle
        """Schedules the execution of a timeout.

        The function `callback` will be called in `timeout` seconds.

        Returns a handle that can be used to remove the timeout."""
        when = TimeoutScheduler._time() + timeout
        handle = TimeoutScheduler.Handle(when, callback)
        handles = TimeoutScheduler._handles

        with TimeoutScheduler._mutex:
            # Add the handler to the heap, keeping the invariant
            # Time complexity is O(log n)
            heapq.heappush(handles, handle)
            must_interrupt = (handles[0] == handle)

            # Start the scheduling thread if it is not started already
            if TimeoutScheduler._thread is None:
                t = Thread(target=TimeoutScheduler._task,
                           name="TimeoutScheduler._task")
                must_interrupt = False
                TimeoutScheduler._thread = t
                TimeoutScheduler._event.clear()
                t.start()

        if must_interrupt:
            # if the new timeout got in front of the one we are currently
            # waiting on, the current wait operation must be aborted and
            # updated with the new timeout
            TimeoutScheduler._event.set()

        # Return the handle to the timeout so that the user can cancel it
        return handle

    @staticmethod
    def cancel(handle):
        # type: (TimeoutScheduler.Handle) -> None
        """Provided its handle, cancels the execution of a timeout."""

        handles = TimeoutScheduler._handles
        with TimeoutScheduler._mutex:
            if handle in handles:
                # Time complexity is O(n)
                handle._cb = None
                handles.remove(handle)
                heapq.heapify(handles)

                if len(handles) == 0:
                    # set the event to stop the wait - this kills the thread
                    TimeoutScheduler._event.set()
            else:
                raise Scapy_Exception("Handle not found")

    @staticmethod
    def clear():
        # type: () -> None
        """Cancels the execution of all timeouts."""
        with TimeoutScheduler._mutex:
            TimeoutScheduler._handles.clear()

        # set the event to stop the wait - this kills the thread
        TimeoutScheduler._event.set()

    @staticmethod
    def _peek_next():
        # type: () -> Optional[TimeoutScheduler.Handle]
        """Returns the next timeout to execute, or `None` if list is empty,
        without modifying the list"""
        with TimeoutScheduler._mutex:
            handles = TimeoutScheduler._handles
            if len(handles) == 0:
                return None
            else:
                return handles[0]

    @staticmethod
    def _wait(handle):
        # type: (Optional[TimeoutScheduler.Handle]) -> None
        """Waits until it is time to execute the provided handle, or until
        another thread calls _event.set()"""

        if handle is None:
            when = TimeoutScheduler.GRACE
        else:
            when = handle._when

        # Check how much time until the next timeout
        now = TimeoutScheduler._time()
        to_wait = when - now

        # Wait until the next timeout,
        # or until event.set() gets called in another thread.
        if to_wait > 0:
            log_runtime.debug("TimeoutScheduler Thread going to sleep @ %f " +
                              "for %fs", now, to_wait)
            interrupted = TimeoutScheduler._event.wait(to_wait)
            new = TimeoutScheduler._time()
            log_runtime.debug("TimeoutScheduler Thread awake @ %f, slept for" +
                              " %f, interrupted=%d", new, new - now,
                              interrupted)

        # Clear the event so that we can wait on it again,
        # Must be done before doing the callbacks to avoid losing a set().
        TimeoutScheduler._event.clear()

    @staticmethod
    def _task():
        # type: () -> None
        """Executed in a background thread, this thread will automatically
        start when the first timeout is added and stop when the last timeout
        is removed or executed."""

        log_runtime.debug("TimeoutScheduler Thread spawning @ %f",
                          TimeoutScheduler._time())

        time_empty = None

        try:
            while 1:
                handle = TimeoutScheduler._peek_next()
                if handle is None:
                    now = TimeoutScheduler._time()
                    if time_empty is None:
                        time_empty = now
                    # 100 ms of grace time before killing the thread
                    if TimeoutScheduler.GRACE < now - time_empty:
                        return
                TimeoutScheduler._wait(handle)
                TimeoutScheduler._poll()

        finally:
            # Worst case scenario: if this thread dies, the next scheduled
            # timeout will start a new one
            log_runtime.debug("TimeoutScheduler Thread dying @ %f",
                              TimeoutScheduler._time())
            TimeoutScheduler._thread = None

    @staticmethod
    def _poll():
        # type: () -> None
        """Execute all the callbacks that were due until now"""

        handles = TimeoutScheduler._handles
        handle = None
        while 1:
            with TimeoutScheduler._mutex:
                now = TimeoutScheduler._time()
                if len(handles) == 0 or handles[0]._when > now:
                    # There is nothing to execute yet
                    return

                # Time complexity is O(log n)
                handle = heapq.heappop(handles)
                callback = None
                if handle is not None:
                    callback = handle._cb
                    handle._cb = True

            # Call the callback here, outside of the mutex
            if callable(callback):
                try:
                    callback()
                except Exception:
                    traceback.print_exc()

    @staticmethod
    def _time():
        # type: () -> float
        if six.PY2:
            return time.clock()
        return time.monotonic()

    class Handle:
        """Handle for a timeout, consisting of a callback and a time when it
        should be executed."""
        __slots__ = ['_when', '_cb']

        def __init__(self,
                     when,  # type: float
                     cb  # type: Optional[Union[Callable[[], None], bool]]
                     ):
            # type: (...) -> None
            self._when = when
            self._cb = cb

        def cancel(self):
            # type: () -> bool
            """Cancels this timeout, preventing it from executing its
            callback"""
            if self._cb is None:
                raise Scapy_Exception("cancel() called on "
                                      "previous canceled Handle")
            else:
                if isinstance(self._cb, bool):
                    # Handle was already executed.
                    # We don't need to cancel anymore
                    return False
                else:
                    self._cb = None
                    TimeoutScheduler.cancel(self)
                    return True

        def __lt__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when < other._when

        def __le__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when <= other._when

        def __gt__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when > other._when

        def __ge__(self, other):
            # type: (Any) -> bool
            if not isinstance(other, TimeoutScheduler.Handle):
                raise TypeError()
            return self._when >= other._when


class ISOTPSocketImplementation:
    """
    Implementation of an ISOTP "state machine".

    Most of the ISOTP logic was taken from
    https://github.com/hartkopp/can-isotp/blob/master/net/can/isotp.c

    This class is separated from ISOTPSoftSocket to make sure the background
    thread can't hold a reference to ISOTPSoftSocket, allowing it to be
    collected by the GC.

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

    def __init__(self,
                 can_socket,  # type: "CANSocket"
                 src_id,  # type: int
                 dst_id,  # type: int
                 padding=False,  # type: bool
                 extended_addr=None,  # type: Optional[int]
                 extended_rx_addr=None,  # type: Optional[int]
                 rx_block_size=0,  # type: int
                 rx_separation_time_min=0,  # type: int
                 listen_only=False  # type: bool
                 ):
        # type: (...) -> None
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
        self.rx_buf = None  # type: Optional[bytes]
        self.rx_sn = 0
        self.rx_bs = 0
        self.rx_idx = 0
        self.rx_ts = 0.0  # type: Union[float, EDecimal]
        self.rx_state = ISOTP_IDLE

        self.txfc_bs = 0
        self.txfc_stmin = 0
        self.tx_gap = 0

        self.tx_buf = None  # type: Optional[bytes]
        self.tx_sn = 0
        self.tx_bs = 0
        self.tx_idx = 0
        self.rx_ll_dl = 0
        self.tx_state = ISOTP_IDLE

        self.tx_timeout_handle = None  # type: Optional[TimeoutScheduler.Handle]  # noqa: E501
        self.rx_timeout_handle = None  # type: Optional[TimeoutScheduler.Handle]  # noqa: E501
        self.rx_thread = CANReceiverThread(can_socket, self.on_can_recv)

        self.tx_mutex = Lock()
        self.rx_mutex = Lock()
        self.send_mutex = Lock()

        self.tx_done = Event()
        self.tx_exception = None  # type: Optional[str]

        self.tx_callbacks = []  # type: List[Callable[[], None]]
        self.rx_callbacks = []  # type: List[Callable[[bytes], None]]

        self.rx_thread.start()

    def __del__(self):
        # type: () -> None
        self.close()

    def can_send(self, load):
        # type: (bytes) -> None
        if self.padding:
            load += b"\xCC" * (CAN_MAX_DLEN - len(load))
        if self.src_id is None or self.src_id <= 0x7ff:
            self.can_socket.send(CAN(identifier=self.src_id, data=load))
        else:
            self.can_socket.send(CAN(identifier=self.src_id, flags="extended",
                                     data=load))

    def on_can_recv(self, p):
        # type: (Packet) -> None
        if not isinstance(p, CAN):
            raise Scapy_Exception("argument is not a CAN frame")
        if p.identifier != self.dst_id:
            if not self.filter_warning_emitted and conf.verb >= 2:
                warning("You should put a filter for identifier=%x on your "
                        "CAN socket", self.dst_id)
                self.filter_warning_emitted = True
        else:
            self.on_recv(p)

    def close(self):
        # type: () -> None
        self.rx_thread.stop()

    def _rx_timer_handler(self):
        # type: () -> None
        """Method called every time the rx_timer times out, due to the peer not
        sending a consecutive frame within the expected time window"""

        with self.rx_mutex:
            if self.rx_state == ISOTP_WAIT_DATA:
                # we did not get new data frames in time.
                # reset rx state
                self.rx_state = ISOTP_IDLE
                if conf.verb > 2:
                    warning("RX state was reset due to timeout")

    def _tx_timer_handler(self):
        # type: () -> None
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
                if self.tx_buf is None:
                    self.tx_exception = "TX buffer is not filled"
                    raise Scapy_Exception(self.tx_exception)

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
                        self.tx_timeout_handle = TimeoutScheduler.schedule(
                            self.fc_timeout, self._tx_timer_handler)
                        return

                    if self.tx_gap == 0:
                        continue
                    else:
                        # stop and wait for tx gap
                        self.tx_timeout_handle = TimeoutScheduler.schedule(
                            self.tx_gap, self._tx_timer_handler)
                        return

    def on_recv(self, cf):
        # type: (Packet) -> None
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
                self._recv_sf(data[ae:], cf.time)
        elif n_pci == N_PCI_FF:
            with self.rx_mutex:
                self._recv_ff(data[ae:], cf.time)
        elif n_pci == N_PCI_CF:
            with self.rx_mutex:
                self._recv_cf(data[ae:])

    def _recv_fc(self, data):
        # type: (bytes) -> None
        """Process a received 'Flow Control' frame"""
        if (self.tx_state != ISOTP_WAIT_FC and
                self.tx_state != ISOTP_WAIT_FIRST_FC):
            return

        if self.tx_timeout_handle is not None:
            self.tx_timeout_handle.cancel()
            self.tx_timeout_handle = None

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
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.tx_gap, self._tx_timer_handler)
        elif isotp_fc == ISOTP_FC_WT:
            # start timer to wait for next FC frame
            self.tx_state = ISOTP_WAIT_FC
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.fc_timeout, self._tx_timer_handler)
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

    def _recv_sf(self, data, ts):
        # type: (bytes, Union[float, EDecimal]) -> None
        """Process a received 'Single Frame' frame"""
        if self.rx_timeout_handle is not None:
            self.rx_timeout_handle.cancel()
            self.rx_timeout_handle = None

        if self.rx_state != ISOTP_IDLE:
            if conf.verb > 2:
                warning("RX state was reset because single frame was received")
            self.rx_state = ISOTP_IDLE

        length = six.indexbytes(data, 0) & 0xf
        if len(data) - 1 < length:
            return

        msg = data[1:1 + length]
        self.rx_queue.put((msg, ts))
        for cb in self.rx_callbacks:
            cb(msg)

    def _recv_ff(self, data, ts):
        # type: (bytes, Union[float, EDecimal]) -> None
        """Process a received 'First Frame' frame"""
        if self.rx_timeout_handle is not None:
            self.rx_timeout_handle.cancel()
            self.rx_timeout_handle = None

        if self.rx_state != ISOTP_IDLE:
            if conf.verb > 2:
                warning("RX state was reset because first frame was received")
            self.rx_state = ISOTP_IDLE

        if len(data) < 7:
            return
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
        self.rx_ts = ts

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
        self.rx_timeout_handle = TimeoutScheduler.schedule(
            self.cf_timeout, self._rx_timer_handler)

    def _recv_cf(self, data):
        # type: (bytes) -> None
        """Process a received 'Consecutive Frame' frame"""
        if self.rx_state != ISOTP_WAIT_DATA:
            return

        if self.rx_timeout_handle is not None:
            self.rx_timeout_handle.cancel()
            self.rx_timeout_handle = None

        # CFs are never longer than the FF
        if len(data) > self.rx_ll_dl:
            return

        # CFs have usually the LL_DL length
        if len(data) < self.rx_ll_dl:
            # this is only allowed for the last CF
            if self.rx_len - self.rx_idx > self.rx_ll_dl:
                if conf.verb > 2:
                    warning("Received a CF with insufficient length")
                return

        if six.indexbytes(data, 0) & 0x0f != self.rx_sn:
            # Wrong sequence number
            if conf.verb > 2:
                warning("RX state was reset because wrong sequence number was "
                        "received")
            self.rx_state = ISOTP_IDLE
            return

        if self.rx_buf is None:
            raise Scapy_Exception("rx_buf not filled with data!")

        self.rx_sn = (self.rx_sn + 1) % 16
        self.rx_buf += data[1:]
        self.rx_idx = len(self.rx_buf)

        if self.rx_idx >= self.rx_len:
            # we are done
            self.rx_buf = self.rx_buf[0:self.rx_len]
            self.rx_state = ISOTP_IDLE
            self.rx_queue.put((self.rx_buf, self.rx_ts))
            for cb in self.rx_callbacks:
                cb(self.rx_buf)
            self.rx_buf = None
            return

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
        self.rx_timeout_handle = TimeoutScheduler.schedule(
            self.cf_timeout, self._rx_timer_handler)

    def begin_send(self, x):
        # type: (bytes) -> None
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
            self.tx_timeout_handle = TimeoutScheduler.schedule(
                self.fc_timeout, self._tx_timer_handler)

    def send(self, p):
        # type: (bytes) -> None
        """Send an ISOTP frame and block until the message is sent or an error
        happens."""
        with self.send_mutex:
            self.begin_send(p)

            # Wait until the tx callback is called
            send_done = self.tx_done.wait(30)
            if self.tx_exception is not None:
                raise Scapy_Exception(self.tx_exception)
            if not send_done:
                raise Scapy_Exception("ISOTP send not completed in 30s")
            return

    def recv(self, timeout=None):
        # type: (Optional[int]) -> Optional[Tuple[bytes, Union[float, EDecimal]]]  # noqa: E501
        """Receive an ISOTP frame, blocking if none is available in the buffer
        for at most 'timeout' seconds."""

        try:
            return self.rx_queue.get(timeout is None or timeout > 0, timeout)
        except queue.Empty:
            return None
