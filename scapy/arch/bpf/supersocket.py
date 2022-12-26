# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - BPF sockets
"""

from select import select
import ctypes
import errno
import fcntl
import os
import platform
import struct
import sys
import time

from scapy.arch.bpf.core import get_dev_bpf, attach_filter
from scapy.arch.bpf.consts import (
    BIOCGBLEN,
    BIOCGDLT,
    BIOCGSTATS,
    BIOCIMMEDIATE,
    BIOCPROMISC,
    BIOCSBLEN,
    BIOCSDLT,
    BIOCSETIF,
    BIOCSHDRCMPLT,
    BIOCSTSTAMP,
    BPF_BUFFER_LENGTH,
    BPF_T_NANOTIME,
)
from scapy.config import conf
from scapy.consts import DARWIN, FREEBSD, NETBSD
from scapy.data import ETH_P_ALL, DLT_IEEE802_11_RADIO
from scapy.error import Scapy_Exception, warning
from scapy.interfaces import network_name
from scapy.supersocket import SuperSocket
from scapy.compat import raw

# Structures & c types

if FREEBSD or NETBSD:
    # On 32bit architectures long might be 32bit.
    BPF_ALIGNMENT = ctypes.sizeof(ctypes.c_long)
else:
    # DARWIN, OPENBSD
    BPF_ALIGNMENT = ctypes.sizeof(ctypes.c_int32)

_NANOTIME = FREEBSD  # Kinda disappointing availability TBH

if _NANOTIME:
    class bpf_timeval(ctypes.Structure):
        # actually a bpf_timespec
        _fields_ = [("tv_sec", ctypes.c_ulong),
                    ("tv_nsec", ctypes.c_ulong)]
elif NETBSD:
    class bpf_timeval(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_ulong),
                    ("tv_usec", ctypes.c_ulong)]
else:
    class bpf_timeval(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_uint32),
                    ("tv_usec", ctypes.c_uint32)]


class bpf_hdr(ctypes.Structure):
    # Also called bpf_xhdr on some OSes
    _fields_ = [("bh_tstamp", bpf_timeval),
                ("bh_caplen", ctypes.c_uint32),
                ("bh_datalen", ctypes.c_uint32),
                ("bh_hdrlen", ctypes.c_uint16)]


_bpf_hdr_len = ctypes.sizeof(bpf_hdr)

# SuperSockets definitions


class _L2bpfSocket(SuperSocket):
    """"Generic Scapy BPF Super Socket"""

    desc = "read/write packets using BPF"
    nonblocking_socket = True

    def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None,
                 nofilter=0, monitor=False):
        if monitor:
            raise Scapy_Exception(
                "We do not natively support monitor mode on BPF. "
                "Please turn on libpcap using conf.use_pcap = True"
            )

        self.fd_flags = None
        self.assigned_interface = None

        # SuperSocket mandatory variables
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc

        self.iface = network_name(iface or conf.iface)

        # Get the BPF handle
        self.ins = None
        (self.ins, self.dev_bpf) = get_dev_bpf()
        self.outs = self.ins

        if FREEBSD:
            # Set the BPF timeval format. Availability issues here !
            try:
                fcntl.ioctl(
                    self.ins, BIOCSTSTAMP,
                    struct.pack('I', BPF_T_NANOTIME)
                )
            except IOError:
                raise Scapy_Exception("BIOCSTSTAMP failed on /dev/bpf%i" %
                                      self.dev_bpf)
        # Set the BPF buffer length
        try:
            fcntl.ioctl(
                self.ins, BIOCSBLEN,
                struct.pack('I', BPF_BUFFER_LENGTH)
            )
        except IOError:
            raise Scapy_Exception("BIOCSBLEN failed on /dev/bpf%i" %
                                  self.dev_bpf)

        # Assign the network interface to the BPF handle
        try:
            fcntl.ioctl(
                self.ins, BIOCSETIF,
                struct.pack("16s16x", self.iface.encode())
            )
        except IOError:
            raise Scapy_Exception("BIOCSETIF failed on %s" % self.iface)
        self.assigned_interface = self.iface

        # Set the interface into promiscuous
        if self.promisc:
            self.set_promisc(1)

        # Set the interface to monitor mode
        # Note: - trick from libpcap/pcap-bpf.c - monitor_mode()
        #       - it only works on OS X 10.5 and later
        if DARWIN and monitor:
            # Convert macOS version to an integer
            try:
                tmp_mac_version = platform.mac_ver()[0].split(".")
                tmp_mac_version = [int(num) for num in tmp_mac_version]
                macos_version = tmp_mac_version[0] * 10000
                macos_version += tmp_mac_version[1] * 100 + tmp_mac_version[2]
            except (IndexError, ValueError):
                warning("Could not determine your macOS version!")
                macos_version = sys.maxint

            # Disable 802.11 monitoring on macOS Catalina (aka 10.15) and upper
            if macos_version < 101500:
                dlt_radiotap = struct.pack('I', DLT_IEEE802_11_RADIO)
                try:
                    fcntl.ioctl(self.ins, BIOCSDLT, dlt_radiotap)
                except IOError:
                    raise Scapy_Exception("Can't set %s into monitor mode!" %
                                          self.iface)
            else:
                warning("Scapy won't activate 802.11 monitoring, "
                        "as it will crash your macOS kernel!")

        # Don't block on read
        try:
            fcntl.ioctl(self.ins, BIOCIMMEDIATE, struct.pack('I', 1))
        except IOError:
            raise Scapy_Exception("BIOCIMMEDIATE failed on /dev/bpf%i" %
                                  self.dev_bpf)

        # Scapy will provide the link layer source address
        # Otherwise, it is written by the kernel
        try:
            fcntl.ioctl(self.ins, BIOCSHDRCMPLT, struct.pack('i', 1))
        except IOError:
            raise Scapy_Exception("BIOCSHDRCMPLT failed on /dev/bpf%i" %
                                  self.dev_bpf)

        # Configure the BPF filter
        filter_attached = False
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                try:
                    attach_filter(self.ins, filter, self.iface)
                    filter_attached = True
                except ImportError as ex:
                    warning("Cannot set filter: %s" % ex)
        if NETBSD and filter_attached is False:
            # On NetBSD, a filter must be attached to an interface, otherwise
            # no frame will be received by os.read(). When no filter has been
            # configured, Scapy uses a simple tcpdump filter that does nothing
            # more than ensuring the length frame is not null.
            filter = "greater 0"
            try:
                attach_filter(self.ins, filter, self.iface)
            except ImportError as ex:
                warning("Cannot set filter: %s" % ex)

        # Set the guessed packet class
        self.guessed_cls = self.guess_cls()

    def set_promisc(self, value):
        """Set the interface in promiscuous mode"""

        try:
            fcntl.ioctl(self.ins, BIOCPROMISC, struct.pack('i', value))
        except IOError:
            raise Scapy_Exception("Cannot set promiscuous mode on interface "
                                  "(%s)!" % self.iface)

    def __del__(self):
        """Close the file descriptor on delete"""
        # When the socket is deleted on Scapy exits, __del__ is
        # sometimes called "too late", and self is None
        if self is not None:
            self.close()

    def guess_cls(self):
        """Guess the packet class that must be used on the interface"""

        # Get the data link type
        try:
            ret = fcntl.ioctl(self.ins, BIOCGDLT, struct.pack('I', 0))
            ret = struct.unpack('I', ret)[0]
        except IOError:
            cls = conf.default_l2
            warning("BIOCGDLT failed: unable to guess type. Using %s !",
                    cls.name)
            return cls

        # Retrieve the corresponding class
        try:
            return conf.l2types[ret]
        except KeyError:
            cls = conf.default_l2
            warning("Unable to guess type (type %i). Using %s", ret, cls.name)

    def set_nonblock(self, set_flag=True):
        """Set the non blocking flag on the socket"""

        # Get the current flags
        if self.fd_flags is None:
            try:
                self.fd_flags = fcntl.fcntl(self.ins, fcntl.F_GETFL)
            except IOError:
                warning("Cannot get flags on this file descriptor !")
                return

        # Set the non blocking flag
        if set_flag:
            new_fd_flags = self.fd_flags | os.O_NONBLOCK
        else:
            new_fd_flags = self.fd_flags & ~os.O_NONBLOCK

        try:
            fcntl.fcntl(self.ins, fcntl.F_SETFL, new_fd_flags)
            self.fd_flags = new_fd_flags
        except Exception:
            warning("Can't set flags on this file descriptor !")

    def get_stats(self):
        """Get received / dropped statistics"""

        try:
            ret = fcntl.ioctl(self.ins, BIOCGSTATS, struct.pack("2I", 0, 0))
            return struct.unpack("2I", ret)
        except IOError:
            warning("Unable to get stats from BPF !")
            return (None, None)

    def get_blen(self):
        """Get the BPF buffer length"""

        try:
            ret = fcntl.ioctl(self.ins, BIOCGBLEN, struct.pack("I", 0))
            return struct.unpack("I", ret)[0]
        except IOError:
            warning("Unable to get the BPF buffer length")
            return

    def fileno(self):
        """Get the underlying file descriptor"""
        return self.ins

    def close(self):
        """Close the Super Socket"""

        if not self.closed and self.ins is not None:
            os.close(self.ins)
            self.closed = True
            self.ins = None

    def send(self, x):
        """Dummy send method"""
        raise Exception(
            "Can't send anything with %s" % self.__class__.__name__
        )

    def recv_raw(self, x=BPF_BUFFER_LENGTH):
        """Dummy recv method"""
        raise Exception(
            "Can't recv anything with %s" % self.__class__.__name__
        )

    @staticmethod
    def select(sockets, remain=None):
        """This function is called during sendrecv() routine to select
        the available sockets.
        """
        # sockets, None (means use the socket's recv() )
        return bpf_select(sockets, remain)


class L2bpfListenSocket(_L2bpfSocket):
    """"Scapy L2 BPF Listen Super Socket"""

    def __init__(self, *args, **kwargs):
        self.received_frames = []
        super(L2bpfListenSocket, self).__init__(*args, **kwargs)

    def buffered_frames(self):
        """Return the number of frames in the buffer"""
        return len(self.received_frames)

    def get_frame(self):
        """Get a frame or packet from the received list"""
        if self.received_frames:
            return self.received_frames.pop(0)
        else:
            return None, None, None

    @staticmethod
    def bpf_align(bh_h, bh_c):
        """Return the index to the end of the current packet"""

        # from <net/bpf.h>
        return ((bh_h + bh_c) + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1)

    def extract_frames(self, bpf_buffer):
        """
        Extract all frames from the buffer and stored them in the received list
        """

        # Ensure that the BPF buffer contains at least the header
        len_bb = len(bpf_buffer)
        if len_bb < _bpf_hdr_len:
            return

        # Extract useful information from the BPF header
        bh_hdr = bpf_hdr.from_buffer_copy(bpf_buffer)
        if bh_hdr.bh_datalen == 0:
            return

        # Get and store the Scapy object
        frame_str = bpf_buffer[
            bh_hdr.bh_hdrlen:bh_hdr.bh_hdrlen + bh_hdr.bh_caplen
        ]
        if _NANOTIME:
            ts = bh_hdr.bh_tstamp.tv_sec + 1e-9 * bh_hdr.bh_tstamp.tv_nsec
        else:
            ts = bh_hdr.bh_tstamp.tv_sec + 1e-6 * bh_hdr.bh_tstamp.tv_usec
        self.received_frames.append(
            (self.guessed_cls, frame_str, ts)
        )

        # Extract the next frame
        end = self.bpf_align(bh_hdr.bh_hdrlen, bh_hdr.bh_caplen)
        if (len_bb - end) >= 20:
            self.extract_frames(bpf_buffer[end:])

    def recv_raw(self, x=BPF_BUFFER_LENGTH):
        """Receive a frame from the network"""

        x = min(x, BPF_BUFFER_LENGTH)

        if self.buffered_frames():
            # Get a frame from the buffer
            return self.get_frame()

        # Get data from BPF
        try:
            bpf_buffer = os.read(self.ins, x)
        except EnvironmentError as exc:
            if exc.errno != errno.EAGAIN:
                warning("BPF recv_raw()", exc_info=True)
            return None, None, None

        # Extract all frames from the BPF buffer
        self.extract_frames(bpf_buffer)
        return self.get_frame()


class L2bpfSocket(L2bpfListenSocket):
    """"Scapy L2 BPF Super Socket"""

    def send(self, x):
        """Send a frame"""
        return os.write(self.outs, raw(x))

    def nonblock_recv(self):
        """Non blocking receive"""

        if self.buffered_frames():
            # Get a frame from the buffer
            return L2bpfListenSocket.recv(self)

        # Set the non blocking flag, read from the socket, and unset the flag
        self.set_nonblock(True)
        pkt = L2bpfListenSocket.recv(self)
        self.set_nonblock(False)
        return pkt


class L3bpfSocket(L2bpfSocket):

    def recv(self, x=BPF_BUFFER_LENGTH):
        """Receive on layer 3"""
        r = SuperSocket.recv(self, x)
        if r:
            r.payload.time = r.time
            return r.payload
        return r

    def send(self, pkt):
        """Send a packet"""
        from scapy.layers.l2 import Loopback

        # Use the routing table to find the output interface
        iff = pkt.route()[0]
        if iff is None:
            iff = network_name(conf.iface)

        # Assign the network interface to the BPF handle
        if self.assigned_interface != iff:
            try:
                fcntl.ioctl(self.outs, BIOCSETIF, struct.pack("16s16x", iff.encode()))  # noqa: E501
            except IOError:
                raise Scapy_Exception("BIOCSETIF failed on %s" % iff)
            self.assigned_interface = iff

        # Build the frame
        #
        # LINKTYPE_NULL / DLT_NULL (Loopback) is a special case. From the
        # bpf(4) man page (from macOS/Darwin, but also for BSD):
        #
        # "A packet can be sent out on the network by writing to a bpf file
        # descriptor. [...] Currently only writes to Ethernets and SLIP links
        # are supported."
        #
        # Headers are only mentioned for reads, not writes, and it has the
        # name "NULL" and id=0.
        #
        # The _correct_ behaviour appears to be that one should add a BSD
        # Loopback header to every sent packet. This is needed by FreeBSD's
        # if_lo, and Darwin's if_lo & if_utun.
        #
        # tuntaposx appears to have interpreted "NULL" as "no headers".
        # Thankfully its interfaces have a different name (tunX) to Darwin's
        # if_utun interfaces (utunX).
        #
        # There might be other drivers which make the same mistake as
        # tuntaposx, but these are typically provided with VPN software, and
        # Apple are breaking these kexts in a future version of macOS... so
        # the problem will eventually go away. They already don't work on Macs
        # with Apple Silicon (M1).
        if DARWIN and iff.startswith('tun') and self.guessed_cls == Loopback:
            frame = raw(pkt)
        elif FREEBSD and (iff.startswith('tun') or iff.startswith('tap')):
            # On FreeBSD, the bpf manpage states that it is only possible
            # to write packets to Ethernet and SLIP network interfaces
            # using /dev/bpf
            #
            # Note: `open("/dev/tun0", "wb").write(raw(pkt())) should be
            #   used
            warning("Cannot write to %s according to the documentation!", iff)
            return
        else:
            frame = raw(self.guessed_cls() / pkt)

        pkt.sent_time = time.time()

        # Send the frame
        L2bpfSocket.send(self, frame)


# Sockets manipulation functions

def isBPFSocket(obj):
    """Return True is obj is a BPF Super Socket"""
    return isinstance(
        obj,
        (L2bpfListenSocket, L2bpfListenSocket, L3bpfSocket)
    )


def bpf_select(fds_list, timeout=None):
    """A call to recv() can return several frames. This functions hides the fact
       that some frames are read from the internal buffer."""

    # Check file descriptors types
    bpf_scks_buffered = list()
    select_fds = list()

    for tmp_fd in fds_list:

        # Specific BPF sockets: get buffers status
        if isBPFSocket(tmp_fd) and tmp_fd.buffered_frames():
            bpf_scks_buffered.append(tmp_fd)
            continue

        # Regular file descriptors or empty BPF buffer
        select_fds.append(tmp_fd)

    if select_fds:
        # Call select for sockets with empty buffers
        if timeout is None:
            timeout = 0.05
        ready_list, _, _ = select(select_fds, [], [], timeout)
        return bpf_scks_buffered + ready_list
    else:
        return bpf_scks_buffered
