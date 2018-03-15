# Guillaume Valadon <guillaume@valadon.net>

"""
Scapy *BSD native support - BPF sockets
"""

import errno
import fcntl
import os
from select import select
import struct
import time

from scapy.arch.bpf.core import get_dev_bpf, attach_filter
from scapy.arch.bpf.consts import BIOCGBLEN, BIOCGDLT, BIOCGSTATS, \
    BIOCIMMEDIATE, BIOCPROMISC, BIOCSBLEN, BIOCSETIF, BIOCSHDRCMPLT, \
    BPF_BUFFER_LENGTH, BIOCSDLT, DLT_IEEE802_11_RADIO
from scapy.config import conf
from scapy.consts import FREEBSD, NETBSD, DARWIN
from scapy.data import ETH_P_ALL
from scapy.error import Scapy_Exception, warning
from scapy.supersocket import SuperSocket
from scapy.compat import raw


if FREEBSD or NETBSD:
    BPF_ALIGNMENT = 8  # sizeof(long)
else:
    BPF_ALIGNMENT = 4  # sizeof(int32_t)


# SuperSockets definitions

class _L2bpfSocket(SuperSocket):
    """"Generic Scapy BPF Super Socket"""

    desc = "read/write packets using BPF"
    assigned_interface = None
    fd_flags = None
    ins = None
    closed = False

    def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None,
                 nofilter=0, monitor=False):

        # SuperSocket mandatory variables
        if promisc is None:
            self.promisc = conf.sniff_promisc
        else:
            self.promisc = promisc

        if iface is None:
            self.iface = conf.iface
        else:
            self.iface = iface

        # Get the BPF handle
        (self.ins, self.dev_bpf) = get_dev_bpf()
        self.outs = self.ins

        # Set the BPF buffer length
        try:
            fcntl.ioctl(self.ins, BIOCSBLEN, struct.pack('I', BPF_BUFFER_LENGTH))
        except IOError:
            raise Scapy_Exception("BIOCSBLEN failed on /dev/bpf%i" %
                                  self.dev_bpf)

        # Assign the network interface to the BPF handle
        try:
            fcntl.ioctl(self.ins, BIOCSETIF, struct.pack("16s16x", self.iface.encode()))
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
            dlt_radiotap = struct.pack('I', DLT_IEEE802_11_RADIO)
            try:
                fcntl.ioctl(self.ins, BIOCSDLT, dlt_radiotap)
            except IOError:
                raise Scapy_Exception("Can't set %s into monitor mode!" %
                                      self.iface)

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
        if not nofilter:
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, self.iface, filter)

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
        except:
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
        raise Exception("Can't send anything with %s" % self.__name__)

    def recv(self, x=BPF_BUFFER_LENGTH):
        """Dummy recv method"""
        raise Exception("Can't recv anything with %s" % self.__name__)


class L2bpfListenSocket(_L2bpfSocket):
    """"Scapy L2 BPF Listen Super Socket"""

    received_frames = []

    def buffered_frames(self):
        """Return the number of frames in the buffer"""
        return len(self.received_frames)

    def get_frame(self):
        """Get a frame or packet from the received list"""
        if self.received_frames:
            return self.received_frames.pop(0)

    @staticmethod
    def bpf_align(bh_h, bh_c):
        """Return the index to the end of the current packet"""

        # from <net/bpf.h>
        return ((bh_h + bh_c)+(BPF_ALIGNMENT-1)) & ~(BPF_ALIGNMENT-1)

    def extract_frames(self, bpf_buffer):
        """Extract all frames from the buffer and stored them in the received list."""

        # Ensure that the BPF buffer contains at least the header
        len_bb = len(bpf_buffer)
        if len_bb < 20:  # Note: 20 == sizeof(struct bfp_hdr)
            return

        # Extract useful information from the BPF header
        if FREEBSD or NETBSD:
            # struct bpf_xhdr or struct bpf_hdr32
            bh_tstamp_offset = 16
        else:
            # struct bpf_hdr
            bh_tstamp_offset = 8

        # Parse the BPF header
        bh_caplen = struct.unpack('I', bpf_buffer[bh_tstamp_offset:bh_tstamp_offset+4])[0]
        next_offset = bh_tstamp_offset + 4
        bh_datalen = struct.unpack('I', bpf_buffer[next_offset:next_offset+4])[0]
        next_offset += 4
        bh_hdrlen = struct.unpack('H', bpf_buffer[next_offset:next_offset+2])[0]
        if bh_datalen == 0:
            return

        # Get and store the Scapy object
        frame_str = bpf_buffer[bh_hdrlen:bh_hdrlen+bh_caplen]
        try:
            pkt = self.guessed_cls(frame_str)
        except:
            if conf.debug_dissector:
                raise
            pkt = conf.raw_layer(frame_str)
        self.received_frames.append(pkt)

        # Extract the next frame
        end = self.bpf_align(bh_hdrlen, bh_caplen)
        if (len_bb - end) >= 20:
            self.extract_frames(bpf_buffer[end:])

    def recv(self, x=BPF_BUFFER_LENGTH):
        """Receive a frame from the network"""

        if self.buffered_frames():
            # Get a frame from the buffer
            return self.get_frame()

        # Get data from BPF
        try:
            bpf_buffer = os.read(self.ins, x)
        except EnvironmentError as exc:
            if exc.errno != errno.EAGAIN:
                warning("BPF recv()", exc_info=True)
            return

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
            return self.get_frame()

        # Set the non blocking flag, read from the socket, and unset the flag
        self.set_nonblock(True)
        pkt = L2bpfListenSocket.recv(self)
        self.set_nonblock(False)
        return pkt


class L3bpfSocket(L2bpfSocket):

    def get_frame(self):
        """Get a frame or packet from the received list"""
        pkt = super(L3bpfSocket, self).get_frame()
        if pkt is not None:
            return pkt.payload

    def send(self, pkt):
        """Send a packet"""

        # Use the routing table to find the output interface
        iff = pkt.route()[0]
        if iff is None:
            iff = conf.iface

        # Assign the network interface to the BPF handle
        if self.assigned_interface != iff:
            try:
                fcntl.ioctl(self.outs, BIOCSETIF, struct.pack("16s16x", iff.encode()))
            except IOError:
                raise Scapy_Exception("BIOCSETIF failed on %s" % iff)
            self.assigned_interface = iff

        # Build the frame
        frame = raw(self.guessed_cls()/pkt)
        pkt.sent_time = time.time()

        # Send the frame
        L2bpfSocket.send(self, frame)


# Sockets manipulation functions

def isBPFSocket(obj):
    """Return True is obj is a BPF Super Socket"""
    return isinstance(obj, L2bpfListenSocket) or isinstance(obj, L2bpfListenSocket) or isinstance(obj, L3bpfSocket)


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
