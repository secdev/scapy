"""
Scapy *BSD native support
"""

from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.data import ARPHDR_LOOPBACK, ARPHDR_ETHER
from scapy.arch.common import get_if
from scapy.arch.bsd import LOOPBACK_NAME
from scapy.arch import FREEBSD, NETBSD
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.data import MTU, ETH_P_ALL
from scapy.supersocket import SuperSocket
from scapy.utils import warning

import os
import socket
import fcntl
import errno
import struct
import time
from select import select

from ctypes import cdll, cast, pointer, POINTER, Structure
from ctypes import c_uint, c_uint32, c_int, c_ulong, c_char_p, c_ushort, c_ubyte
from ctypes.util import find_library


# Constants definitions
SIOCGIFFLAGS = 0xc0206911
BPF_BUFFER_LENGTH = MTU

# From net/bpf.h
BIOCIMMEDIATE = 0x80044270
BIOCGSTATS = 0x4008426f
BIOCPROMISC = 0x20004269
BIOCSETIF = 0x8020426c
BIOCSBLEN = 0xc0044266
BIOCGBLEN = 0x40044266
BIOCSETF = 0x80104267
BIOCSHDRCMPLT = 0x80044275
BIOCGDLT = 0x4004426a


# ctypes definitions

LIBC = cdll.LoadLibrary(find_library("libc"))
LIBC.ioctl.argtypes = [c_int, c_ulong, c_char_p]
LIBC.ioctl.restype = c_int


class bpf_insn(Structure):
    """"The BPF instruction data structure"""
    _fields_ = [("code", c_ushort),
                ("jt", c_ubyte),
                ("jf", c_ubyte),
                ("k", c_uint32)]


class bpf_program(Structure):
    """"Structure for BIOCSETF"""
    _fields_ = [("bf_len", c_uint),
                ("bf_insns", POINTER(bpf_insn))]


# Addresses manipulation functions

def get_if_raw_addr(ifname):
    """Returns the IPv4 address configured on 'ifname', packed with inet_pton."""

    # Get ifconfig output
    try:
        fd = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError, msg:
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" % msg)

    # Get IPv4 addresses
    addresses = [l for l in fd.readlines() if l.find("netmask") >= 0]
    if not addresses:
        raise Scapy_Exception("No IPv4 address found on %s !" % ifname)

    # Pack the first address
    address = addresses[0].split(' ')[1]
    return socket.inet_pton(socket.AF_INET, address)


def get_if_raw_hwaddr(ifname):
    """Returns the packed MAC address configured on 'ifname'."""

    NULL_MAC_ADDRESS = '\x00'*6

    # Handle the loopback interface separately
    if ifname == LOOPBACK_NAME:
        return (ARPHDR_LOOPBACK, NULL_MAC_ADDRESS)

    # Get ifconfig output
    try:
        fd = os.popen("%s %s" % (conf.prog.ifconfig, ifname))
    except OSError, msg:
        warning("Failed to execute ifconfig: (%s)" % msg)
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" % msg)

    # Get MAC addresses
    addresses = [l for l in fd.readlines() if l.find("ether") >= 0 or
                                              l.find("lladdr") >= 0 or
                                              l.find("address") >= 0]
    if not addresses:
        raise Scapy_Exception("No MAC address found on %s !" % ifname)

    # Pack and return the MAC address
    mac = addresses[0].split(' ')[1]
    mac = [chr(int(b, 16)) for b in mac.split(':')]
    return (ARPHDR_ETHER, ''.join(mac))


# BPF specific functions

def get_dev_bpf():
    """Returns an opened BPF file object"""

    # Get the first available BPF handle
    for bpf in range(0, 8):
        try:
            fd = os.open("/dev/bpf%i" % bpf, os.O_RDWR)
            return (fd, bpf)
        except OSError, err:
            continue

    raise Scapy_Exception("No /dev/bpf handle is available !")


def attach_filter(fd, iface, bpf_filter_string):  # GV: move to a method of _L2bpfSocket
    """Attach a BPF filter to the BPF file descriptor"""

    # Retrieve the BPF byte code in decimal
    command = "%s -i %s -ddd -s 1600 '%s'" % (conf.prog.tcpdump, iface, bpf_filter_string)
    try:
        f = os.popen(command)
    except OSError, msg:
        raise Scapy_Exception("Failed to execute tcpdump: (%s)" % msg)

    # Convert the byte code to a BPF program structure
    lines = f.readlines()
    if lines == []:
        raise Scapy_Exception("Got an empty BPF filter from tcpdump !")

    # Allocate BPF instructions
    size = int(lines[0])
    bpf_insn_a = bpf_insn * size
    bip = bpf_insn_a()

    # Fill the BPF instruction structures with the byte code
    lines = lines[1:]
    for i in xrange(len(lines)):
        values = [int(v) for v in lines[i].split()]
        bip[i].code = c_ushort(values[0])
        bip[i].jt = c_ubyte(values[1])
        bip[i].j = c_ubyte(values[2])
        bip[i].k = c_uint(values[3])

    # Create the BPF program and assign it to the interface
    bp = bpf_program(size, bip)
    ret = LIBC.ioctl(c_int(fd), BIOCSETF, cast(pointer(bp), c_char_p))
    if ret < 0:
        raise Scapy_Exception("Can't attach the BPF filter !")


# Interface manipulation functions

def get_if_list():
    """Returns a list containing all network interfaces."""

    # Get ifconfig output
    try:
        fd = os.popen("%s -a" % conf.prog.ifconfig)
    except OSError, msg:
        raise Scapy_Exception("Failed to execute ifconfig: (%s)" % msg)

    # Get interfaces
    interfaces = [line[:line.find(':')] for line in fd.readlines()
                                        if ": flags" in line.lower()]
    return interfaces


def get_working_ifaces():
    """
    Returns an ordered list of interfaces that could be used with BPF.
    Note: the order mimics pcap_findalldevs() behavior
    """

    # Only root is allowed to perform the following ioctl() call
    if os.getuid() != 0:
        return []

    # Test all network interfaces
    interfaces = []
    for ifname in get_if_list():

        # Unlike pcap_findalldevs(), we do not care of loopback interfaces.  # GV: why ?!?
        if ifname == LOOPBACK_NAME:
            continue

        # Get interface flags
        try:
            result = get_if(ifname, SIOCGIFFLAGS)
        except IOError, msg:
            warning("ioctl(SIOCGIFFLAGS) failed on %s !" % ifname)
            continue

        # Convert flags
        ifflags = struct.unpack("16xH14x", result)[0]
        if ifflags & 0x1:  # IFF_UP

            # Get a BPF handle
            fd, _ = get_dev_bpf()
            if fd is None:
                raise Scapy_Exception("No /dev/bpf are available !")

            # Check if the interface can be used
            try:
                fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", ifname))
                interfaces.append((ifname, int(ifname[-1])))
            except IOError, err:
                pass

            # Close the file descriptor
            os.close(fd)

    # Sort to mimic pcap_findalldevs() order
    interfaces.sort(lambda (ifname_left, ifid_left),
                        (ifname_right, ifid_right): ifid_left-ifid_right)
    return interfaces


def get_working_if():
    """Returns the first interface than can be used with BPF"""

    ifaces = get_working_ifaces()
    if not ifaces:
        # A better interface will be selected later using the routing table
        return LOOPBACK_NAME  # GV why ?!?
    return ifaces[0][0]


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

        # Specific BPF sockets
        if isBPFSocket(tmp_fd):
            # Get buffers status
            if tmp_fd.buffered_frames():
                bpf_scks_buffered.append(tmp_fd)
                continue

        # Regular file descriptors or empty BPF buffer
        select_fds.append(tmp_fd)

    if len(bpf_scks_buffered) != len(fds_list):
        # Call select for sockets with empty buffers
        if timeout is None and FREEBSD:
            timeout = 0.05
        ready_list, _, _ = select(select_fds, [], [], timeout)
        return bpf_scks_buffered + ready_list

    else:
        return bpf_scks_buffered


# BPF sockets

class _L2bpfSocket(SuperSocket):
    """"Generic Scapy BPF Super Socket"""

    desc = "read/write packets using BPF"
    assigned_interface = None
    fd_flags = None
    ins = None
    closed = False

    def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None, nofilter=0):

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
        except IOError, err:
            msg = "BIOCSBLEN failed on /dev/bpf%i" % self.dev_bpf
            raise Scapy_Exception(msg)

        # Assign the network interface to the BPF handle
        try:
            fcntl.ioctl(self.ins, BIOCSETIF, struct.pack("16s16x", self.iface))
        except IOError, err:
            msg = "BIOCSETIF failed on %s" % self.iface
            raise Scapy_Exception(msg)
        self.assigned_interface = self.iface

        # Set the interface into promiscuous
        if self.promisc:
            self.set_promisc(1)

        # Don't block on read
        try:
            fcntl.ioctl(self.ins, BIOCIMMEDIATE, struct.pack('I', 1))
        except IOError, err:
            msg = "BIOCIMMEDIATE failed on /dev/bpf%i" % self.dev_bpf
            raise Scapy_Exception(msg)

        # Scapy will provide the link layer source address
        # Otherwise, it is written by the kernel
        try:
            fcntl.ioctl(self.ins, BIOCSHDRCMPLT, struct.pack('i', 1))
        except IOError, err:
            msg = "BIOCSHDRCMPLT failed on /dev/bpf%i" % self.dev_bpf
            raise Scapy_Exception(msg)

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
        except IOError, err:
            msg = "Can't put your interface (%s) into promiscuous mode !" % self.iface
            raise Scapy_Exception(msg)

    def __del__(self):
        """Close the file descriptor on delete"""
        self.close()

    def guess_cls(self):
        """Guess the packet class that must be used on the interface"""

        # Get the data link type
        try:
            ret = fcntl.ioctl(self.ins, BIOCGDLT, struct.pack('I', 0))
            ret = struct.unpack('I', ret)[0]
        except IOError, err:
            warning("BIOCGDLT failed: unable to guess type. Using Ethernet !")
            return Ether

        # Retrieve the corresponding class
        cls = conf.l2types.get(ret, None)
        if cls is None:
            cls = Ether
            warning("Unable to guess type. Using Ethernet !")

        return cls

    def set_nonblock(self, set_flag=True):
        """Set the non blocking flag on the socket"""

        # Get the current flags
        if self.fd_flags is None:
            try:
                self.fd_flags = fcntl.fcntl(self.ins, fcntl.F_GETFL)
            except IOError, err:
                warning("Can't get flags on this file descriptor !")
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
        except IOError, err:
            warning("Unable to get stats from BPF !")
            return (None, None)

    def get_blen(self):
        """Get the BPF buffer length"""

        try:
            ret = fcntl.ioctl(self.ins, BIOCGBLEN, struct.pack("I", 0))
            return struct.unpack("I", ret)[0]
        except IOError, err:
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
            pkt = self.received_frames.pop(0)
            if isinstance(self, L3bpfSocket):
                pkt = pkt.payload
            return pkt

        return None

    def bpf_align(self, bh_h, bh_c):
        """Return the index to the end of the current packet"""

        if FREEBSD or NETBSD:
            BPF_ALIGNMENT = 8  # sizeof(long)
        else:
            BPF_ALIGNMENT = 4  # sizeof(int32_t)

        x = bh_h + bh_c
        return ((x)+(BPF_ALIGNMENT-1)) & ~(BPF_ALIGNMENT-1)  # from <net/bpf.h>

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
            pkt = Raw(frame_str)
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

        else:
            # Get data from BPF
            try:
                bpf_buffer = os.read(self.ins, x)
            except EnvironmentError, e:
                if e.errno == errno.EAGAIN:
                    return
                else:
                    warning("BPF recv(): %s" % e)
                    return

            # Extract all frames from the BPF buffer
            self.extract_frames(bpf_buffer)
            return self.get_frame()


class L2bpfSocket(L2bpfListenSocket):
    """"Scapy L2 BPF Super Socket"""

    def send(self, x):
        """Send a frame"""
        return os.write(self.outs, str(x))

    def nonblock_recv(self):
        """Non blocking receive"""

        if self.buffered_frames():
            # Get a frame from the buffer
            return self.get_frame()

        else:
            # Set the non blocking flag, read from the socket, and unset the flag
            self.set_nonblock(True)
            pkt = L2bpfListenSocket.recv(self)
            self.set_nonblock(False)
            return pkt


class L3bpfSocket(L2bpfSocket):

    def send(self, pkt):
        """Send a packet"""

        # Use the routing table to find the output interface
        if isinstance(pkt, IPv6):
            iff, a, gw = conf.route6.route(pkt.dst)
        if isinstance(pkt, IP):
            iff, a, gw = conf.route.route(pkt.dst)
        else:
            iff = conf.iface

        # Assign the network interface to the BPF handle
        # GV: use a generic method for ioctl calls ?
        if self.assigned_interface != iff:
            try:
                fcntl.ioctl(self.outs, BIOCSETIF, struct.pack("16s16x", iff))
            except IOError, err:
                msg = "BIOCSETIF failed on %s" % iff
                raise Scapy_Exception(msg)
            self.assigned_interface = iff

        # Build the frame
        frame = str(self.guessed_cls()/pkt)
        pkt.sent_time = time.time()

        # Send the frame
        L2bpfSocket.send(self, frame)
