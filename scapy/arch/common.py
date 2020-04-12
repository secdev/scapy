# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Functions common to different architectures
"""

import ctypes
import socket
import struct
import sys
import time
from scapy.consts import WINDOWS
from scapy.config import conf
from scapy.data import MTU, ARPHRD_TO_DLT
from scapy.error import Scapy_Exception

if not WINDOWS:
    from fcntl import ioctl

# UTILS


def get_if(iff, cmd):
    """Ease SIOCGIF* ioctl calls"""

    sck = socket.socket()
    try:
        return ioctl(sck, cmd, struct.pack("16s16x", iff.encode("utf8")))
    finally:
        sck.close()


def get_if_raw_hwaddr(iff):
    """Get the raw MAC address of a local interface.

    This function uses SIOCGIFHWADDR calls, therefore only works
    on some distros.

    :param iff: the network interface name as a string
    :returns: the corresponding raw MAC address
    """
    from scapy.arch import SIOCGIFHWADDR
    return struct.unpack("16xh6s8x", get_if(iff, SIOCGIFHWADDR))

# SOCKET UTILS


def _select_nonblock(sockets, remain=None):
    """This function is called during sendrecv() routine to select
    the available sockets.
    """
    # pcap sockets aren't selectable, so we return all of them
    # and ask the selecting functions to use nonblock_recv instead of recv
    def _sleep_nonblock_recv(self):
        res = self.nonblock_recv()
        if res is None:
            time.sleep(conf.recv_poll_rate)
        return res
    # we enforce remain=None: don't wait.
    return sockets, _sleep_nonblock_recv

# BPF HANDLERS


def compile_filter(filter_exp, iface=None, linktype=None,
                   promisc=False):
    """Asks libpcap to parse the filter, then build the matching
    BPF bytecode.

    :param iface: if provided, use the interface to compile
    :param linktype: if provided, use the linktype to compile
    """
    try:
        from scapy.libs.winpcapy import (
            PCAP_ERRBUF_SIZE,
            pcap_open_live,
            pcap_compile,
            pcap_compile_nopcap,
            pcap_close
        )
        from scapy.libs.structures import bpf_program
    except OSError:
        raise ImportError(
            "libpcap is not available. Cannot compile filter !"
        )
    from ctypes import create_string_buffer
    bpf = bpf_program()
    bpf_filter = create_string_buffer(filter_exp.encode("utf8"))
    if not linktype:
        # Try to guess linktype to avoid root
        if not iface:
            if not conf.iface:
                raise Scapy_Exception(
                    "Please provide an interface or linktype!"
                )
            if WINDOWS:
                iface = conf.iface.pcap_name
            else:
                iface = conf.iface
        # Try to guess linktype to avoid requiring root
        try:
            arphd = get_if_raw_hwaddr(iface)[0]
            linktype = ARPHRD_TO_DLT.get(arphd)
        except Exception:
            # Failed to use linktype: use the interface
            pass
    if linktype is not None:
        ret = pcap_compile_nopcap(
            MTU, linktype, ctypes.byref(bpf), bpf_filter, 0, -1
        )
    elif iface:
        err = create_string_buffer(PCAP_ERRBUF_SIZE)
        iface = create_string_buffer(iface.encode("utf8"))
        pcap = pcap_open_live(
            iface, MTU, promisc, 0, err
        )
        error = bytes(bytearray(err)).strip(b"\x00")
        if error:
            raise OSError(error)
        ret = pcap_compile(
            pcap, ctypes.byref(bpf), bpf_filter, 0, -1
        )
        pcap_close(pcap)
    if ret == -1:
        raise Scapy_Exception(
            "Failed to compile filter expression %s (%s)" % (filter_exp, ret)
        )
    if conf.use_pypy and sys.pypy_version_info <= (7, 3, 0):
        # PyPy < 7.3.0 has a broken behavior
        # https://bitbucket.org/pypy/pypy/issues/3114
        return struct.pack(
            'HL',
            bpf.bf_len, ctypes.addressof(bpf.bf_insns.contents)
        )
    return bpf
