#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

"""
ISOTPSocket.
"""


import ctypes
from ctypes.util import find_library
import struct
import socket
import time

import scapy.modules.six as six
from scapy.error import Scapy_Exception, warning
from scapy.packet import Packet
from scapy.fields import StrField
from scapy.supersocket import SuperSocket
from scapy.sendrecv import sndrcv, sniff
from scapy.arch.linux import get_last_packet_timestamp, SIOCGIFINDEX
from scapy.config import conf
from scapy.consts import WINDOWS

if six.PY2:
    Scapy_Exception("ISOTP is not supported on python2, yet. "
                    "Switch to python3 and try it again.")


if not WINDOWS:
    LIBC = ctypes.cdll.LoadLibrary(find_library("c"))
    warning("Loading libc with ctypes")
else:
    warning("libc is unavailable")


"""
ISOTP Packet
"""


class ISOTP(Packet):
    name = 'ISOTP'
    fields_desc = [
        StrField('data', B"")
    ]

    def hashret(self):
        return self.payload.hashret()

    def answers(self, other):
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0


CAN_MTU = 16
CAN_MAX_DLEN = 8

CAN_ISOTP = 6  # ISO 15765-2 Transport Protocol

SOL_CAN_ISOTP = (socket.SOL_CAN_BASE + CAN_ISOTP)
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


class ISOTPSocket(SuperSocket):
    desc = "read/write packets at a given CAN interface using CAN_ISOTP socket"
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
                                     tx_flags=CAN_ISOTP_DEFAULT_LL_TX_FLAGS):
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
        socketID = ctypes.c_int(sock.fileno())
        ifr = IFREQ()
        ifr.ifr_name = iface.encode('ascii')
        ret = LIBC.ioctl(socketID, SIOCGIFINDEX, ctypes.byref(ifr))

        if ret < 0:
            m = u'Failure while getting "{}" interface index.'.format(iface)
            raise Scapy_Exception(m)
        return ifr

    def __bind_socket(self, sock, iface, sid, did):
        socketID = ctypes.c_int(sock.fileno())
        ifr = self.__get_sock_ifreq(sock, iface)

        if sid > 0x7ff:
            sid = sid | socket.CAN_EFF_FLAG
        if did > 0x7ff:
            did = did | socket.CAN_EFF_FLAG

        # select the CAN interface and bind the socket to it
        addr = SOCKADDR_CAN(ctypes.c_uint16(socket.PF_CAN),
                            ifr.ifr_ifindex,
                            ADDR_INFO(TP(ctypes.c_uint32(sid),
                                         ctypes.c_uint32(did))))

        error = LIBC.bind(socketID, ctypes.byref(addr), ctypes.sizeof(addr))

        if error < 0:
            warning("Couldn't bind socket")

    def __set_option_flags(self, sock, extended_addr=None,
                           extended_rx_addr=None,
                           listen_only=False):
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

        sock.setsockopt(SOL_CAN_ISOTP,
                        CAN_ISOTP_OPTS,
                        self.__build_can_isotp_options(
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
                 basecls=ISOTP):
        self.iface = conf.contribs['NativeCANSocket']['iface'] \
            if iface is None else iface
        self.ins = socket.socket(socket.PF_CAN, socket.SOCK_DGRAM, CAN_ISOTP)
        self.__set_option_flags(self.ins,
                                extended_addr,
                                extended_rx_addr,
                                listen_only)

        self.ins.setsockopt(SOL_CAN_ISOTP,
                            CAN_ISOTP_RECV_FC,
                            self.__build_can_isotp_fc_options())
        self.ins.setsockopt(SOL_CAN_ISOTP,
                            CAN_ISOTP_LL_OPTS,
                            self.__build_can_isotp_ll_options())

        self.__bind_socket(self.ins, iface, sid, did)
        self.outs = self.ins
        if basecls is None:
            warning('Provide a basecls ')
        self.basecls = basecls

    def recv_raw(self, x=0xffff):
        """Receives a packet, then returns a tuple containing (cls, pkt_data, time)"""  # noqa: E501
        try:
            pkt = self.ins.recvfrom(x)[0]
        except BlockingIOError:         # noqa: F821
            warning('Captured no data, socket in non-blocking mode.')
            return None
        except socket.timeout:
            warning('Captured no data, socket read timed out.')
            return None
        except OSError:
            # something bad happened (e.g. the interface went down)
            warning("Captured no data.")
            return None

        ts = get_last_packet_timestamp(self.ins)
        return self.basecls, pkt, ts

    def send(self, x):
        if hasattr(x, "sent_time"):
            x.sent_time = time.time()
        return self.outs.send(bytes(x))

    def sr(self, *args, **kargs):
        return sndrcv(self, *args, **kargs)

    def sr1(self, *args, **kargs):
        data = sndrcv(self, *args, **kargs)
        if data:
            return data[0][0][1]

    def sniff(self, *args, **kargs):
        return sniff(opened_socket=self, *args, **kargs)
