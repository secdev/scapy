# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Packet sending and receiving with libdnet and libpcap/WinPcap.
"""

import os
import platform
import socket
import struct
import time

from scapy.automaton import SelectableObject
from scapy.arch.common import _select_nonblock
from scapy.compat import raw, plain_str, chb
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.data import MTU, ETH_P_ALL, ARPHDR_ETHER, ARPHDR_LOOPBACK
from scapy.pton_ntop import inet_ntop
from scapy.utils import mac2str
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception, log_loading, warning
import scapy.consts

if not scapy.consts.WINDOWS:
    from fcntl import ioctl

############
#  COMMON  #
############

# From BSD net/bpf.h
# BIOCIMMEDIATE = 0x80044270
BIOCIMMEDIATE = -2147204496


class _L2pcapdnetSocket(SuperSocket, SelectableObject):
    nonblocking_socket = True

    def __init__(self):
        SelectableObject.__init__(self)

    def check_recv(self):
        return True

    def recv_raw(self, x=MTU):
        """Receives a packet, then returns a tuple containing (cls, pkt_data, time)"""  # noqa: E501
        ll = self.ins.datalink()
        if ll in conf.l2types:
            cls = conf.l2types[ll]
        else:
            cls = conf.default_l2
            warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s",  # noqa: E501
                    self.iface, ll, cls.name)

        pkt = None
        while pkt is None:
            pkt = self.ins.next()
            if pkt is not None:
                ts, pkt = pkt
            if pkt is None:
                return None, None, None
        return cls, pkt, ts

    def nonblock_recv(self):
        """Receives and dissect a packet in non-blocking mode.
        Note: on Windows, this won't do anything."""
        self.ins.setnonblock(1)
        p = self.recv(MTU)
        self.ins.setnonblock(0)
        return p

    @staticmethod
    def select(sockets, remain=None):
        return _select_nonblock(sockets, remain=None)

##########
#  PCAP  #
##########


if conf.use_pcap:
    if WINDOWS:
        # Windows specific
        NPCAP_PATH = os.environ["WINDIR"] + "\\System32\\Npcap"
        from scapy.modules.winpcapy import pcap_setmintocopy
    else:
        from scapy.modules.winpcapy import pcap_get_selectable_fd
    from ctypes import POINTER, byref, create_string_buffer, c_ubyte, cast

    # Part of the Winpcapy integration was inspired by phaethon/scapy
    # but he destroyed the commit history, so there is no link to that
    try:
        from scapy.modules.winpcapy import PCAP_ERRBUF_SIZE, pcap_if_t, \
            sockaddr_in, sockaddr_in6, pcap_findalldevs, pcap_freealldevs, \
            pcap_lib_version, pcap_close, \
            pcap_open_live, pcap_pkthdr, \
            pcap_next_ex, pcap_datalink, \
            pcap_compile, pcap_setfilter, pcap_setnonblock, pcap_sendpacket, \
            bpf_program as winpcapy_bpf_program

        def load_winpcapy():
            """This functions calls Winpcap/Npcap pcap_findalldevs function,
            and extracts and parse all the data scapy will need to use it:
             - the Interface List
            This data is stored in their respective conf.cache_* subfields:
                conf.cache_iflist
            """
            err = create_string_buffer(PCAP_ERRBUF_SIZE)
            devs = POINTER(pcap_if_t)()
            if_list = {}
            if pcap_findalldevs(byref(devs), err) < 0:
                return
            try:
                p = devs
                # Iterate through the different interfaces
                while p:
                    name = plain_str(p.contents.name)  # GUID
                    description = plain_str(p.contents.description)  # NAME
                    flags = p.contents.flags  # FLAGS
                    ips = []
                    a = p.contents.addresses
                    while a:
                        # IPv4 address
                        family = a.contents.addr.contents.sa_family
                        ap = a.contents.addr
                        if family == socket.AF_INET:
                            val = cast(ap, POINTER(sockaddr_in))
                            val = val.contents.sin_addr[:]
                        elif family == socket.AF_INET6:
                            val = cast(ap, POINTER(sockaddr_in6))
                            val = val.contents.sin6_addr[:]
                        else:
                            # Unknown address family
                            # (AF_LINK isn't a thing on Windows)
                            a = a.contents.next
                            continue
                        addr = inet_ntop(family, bytes(bytearray(val)))
                        if addr != "0.0.0.0":
                            ips.append(addr)
                        a = a.contents.next
                    if_list[name] = (description, ips, flags)
                    p = p.contents.next
                conf.cache_iflist = if_list
            except Exception:
                raise
            finally:
                pcap_freealldevs(devs)
    except OSError:
        conf.use_pcap = False
        if WINDOWS:
            if conf.interactive:
                log_loading.critical(
                    "Npcap/Winpcap is not installed ! See "
                    "https://scapy.readthedocs.io/en/latest/installation.html#windows"  # noqa: E501
                )
        else:
            if conf.interactive:
                log_loading.critical(
                    "Libpcap is not installed!"
                )
    else:
        if WINDOWS:
            # Detect Pcap version: check for Npcap
            version = pcap_lib_version()
            if b"winpcap" in version.lower():
                if os.path.exists(NPCAP_PATH + "\\wpcap.dll"):
                    warning("Winpcap is installed over Npcap. "
                            "Will use Winpcap (see 'Winpcap/Npcap conflicts' "
                            "in Scapy's docs)")
                elif platform.release() != "XP":
                    warning("WinPcap is now deprecated (not maintained). "
                            "Please use Npcap instead")
            elif b"npcap" in version.lower():
                conf.use_npcap = True
                LOOPBACK_NAME = scapy.consts.LOOPBACK_NAME = "Npcap Loopback Adapter"  # noqa: E501

if conf.use_pcap:
    def get_if_list():
        """Returns all pcap names"""
        if not conf.cache_iflist:
            load_winpcapy()
        return list(conf.cache_iflist)

    class _PcapWrapper_winpcap:  # noqa: F811
        """Wrapper for the WinPcap calls"""

        def __init__(self, device, snaplen, promisc, to_ms, monitor=None):
            self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
            self.iface = create_string_buffer(device.encode("utf8"))
            if monitor:
                if WINDOWS and not conf.use_npcap:
                    raise OSError("On Windows, this feature requires NPcap !")
                # Npcap-only functions
                from scapy.modules.winpcapy import pcap_create, \
                    pcap_set_snaplen, pcap_set_promisc, \
                    pcap_set_timeout, pcap_set_rfmon, pcap_activate
                self.pcap = pcap_create(self.iface, self.errbuf)
                pcap_set_snaplen(self.pcap, snaplen)
                pcap_set_promisc(self.pcap, promisc)
                pcap_set_timeout(self.pcap, to_ms)
                if pcap_set_rfmon(self.pcap, 1) != 0:
                    warning("Could not set monitor mode")
                if pcap_activate(self.pcap) != 0:
                    raise OSError("Could not activate the pcap handler")
            else:
                self.pcap = pcap_open_live(self.iface,
                                           snaplen, promisc, to_ms,
                                           self.errbuf)

            if WINDOWS:
                # Winpcap/Npcap exclusive: make every packet to be instantly
                # returned, and not buffered within Winpcap/Npcap
                pcap_setmintocopy(self.pcap, 0)

            self.header = POINTER(pcap_pkthdr)()
            self.pkt_data = POINTER(c_ubyte)()
            self.bpf_program = winpcapy_bpf_program()

        def next(self):
            c = pcap_next_ex(self.pcap, byref(self.header), byref(self.pkt_data))  # noqa: E501
            if not c > 0:
                return
            ts = self.header.contents.ts.tv_sec + float(self.header.contents.ts.tv_usec) / 1000000  # noqa: E501
            pkt = b"".join(chb(i) for i in self.pkt_data[:self.header.contents.len])  # noqa: E501
            return ts, pkt
        __next__ = next

        def datalink(self):
            return pcap_datalink(self.pcap)

        def fileno(self):
            if WINDOWS:
                log_loading.error("Cannot get selectable PCAP fd on Windows")
                return 0
            else:
                # This does not exist under Windows
                return pcap_get_selectable_fd(self.pcap)

        def setfilter(self, f):
            filter_exp = create_string_buffer(f.encode("utf8"))
            if pcap_compile(self.pcap, byref(self.bpf_program), filter_exp, 0, -1) == -1:  # noqa: E501
                log_loading.error("Could not compile filter expression %s", f)
                return False
            else:
                if pcap_setfilter(self.pcap, byref(self.bpf_program)) == -1:
                    log_loading.error("Could not install filter %s", f)
                    return False
            return True

        def setnonblock(self, i):
            pcap_setnonblock(self.pcap, i, self.errbuf)

        def send(self, x):
            pcap_sendpacket(self.pcap, x, len(x))

        def close(self):
            pcap_close(self.pcap)
    open_pcap = lambda *args, **kargs: _PcapWrapper_winpcap(*args, **kargs)

    # pcap sockets

    class L2pcapListenSocket(_L2pcapdnetSocket):
        desc = "read packets at layer 2 using libpcap"

        def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None, monitor=None):  # noqa: E501
            super(L2pcapListenSocket, self).__init__()
            self.type = type
            self.outs = None
            self.iface = iface
            if iface is None:
                iface = conf.iface
            if promisc is None:
                promisc = conf.sniff_promisc
            self.promisc = promisc
            # Note: Timeout with Winpcap/Npcap
            #   The 4th argument of open_pcap corresponds to timeout. In an ideal world, we would  # noqa: E501
            # set it to 0 ==> blocking pcap_next_ex.
            #   However, the way it is handled is very poor, and result in a jerky packet stream.  # noqa: E501
            # To fix this, we set 100 and the implementation under windows is slightly different, as  # noqa: E501
            # everything is always received as non-blocking
            self.ins = open_pcap(iface, MTU, self.promisc, 100,
                                 monitor=monitor)
            try:
                ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
            except Exception:
                pass
            if type == ETH_P_ALL:  # Do not apply any filter if Ethernet type is given  # noqa: E501
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)  # noqa: E501
                    else:
                        filter = "not (%s)" % conf.except_filter
                if filter:
                    self.ins.setfilter(filter)

        def send(self, x):
            raise Scapy_Exception("Can't send anything with L2pcapListenSocket")  # noqa: E501

    class L2pcapSocket(_L2pcapdnetSocket):
        desc = "read/write packets at layer 2 using only libpcap"

        def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None, nofilter=0,  # noqa: E501
                     monitor=None):
            super(L2pcapSocket, self).__init__()
            if iface is None:
                iface = conf.iface
            self.iface = iface
            if promisc is None:
                promisc = 0
            self.promisc = promisc
            # See L2pcapListenSocket for infos about this line
            self.ins = open_pcap(iface, MTU, self.promisc, 100,
                                 monitor=monitor)
            self.outs = self.ins
            try:
                ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
            except Exception:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap  # noqa: E501
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)  # noqa: E501
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap  # noqa: E501
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type, filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)

        def send(self, x):
            sx = raw(x)
            if hasattr(x, "sent_time"):
                x.sent_time = time.time()
            return self.outs.send(sx)

    class L3pcapSocket(L2pcapSocket):
        desc = "read/write packets at layer 3 using only libpcap"

        def recv(self, x=MTU):
            r = L2pcapSocket.recv(self, x)
            if r:
                return r.payload

        def send(self, x):
            # Makes send detects when it should add Loopback(), Dot11... instead of Ether()  # noqa: E501
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s", self.iface, ll, cls.name)  # noqa: E501
            sx = raw(cls() / x)
            if hasattr(x, "sent_time"):
                x.sent_time = time.time()
            return self.ins.send(sx)
else:
    # No libpcap installed
    get_if_list = lambda: []
    if WINDOWS:
        NPCAP_PATH = ""

##########
#  DNET  #
##########

# DEPRECATED

if conf.use_dnet:
    warning("dnet usage with scapy is deprecated, and will be removed in a future version.")  # noqa: E501
    try:
        try:
            # First try to import dnet
            import dnet
        except ImportError:
            # Then, try to import dumbnet as dnet
            import dumbnet as dnet
    except ImportError as e:
        if conf.interactive:
            log_loading.error("Unable to import dnet module: %s", e)
            conf.use_dnet = False

            def get_if_raw_hwaddr(iff):
                "dummy"
                return (0, b"\0\0\0\0\0\0")

            def get_if_raw_addr(iff):  # noqa: F811
                "dummy"
                return b"\0\0\0\0"

            def get_if_list():
                "dummy"
                return {}
        else:
            raise
    else:
        def get_if_raw_hwaddr(iff):
            """Return a tuple containing the link type and the raw hardware
               address corresponding to the interface 'iff'"""

            if iff == scapy.arch.LOOPBACK_NAME:
                return (ARPHDR_LOOPBACK, b'\x00' * 6)

            # Retrieve interface information
            try:
                tmp_intf = dnet.intf().get(iff)
                link_addr = tmp_intf["link_addr"]
            except Exception:
                raise Scapy_Exception("Error in attempting to get hw address"
                                      " for interface [%s]" % iff)

            if hasattr(link_addr, "type"):
                # Legacy dnet module
                return link_addr.type, link_addr.data

            else:
                # dumbnet module
                mac = mac2str(str(link_addr))

                # Adjust the link type
                if tmp_intf["type"] == 6:  # INTF_TYPE_ETH from dnet
                    return (ARPHDR_ETHER, mac)

                return (tmp_intf["type"], mac)

        def get_if_raw_addr(ifname):  # noqa: F811
            i = dnet.intf()
            try:
                return i.get(ifname)["addr"].data
            except (OSError, KeyError):
                warning("No MAC address found on %s !" % ifname)
                return b"\0\0\0\0"

        def get_if_list():
            """Returns all dnet names"""
            return [i.get("name", None) for i in dnet.intf()]

        def get_working_if():
            """Returns the first interface than can be used with dnet"""

            if_iter = iter(dnet.intf())

            try:
                intf = next(if_iter)
            except (StopIteration, RuntimeError):
                return scapy.consts.LOOPBACK_NAME

            return intf.get("name", scapy.consts.LOOPBACK_NAME)
