# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Packet sending and receiving with libdnet and libpcap/WinPcap.
"""

import time
import struct
import sys
import platform
import socket

from scapy.data import *
from scapy.compat import *
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.utils import mac2str
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception, log_loading, warning
from scapy.pton_ntop import inet_ntop
from scapy.automaton import SelectableObject
import scapy.arch
import scapy.consts

if not scapy.consts.WINDOWS:
    from fcntl import ioctl

############
#  COMMON  #
############


class PcapTimeoutElapsed(Scapy_Exception):
    pass


class _L2pcapdnetSocket(SuperSocket, SelectableObject):
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
            if pkt is None and scapy.consts.WINDOWS:
                raise PcapTimeoutElapsed  # To understand this behavior, have a look at L2pcapListenSocket's note  # noqa: E501
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


###################
#  WINPCAP/NPCAP  #
###################


if conf.use_winpcapy:
    NPCAP_PATH = os.environ["WINDIR"] + "\\System32\\Npcap"
    #  Part of the code from https://github.com/phaethon/scapy translated to python2.X  # noqa: E501
    try:
        from scapy.modules.winpcapy import *

        def winpcapy_get_if_list():
            err = create_string_buffer(PCAP_ERRBUF_SIZE)
            devs = POINTER(pcap_if_t)()
            ret = []
            if pcap_findalldevs(byref(devs), err) < 0:
                return ret
            try:
                p = devs
                while p:
                    ret.append(plain_str(p.contents.name))
                    p = p.contents.next
                return ret
            except:
                raise
            finally:
                pcap_freealldevs(devs)
        # Detect Pcap version
        version = pcap_lib_version()
        if b"winpcap" in version.lower():
            if os.path.exists(NPCAP_PATH + "\\wpcap.dll"):
                warning("Winpcap is installed over Npcap. Will use Winpcap (see 'Winpcap/Npcap conflicts' in scapy's docs)")  # noqa: E501
            elif platform.release() != "XP":
                warning("WinPcap is now deprecated (not maintened). Please use Npcap instead")  # noqa: E501
        elif b"npcap" in version.lower():
            conf.use_npcap = True
            LOOPBACK_NAME = scapy.consts.LOOPBACK_NAME = "Npcap Loopback Adapter"  # noqa: E501
    except OSError as e:
        def winpcapy_get_if_list():
            return []
        conf.use_winpcapy = False
        if conf.interactive:
            log_loading.warning("wpcap.dll is not installed. You won't be able to send/recieve packets. Visit the scapy's doc to install it")  # noqa: E501

    # From BSD net/bpf.h
    # BIOCIMMEDIATE=0x80044270
    BIOCIMMEDIATE = -2147204496

    def get_if_raw_addr(iff):  # noqa: F811
        """Returns the raw ip address corresponding to the NetworkInterface."""
        if conf.cache_ipaddrs:
            return conf.cache_ipaddrs.get(iff.pcap_name, None)
        err = create_string_buffer(PCAP_ERRBUF_SIZE)
        devs = POINTER(pcap_if_t)()

        if pcap_findalldevs(byref(devs), err) < 0:
            return None
        try:
            p = devs
            while p:
                a = p.contents.addresses
                while a:
                    if a.contents.addr.contents.sa_family == socket.AF_INET:
                        ap = a.contents.addr
                        val = cast(ap, POINTER(sockaddr_in))
                        if_raw_addr = b"".join(chb(x) for x in val.contents.sin_addr[:4])  # noqa: E501
                        if if_raw_addr != b'\x00\x00\x00\x00':
                            conf.cache_ipaddrs[plain_str(p.contents.name)] = if_raw_addr  # noqa: E501
                    a = a.contents.next
                p = p.contents.next
            return conf.cache_ipaddrs.get(iff.pcap_name, None)
        finally:
            pcap_freealldevs(devs)
    if conf.use_winpcapy:
        def get_if_list():
            """Returns all pcap names"""
            if conf.cache_iflist:
                return conf.cache_iflist
            iflist = winpcapy_get_if_list()
            conf.cache_iflist = iflist
            return iflist
    else:
        get_if_list = winpcapy_get_if_list

    def in6_getifaddr_raw():
        """Returns all available IPv6 on the computer, read from winpcap."""
        err = create_string_buffer(PCAP_ERRBUF_SIZE)
        devs = POINTER(pcap_if_t)()
        ret = []
        if pcap_findalldevs(byref(devs), err) < 0:
            return ret
        try:
            p = devs
            ret = []
            while p:
                a = p.contents.addresses
                while a:
                    if a.contents.addr.contents.sa_family == socket.AF_INET6:
                        ap = a.contents.addr
                        val = cast(ap, POINTER(sockaddr_in6))
                        addr = inet_ntop(socket.AF_INET6, b"".join(chb(x) for x in val.contents.sin6_addr[:]))  # noqa: E501
                        scope = scapy.utils6.in6_getscope(addr)
                        ret.append((addr, scope, plain_str(p.contents.name)))
                    a = a.contents.next
                p = p.contents.next
            return ret
        finally:
            pcap_freealldevs(devs)

    from ctypes import POINTER, byref, create_string_buffer

    class _PcapWrapper_pypcap:  # noqa: F811
        """Wrapper for the WinPcap calls"""

        def __init__(self, device, snaplen, promisc, to_ms, monitor=None):
            self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
            self.iface = create_string_buffer(device.encode("utf8"))
            if monitor:
                self.pcap = pcap_create(self.iface, self.errbuf)
                pcap_set_snaplen(self.pcap, snaplen)
                pcap_set_promisc(self.pcap, promisc)
                pcap_set_timeout(self.pcap, to_ms)
                if pcap_set_rfmon(self.pcap, 1) != 0:
                    warning("Could not set monitor mode")
                if pcap_activate(self.pcap) != 0:
                    raise OSError("Could not activate the pcap handler")
            else:
                self.pcap = pcap_open_live(self.iface, snaplen, promisc, to_ms, self.errbuf)  # noqa: E501

            # Winpcap exclusive: make every packet to be instantly
            # returned, and not buffered withing Winpcap
            pcap_setmintocopy(self.pcap, 0)

            self.header = POINTER(pcap_pkthdr)()
            self.pkt_data = POINTER(c_ubyte)()
            self.bpf_program = bpf_program()

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

    open_pcap = lambda *args, **kargs: _PcapWrapper_pypcap(*args, **kargs)

################
#  PCAP/PCAPY  #
################


if conf.use_pcap:
    try:
        import pcap  # python-pypcap
        _PCAP_MODE = "pypcap"
    except ImportError as e:
        try:
            import libpcap as pcap  # python-libpcap
            _PCAP_MODE = "libpcap"
        except ImportError as e2:
            try:
                import pcapy as pcap  # python-pcapy
                _PCAP_MODE = "pcapy"
            except ImportError as e3:
                if conf.interactive:
                    log_loading.error("Unable to import pcap module: %s/%s", e, e2)  # noqa: E501
                    conf.use_pcap = False
                else:
                    raise
    if conf.use_pcap:

        # From BSD net/bpf.h
        # BIOCIMMEDIATE=0x80044270
        BIOCIMMEDIATE = -2147204496

        if _PCAP_MODE == "pypcap":  # python-pypcap
            class _PcapWrapper_pypcap:  # noqa: F811
                def __init__(self, device, snaplen, promisc, to_ms, monitor=False):  # noqa: E501
                    try:
                        self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1, timeout_ms=to_ms, rfmon=monitor)  # noqa: E501
                    except TypeError:
                        try:
                            if monitor:
                                warning("Your pypcap version is too old to support monitor mode, Please use pypcap 1.2.1+ !")  # noqa: E501
                            self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1, timeout_ms=to_ms)  # noqa: E501
                        except TypeError:
                            # Even older pypcap versions do not support the timeout_ms argument  # noqa: E501
                            self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1)  # noqa: E501

                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)

                def setnonblock(self, i):
                    self.pcap.setnonblock(i)

                def __del__(self):
                    try:
                        self.pcap.close()
                    except AttributeError:
                        warning("__del__: don't know how to close the file "
                                "descriptor. Bugs ahead! Please use python-pypcap 1.2.1+")  # noqa: E501

                def send(self, x):
                    self.pcap.sendpacket(x)

                def next(self):
                    c = self.pcap.next()
                    if c is None:
                        return
                    ts, pkt = c
                    return ts, raw(pkt)
                __next__ = next
            open_pcap = lambda *args, **kargs: _PcapWrapper_pypcap(*args, **kargs)  # noqa: E501
        elif _PCAP_MODE == "libpcap":  # python-libpcap
            class _PcapWrapper_libpcap:
                def __init__(self, device, snaplen, promisc, to_ms, monitor=False):  # noqa: E501
                    self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
                    if monitor:
                        self.pcap = pcap.pcap_create(device, self.errbuf)
                        pcap.pcap_set_snaplen(self.pcap, snaplen)
                        pcap.pcap_set_promisc(self.pcap, promisc)
                        pcap.pcap_set_timeout(self.pcap, to_ms)
                        if pcap.pcap_set_rfmon(self.pcap, 1) != 0:
                            warning("Could not set monitor mode")
                        if pcap.pcap_activate(self.pcap) != 0:
                            raise OSError("Could not activate the pcap handler")  # noqa: E501
                    else:
                        self.pcap = pcap.open_live(device, snaplen, promisc, to_ms)  # noqa: E501

                def setfilter(self, filter):
                    self.pcap.setfilter(filter, 0, 0)

                def next(self):
                    c = self.pcap.next()
                    if c is None:
                        return
                    l, pkt, ts = c
                    return ts, pkt
                __next__ = next

                def setnonblock(self, i):
                    pcap.pcap_setnonblock(self.pcap, i, self.errbuf)

                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)

                def send(self, x):
                    pcap.pcap_sendpacket(self.pcap, x, len(x))

                def __del__(self):
                    pcap.close(self.pcap)
            open_pcap = lambda *args, **kargs: _PcapWrapper_libpcap(*args, **kargs)  # noqa: E501
        elif _PCAP_MODE == "pcapy":  # python-pcapy
            class _PcapWrapper_pcapy:
                def __init__(self, device, snaplen, promisc, to_ms, monitor=False):  # noqa: E501
                    if monitor:
                        warning("pcapy does not support monitor mode ! Use pypcap or libpcap instead !")  # noqa: E501
                    self.pcap = pcap.open_live(device, snaplen, promisc, to_ms)

                def next(self):
                    try:
                        c = self.pcap.next()
                    except pcap.PcapError:
                        return None
                    else:
                        h, p = c
                        if h is None:
                            return
                        s, us = h.getts()
                        return (s + 0.000001 * us), p
                __next__ = next

                def fileno(self):
                    try:
                        return self.pcap.getfd()
                    except AttributeError:
                        warning("fileno: getfd() does not exist. Please use "
                                "pcapy 0.11.3+ !")

                def setnonblock(self, i):
                    self.pcap.setnonblock(i)

                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)

                def send(self, x):
                    self.pcap.sendpacket(x)

                def __del__(self):
                    try:
                        self.pcap.close()
                    except AttributeError:
                        warning("__del__: don't know how to close the file "
                                "descriptor. Bugs ahead! Please update pcapy!")
            open_pcap = lambda *args, **kargs: _PcapWrapper_pcapy(*args, **kargs)  # noqa: E501


#################
# PCAP/WINPCAPY #
#################

if conf.use_pcap or conf.use_winpcapy:
    class L2pcapListenSocket(_L2pcapdnetSocket):
        desc = "read packets at layer 2 using libpcap"

        def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None, monitor=None):  # noqa: E501
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
            # everything is always recieved as non-blocking
            self.ins = open_pcap(iface, MTU, self.promisc, 100, monitor=monitor)  # noqa: E501
            try:
                ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
            except:
                pass
            if type == ETH_P_ALL:  # Do not apply any filter if Ethernet type is given  # noqa: E501
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)  # noqa: E501
                    else:
                        filter = "not (%s)" % conf.except_filter
                if filter:
                    self.ins.setfilter(filter)

        def close(self):
            self.ins.close()

        def send(self, x):
            raise Scapy_Exception("Can't send anything with L2pcapListenSocket")  # noqa: E501

    conf.L2listen = L2pcapListenSocket

    class L2pcapSocket(_L2pcapdnetSocket):
        desc = "read/write packets at layer 2 using only libpcap"

        def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter=None, nofilter=0,  # noqa: E501
                     monitor=None):
            if iface is None:
                iface = conf.iface
            self.iface = iface
            if promisc is None:
                promisc = 0
            self.promisc = promisc
            # See L2pcapListenSocket for infos about this line
            self.ins = open_pcap(iface, MTU, self.promisc, 100, monitor=monitor)  # noqa: E501
            # We need to have a different interface open because of an
            # access violation in Npcap that occurs in multi-threading
            # (see https://github.com/nmap/nmap/issues/982)
            self.outs = open_pcap(iface, MTU, self.promisc, 100)
            try:
                ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
            except:
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

        def close(self):
            if not self.closed:
                if hasattr(self, "ins"):
                    self.ins.close()
                if hasattr(self, "outs"):
                    self.outs.close()
            self.closed = True

    class L3pcapSocket(L2pcapSocket):
        desc = "read/write packets at layer 3 using only libpcap"
        # def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):  # noqa: E501
        #    L2pcapSocket.__init__(self, iface, type, filter, nofilter)

        def recv(self, x=MTU):
            r = L2pcapSocket.recv(self, x)
            if r:
                return r.payload
            else:
                return

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
    conf.L2socket = L2pcapSocket
    conf.L3socket = L3pcapSocket

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
                return []
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
                l = dnet.intf().get(iff)
                link_addr = l["link_addr"]
            except:
                raise Scapy_Exception("Error in attempting to get hw address"
                                      " for interface [%s]" % iff)

            if hasattr(link_addr, "type"):
                # Legacy dnet module
                return link_addr.type, link_addr.data

            else:
                # dumbnet module
                mac = mac2str(str(link_addr))

                # Adjust the link type
                if l["type"] == 6:  # INTF_TYPE_ETH from dnet
                    return (ARPHDR_ETHER, mac)

                return (l["type"], mac)

        def get_if_raw_addr(ifname):  # noqa: F811
            i = dnet.intf()
            try:
                return i.get(ifname)["addr"].data
            except (OSError, KeyError):
                warning("No MAC address found on %s !" % ifname)
                return b"\0\0\0\0"

        def get_if_list():
            return [i.get("name", None) for i in dnet.intf()]

        def get_working_if():
            """Returns the first interface than can be used with dnet"""

            if_iter = iter(dnet.intf())

            try:
                intf = next(if_iter)
            except StopIteration:
                return scapy.consts.LOOPBACK_NAME

            return intf.get("name", scapy.consts.LOOPBACK_NAME)
