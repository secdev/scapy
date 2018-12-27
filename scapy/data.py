# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Global variables and functions for handling external data sets.
"""


import os
import re
import time


from scapy.dadict import DADict
from scapy.consts import FREEBSD, NETBSD, OPENBSD, WINDOWS
from scapy.error import log_loading
from scapy.compat import plain_str
import scapy.modules.six as six


############
#  Consts  #
############

ETHER_ANY = b"\x00" * 6
ETHER_BROADCAST = b"\xff" * 6

ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806
ETH_P_IPV6 = 0x86dd
ETH_P_MACSEC = 0x88e5

# From net/if_arp.h
ARPHDR_ETHER = 1
ARPHDR_METRICOM = 23
ARPHDR_PPP = 512
ARPHDR_LOOPBACK = 772
ARPHDR_TUN = 65534

# From pcap/dlt.h
DLT_NULL = 0
DLT_EN10MB = 1
DLT_EN3MB = 2
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
if OPENBSD:
    DLT_RAW = 14
else:
    DLT_RAW = 12
DLT_RAW_ALT = 101  # At least in Argus
if FREEBSD or NETBSD:
    DLT_SLIP_BSDOS = 13
    DLT_PPP_BSDOS = 14
else:
    DLT_SLIP_BSDOS = 15
    DLT_PPP_BSDOS = 16
if FREEBSD:
    DLT_PFSYNC = 121
else:
    DLT_PFSYNC = 18
    DLT_HHDLC = 121
DLT_ATM_CLIP = 19
DLT_PPP_SERIAL = 50
DLT_PPP_ETHER = 51
DLT_SYMANTEC_FIREWALL = 99
DLT_C_HDLC = 104
DLT_IEEE802_11 = 105
if OPENBSD:
    DLT_LOOP = 12
    DLT_ENC = 13
else:
    DLT_LOOP = 108
    DLT_ENC = 109
DLT_LINUX_SLL = 113
DLT_PFLOG = 117
DLT_PRISM_HEADER = 119
DLT_AIRONET_HEADER = 120
DLT_IEEE802_11_RADIO = 127
DLT_LINUX_IRDA = 144
DLT_IEEE802_11_RADIO_AVS = 163
DLT_BLUETOOTH_HCI_H4 = 187
DLT_USB_LINUX = 189
DLT_IEEE802_15_4_WITHFCS = 195
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_PPP_WITH_DIR = 204
DLT_PPI = 192
DLT_CAN_SOCKETCAN = 227
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_IEEE802_15_4_NOFCS = 230
DLT_USBPCAP = 249
DLT_USB_DARWIN = 266
DLT_BLUETOOTH_LE_LL = 251
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256

# From net/ipv6.h on Linux (+ Additions)
IPV6_ADDR_UNICAST = 0x01
IPV6_ADDR_MULTICAST = 0x02
IPV6_ADDR_CAST_MASK = 0x0F
IPV6_ADDR_LOOPBACK = 0x10
IPV6_ADDR_GLOBAL = 0x00
IPV6_ADDR_LINKLOCAL = 0x20
IPV6_ADDR_SITELOCAL = 0x40     # deprecated since Sept. 2004 by RFC 3879
IPV6_ADDR_SCOPE_MASK = 0xF0
# IPV6_ADDR_COMPATv4   = 0x80     # deprecated; i.e. ::/96
# IPV6_ADDR_MAPPED     = 0x1000   # i.e.; ::ffff:0.0.0.0/96
IPV6_ADDR_6TO4 = 0x0100   # Added to have more specific info (should be 0x0101 ?)  # noqa: E501
IPV6_ADDR_UNSPECIFIED = 0x10000


# On windows, epoch is 01/02/1970 at 00:00
EPOCH = time.mktime((1970, 1, 2, 0, 0, 0, 3, 1, 0)) - 86400

MTU = 0xffff  # a.k.a give me all you have


def load_protocols(filename, _integer_base=10):
    """"Parse /etc/protocols and return values as a dictionary."""
    spaces = re.compile(b"[ \t]+|\n")
    dct = DADict(_name=filename)
    try:
        with open(filename, "rb") as fdesc:
            for line in fdesc:
                try:
                    shrp = line.find(b"#")
                    if shrp >= 0:
                        line = line[:shrp]
                    line = line.strip()
                    if not line:
                        continue
                    lt = tuple(re.split(spaces, line))
                    if len(lt) < 2 or not lt[0]:
                        continue
                    dct[lt[0]] = int(lt[1], _integer_base)
                except Exception as e:
                    log_loading.info(
                        "Couldn't parse file [%s]: line [%r] (%s)",
                        filename,
                        line,
                        e,
                    )
    except IOError:
        log_loading.info("Can't open %s file", filename)
    return dct


def load_ethertypes(filename):
    """"Parse /etc/ethertypes and return values as a dictionary."""
    return load_protocols(filename, _integer_base=16)


def load_services(filename):
    spaces = re.compile(b"[ \t]+|\n")
    tdct = DADict(_name="%s-tcp" % filename)
    udct = DADict(_name="%s-udp" % filename)
    try:
        with open(filename, "rb") as fdesc:
            for line in fdesc:
                try:
                    shrp = line.find(b"#")
                    if shrp >= 0:
                        line = line[:shrp]
                    line = line.strip()
                    if not line:
                        continue
                    lt = tuple(re.split(spaces, line))
                    if len(lt) < 2 or not lt[0]:
                        continue
                    if lt[1].endswith(b"/tcp"):
                        tdct[lt[0]] = int(lt[1].split(b'/')[0])
                    elif lt[1].endswith(b"/udp"):
                        udct[lt[0]] = int(lt[1].split(b'/')[0])
                except Exception as e:
                    log_loading.warning(
                        "Couldn't parse file [%s]: line [%r] (%s)",
                        filename,
                        line,
                        e,
                    )
    except IOError:
        log_loading.info("Can't open /etc/services file")
    return tdct, udct


class ManufDA(DADict):
    def fixname(self, val):
        return plain_str(val)

    def __dir__(self):
        return ["lookup", "reverse_lookup"]

    def _get_manuf_couple(self, mac):
        oui = ":".join(mac.split(":")[:3]).upper()
        return self.__dict__.get(oui, (mac, mac))

    def _get_manuf(self, mac):
        return self._get_manuf_couple(mac)[1]

    def _get_short_manuf(self, mac):
        return self._get_manuf_couple(mac)[0]

    def _resolve_MAC(self, mac):
        oui = ":".join(mac.split(":")[:3]).upper()
        if oui in self:
            return ":".join([self[oui][0]] + mac.split(":")[3:])
        return mac

    def lookup(self, mac):
        """Find OUI name matching to a MAC"""
        oui = ":".join(mac.split(":")[:3]).upper()
        return self[oui]

    def reverse_lookup(self, name, case_sensitive=False):
        """Find all MACs registered to a OUI
        params:
         - name: the OUI name
         - case_sensitive: default to False
        returns: a dict of mac:tuples (Name, Extended Name)
        """
        if case_sensitive:
            filtr = lambda x, l: any(x == z for z in l)
        else:
            name = name.lower()
            filtr = lambda x, l: any(x == z.lower() for z in l)
        return {k: v for k, v in six.iteritems(self.__dict__)
                if filtr(name, v)}


def load_manuf(filename):
    """Load manuf file from Wireshark.
    param:
     - filename: the file to load the manuf file from"""
    manufdb = ManufDA(_name=filename)
    with open(filename, "rb") as fdesc:
        for line in fdesc:
            try:
                line = line.strip()
                if not line or line.startswith(b"#"):
                    continue
                parts = line.split(None, 2)
                oui, shrt = parts[:2]
                lng = parts[2].lstrip(b"#").strip() if len(parts) > 2 else ""
                lng = lng or shrt
                manufdb[oui] = plain_str(shrt), plain_str(lng)
            except Exception:
                log_loading.warning("Couldn't parse one line from [%s] [%r]",
                                    filename, line, exc_info=True)
    return manufdb


if WINDOWS:
    ETHER_TYPES = load_ethertypes("ethertypes")
    IP_PROTOS = load_protocols(os.environ["SystemRoot"] + "\\system32\\drivers\\etc\\protocol")  # noqa: E501
    TCP_SERVICES, UDP_SERVICES = load_services(os.environ["SystemRoot"] + "\\system32\\drivers\\etc\\services")  # noqa: E501
    # Default value, will be updated by arch.windows
    try:
        MANUFDB = load_manuf(os.environ["ProgramFiles"] + "\\wireshark\\manuf")
    except (IOError, OSError):  # FileNotFoundError not available on Py2 - using OSError  # noqa: E501
        MANUFDB = None
else:
    IP_PROTOS = load_protocols("/etc/protocols")
    ETHER_TYPES = load_ethertypes("/etc/ethertypes")
    TCP_SERVICES, UDP_SERVICES = load_services("/etc/services")
    MANUFDB = None
    for prefix in ['/usr', '/usr/local', '/opt', '/opt/wireshark']:
        try:
            MANUFDB = load_manuf(os.path.join(prefix, "share", "wireshark",
                                              "manuf"))
            if MANUFDB:
                break
        except (IOError, OSError):  # Same as above
            pass
    if not MANUFDB:
        log_loading.warning("Cannot read wireshark manuf database")


#####################
#  knowledge bases  #
#####################

class KnowledgeBase:
    def __init__(self, filename):
        self.filename = filename
        self.base = None

    def lazy_init(self):
        self.base = ""

    def reload(self, filename=None):
        if filename is not None:
            self.filename = filename
        oldbase = self.base
        self.base = None
        self.lazy_init()
        if self.base is None:
            self.base = oldbase

    def get_base(self):
        if self.base is None:
            self.lazy_init()
        return self.base
