# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Implementation of the configuration object.
"""


import atexit
import copy
import functools
import os
import re
import socket
import sys
import time
import warnings

import scapy
from scapy import VERSION
from scapy.base_classes import BasePacket
from scapy.consts import DARWIN, WINDOWS, LINUX, BSD, SOLARIS
from scapy.error import log_scapy, warning, ScapyInvalidPlatformException
from scapy.themes import NoTheme, apply_ipython_style

# Typing imports
from typing import (
    cast,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    NoReturn,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
    overload,
    TYPE_CHECKING,
)
from types import ModuleType
from scapy.compat import DecoratorCallable

if TYPE_CHECKING:
    # Do not import at runtime
    import scapy.as_resolvers
    from scapy.modules.nmap import NmapKnowledgeBase
    from scapy.packet import Packet
    from scapy.supersocket import SuperSocket  # noqa: F401
    import scapy.asn1.asn1
    import scapy.asn1.mib

############
#  Config  #
############


class ConfClass(object):
    def configure(self, cnf):
        # type: (ConfClass) -> None
        self.__dict__ = cnf.__dict__.copy()

    def __repr__(self):
        # type: () -> str
        return str(self)

    def __str__(self):
        # type: () -> str
        s = ""
        dkeys = self.__class__.__dict__.copy()
        dkeys.update(self.__dict__)
        keys = sorted(dkeys)
        for i in keys:
            if i[0] != "_":
                r = repr(getattr(self, i))
                r = " ".join(r.split())
                wlen = 76 - max(len(i), 10)
                if len(r) > wlen:
                    r = r[:wlen - 3] + "..."
                s += "%-10s = %s\n" % (i, r)
        return s[:-1]


class Interceptor(object):
    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 hook,  # type: Callable[..., Any]
                 args=None,  # type: Optional[List[Any]]
                 kargs=None  # type: Optional[Dict[str, Any]]
                 ):
        # type: (...) -> None
        self.name = name
        self.intname = "_intercepted_%s" % name
        self.default = default
        self.hook = hook
        self.args = args if args is not None else []
        self.kargs = kargs if kargs is not None else {}

    def __get__(self, obj, typ=None):
        # type: (Conf, Optional[type]) -> Any
        if not hasattr(obj, self.intname):
            setattr(obj, self.intname, self.default)
        return getattr(obj, self.intname)

    @staticmethod
    def set_from_hook(obj, name, val):
        # type: (Conf, str, bool) -> None
        int_name = "_intercepted_%s" % name
        setattr(obj, int_name, val)

    def __set__(self, obj, val):
        # type: (Conf, Any) -> None
        old = getattr(obj, self.intname, self.default)
        val = self.hook(self.name, val, old, *self.args, **self.kargs)
        setattr(obj, self.intname, val)


def _readonly(name):
    # type: (str) -> NoReturn
    default = Conf.__dict__[name].default
    Interceptor.set_from_hook(conf, name, default)
    raise ValueError("Read-only value !")


ReadOnlyAttribute = functools.partial(
    Interceptor,
    hook=(lambda name, *args, **kwargs: _readonly(name))
)
ReadOnlyAttribute.__doc__ = "Read-only class attribute"


class ProgPath(ConfClass):
    _default = "<System default>"
    universal_open = "open" if DARWIN else "xdg-open"
    pdfreader = universal_open
    psreader = universal_open
    svgreader = universal_open
    dot = "dot"
    display = "display"
    tcpdump = "tcpdump"
    tcpreplay = "tcpreplay"
    hexedit = "hexer"
    tshark = "tshark"
    wireshark = "wireshark"
    ifconfig = "ifconfig"


class ConfigFieldList:
    def __init__(self):
        # type: () -> None
        self.fields = set()  # type: Set[Any]
        self.layers = set()  # type: Set[Any]

    @staticmethod
    def _is_field(f):
        # type: (Any) -> bool
        return hasattr(f, "owners")

    def _recalc_layer_list(self):
        # type: () -> None
        self.layers = {owner for f in self.fields for owner in f.owners}

    def add(self, *flds):
        # type: (*Any) -> None
        self.fields |= {f for f in flds if self._is_field(f)}
        self._recalc_layer_list()

    def remove(self, *flds):
        # type: (*Any) -> None
        self.fields -= set(flds)
        self._recalc_layer_list()

    def __contains__(self, elt):
        # type: (Any) -> bool
        if isinstance(elt, BasePacket):
            return elt in self.layers
        return elt in self.fields

    def __repr__(self):
        # type: () -> str
        return "<%s [%s]>" % (self.__class__.__name__, " ".join(str(x) for x in self.fields))  # noqa: E501


class Emphasize(ConfigFieldList):
    pass


class Resolve(ConfigFieldList):
    pass


class Num2Layer:
    def __init__(self):
        # type: () -> None
        self.num2layer = {}  # type: Dict[int, Type[Packet]]
        self.layer2num = {}  # type: Dict[Type[Packet], int]

    def register(self, num, layer):
        # type: (int, Type[Packet]) -> None
        self.register_num2layer(num, layer)
        self.register_layer2num(num, layer)

    def register_num2layer(self, num, layer):
        # type: (int, Type[Packet]) -> None
        self.num2layer[num] = layer

    def register_layer2num(self, num, layer):
        # type: (int, Type[Packet]) -> None
        self.layer2num[layer] = num

    @overload
    def __getitem__(self, item):
        # type: (Type[Packet]) -> int
        pass

    @overload
    def __getitem__(self, item):  # noqa: F811
        # type: (int) -> Type[Packet]
        pass

    def __getitem__(self, item):  # noqa: F811
        # type: (Union[int, Type[Packet]]) -> Union[int, Type[Packet]]
        if isinstance(item, int):
            return self.num2layer[item]
        else:
            return self.layer2num[item]

    def __contains__(self, item):
        # type: (Union[int, Type[Packet]]) -> bool
        if isinstance(item, int):
            return item in self.num2layer
        else:
            return item in self.layer2num

    def get(self,
            item,  # type: Union[int, Type[Packet]]
            default=None,  # type: Optional[Type[Packet]]
            ):
        # type: (...) -> Optional[Union[int, Type[Packet]]]
        return self[item] if item in self else default

    def __repr__(self):
        # type: () -> str
        lst = []
        for num, layer in self.num2layer.items():
            if layer in self.layer2num and self.layer2num[layer] == num:
                dir = "<->"
            else:
                dir = " ->"
            lst.append((num, "%#6x %s %-20s (%s)" % (num, dir, layer.__name__,
                                                     layer._name)))
        for layer, num in self.layer2num.items():
            if num not in self.num2layer or self.num2layer[num] != layer:
                lst.append((num, "%#6x <-  %-20s (%s)" % (num, layer.__name__,
                                                          layer._name)))
        lst.sort()
        return "\n".join(y for x, y in lst)


class LayersList(List[Type['scapy.packet.Packet']]):
    def __init__(self):
        # type: () -> None
        list.__init__(self)
        self.ldict = {}  # type: Dict[str, List[Type[Packet]]]
        self.filtered = False
        self._backup_dict = {}  # type: Dict[Type[Packet], List[Tuple[Dict[str, Any], Type[Packet]]]]  # noqa: E501

    def __repr__(self):
        # type: () -> str
        return "\n".join("%-20s: %s" % (layer.__name__, layer.name)
                         for layer in self)

    def register(self, layer):
        # type: (Type[Packet]) -> None
        self.append(layer)
        if layer.__module__ not in self.ldict:
            self.ldict[layer.__module__] = []
        self.ldict[layer.__module__].append(layer)

    def layers(self):
        # type: () -> List[Tuple[str, str]]
        result = []
        # This import may feel useless, but it is required for the eval below
        import scapy  # noqa: F401
        try:
            import builtins  # noqa: F401
        except ImportError:
            import __builtin__  # noqa: F401
        for lay in self.ldict:
            doc = eval(lay).__doc__
            result.append((lay, doc.strip().split("\n")[0] if doc else lay))
        return result

    def filter(self, items):
        # type: (List[Type[Packet]]) -> None
        """Disable dissection of unused layers to speed up dissection"""
        if self.filtered:
            raise ValueError("Already filtered. Please disable it first")
        for lay in self.ldict.values():
            for cls in lay:
                if cls not in self._backup_dict:
                    self._backup_dict[cls] = cls.payload_guess[:]
                    cls.payload_guess = [
                        y for y in cls.payload_guess if y[1] in items
                    ]
        self.filtered = True

    def unfilter(self):
        # type: () -> None
        """Re-enable dissection for all layers"""
        if not self.filtered:
            raise ValueError("Not filtered. Please filter first")
        for lay in self.ldict.values():
            for cls in lay:
                cls.payload_guess = self._backup_dict[cls]
        self._backup_dict.clear()
        self.filtered = False


class CommandsList(List[Callable[..., Any]]):
    def __repr__(self):
        # type: () -> str
        s = []
        for li in sorted(self, key=lambda x: x.__name__):
            doc = li.__doc__ if li.__doc__ else "--"
            doc = doc.lstrip().split('\n', 1)[0]
            s.append("%-22s: %s" % (li.__name__, doc))
        return "\n".join(s)

    def register(self, cmd):
        # type: (DecoratorCallable) -> DecoratorCallable
        self.append(cmd)
        return cmd  # return cmd so that method can be used as a decorator


def lsc():
    # type: () -> None
    """Displays Scapy's default commands"""
    print(repr(conf.commands))


class CacheInstance(Dict[str, Any]):
    __slots__ = ["timeout", "name", "_timetable"]

    def __init__(self, name="noname", timeout=None):
        # type: (str, Optional[int]) -> None
        self.timeout = timeout
        self.name = name
        self._timetable = {}  # type: Dict[str, float]

    def flush(self):
        # type: () -> None
        self._timetable.clear()
        self.clear()

    def __getitem__(self, item):
        # type: (str) -> Any
        if item in self.__slots__:
            return object.__getattribute__(self, item)
        val = super(CacheInstance, self).__getitem__(item)
        if self.timeout is not None:
            t = self._timetable[item]
            if time.time() - t > self.timeout:
                raise KeyError(item)
        return val

    def get(self, item, default=None):
        # type: (str, Optional[Any]) -> Any
        # overloading this method is needed to force the dict to go through
        # the timetable check
        try:
            return self[item]
        except KeyError:
            return default

    def __setitem__(self, item, v):
        # type: (str, str) -> None
        if item in self.__slots__:
            return object.__setattr__(self, item, v)
        self._timetable[item] = time.time()
        super(CacheInstance, self).__setitem__(item, v)

    def update(self,  # type: ignore
               other,  # type: Any
               **kwargs  # type: Any
               ):
        # type: (...) -> None
        for key, value in other.items():
            # We only update an element from `other` either if it does
            # not exist in `self` or if the entry in `self` is older.
            if key not in self or self._timetable[key] < other._timetable[key]:
                dict.__setitem__(self, key, value)
                self._timetable[key] = other._timetable[key]

    def iteritems(self):
        # type: () -> Iterator[Tuple[str, Any]]
        if self.timeout is None:
            return super(CacheInstance, self).items()  # type: ignore
        t0 = time.time()
        return (
            (k, v)
            for (k, v) in super(CacheInstance, self).items()
            if t0 - self._timetable[k] < self.timeout
        )

    def iterkeys(self):
        # type: () -> Iterator[str]
        if self.timeout is None:
            return super(CacheInstance, self).keys()  # type: ignore
        t0 = time.time()
        return (
            k
            for k in super(CacheInstance, self).keys()
            if t0 - self._timetable[k] < self.timeout
        )

    def __iter__(self):
        # type: () -> Iterator[str]
        return self.iterkeys()

    def itervalues(self):
        # type: () -> Iterator[Tuple[str, Any]]
        if self.timeout is None:
            return super(CacheInstance, self).values()  # type: ignore
        t0 = time.time()
        return (
            v
            for (k, v) in super(CacheInstance, self).items()
            if t0 - self._timetable[k] < self.timeout
        )

    def items(self):
        # type: () -> Any
        return list(self.iteritems())

    def keys(self):
        # type: () -> Any
        return list(self.iterkeys())

    def values(self):
        # type: () -> Any
        return list(self.itervalues())

    def __len__(self):
        # type: () -> int
        if self.timeout is None:
            return super(CacheInstance, self).__len__()
        return len(self.keys())

    def summary(self):
        # type: () -> str
        return "%s: %i valid items. Timeout=%rs" % (self.name, len(self), self.timeout)  # noqa: E501

    def __repr__(self):
        # type: () -> str
        s = []
        if self:
            mk = max(len(k) for k in self)
            fmt = "%%-%is %%s" % (mk + 1)
            for item in self.items():
                s.append(fmt % item)
        return "\n".join(s)

    def copy(self):
        # type: () -> CacheInstance
        return copy.copy(self)


class NetCache:
    def __init__(self):
        # type: () -> None
        self._caches_list = []  # type: List[CacheInstance]

    def add_cache(self, cache):
        # type: (CacheInstance) -> None
        self._caches_list.append(cache)
        setattr(self, cache.name, cache)

    def new_cache(self, name, timeout=None):
        # type: (str, Optional[int]) -> CacheInstance
        c = CacheInstance(name=name, timeout=timeout)
        self.add_cache(c)
        return c

    def __delattr__(self, attr):
        # type: (str) -> NoReturn
        raise AttributeError("Cannot delete attributes")

    def update(self, other):
        # type: (NetCache) -> None
        for co in other._caches_list:
            if hasattr(self, co.name):
                getattr(self, co.name).update(co)
            else:
                self.add_cache(co.copy())

    def flush(self):
        # type: () -> None
        for c in self._caches_list:
            c.flush()

    def __repr__(self):
        # type: () -> str
        return "\n".join(c.summary() for c in self._caches_list)


def _version_checker(module, minver):
    # type: (ModuleType, Tuple[int, ...]) -> bool
    """Checks that module has a higher version that minver.

    params:
     - module: a module to test
     - minver: a tuple of versions
    """
    # We could use LooseVersion, but distutils imports imp which is deprecated
    version_regexp = r'[a-z]?((?:\d|\.)+\d+)(?:\.dev[0-9]+)?'
    version_tags_r = re.match(
        version_regexp,
        getattr(module, "__version__", "")
    )
    if not version_tags_r:
        return False
    version_tags_i = version_tags_r.group(1).split(".")
    version_tags = tuple(int(x) for x in version_tags_i)
    return bool(version_tags >= minver)


def isCryptographyValid():
    # type: () -> bool
    """
    Check if the cryptography module >= 2.0.0 is present. This is the minimum
    version for most usages in Scapy.
    """
    try:
        import cryptography
    except ImportError:
        return False
    return _version_checker(cryptography, (2, 0, 0))


def isCryptographyAdvanced():
    # type: () -> bool
    """
    Check if the cryptography module is present, and if it supports X25519,
    ChaCha20Poly1305 and such.

    Notes:
    - cryptography >= 2.0 is required
    - OpenSSL >= 1.1.0 is required
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E501
        X25519PrivateKey.generate()
    except Exception:
        return False
    else:
        return True


def isPyPy():
    # type: () -> bool
    """Returns either scapy is running under PyPy or not"""
    try:
        import __pypy__  # noqa: F401
        return True
    except ImportError:
        return False


def _prompt_changer(attr, val, old):
    # type: (str, Any, Any) -> Any
    """Change the current prompt theme"""
    Interceptor.set_from_hook(conf, attr, val)
    try:
        sys.ps1 = conf.color_theme.prompt(conf.prompt)
    except Exception:
        pass
    try:
        apply_ipython_style(
            get_ipython()  # type: ignore
        )
    except NameError:
        pass
    return getattr(conf, attr, old)


def _set_conf_sockets():
    # type: () -> None
    """Populate the conf.L2Socket and conf.L3Socket
    according to the various use_* parameters
    """
    if conf.use_bpf and not BSD:
        Interceptor.set_from_hook(conf, "use_bpf", False)
        raise ScapyInvalidPlatformException("BSD-like (OSX, *BSD...) only !")
    if not conf.use_pcap and SOLARIS:
        Interceptor.set_from_hook(conf, "use_pcap", True)
        raise ScapyInvalidPlatformException(
            "Scapy only supports libpcap on Solaris !"
        )
    # we are already in an Interceptor hook, use Interceptor.set_from_hook
    if conf.use_pcap:
        try:
            from scapy.arch.libpcap import L2pcapListenSocket, L2pcapSocket, \
                L3pcapSocket
        except (OSError, ImportError):
            warning("No libpcap provider available ! pcap won't be used")
            Interceptor.set_from_hook(conf, "use_pcap", False)
        else:
            conf.L3socket = L3pcapSocket
            conf.L3socket6 = functools.partial(  # type: ignore
                L3pcapSocket, filter="ip6")
            conf.L2socket = L2pcapSocket
            conf.L2listen = L2pcapListenSocket
            conf.ifaces.reload()
            return
    if conf.use_bpf:
        from scapy.arch.bpf.supersocket import L2bpfListenSocket, \
            L2bpfSocket, L3bpfSocket
        conf.L3socket = L3bpfSocket
        conf.L3socket6 = functools.partial(  # type: ignore
            L3bpfSocket, filter="ip6")
        conf.L2socket = L2bpfSocket
        conf.L2listen = L2bpfListenSocket
        conf.ifaces.reload()
        return
    if LINUX:
        from scapy.arch.linux import L3PacketSocket, L2Socket, L2ListenSocket
        conf.L3socket = L3PacketSocket
        conf.L3socket6 = cast(
            "Type[SuperSocket]",
            functools.partial(
                L3PacketSocket,
                filter="ip6"
            )
        )
        conf.L2socket = L2Socket
        conf.L2listen = L2ListenSocket
        conf.ifaces.reload()
        return
    if WINDOWS:
        from scapy.arch.windows import _NotAvailableSocket
        from scapy.arch.windows.native import L3WinSocket, L3WinSocket6
        conf.L3socket = L3WinSocket
        conf.L3socket6 = L3WinSocket6
        conf.L2socket = _NotAvailableSocket
        conf.L2listen = _NotAvailableSocket
        conf.ifaces.reload()
        # No need to update globals on Windows
        return
    else:
        from scapy.supersocket import L3RawSocket
        from scapy.layers.inet6 import L3RawSocket6
        conf.L3socket = L3RawSocket
        conf.L3socket6 = L3RawSocket6


def _socket_changer(attr, val, old):
    # type: (str, bool, bool) -> Any
    if not isinstance(val, bool):
        raise TypeError("This argument should be a boolean")
    Interceptor.set_from_hook(conf, attr, val)
    dependencies = {  # Things that will be turned off
        "use_pcap": ["use_bpf"],
        "use_bpf": ["use_pcap"],
    }
    restore = {k: getattr(conf, k) for k in dependencies}
    del restore[attr]  # This is handled directly by _set_conf_sockets
    if val:  # Only if True
        for param in dependencies[attr]:
            Interceptor.set_from_hook(conf, param, False)
    try:
        _set_conf_sockets()
    except (ScapyInvalidPlatformException, ImportError) as e:
        for key, value in restore.items():
            Interceptor.set_from_hook(conf, key, value)
        if isinstance(e, ScapyInvalidPlatformException):
            raise
    return getattr(conf, attr)


def _loglevel_changer(attr, val, old):
    # type: (str, int, int) -> int
    """Handle a change of conf.logLevel"""
    log_scapy.setLevel(val)
    return val


def _iface_changer(attr, val, old):
    # type: (str, Any, Any) -> 'scapy.interfaces.NetworkInterface'
    """Resolves the interface in conf.iface"""
    if isinstance(val, str):
        from scapy.interfaces import resolve_iface
        iface = resolve_iface(val)
        if old and iface.dummy:
            warning(
                "This interface is not specified in any provider ! "
                "See conf.ifaces output"
            )
        return iface
    return val  # type: ignore


class Conf(ConfClass):
    """
    This object contains the configuration of Scapy.
    """
    version = ReadOnlyAttribute("version", VERSION)
    session = ""  #: filename where the session will be saved
    interactive = False
    #: can be "ipython", "bpython", "ptpython", "ptipython", "python" or "auto".
    #: Default: Auto
    interactive_shell = "auto"
    #: Configuration for "ipython" to use jedi (disabled by default)
    ipython_use_jedi = False
    #: if 1, prevents any unwanted packet to go out (ARP, DNS, ...)
    stealth = "not implemented"
    #: selects the default output interface for srp() and sendp().
    iface = Interceptor("iface", None, _iface_changer)  # type: 'scapy.interfaces.NetworkInterface'  # type: ignore  # noqa: E501
    layers = LayersList()
    commands = CommandsList()  # type: CommandsList
    #: Codec used by default for ASN1 objects
    ASN1_default_codec = None  # type: 'scapy.asn1.asn1.ASN1Codec'
    #: choose the AS resolver class to use
    AS_resolver = None  # type: scapy.as_resolvers.AS_resolver
    dot15d4_protocol = None  # Used in dot15d4.py
    logLevel = Interceptor("logLevel", log_scapy.level, _loglevel_changer)
    #: if 0, doesn't check that IPID matches between IP sent and
    #: ICMP IP citation received
    #: if 1, checks that they either are equal or byte swapped
    #: equals (bug in some IP stacks)
    #: if 2, strictly checks that they are equals
    checkIPID = False
    #: if 1, checks IP src in IP and ICMP IP citation match
    #: (bug in some NAT stacks)
    checkIPsrc = True
    checkIPaddr = True
    #: if True, checks that IP-in-IP layers match. If False, do
    #: not check IP layers that encapsulates another IP layer
    checkIPinIP = True
    #: if 1, also check that TCP seq and ack match the
    #: ones in ICMP citation
    check_TCPerror_seqack = False
    verb = 2  #: level of verbosity, from 0 (almost mute) to 3 (verbose)
    prompt = Interceptor("prompt", ">>> ", _prompt_changer)
    #: default mode for the promiscuous mode of a socket (to get answers if you
    #: spoof on a lan)
    sniff_promisc = True  # type: bool
    raw_layer = None  # type: Type[Packet]
    raw_summary = False  # type: Union[bool, Callable[[bytes], Any]]
    padding_layer = None  # type: Type[Packet]
    default_l2 = None  # type: Type[Packet]
    l2types = Num2Layer()
    l3types = Num2Layer()
    L3socket = None  # type: Type[scapy.supersocket.SuperSocket]
    L3socket6 = None  # type: Type[scapy.supersocket.SuperSocket]
    L2socket = None  # type: Type[scapy.supersocket.SuperSocket]
    L2listen = None  # type: Type[scapy.supersocket.SuperSocket]
    BTsocket = None  # type: Type[scapy.supersocket.SuperSocket]
    USBsocket = None  # type: Type[scapy.supersocket.SuperSocket]
    min_pkt_size = 60
    #: holds MIB direct access dictionary
    mib = None  # type: 'scapy.asn1.mib.MIBDict'
    bufsize = 2**16
    #: history file
    histfile = os.getenv('SCAPY_HISTFILE',
                         os.path.join(os.path.expanduser("~"),
                                      ".config", "scapy",
                                      "history"))
    #: includes padding in disassembled packets
    padding = 1
    #: BPF filter for packets to ignore
    except_filter = ""
    #: bpf filter added to every sniffing socket to exclude traffic
    #: from analysis
    filter = ""
    #: when 1, store received packet that are not matched into `debug.recv`
    debug_match = False
    #: When 1, print some TLS session secrets when they are computed.
    debug_tls = False
    wepkey = ""
    #: holds the Scapy interface list and manager
    ifaces = None  # type: 'scapy.interfaces.NetworkInterfaceDict'
    #: holds the cache of interfaces loaded from Libpcap
    cache_pcapiflist = {}  # type: Dict[str, Tuple[str, List[str], Any, str]]
    # `neighbor` will be filed by scapy.layers.l2
    neighbor = None  # type: 'scapy.layers.l2.Neighbor'
    #: holds the name servers IP/hosts used for custom DNS resolution
    nameservers = None  # type: str
    #: holds the Scapy IPv4 routing table and provides methods to
    #: manipulate it
    route = None  # type: 'scapy.route.Route'
    # `route` will be filed by route.py
    #: holds the Scapy IPv6 routing table and provides methods to
    #: manipulate it
    route6 = None  # type: 'scapy.route6.Route6'
    manufdb = None  # type: 'scapy.data.ManufDA'
    # 'route6' will be filed by route6.py
    teredoPrefix = ""  # type: str
    teredoServerPort = None  # type: int
    auto_fragment = True
    #: raise exception when a packet dissector raises an exception
    debug_dissector = False
    color_theme = Interceptor("color_theme", NoTheme(), _prompt_changer)
    #: how much time between warnings from the same place
    warning_threshold = 5
    prog = ProgPath()
    #: holds list of fields for which resolution should be done
    resolve = Resolve()
    #: holds list of enum fields for which conversion to string
    #: should NOT be done
    noenum = Resolve()
    emph = Emphasize()
    #: read only attribute to show if PyPy is in use
    use_pypy = ReadOnlyAttribute("use_pypy", isPyPy())
    #: use libpcap integration or not. Changing this value will update
    #: the conf.L[2/3] sockets
    use_pcap = Interceptor(
        "use_pcap",
        os.getenv("SCAPY_USE_LIBPCAP", "").lower().startswith("y"),
        _socket_changer
    )
    use_bpf = Interceptor("use_bpf", False, _socket_changer)
    use_npcap = False
    ipv6_enabled = socket.has_ipv6
    #: path or list of paths where extensions are to be looked for
    extensions_paths = "."
    stats_classic_protocols = []  # type: List[Type[Packet]]
    stats_dot11_protocols = []  # type: List[Type[Packet]]
    temp_files = []  # type: List[str]
    #: netcache holds time-based caches for net operations
    netcache = NetCache()
    geoip_city = None
    # can, tls, http and a few others are not loaded by default
    load_layers = [
        'bluetooth',
        'bluetooth4LE',
        'dcerpc',
        'dhcp',
        'dhcp6',
        'dns',
        'dot11',
        'dot15d4',
        'eap',
        'gprs',
        'hsrp',
        'inet',
        'inet6',
        'ipsec',
        'ir',
        'isakmp',
        'kerberos',
        'l2',
        'l2tp',
        'ldap',
        'llmnr',
        'lltd',
        'mgcp',
        'mobileip',
        'mspac',
        'netbios',
        'netflow',
        'ntlm',
        'ntp',
        'ppi',
        'ppp',
        'pptp',
        'radius',
        'rip',
        'rtp',
        'sctp',
        'sixlowpan',
        'skinny',
        'smb',
        'smb2',
        'smbclient',
        'smbserver',
        'snmp',
        'tftp',
        'vrrp',
        'vxlan',
        'x509',
        'zigbee'
    ]
    #: a dict which can be used by contrib layers to store local
    #: configuration
    contribs = dict()  # type: Dict[str, Any]
    crypto_valid = isCryptographyValid()
    crypto_valid_advanced = isCryptographyAdvanced()
    #: controls whether or not to display the fancy banner
    fancy_banner = True
    #: controls whether tables (conf.iface, conf.route...) should be cropped
    #: to fit the terminal
    auto_crop_tables = True
    #: how often to check for new packets.
    #: Defaults to 0.05s.
    recv_poll_rate = 0.05
    #: When True, raise exception if no dst MAC found otherwise broadcast.
    #: Default is False.
    raise_no_dst_mac = False
    loopback_name = "lo" if LINUX else "lo0"
    nmap_base = ""  # type: str
    nmap_kdb = None  # type: Optional[NmapKnowledgeBase]
    #: a safety mechanism: the maximum amount of items included in a PacketListField
    #: or a FieldListField
    max_list_count = 100

    def __getattribute__(self, attr):
        # type: (str) -> Any
        # Those are loaded on runtime to avoid import loops
        if attr == "manufdb":
            from scapy.data import MANUFDB
            return MANUFDB
        if attr == "ethertypes":
            from scapy.data import ETHER_TYPES
            return ETHER_TYPES
        if attr == "protocols":
            from scapy.data import IP_PROTOS
            return IP_PROTOS
        if attr == "services_udp":
            from scapy.data import UDP_SERVICES
            return UDP_SERVICES
        if attr == "services_tcp":
            from scapy.data import TCP_SERVICES
            return TCP_SERVICES
        if attr == "services_sctp":
            from scapy.data import SCTP_SERVICES
            return SCTP_SERVICES
        if attr == "iface6":
            warnings.warn(
                "conf.iface6 is deprecated in favor of conf.iface",
                DeprecationWarning
            )
            attr = "iface"
        return object.__getattribute__(self, attr)


if not Conf.ipv6_enabled:
    log_scapy.warning("IPv6 support disabled in Python. Cannot load Scapy IPv6 layers.")  # noqa: E501
    for m in ["inet6", "dhcp6"]:
        if m in Conf.load_layers:
            Conf.load_layers.remove(m)

conf = Conf()  # type: Conf


def crypto_validator(func):
    # type: (DecoratorCallable) -> DecoratorCallable
    """
    This a decorator to be used for any method relying on the cryptography library.  # noqa: E501
    Its behaviour depends on the 'crypto_valid' attribute of the global 'conf'.
    """
    def func_in(*args, **kwargs):
        # type: (*Any, **Any) -> Any
        if not conf.crypto_valid:
            raise ImportError("Cannot execute crypto-related method! "
                              "Please install python-cryptography v1.7 or later.")  # noqa: E501
        return func(*args, **kwargs)
    return func_in  # type: ignore


def scapy_delete_temp_files():
    # type: () -> None
    for f in conf.temp_files:
        try:
            os.unlink(f)
        except Exception:
            pass
    del conf.temp_files[:]


atexit.register(scapy_delete_temp_files)
