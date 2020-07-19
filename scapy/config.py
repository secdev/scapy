# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Implementation of the configuration object.
"""

from __future__ import absolute_import
from __future__ import print_function
import functools
import os
import re
import time
import socket
import sys
import atexit

from scapy import VERSION, base_classes
from scapy.consts import DARWIN, WINDOWS, LINUX, BSD, SOLARIS
from scapy.error import log_scapy, warning, ScapyInvalidPlatformException
from scapy.modules import six
from scapy.themes import NoTheme, apply_ipython_style

############
#  Config  #
############


class ConfClass(object):
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()

    def __repr__(self):
        return str(self)

    def __str__(self):
        s = ""
        keys = self.__class__.__dict__.copy()
        keys.update(self.__dict__)
        keys = sorted(keys)
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
    def __init__(self, name=None, default=None,
                 hook=None, args=None, kargs=None):
        self.name = name
        self.intname = "_intercepted_%s" % name
        self.default = default
        self.hook = hook
        self.args = args if args is not None else []
        self.kargs = kargs if kargs is not None else {}

    def __get__(self, obj, typ=None):
        if not hasattr(obj, self.intname):
            setattr(obj, self.intname, self.default)
        return getattr(obj, self.intname)

    @staticmethod
    def set_from_hook(obj, name, val):
        int_name = "_intercepted_%s" % name
        setattr(obj, int_name, val)

    def __set__(self, obj, val):
        setattr(obj, self.intname, val)
        self.hook(self.name, val, *self.args, **self.kargs)


def _readonly(name):
    default = Conf.__dict__[name].default
    Interceptor.set_from_hook(conf, name, default)
    raise ValueError("Read-only value !")


ReadOnlyAttribute = functools.partial(
    Interceptor,
    hook=(lambda name, *args, **kwargs: _readonly(name))
)
ReadOnlyAttribute.__doc__ = "Read-only class attribute"


class ProgPath(ConfClass):
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
        self.fields = set()
        self.layers = set()

    @staticmethod
    def _is_field(f):
        return hasattr(f, "owners")

    def _recalc_layer_list(self):
        self.layers = {owner for f in self.fields for owner in f.owners}

    def add(self, *flds):
        self.fields |= {f for f in flds if self._is_field(f)}
        self._recalc_layer_list()

    def remove(self, *flds):
        self.fields -= set(flds)
        self._recalc_layer_list()

    def __contains__(self, elt):
        if isinstance(elt, base_classes.Packet_metaclass):
            return elt in self.layers
        return elt in self.fields

    def __repr__(self):
        return "<%s [%s]>" % (self.__class__.__name__, " ".join(str(x) for x in self.fields))  # noqa: E501


class Emphasize(ConfigFieldList):
    pass


class Resolve(ConfigFieldList):
    pass


class Num2Layer:
    def __init__(self):
        self.num2layer = {}
        self.layer2num = {}

    def register(self, num, layer):
        self.register_num2layer(num, layer)
        self.register_layer2num(num, layer)

    def register_num2layer(self, num, layer):
        self.num2layer[num] = layer

    def register_layer2num(self, num, layer):
        self.layer2num[layer] = num

    def __getitem__(self, item):
        if isinstance(item, base_classes.Packet_metaclass):
            return self.layer2num[item]
        return self.num2layer[item]

    def __contains__(self, item):
        if isinstance(item, base_classes.Packet_metaclass):
            return item in self.layer2num
        return item in self.num2layer

    def get(self, item, default=None):
        return self[item] if item in self else default

    def __repr__(self):
        lst = []
        for num, layer in six.iteritems(self.num2layer):
            if layer in self.layer2num and self.layer2num[layer] == num:
                dir = "<->"
            else:
                dir = " ->"
            lst.append((num, "%#6x %s %-20s (%s)" % (num, dir, layer.__name__,
                                                     layer._name)))
        for layer, num in six.iteritems(self.layer2num):
            if num not in self.num2layer or self.num2layer[num] != layer:
                lst.append((num, "%#6x <-  %-20s (%s)" % (num, layer.__name__,
                                                          layer._name)))
        lst.sort()
        return "\n".join(y for x, y in lst)


class LayersList(list):

    def __init__(self):
        list.__init__(self)
        self.ldict = {}
        self.filtered = False
        self._backup_dict = {}

    def __repr__(self):
        return "\n".join("%-20s: %s" % (layer.__name__, layer.name)
                         for layer in self)

    def register(self, layer):
        self.append(layer)
        if layer.__module__ not in self.ldict:
            self.ldict[layer.__module__] = []
        self.ldict[layer.__module__].append(layer)

    def layers(self):
        result = []
        # This import may feel useless, but it is required for the eval below
        import scapy  # noqa: F401
        for lay in self.ldict:
            doc = eval(lay).__doc__
            result.append((lay, doc.strip().split("\n")[0] if doc else lay))
        return result

    def filter(self, items):
        """Disable dissection of unused layers to speed up dissection"""
        if self.filtered:
            raise ValueError("Already filtered. Please disable it first")
        for lay in six.itervalues(self.ldict):
            for cls in lay:
                if cls not in self._backup_dict:
                    self._backup_dict[cls] = cls.payload_guess[:]
                    cls.payload_guess = [
                        y for y in cls.payload_guess if y[1] in items
                    ]
        self.filtered = True

    def unfilter(self):
        """Re-enable dissection for all layers"""
        if not self.filtered:
            raise ValueError("Not filtered. Please filter first")
        for lay in six.itervalues(self.ldict):
            for cls in lay:
                cls.payload_guess = self._backup_dict[cls]
        self._backup_dict.clear()
        self.filtered = False


class CommandsList(list):
    def __repr__(self):
        s = []
        for li in sorted(self, key=lambda x: x.__name__):
            doc = li.__doc__.split("\n")[0] if li.__doc__ else "--"
            s.append("%-20s: %s" % (li.__name__, doc))
        return "\n".join(s)

    def register(self, cmd):
        self.append(cmd)
        return cmd  # return cmd so that method can be used as a decorator


def lsc():
    """Displays Scapy's default commands"""
    print(repr(conf.commands))


class CacheInstance(dict, object):
    __slots__ = ["timeout", "name", "_timetable", "__dict__"]

    def __init__(self, name="noname", timeout=None):
        self.timeout = timeout
        self.name = name
        self._timetable = {}

    def flush(self):
        self.__init__(name=self.name, timeout=self.timeout)

    def __getitem__(self, item):
        if item in self.__slots__:
            return object.__getattribute__(self, item)
        val = dict.__getitem__(self, item)
        if self.timeout is not None:
            t = self._timetable[item]
            if time.time() - t > self.timeout:
                raise KeyError(item)
        return val

    def get(self, item, default=None):
        # overloading this method is needed to force the dict to go through
        # the timetable check
        try:
            return self[item]
        except KeyError:
            return default

    def __setitem__(self, item, v):
        if item in self.__slots__:
            return object.__setattr__(self, item, v)
        self._timetable[item] = time.time()
        dict.__setitem__(self, item, v)

    def update(self, other):
        for key, value in six.iteritems(other):
            # We only update an element from `other` either if it does
            # not exist in `self` or if the entry in `self` is older.
            if key not in self or self._timetable[key] < other._timetable[key]:
                dict.__setitem__(self, key, value)
                self._timetable[key] = other._timetable[key]

    def iteritems(self):
        if self.timeout is None:
            return six.iteritems(self.__dict__)
        t0 = time.time()
        return ((k, v) for (k, v) in six.iteritems(self.__dict__) if t0 - self._timetable[k] < self.timeout)  # noqa: E501

    def iterkeys(self):
        if self.timeout is None:
            return six.iterkeys(self.__dict__)
        t0 = time.time()
        return (k for k in six.iterkeys(self.__dict__) if t0 - self._timetable[k] < self.timeout)  # noqa: E501

    def __iter__(self):
        return six.iterkeys(self.__dict__)

    def itervalues(self):
        if self.timeout is None:
            return six.itervalues(self.__dict__)
        t0 = time.time()
        return (v for (k, v) in six.iteritems(self.__dict__) if t0 - self._timetable[k] < self.timeout)  # noqa: E501

    def items(self):
        if self.timeout is None:
            return dict.items(self)
        t0 = time.time()
        return [(k, v) for (k, v) in six.iteritems(self.__dict__) if t0 - self._timetable[k] < self.timeout]  # noqa: E501

    def keys(self):
        if self.timeout is None:
            return dict.keys(self)
        t0 = time.time()
        return [k for k in six.iterkeys(self.__dict__) if t0 - self._timetable[k] < self.timeout]  # noqa: E501

    def values(self):
        if self.timeout is None:
            return list(six.itervalues(self))
        t0 = time.time()
        return [v for (k, v) in six.iteritems(self.__dict__) if t0 - self._timetable[k] < self.timeout]  # noqa: E501

    def __len__(self):
        if self.timeout is None:
            return dict.__len__(self)
        return len(self.keys())

    def summary(self):
        return "%s: %i valid items. Timeout=%rs" % (self.name, len(self), self.timeout)  # noqa: E501

    def __repr__(self):
        s = []
        if self:
            mk = max(len(k) for k in six.iterkeys(self.__dict__))
            fmt = "%%-%is %%s" % (mk + 1)
            for item in six.iteritems(self.__dict__):
                s.append(fmt % item)
        return "\n".join(s)


class NetCache:
    def __init__(self):
        self._caches_list = []

    def add_cache(self, cache):
        self._caches_list.append(cache)
        setattr(self, cache.name, cache)

    def new_cache(self, name, timeout=None):
        c = CacheInstance(name=name, timeout=timeout)
        self.add_cache(c)

    def __delattr__(self, attr):
        raise AttributeError("Cannot delete attributes")

    def update(self, other):
        for co in other._caches_list:
            if hasattr(self, co.name):
                getattr(self, co.name).update(co)
            else:
                self.add_cache(co.copy())

    def flush(self):
        for c in self._caches_list:
            c.flush()

    def __repr__(self):
        return "\n".join(c.summary() for c in self._caches_list)


def _version_checker(module, minver):
    """Checks that module has a higher version that minver.

    params:
     - module: a module to test
     - minver: a tuple of versions
    """
    # We could use LooseVersion, but distutils imports imp which is deprecated
    version_regexp = r'[a-z]?((?:\d|\.)+\d+)(?:\.dev[0-9]+)?'
    version_tags = re.match(version_regexp, module.__version__)
    if not version_tags:
        return False
    version_tags = version_tags.group(1).split(".")
    version_tags = tuple(int(x) for x in version_tags)
    return version_tags >= minver


def isCryptographyValid():
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
    """Returns either scapy is running under PyPy or not"""
    try:
        import __pypy__  # noqa: F401
        return True
    except ImportError:
        return False


def _prompt_changer(attr, val):
    """Change the current prompt theme"""
    try:
        sys.ps1 = conf.color_theme.prompt(conf.prompt)
    except Exception:
        pass
    try:
        apply_ipython_style(get_ipython())
    except NameError:
        pass


def _set_conf_sockets():
    """Populate the conf.L2Socket and conf.L3Socket
    according to the various use_* parameters
    """
    from scapy.main import _load
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
            from scapy.arch.pcapdnet import L2pcapListenSocket, L2pcapSocket, \
                L3pcapSocket
        except (OSError, ImportError):
            warning("No libpcap provider available ! pcap won't be used")
            Interceptor.set_from_hook(conf, "use_pcap", False)
        else:
            conf.L3socket = L3pcapSocket
            conf.L3socket6 = functools.partial(L3pcapSocket, filter="ip6")
            conf.L2socket = L2pcapSocket
            conf.L2listen = L2pcapListenSocket
            if conf.interactive:
                # Update globals
                _load("scapy.arch.pcapdnet")
            return
    if conf.use_bpf:
        from scapy.arch.bpf.supersocket import L2bpfListenSocket, \
            L2bpfSocket, L3bpfSocket
        conf.L3socket = L3bpfSocket
        conf.L3socket6 = functools.partial(L3bpfSocket, filter="ip6")
        conf.L2socket = L2bpfSocket
        conf.L2listen = L2bpfListenSocket
        if conf.interactive:
            # Update globals
            _load("scapy.arch.bpf")
        return
    if LINUX:
        from scapy.arch.linux import L3PacketSocket, L2Socket, L2ListenSocket
        conf.L3socket = L3PacketSocket
        conf.L3socket6 = functools.partial(L3PacketSocket, filter="ip6")
        conf.L2socket = L2Socket
        conf.L2listen = L2ListenSocket
        if conf.interactive:
            # Update globals
            _load("scapy.arch.linux")
        return
    if WINDOWS:
        from scapy.arch.windows import _NotAvailableSocket
        from scapy.arch.windows.native import L3WinSocket, L3WinSocket6
        conf.L3socket = L3WinSocket
        conf.L3socket6 = L3WinSocket6
        conf.L2socket = _NotAvailableSocket
        conf.L2listen = _NotAvailableSocket
        # No need to update globals on Windows
        return
    from scapy.supersocket import L3RawSocket
    from scapy.layers.inet6 import L3RawSocket6
    conf.L3socket = L3RawSocket
    conf.L3socket6 = L3RawSocket6


def _socket_changer(attr, val):
    if not isinstance(val, bool):
        raise TypeError("This argument should be a boolean")
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


def _loglevel_changer(attr, val):
    """Handle a change of conf.logLevel"""
    log_scapy.setLevel(val)


class Conf(ConfClass):
    """
    This object contains the configuration of Scapy.
    """
    version = ReadOnlyAttribute("version", VERSION)
    session = ""  #: filename where the session will be saved
    interactive = False
    #: can be "ipython", "python" or "auto". Default: Auto
    interactive_shell = ""
    #: if 1, prevents any unwanted packet to go out (ARP, DNS, ...)
    stealth = "not implemented"
    #: selects the default output interface for srp() and sendp().
    iface = None
    layers = LayersList()
    commands = CommandsList()
    ASN1_default_codec = None  #: Codec used by default for ASN1 objects
    AS_resolver = None  #: choose the AS resolver class to use
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
    #: default mode for listening socket (to get answers if you
    #: spoof on a lan)
    promisc = True
    sniff_promisc = 1  #: default mode for sniff()
    raw_layer = None
    raw_summary = False
    default_l2 = None
    l2types = Num2Layer()
    l3types = Num2Layer()
    L3socket = None
    L3socket6 = None
    L2socket = None
    L2listen = None
    BTsocket = None
    USBsocket = None
    min_pkt_size = 60
    mib = None  #: holds MIB direct access dictionary
    bufsize = 2**16
    #: history file
    histfile = os.getenv('SCAPY_HISTFILE',
                         os.path.join(os.path.expanduser("~"),
                                      ".scapy_history"))
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
    cache_iflist = {}
    #: holds the Scapy IPv4 routing table and provides methods to
    #: manipulate it
    route = None  # Filed by route.py
    #: holds the Scapy IPv6 routing table and provides methods to
    #: manipulate it
    route6 = None  # Filed by route6.py
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
        os.getenv("SCAPY_USE_PCAPDNET", "").lower().startswith("y"),
        _socket_changer
    )
    use_bpf = Interceptor("use_bpf", False, _socket_changer)
    use_npcap = False
    ipv6_enabled = socket.has_ipv6
    #: path or list of paths where extensions are to be looked for
    extensions_paths = "."
    stats_classic_protocols = []
    stats_dot11_protocols = []
    temp_files = []
    netcache = NetCache()
    geoip_city = None
    # can, tls, http are not loaded by default
    load_layers = ['bluetooth', 'bluetooth4LE', 'dhcp', 'dhcp6', 'dns',
                   'dot11', 'dot15d4', 'eap', 'gprs', 'hsrp', 'inet',
                   'inet6', 'ipsec', 'ir', 'isakmp', 'l2', 'l2tp',
                   'llmnr', 'lltd', 'mgcp', 'mobileip', 'netbios',
                   'netflow', 'ntp', 'ppi', 'ppp', 'pptp', 'radius', 'rip',
                   'rtp', 'sctp', 'sixlowpan', 'skinny', 'smb', 'smb2', 'snmp',
                   'tftp', 'vrrp', 'vxlan', 'x509', 'zigbee']
    #: a dict which can be used by contrib layers to store local
    #: configuration
    contribs = dict()
    crypto_valid = isCryptographyValid()
    crypto_valid_advanced = isCryptographyAdvanced()
    fancy_prompt = True
    auto_crop_tables = True
    #: how often to check for new packets.
    #: Defaults to 0.05s.
    recv_poll_rate = 0.05
    #: When True, raise exception if no dst MAC found otherwise broadcast.
    #: Default is False.
    raise_no_dst_mac = False
    loopback_name = "lo" if LINUX else "lo0"

    def __getattr__(self, attr):
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
        if attr == "iface6":
            warning("conf.iface6 is deprecated in favor of conf.iface")
            attr = "iface"
        return object.__getattribute__(self, attr)


if not Conf.ipv6_enabled:
    log_scapy.warning("IPv6 support disabled in Python. Cannot load Scapy IPv6 layers.")  # noqa: E501
    for m in ["inet6", "dhcp6"]:
        if m in Conf.load_layers:
            Conf.load_layers.remove(m)

conf = Conf()


def crypto_validator(func):
    """
    This a decorator to be used for any method relying on the cryptography library.  # noqa: E501
    Its behaviour depends on the 'crypto_valid' attribute of the global 'conf'.
    """
    def func_in(*args, **kwargs):
        if not conf.crypto_valid:
            raise ImportError("Cannot execute crypto-related method! "
                              "Please install python-cryptography v1.7 or later.")  # noqa: E501
        return func(*args, **kwargs)
    return func_in


def scapy_delete_temp_files():
    # type: () -> None
    for f in conf.temp_files:
        try:
            os.unlink(f)
        except Exception:
            pass
    del conf.temp_files[:]


atexit.register(scapy_delete_temp_files)
