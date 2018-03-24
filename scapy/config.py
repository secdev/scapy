## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Implementation of the configuration object.
"""

from __future__ import absolute_import
from __future__ import print_function
import os,time,socket,sys

from scapy import VERSION, base_classes
from scapy.consts import DARWIN
from scapy.data import ETHER_TYPES, IP_PROTOS, TCP_SERVICES, UDP_SERVICES, \
    MANUFDB
from scapy.error import log_scapy
from scapy.modules import six
from scapy.themes import NoTheme, apply_ipython_style

############
## Config ##
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
                wlen = 76-max(len(i),10)
                if len(r) > wlen:
                    r = r[:wlen-3]+"..."
                s += "%-10s = %s\n" % (i, r)
        return s[:-1]

class Interceptor(object):
    def __init__(self, name, default, hook, args=None, kargs=None):
        self.name = name
        self.intname = "_intercepted_%s" % name
        self.default=default
        self.hook = hook
        self.args = args if args is not None else []
        self.kargs = kargs if kargs is not None else {}
    def __get__(self, obj, typ=None):
        if not hasattr(obj, self.intname):
            setattr(obj, self.intname, self.default)
        return getattr(obj, self.intname)
    def __set__(self, obj, val):
        setattr(obj, self.intname, val)
        self.hook(self.name, val, *self.args, **self.kargs)

    
class ProgPath(ConfClass):
    pdfreader = "open" if DARWIN else "xdg-open"
    psreader = "open" if DARWIN else "xdg-open"
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
        return "<%s [%s]>" %  (self.__class__.__name__," ".join(str(x) for x in self.fields))

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
        for num,layer in six.iteritems(self.num2layer):
            if layer in self.layer2num and self.layer2num[layer] == num:
                dir = "<->"
            else:
                dir = " ->"
            lst.append((num,"%#6x %s %-20s (%s)" % (num, dir, layer.__name__,
                                                    layer._name)))
        for layer,num in six.iteritems(self.layer2num):
            if num not in self.num2layer or self.num2layer[num] != layer:
                lst.append((num,"%#6x <-  %-20s (%s)" % (num, layer.__name__,
                                                         layer._name)))
        lst.sort()
        return "\n".join(y for x,y in lst)


class LayersList(list):

    def __repr__(self):
        return "\n".join("%-20s: %s" % (l.__name__, l.name) for l in self)

    def register(self, layer):
        self.append(layer)

class CommandsList(list):
    def __repr__(self):
        s=[]
        for l in sorted(self,key=lambda x:x.__name__):
            doc = l.__doc__.split("\n")[0] if l.__doc__ else "--"
            s.append("%-20s: %s" % (l.__name__,doc))
        return "\n".join(s)
    def register(self, cmd):
        self.append(cmd)
        return cmd # return cmd so that method can be used as a decorator

def lsc():
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
        val = dict.__getitem__(self,item)
        if self.timeout is not None:
            t = self._timetable[item]
            if time.time()-t > self.timeout:
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
        dict.__setitem__(self, item,v)
    def update(self, other):
        for key, value in other.iteritems():
            # We only update an element from `other` either if it does
            # not exist in `self` or if the entry in `self` is older.
            if key not in self or self._timetable[key] < other._timetable[key]:
                dict.__setitem__(self, key, value)
                self._timetable[key] = other._timetable[key]
    def iteritems(self):
        if self.timeout is None:
            return six.iteritems(self.__dict__)
        t0=time.time()
        return ((k,v) for (k,v) in six.iteritems(self.__dict__) if t0-self._timetable[k] < self.timeout)
    def iterkeys(self):
        if self.timeout is None:
            return six.iterkeys(self.__dict__)
        t0=time.time()
        return (k for k in six.iterkeys(self.__dict__) if t0-self._timetable[k] < self.timeout)
    def __iter__(self):
        return six.iterkeys(self.__dict__)
    def itervalues(self):
        if self.timeout is None:
            return six.itervalues(self.__dict__)
        t0=time.time()
        return (v for (k,v) in six.iteritems(self.__dict__) if t0-self._timetable[k] < self.timeout)
    def items(self):
        if self.timeout is None:
            return dict.items(self)
        t0=time.time()
        return [(k,v) for (k,v) in six.iteritems(self.__dict__) if t0-self._timetable[k] < self.timeout]
    def keys(self):
        if self.timeout is None:
            return dict.keys(self)
        t0=time.time()
        return [k for k in six.iterkeys(self.__dict__) if t0-self._timetable[k] < self.timeout]
    def values(self):
        if self.timeout is None:
            return list(six.itervalues(self))
        t0=time.time()
        return [v for (k,v) in six.iteritems(self.__dict__) if t0-self._timetable[k] < self.timeout]
    def __len__(self):
        if self.timeout is None:
            return dict.__len__(self)
        return len(self.keys())
    def summary(self):
        return "%s: %i valid items. Timeout=%rs" % (self.name, len(self), self.timeout)
    def __repr__(self):
        s = []
        if self:
            mk = max(len(k) for k in six.iterkeys(self.__dict__))
            fmt = "%%-%is %%s" % (mk+1)
            for item in six.iteritems(self.__dict__):
                s.append(fmt % item)
        return "\n".join(s)
            
            


class NetCache:
    def __init__(self):
        self._caches_list = []


    def add_cache(self, cache):
        self._caches_list.append(cache)
        setattr(self,cache.name,cache)
    def new_cache(self, name, timeout=None):
        c = CacheInstance(name=name, timeout=timeout)
        self.add_cache(c)
    def __delattr__(self, attr):
        raise AttributeError("Cannot delete attributes")
    def update(self, other):
        for co in other._caches_list:
            if hasattr(self, co.name):
                getattr(self,co.name).update(co)
            else:
                self.add_cache(co.copy())
    def flush(self):
        for c in self._caches_list:
            c.flush()
    def __repr__(self):
        return "\n".join(c.summary() for c in self._caches_list)
        

class LogLevel(object):
    def __get__(self, obj, otype):
        return obj._logLevel
    def __set__(self,obj,val):
        log_scapy.setLevel(val)
        obj._logLevel = val
        

def isCryptographyValid():
    """
    Check if the cryptography library is present, and if it is recent enough
    for most usages in scapy (v1.7 or later).
    """
    try:
        import cryptography
    except ImportError:
        return False
    from distutils.version import LooseVersion
    return LooseVersion(cryptography.__version__) >= LooseVersion("1.7")


def isCryptographyAdvanced():
    """
    Check if the cryptography library is present, and if it supports X25519,
    ChaCha20Poly1305 and such (v2.0 or later).
    """
    try:
        import cryptography
    except ImportError:
        return False
    from distutils.version import LooseVersion
    lib_valid = LooseVersion(cryptography.__version__) >= LooseVersion("2.0")
    if not lib_valid:
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        X25519PrivateKey.generate()
    except:
        return False
    else:
        return True

def isPyPy():
    """Returns either scapy is running under PyPy or not"""
    try:
        import __pypy__
        return True
    except ImportError:
        return False

def _prompt_changer(attr, val):
    """Change the current prompt theme"""
    try:
        sys.ps1 = conf.color_theme.prompt(conf.prompt)
    except:
        pass
    try:
        apply_ipython_style(get_ipython())
    except NameError:
        pass

class Conf(ConfClass):
    """This object contains the configuration of Scapy.
session  : filename where the session will be saved
interactive_shell : can be "ipython", "python" or "auto". Default: Auto
stealth  : if 1, prevents any unwanted packet to go out (ARP, DNS, ...)
checkIPID: if 0, doesn't check that IPID matches between IP sent and ICMP IP citation received
           if 1, checks that they either are equal or byte swapped equals (bug in some IP stacks)
           if 2, strictly checks that they are equals
checkIPsrc: if 1, checks IP src in IP and ICMP IP citation match (bug in some NAT stacks)
checkIPinIP: if True, checks that IP-in-IP layers match. If False, do not
             check IP layers that encapsulates another IP layer
check_TCPerror_seqack: if 1, also check that TCP seq and ack match the ones in ICMP citation
iff      : selects the default output interface for srp() and sendp(). default:"eth0")
verb     : level of verbosity, from 0 (almost mute) to 3 (verbose)
promisc  : default mode for listening socket (to get answers if you spoof on a lan)
sniff_promisc : default mode for sniff()
filter   : bpf filter added to every sniffing socket to exclude traffic from analysis
histfile : history file
padding  : includes padding in disassembled packets
except_filter : BPF filter for packets to ignore
debug_match : when 1, store received packet that are not matched into debug.recv
route    : holds the Scapy routing table and provides methods to manipulate it
warning_threshold : how much time between warnings from the same place
ASN1_default_codec: Codec used by default for ASN1 objects
mib      : holds MIB direct access dictionary
resolve  : holds list of fields for which resolution should be done
noenum   : holds list of enum fields for which conversion to string should NOT be done
AS_resolver: choose the AS resolver class to use
extensions_paths: path or list of paths where extensions are to be looked for
contribs : a dict which can be used by contrib layers to store local configuration
debug_tls:When 1, print some TLS session secrets when they are computed.
"""
    version = VERSION
    session = ""
    interactive = False
    interactive_shell = ""
    stealth = "not implemented"
    iface = None
    iface6 = None
    layers = LayersList()
    commands = CommandsList()
    logLevel = LogLevel()
    checkIPID = 0
    checkIPsrc = 1
    checkIPaddr = 1
    checkIPinIP = True
    check_TCPerror_seqack = 0
    verb = 2
    prompt = Interceptor("prompt", ">>> ", _prompt_changer)
    promisc = 1
    sniff_promisc = 1
    raw_layer = None
    raw_summary = False
    default_l2 = None
    l2types = Num2Layer()
    l3types = Num2Layer()
    L3socket = None
    L2socket = None
    L2listen = None
    BTsocket = None
    min_pkt_size = 60
    histfile = os.getenv('SCAPY_HISTFILE',
                         os.path.join(os.path.expanduser("~"),
                                      ".scapy_history"))
    padding = 1
    except_filter = ""
    debug_match = 0
    debug_tls = 0
    wepkey = ""
    cache_iflist = {}
    cache_ipaddrs = {}
    route = None # Filed by route.py
    route6 = None # Filed by route6.py
    auto_fragment = 1
    debug_dissector = 0
    color_theme = Interceptor("color_theme", NoTheme(), _prompt_changer)
    warning_threshold = 5
    prog = ProgPath()
    resolve = Resolve()
    noenum = Resolve()
    emph = Emphasize()
    use_pypy = isPyPy()
    use_pcap = os.getenv("SCAPY_USE_PCAPDNET", "").lower().startswith("y")
    use_dnet = os.getenv("SCAPY_USE_PCAPDNET", "").lower().startswith("y")
    use_bpf = False
    use_winpcapy = False
    use_npcap = False
    ipv6_enabled = socket.has_ipv6
    ethertypes = ETHER_TYPES
    protocols = IP_PROTOS
    services_tcp = TCP_SERVICES
    services_udp = UDP_SERVICES
    extensions_paths = "."
    manufdb = MANUFDB
    stats_classic_protocols = []
    stats_dot11_protocols = []
    temp_files = []
    netcache = NetCache()
    geoip_city = None
    load_layers = ["l2", "inet", "dhcp", "dns", "dot11", "gprs",
                   "hsrp", "inet6", "ir", "isakmp", "l2tp", "mgcp",
                   "mobileip", "netbios", "netflow", "ntp", "ppp", "pptp",
                   "radius", "rip", "rtp", "skinny", "smb", "snmp",
                   "tftp", "x509", "bluetooth", "dhcp6", "llmnr",
                   "sctp", "vrrp", "ipsec", "lltd", "vxlan", "eap"]
    contribs = dict()
    crypto_valid = isCryptographyValid()
    crypto_valid_advanced = isCryptographyAdvanced()
    fancy_prompt = True
    auto_crop_tables = True


if not Conf.ipv6_enabled:
    log_scapy.warning("IPv6 support disabled in Python. Cannot load Scapy IPv6 layers.")
    for m in ["inet6","dhcp6"]:
        if m in Conf.load_layers:
            Conf.load_layers.remove(m)

conf=Conf()
conf.logLevel=30 # 30=Warning


def crypto_validator(func):
    """
    This a decorator to be used for any method relying on the cryptography library.
    Its behaviour depends on the 'crypto_valid' attribute of the global 'conf'.
    """
    def func_in(*args, **kwargs):
        if not conf.crypto_valid:
            raise ImportError("Cannot execute crypto-related method! "
                              "Please install python-cryptography v1.7 or later.")
        return func(*args, **kwargs)
    return func_in
