## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Implementation for of the configuration object.
"""

import os,time,socket,sys

from scapy import VERSION
from scapy.data import *
from scapy import base_classes
from scapy import themes
from scapy.error import log_scapy

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
    pdfreader = "acroread"
    psreader = "gv"
    dot = "dot"
    display = "display"
    tcpdump = "tcpdump"
    tcpreplay = "tcpreplay"
    hexedit = "hexer"
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
        self.layers = set([owner for f in self.fields for owner in f.owners])
    def add(self, *flds):
        self.fields |= set([f for f in flds if self._is_field(f)])
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
        if item in self:
            return self[item]
        return default
    
    def __repr__(self):
        lst = []
        for num,layer in self.num2layer.iteritems():
            if layer in self.layer2num and self.layer2num[layer] == num:
                dir = "<->"
            else:
                dir = " ->"
            lst.append((num,"%#6x %s %-20s (%s)" % (num, dir, layer.__name__,
                                                    layer._name)))
        for layer,num in self.layer2num.iteritems():
            if num not in self.num2layer or self.num2layer[num] != layer:
                lst.append((num,"%#6x <-  %-20s (%s)" % (num, layer.__name__,
                                                         layer._name)))
        lst.sort()
        return "\n".join(y for x,y in lst)


class LayersList(list):
    def __repr__(self):
        s=[]
        for l in self:
            s.append("%-20s: %s" % (l.__name__,l.name))
        return "\n".join(s)
    def register(self, layer):
        self.append(layer)

class CommandsList(list):
    def __repr__(self):
        s=[]
        for l in sorted(self,key=lambda x:x.__name__):
            if l.__doc__:
                doc = l.__doc__.split("\n")[0]
            else:
                doc = "--"
            s.append("%-20s: %s" % (l.__name__,doc))
        return "\n".join(s)
    def register(self, cmd):
        self.append(cmd)
        return cmd # return cmd so that method can be used as a decorator

def lsc():
    print repr(conf.commands)

class CacheInstance(dict):
    def __init__(self, name="noname", timeout=None):
        self.timeout = timeout
        self.name = name
        self._timetable = {}
    def __getitem__(self, item):
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
        self._timetable[item] = time.time()
        dict.__setitem__(self, item,v)
    def update(self, other):
        dict.update(self, other)
        self._timetable.update(other._timetable)
    def iteritems(self):
        if self.timeout is None:
            return dict.iteritems(self)
        t0=time.time()
        return ((k,v) for (k,v) in dict.iteritems(self) if t0-self._timetable[k] < self.timeout) 
    def iterkeys(self):
        if self.timeout is None:
            return dict.iterkeys(self)
        t0=time.time()
        return (k for k in dict.iterkeys(self) if t0-self._timetable[k] < self.timeout)
    def __iter__(self):
        return self.iterkeys()
    def itervalues(self):
        if self.timeout is None:
            return dict.itervalues(self)
        t0=time.time()
        return (v for (k,v) in dict.iteritems(self) if t0-self._timetable[k] < self.timeout)
    def items(self):
        if self.timeout is None:
            return dict.items(self)
        t0=time.time()
        return [(k,v) for (k,v) in dict.iteritems(self) if t0-self._timetable[k] < self.timeout]
    def keys(self):
        if self.timeout is None:
            return dict.keys(self)
        t0=time.time()
        return [k for k in dict.iterkeys(self) if t0-self._timetable[k] < self.timeout]
    def values(self):
        if self.timeout is None:
            return dict.values(self)
        t0=time.time()
        return [v for (k,v) in dict.iteritems(self) if t0-self._timetable[k] < self.timeout]
    def __len__(self):
        if self.timeout is None:
            return dict.__len__(self)
        return len(self.keys())
    def summary(self):
        return "%s: %i valid items. Timeout=%rs" % (self.name, len(self), self.timeout)
    def __repr__(self):
        s = []
        if self:
            mk = max(len(k) for k in self.iterkeys())
            fmt = "%%-%is %%s" % (mk+1)
            for item in self.iteritems():
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
        


def _prompt_changer(attr,val):
    prompt = conf.prompt
    try:
        ct = val
        if isinstance(ct, themes.AnsiColorTheme) and ct.prompt(""):
            ## ^A and ^B delimit invisible caracters for readline to count right.
            ## And we need ct.prompt() to do change something or else ^A and ^B will be
            ## displayed
             prompt = "\001%s\002" % ct.prompt("\002"+prompt+"\001")
        else:
            prompt = ct.prompt(prompt)
    except:
        pass
    sys.ps1 = prompt

class Conf(ConfClass):
    """
    This object contains the configuration of scapy.
    _session
        Filename where the session will be saved.
    _interactive_shell
        If "ipython", use IPython as shell. Default is Python.
    _stealth
        If 1, prevent any unwanted packet to go out (ARP, DNS, ...).
    _checkIPID
        If 0, don't check that IPID matches between IP sent and ICMP IP
        citation received. If 1, check that they either are equal or byte
        swapped equals (bug in some IP stacks). If 2, strictly check that
        they are equals.
    _checkIPsrc
        If 1, check IP src in IP and ICMP IP citation match (bug in some NAT
        stacks).
    _check_TCPerror_seqack
        If 1, also check that TCP seq and ack match the ones in ICMP citation.
    _iff
        Select the output interface for srp() and sendp(). Default is "eth0".
    _verb
        Level of verbosity, from 0 (almost mute) to 3 (verbose).
    _promisc
        Default mode for listening socket (to get answers if you spoof on a
        lan).
    _sniff_promisc
        Default mode for sniff().
    _filter
        BPF filter added to every sniffing socket to exclude traffic from
        analysis.
    _histfile
        History file.
    _padding
        Include padding in desassembled packets.
    _except_filter
        BPF filter for packets to ignore.
    _debug_match
        If 1, store received packet that are not matched into debug.recv.
    _route
        Holds the Scapy routing table and provides methods to manipulate it.
    _warning_threshold
        Set the time threshold between warnings from the same place.
    _ASN1_default_codec
        Codec used by default for ASN1 objects.
    _mib
        Holds MIB direct access dictionary.
    _resolve
        Holds a list of fields for which resolution should be done.
    _noenum
        Holds a list of enum fields for which conversion to string should NOT
        be done.
    _AS_resolver
        Choose the AS resolver class to use.
    _extensions_paths
        Path or list of paths where extensions are to be looked for.
    _contribs
        A dict which can be used by contrib layers to store local configuration.
    _debug_tls
        When 1, print some TLS session secrets when they are computed.
    """
    version = VERSION
    session = ""
    interactive = False
    interactive_shell = ""
    stealth = "not implemented"
    iface = None
    readfunc = None
    layers = LayersList()
    commands = CommandsList()
    logLevel = LogLevel()
    checkIPID = 0
    checkIPsrc = 1
    checkIPaddr = 1
    check_TCPerror_seqack = 0
    verb = 2
    prompt = ">>> "
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
    min_pkt_size = 60
    histfile = os.getenv('SCAPY_HISTFILE',
                         os.path.join(os.path.expanduser("~"),
                                      ".scapy_history"))
    padding = 1
    except_filter = ""
    debug_match = 0
    debug_tls = 0
    wepkey = ""
    route = None # Filed by route.py
    route6 = None # Filed by route6.py
    auto_fragment = 1
    debug_dissector = 0
    color_theme = Interceptor("color_theme", themes.NoTheme(), _prompt_changer)
    warning_threshold = 5
    prog = ProgPath()
    resolve = Resolve()
    noenum = Resolve()
    emph = Emphasize()
    use_pcap = os.getenv("SCAPY_USE_PCAPDNET", "").lower().startswith("y")
    use_dnet = os.getenv("SCAPY_USE_PCAPDNET", "").lower().startswith("y")
    use_winpcapy = False
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
    geoip_city = '/usr/share/GeoIP/GeoLiteCity.dat'
    load_layers = ["l2", "inet", "dhcp", "dns", "dot11", "gprs",
                   "hsrp", "inet6", "ir", "isakmp", "l2tp", "mgcp",
                   "mobileip", "netbios", "netflow", "ntp", "ppp",
                   "radius", "rip", "rtp", "skinny", "smb", "snmp",
                   "tftp", "x509", "bluetooth", "dhcp6", "llmnr",
                   "sctp", "vrrp", "ipsec", "lltd", "vxlan"]
    # The TLS layer has its own directory; it must be imported manually.
    contribs = dict()


if not Conf.ipv6_enabled:
    log_scapy.warning("IPv6 support disabled in Python. Cannot load scapy IPv6 layers.")
    for m in ["inet6","dhcp6"]:
        if m in Conf.load_layers:
            Conf.load_layers.remove(m)
    

conf=Conf()
conf.logLevel=30 # 30=Warning

