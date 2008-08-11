## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os,time
from data import *
import base_classes
import arch,themes
from error import log_scapy

############
## Config ##
############

class ConfClass(object):
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()
    def __repr__(self):
        return str(self)
    def __str__(self):
        s=""
        keys = self.__class__.__dict__.copy()
        keys.update(self.__dict__)
        keys = keys.keys()
        keys.sort()
        for i in keys:
            if i[0] != "_":
                r = repr(getattr(self, i))
                r = r.replace("\n"," ")
                wlen = 78-max(len(i),10)
                if len(r) > wlen:
                    r = r[:wlen-3]+"..."
                s += "%-10s = %s\n" % (i, r)
        return s[:-1]
    
class ProgPath(ConfClass):
    pdfreader = "acroread"
    psreader = "gv"
    dot = "dot"
    display = "display"
    tcpdump = "tcpdump"
    tcpreplay = "tcpreplay"
    hexedit = "hexer"
    wireshark = "wireshark"
    
class Resolve:
    def __init__(self):
        self.fields = {}
    def add(self, *flds):
        for fld in flds:
            self.fields[fld]=None
    def remove(self, *flds):
        for fld in flds:
            if fld in self.fields:
                del(self.fields[fld])
    def __contains__(self, elt):
        return elt in self.fields
    def __repr__(self):
        return "<Resolve [%s]>" %  " ".join(str(x) for x in self.fields)
    

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
            lst.append((num,"%#6x %s %-20s (%s)" % (num,dir,layer.__name__,layer.name)))
        for layer,num in self.layer2num.iteritems():
            if num not in self.num2layer or self.num2layer[num] != layer:
                lst.append((num,"%#6x <-  %-20s (%s)" % (num,layer.__name__,layer.name)))
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
        try:
            return self[item]
        except KeyError:
            return default
    def __setitem__(self, item, v):
        self._timetable[item] = time.time()
        dict.__setitem__(self, item,v)
    def __repr__(self):
        if self.timeout is None:
            n = len(self)
        else:
            n = 0
            t0 = time.time()
            for t,v in self.itervalues():
                if t0-t <= self.timeout:
                    n += 1
        return "%s: %i valid items. Timeout=%rs" % (self.name, n, self.timeout)
            


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
        return "\n".join(repr(c) for c in self._caches_list)
        

class LogLevel(object):
    def __get__(self, obj, otype):
        return obj._logLevel
    def __set__(self,obj,val):
        log_scapy.setLevel(val)
        obj._logLevel = val
        

class Conf(ConfClass):
    """This object contains the configuration of scapy.
session  : filename where the session will be saved
stealth  : if 1, prevents any unwanted packet to go out (ARP, DNS, ...)
checkIPID: if 0, doesn't check that IPID matches between IP sent and ICMP IP citation received
           if 1, checks that they either are equal or byte swapped equals (bug in some IP stacks)
           if 2, strictly checks that they are equals
checkIPsrc: if 1, checks IP src in IP and ICMP IP citation match (bug in some NAT stacks)
check_TCPerror_seqack: if 1, also check that TCP seq and ack match the ones in ICMP citation
iff      : selects the default output interface for srp() and sendp(). default:"eth0")
verb     : level of verbosity, from 0 (almost mute) to 3 (verbose)
promisc  : default mode for listening socket (to get answers if you spoof on a lan)
sniff_promisc : default mode for sniff()
filter   : bpf filter added to every sniffing socket to exclude traffic from analysis
histfile : history file
padding  : includes padding in desassembled packets
except_filter : BPF filter for packets to ignore
debug_match : when 1, store received packet that are not matched into debug.recv
route    : holds the Scapy routing table and provides methods to manipulate it
warning_threshold : how much time between warnings from the same place
ASN1_default_codec: Codec used by default for ASN1 objects
mib      : holds MIB direct access dictionnary
resolve   : holds list of fields for which resolution should be done
noenum    : holds list of enum fields for which conversion to string should NOT be done
AS_resolver: choose the AS resolver class to use
extensions_paths: path or list of paths where extensions are to be looked for
"""
    version = "2.0.0.4 beta"
    session = ""  
    stealth = "not implemented"
    iface = arch.get_working_if()
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
    l2types = Num2Layer()
    l3types = Num2Layer()
    L3socket = None
    L2socket = None
    L2listen = None
    histfile = os.path.join(os.environ["HOME"], ".scapy_history")
    padding = 1
    except_filter = ""
    debug_match = 0
    wepkey = ""
    route = None # Filed by route.py
    auto_fragment = 1
    debug_dissector = 0
    color_theme = themes.DefaultTheme()
    warning_threshold = 5
    prog = ProgPath()
    resolve = Resolve()
    noenum = Resolve()
    ethertypes = ETHER_TYPES
    protocols = IP_PROTOS
    services_tcp = TCP_SERVICES
    services_udp = UDP_SERVICES
    extensions_paths = "."
    manufdb = load_manuf("/usr/share/wireshark/wireshark/manuf")
    stats_classic_protocols = []
    stats_dot11_protocols = []
    netcache = NetCache()
    load_layers = ["l2", "inet", "dhcp", "dns", "dot11", "gprs", "hsrp", "ip6", "ir", "isakmp", "l2tp",
                   "mgcp", "mobileip", "netbios", "netflow", "ntp", "ppp", "radius", "rip", "rtp",
                   "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth" ]
    

conf=Conf()
conf.logLevel=30 # 30=Warning


