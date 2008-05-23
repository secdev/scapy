import os
from arch import *
from data import *
from themes import *

############
## Config ##
############

class ConfClass:
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()
    def __repr__(self):
        return str(self)
    def __str__(self):
        s="Version    = %s\n" % VERSION
        keys = self.__class__.__dict__.copy()
        keys.update(self.__dict__)
        keys = keys.keys()
        keys.sort()
        for i in keys:
            if i[0] != "_":
                s += "%-10s = %s\n" % (i, repr(getattr(self, i)))
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
        if isinstance(item, Packet_metaclass):
            return self.layer2num[item]
        return self.num2layer[item]
    def __contains__(self, item):
        if isinstance(item, Packet_metaclass):
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
    session = ""  
    stealth = "not implemented"
    iface = get_working_if()
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
    p0f_base ="/etc/p0f/p0f.fp"
    queso_base ="/etc/queso.conf"
    nmap_base ="/usr/share/nmap/nmap-os-fingerprints"
    IPCountry_base = "GeoIPCountry4Scapy.gz"
    countryLoc_base = "countryLoc.csv"
    gnuplot_world = "world.dat"
    except_filter = ""
    debug_match = 0
    wepkey = ""
    route = None # Filed by arch
    auto_fragment = 1
    debug_dissector = 0
    color_theme = DefaultTheme()
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

conf=Conf()


