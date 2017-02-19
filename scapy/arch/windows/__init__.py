## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Customizations needed to support Microsoft Windows.
"""
import os,re,sys,socket,time, itertools
import subprocess as sp
from glob import glob
import tempfile

from scapy.config import conf, ConfClass
from scapy.error import Scapy_Exception, log_loading, log_runtime, warning
from scapy.utils import atol, itom, inet_aton, inet_ntoa, PcapReader
from scapy.base_classes import Gen, Net, SetGen
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP
from scapy.consts import LOOPBACK_NAME

conf.use_pcap = False
conf.use_dnet = False
conf.use_winpcapy = True

WINDOWS = (os.name == 'nt')

#hot-patching socket for missing variables on Windows
import socket
if not hasattr(socket, 'IPPROTO_IPIP'):
    socket.IPPROTO_IPIP=4
if not hasattr(socket, 'IPPROTO_AH'):
    socket.IPPROTO_AH=51
if not hasattr(socket, 'IPPROTO_ESP'):
    socket.IPPROTO_ESP=50

from scapy.arch import pcapdnet
from scapy.arch.pcapdnet import *

def _exec_query_ps(cmd, fields):
    """Execute a PowerShell query"""
    if not WINDOWS:
        return
    ps = sp.Popen([conf.prog.powershell] + cmd +
                  ['|', 'select %s' % ', '.join(fields), '|', 'fl'],
                  stdout=sp.PIPE,
                  universal_newlines=True)
    l=[]
    for line in ps.stdout:
        if not line.strip(): # skip empty lines
            continue
        sl = line.split(':', 1)
        if len(sl) == 1:
            l[-1] += sl[0].strip()
            continue
        else:
            l.append(sl[1].strip())
        if len(l) == len(fields):
            yield l
            l=[]

def _vbs_exec_code(code):
    if not WINDOWS:
        return
    tmpfile = tempfile.NamedTemporaryFile(suffix=".vbs", delete=False)
    tmpfile.write(code)
    tmpfile.close()
    ps = sp.Popen([conf.prog.cscript, tmpfile.name],
                  stdout=sp.PIPE, stderr=open(os.devnull),
                  universal_newlines=True)
    for _ in xrange(3):
        # skip 3 first lines
        ps.stdout.readline()
    for line in ps.stdout:
        yield line
    os.unlink(tmpfile.name)

def _vbs_get_iface_guid(devid):
    if not WINDOWS:
        return
    try:
        devid = str(int(devid) + 1)
        guid = _vbs_exec_code("""WScript.Echo CreateObject("WScript.Shell").RegRead("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s\\ServiceName")
""" % devid).__iter__().next()
        if guid.startswith('{') and guid.endswith('}\n'):
            return guid[:-1]
    except StopIteration:
        pass

# Some names differ between VBS and PS
## None: field will not be returned under VBS
_VBS_WMI_FIELDS = {
    "Win32_NetworkAdapter": {
        "InterfaceIndex": "Index",
        "InterfaceDescription": "Description",
        "GUID": "DeviceID",
    }
}

_VBS_WMI_OUTPUT = {
    "Win32_NetworkAdapter": {
        "DeviceID": _vbs_get_iface_guid,
    }
}

def _exec_query_vbs(cmd, fields):
    if not WINDOWS:
        return
    """Execute a query using VBS. Currently Get-WmiObject queries are
    supported.

    """
    if not WINDOWS:
        return
    assert len(cmd) == 2 and cmd[0] == "Get-WmiObject"
    fields = [_VBS_WMI_FIELDS.get(cmd[1], {}).get(fld, fld) for fld in fields]
    values = _vbs_exec_code("""Set wmi = GetObject("winmgmts:")
Set lines = wmi.InstancesOf("%s")
On Error Resume Next
Err.clear
For Each line in lines
  %s
Next
""" % (cmd[1], "\n  ".join("WScript.Echo line.%s" % fld for fld in fields
                           if fld is not None))).__iter__()
    while True:
        yield [None if fld is None else
               _VBS_WMI_OUTPUT.get(cmd[1], {}).get(fld, lambda x: x)(
                   values.next().strip()
               )
               for fld in fields]

def exec_query(cmd, fields):
    """Execute a system query using PowerShell if it is available, and
    using VBS/cscript as a fallback.

    """
    if conf.prog.powershell is None:
        return _exec_query_vbs(cmd, fields)
    return _exec_query_ps(cmd, fields)

DEEP_LOOKUP_CACHE = {}

def _deep_lookup(prog_list, max_depth=3):
    """Quickly iterate through Program Files to find the programs"""
    results = {}
    def env_path(key):
        try:
            return os.environ[key]
        except KeyError:
            return ""
    def has_common_item(l1, l2):
        for i in l1:
            if i in l2:
                return True, i, i
            if i + ".exe" in l2:
                return True, i + ".exe", i
        return False, None, None
    def key_in_path(path, key):
        return key.lower() in path.lower()
    deeper_paths = [env_path("ProgramFiles"), env_path("ProgramFiles(x86)")]
    for path in deeper_paths:
        len_p = len(path) + len(os.path.sep)
        for root, subFolders, files in os.walk(path):
            depth = root[len_p:].count(os.path.sep)
            if depth > max_depth:
                del subFolders[:]
                continue
            ye, name, key = has_common_item(prog_list, files)
            if ye:
                _k_path = os.path.normpath(os.path.join(root, name))
                if key_in_path(_k_path, prog_list[key]):
                    results[name] = _k_path
    global DEEP_LOOKUP_CACHE
    DEEP_LOOKUP_CACHE = results

def _where(filename, dirs=None, env="PATH"):
    """Find file in current dir, in deep_lookup cache or in system path"""
    if dirs is None:
        dirs = []
    if not isinstance(dirs, list):
        dirs = [dirs]
    if glob(filename):
        return filename
    global DEEP_LOOKUP_CACHE
    if filename in DEEP_LOOKUP_CACHE:
        return DEEP_LOOKUP_CACHE[filename]
    paths = [os.curdir] + os.environ[env].split(os.path.pathsep) + dirs
    for path in paths:
        for match in glob(os.path.join(path, filename)):
            if match:
                return os.path.normpath(match)
    raise IOError("File not found: %s" % filename)

def win_find_exe(filename, installsubdir=None, env="ProgramFiles"):
    """Find executable in current dir, system path or given ProgramFiles subdir"""
    if not WINDOWS:
        return
    fns = [filename] if filename.endswith(".exe") else [filename+".exe", filename]
    for fn in fns:
        try:
            if installsubdir is None:
                path = _where(fn)
            else:
                path = _where(fn, dirs=[os.path.join(os.environ[env], installsubdir)])
        except IOError:
            path = filename
        else:
            break        
    return path


def is_new_release():
    release = platform.release()
    try:
        if float(release) >= 8:
            return True
    except ValueError:
        if (release=="post2008Server"):
            return True
    return False

class WinProgPath(ConfClass):
    # This is a dict containing the name of the .exe and a keyword
    # that must be in the path of the file
    external_prog_list = {"AcroRd32" : "", "gsview32" : "", "dot" : "graph", "windump" : "", "tshark" : "",
                          "tcpreplay" : "", "hexer" : "", "sox" : "", "wireshark" : ""}
    _default = "<System default>"
    def __init__(self):
        _deep_lookup(self.external_prog_list)
        # We try some magic to find the appropriate executables
        self.pdfreader = win_find_exe("AcroRd32") 
        self.psreader = win_find_exe("gsview32")
        self.dot = win_find_exe("dot")
        self.tcpdump = win_find_exe("windump")
        self.tshark = win_find_exe("tshark")
        self.tcpreplay = win_find_exe("tcpreplay")
        self.display = self._default
        self.hexedit = win_find_exe("hexer")
        self.sox = win_find_exe("sox")
        self.wireshark = win_find_exe("wireshark", "wireshark")
        self.powershell = win_find_exe(
            "powershell",
            installsubdir="System32\\WindowsPowerShell\\v1.0",
            env="SystemRoot"
        )
        self.cscript = win_find_exe("cscript", installsubdir="System32",
                               env="SystemRoot")

conf.prog = WinProgPath()
if conf.prog.powershell == "powershell":
    conf.prog.powershell = None
if conf.prog.sox == "sox":
    conf.prog.sox = None

class PcapNameNotFoundError(Scapy_Exception):
    pass    
import platform

def is_interface_valid(iface):
    if "guid" in iface and iface["guid"]:
        return True
    return False

def get_windows_if_list():
    if is_new_release():
        # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
        # Careful: this is weird, but Get-NetAdaptater works like: (Name isn't the interface name)
        # Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
        # ----                      --------------------                    ------- ------       ----------             ---------
        # Ethernet                  Killer E2200 Gigabit Ethernet Contro...      13 Up           D0-50-99-56-DD-F9         1 Gbps
        
        query = exec_query(['Get-NetAdapter'],
                           ['InterfaceDescription', 'InterfaceIndex', 'Name',
                            'InterfaceGuid', 'MacAddress']) # It is normal that it is in this order
    else:
        query = exec_query(['Get-WmiObject', 'Win32_NetworkAdapter'],
                           ['Name', 'InterfaceIndex', 'InterfaceDescription',
                            'GUID', 'MacAddress'])
    return [
        iface for iface in
        (dict(zip(['name', 'win_index', 'description', 'guid', 'mac'], line))
         for line in query)
        if is_interface_valid(iface)
    ]

def get_ip_from_name(ifname, v6=False):
    for descr, ipaddr in exec_query(['Get-WmiObject',
                                     'Win32_NetworkAdapterConfiguration'],
                                    ['Description', 'IPAddress']):
        if descr == ifname.strip():
            return ipaddr.split(",", 1)[v6].strip('{}').strip()
        
class NetworkInterface(object):
    """A network interface of your local host"""
    
    def __init__(self, data=None):
        self.name = None
        self.ip = None
        self.mac = None
        self.pcap_name = None
        self.description = None
        self.data = data
        self.invalid = False
        if data is not None:
            self.update(data)

    def update(self, data):
        """Update info about network interface according to given dnet dictionary"""
        self.name = data['name']
        self.description = data['description']
        self.win_index = data['win_index']
        self.guid = data['guid']
        if 'invalid' in data:
            self.invalid = data['invalid']
        # Other attributes are optional
        self._update_pcapdata()

        try:
            self.ip = socket.inet_ntoa(get_if_raw_addr(data))
        except (KeyError, AttributeError, NameError):
            pass

        try:
            if not self.ip:
                self.ip=get_ip_from_name(data['name'])
        except (KeyError, AttributeError, NameError) as e:
            print e
        try:
            self.mac = data['mac']
        except KeyError:
            pass

    def _update_pcapdata(self):
        if self.is_invalid():
            return
        for i in winpcapy_get_if_list():
            if i.endswith(self.data['guid']):
                self.pcap_name = i
                return

        raise PcapNameNotFoundError

    def is_invalid(self):
        return self.invalid

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self.name, self.guid)

from UserDict import UserDict

class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names""" 
    def load_from_powershell(self):
        for i in get_windows_if_list():
            try:
                interface = NetworkInterface(i)
                self.data[interface.guid] = interface
            except (KeyError, PcapNameNotFoundError):
                pass
        
        if len(self.data) == 0 and conf.use_winpcapy:
            warning("No match between your pcap and windows network interfaces found. "
                                "You probably won't be able to send packets. "
                                "Deactivating unneeded interfaces and restarting Scapy might help."
                                "Check your winpcap and powershell installation, and access rights.", True)

    def dev_from_name(self, name):
        """Return the first pcap device name for a given Windows
        device name.
        """
        for iface in self.itervalues():
            if iface.name == name:
                return iface
        raise ValueError("Unknown network interface %r" % name)

    def dev_from_pcapname(self, pcap_name):
        """Return Windows device name for given pcap device name."""
        for iface in self.itervalues():
            if iface.pcap_name == pcap_name:
                return iface
        raise ValueError("Unknown pypcap network interface %r" % pcap_name)

    def dev_from_index(self, if_index):
        """Return interface name from interface index"""
        for devname, iface in self.items():
            if iface.win_index == str(if_index):
                return iface
        raise ValueError("Unknown network interface index %r" % if_index)

    def show(self, resolve_mac=True):
        """Print list of available network interfaces in human readable form"""
        print "%s  %s  %s  %s" % ("INDEX".ljust(5), "IFACE".ljust(35), "IP".ljust(15), "MAC")
        for iface_name in sorted(self.data):
            dev = self.data[iface_name]
            mac = dev.mac
            if resolve_mac:
                mac = conf.manufdb._resolve_MAC(mac)
            print "%s  %s  %s  %s" % (str(dev.win_index).ljust(5), str(dev.name).ljust(35), str(dev.ip).ljust(15), mac)
            
IFACES = NetworkInterfaceDict()
IFACES.load_from_powershell()

def pcapname(dev):
    """Return pypcap device name for given interface or libdnet/Scapy
    device name.

    """
    if type(dev) is NetworkInterface:
        if dev.is_invalid():
            return None
        return dev.pcap_name
    try:
        return IFACES.dev_from_name(dev).pcap_name
    except ValueError:
        if conf.use_pcap:
            # pcap.pcap() will choose a sensible default for sniffing if
            # iface=None
            return None
        raise

def dev_from_pcapname(pcap_name):
    """Return libdnet/Scapy device name for given pypcap device name"""
    return IFACES.dev_from_pcapname(pcap_name)

def dev_from_index(if_index):
    """Return Windows adapter name for given Windows interface index"""
    return IFACES.dev_from_index(if_index)
    
def show_interfaces(resolve_mac=True):
    """Print list of available network interfaces"""
    return IFACES.show(resolve_mac)

_orig_open_pcap = pcapdnet.open_pcap
pcapdnet.open_pcap = lambda iface,*args,**kargs: _orig_open_pcap(pcapname(iface),*args,**kargs)

_orig_get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr
pcapdnet.get_if_raw_hwaddr = lambda iface, *args, **kargs: (
    ARPHDR_ETHER, mac2str(IFACES.dev_from_pcapname(pcapname(iface)).mac.replace('-', ':'))
)
get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr

def read_routes_xp():
    # The InterfaceIndex in Win32_IP4RouteTable does not match the
    # InterfaceIndex in Win32_NetworkAdapter under some platforms
    # (namely Windows XP): let's try an IP association
    routes = []
    partial_routes = []
    # map local IP addresses to interfaces
    local_addresses = {iface.ip: iface for iface in IFACES.itervalues()}
    iface_indexes = {}
    for line in exec_query(['Get-WmiObject', 'Win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex']):
        if line[2] in local_addresses:
            iface = local_addresses[line[2]]
            # This gives us an association InterfaceIndex <-> interface
            iface_indexes[line[3]] = iface
            routes.append((atol(line[0]), atol(line[1]), "0.0.0.0", iface,
                           iface.ip))
        else:
            partial_routes.append((atol(line[0]), atol(line[1]), line[2],
                                   line[3]))
    for dst, mask, gw, ifidx in partial_routes:
        if ifidx in iface_indexes:
            iface = iface_indexes[ifidx]
            routes.append((dst, mask, gw, iface, iface.ip))
    return routes

def read_routes_7():
    routes=[]
    for line in exec_query(['Get-WmiObject', 'win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex']):
        try:
            iface = dev_from_index(line[3])
            routes.append((atol(line[0]), atol(line[1]), line[2], iface, iface.ip))
        except ValueError:
            continue
    return routes
        
def read_routes():
    routes = []
    release = platform.release()
    try:
        if is_new_release():
            routes = read_routes_post2008()
        elif release == "XP":
            routes = read_routes_xp()
        else:
            routes = read_routes_7()
    except Exception as e:    
        warning("Error building scapy routing table : %s" % str(e), True)
    else:
        if not routes:
            warning("No default IPv4 routes found. Your Windows release may no be supported and you have to enter your routes manually", True)
    return routes
       
def read_routes_post2008():
    routes = []
    if_index = '(\d+)'
    dest = '(\d+\.\d+\.\d+\.\d+)/(\d+)'
    next_hop = '(\d+\.\d+\.\d+\.\d+)'
    metric_pattern = "(\d+)"
    delim = "\s+"        # The columns are separated by whitespace
    netstat_line = delim.join([if_index, dest, next_hop, metric_pattern])
    pattern = re.compile(netstat_line)
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
    ps = sp.Popen([conf.prog.powershell, 'Get-NetRoute', '-AddressFamily IPV4', '|', 'select ifIndex, DestinationPrefix, NextHop, RouteMetric'], stdout = sp.PIPE, universal_newlines = True)
    stdout, stdin = ps.communicate()
    for l in stdout.split('\n'):
        match = re.search(pattern,l)
        if match:
            try:
                iface = dev_from_index(match.group(1))
                if iface.ip == "0.0.0.0":
                    continue
            except:
                continue
            # try:
            #     intf = pcapdnet.dnet.intf().get_dst(pcapdnet.dnet.addr(type=2, addrtxt=dest))
            # except OSError:
            #     log_loading.warning("Building Scapy's routing table: Couldn't get outgoing interface for destination %s" % dest)
            #     continue               
            routes.append((atol(match.group(2)), itom(int(match.group(3))),
                           match.group(4), iface, iface.ip))
    return routes

############
### IPv6 ###
############

def in6_getifaddr():
    """
    Returns all IPv6 addresses found on the computer
    """
    ret = []
    ps = sp.Popen([conf.prog.powershell, 'Get-NetRoute', '-AddressFamily IPV6', '|', 'select ifIndex, DestinationPrefix'], stdout = sp.PIPE, universal_newlines = True)
    stdout, stdin = ps.communicate()
    netstat_line = '\s+'.join(['(\d+)', ''.join(['([A-z|0-9|:]+)', '(\/\d+)'])])
    pattern = re.compile(netstat_line)
    for l in stdout.split('\n'):
        match = re.search(pattern,l)
        if match:
            try:
                if_index = match.group(1)
                iface = dev_from_index(if_index)
            except:
                continue
            scope = scapy.utils6.in6_getscope(match.group(2))
            ret.append((match.group(2), scope, iface)) # (addr,scope,iface)
            continue
    return ret

def read_routes6():
    routes = []
    ipv6_r = '([A-z|0-9|:]+)' #Hope it is a valid address...
    # The correct IPv6 regex would be:
    # ((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?
    # but is too big to be used (PyCParser): AssertionError: sorry, but this version only supports 100 named groups
    netmask = '(\/\d+)?'
    if_index = '(\d+)'
    delim = '\s+'        # The columns are separated by whitespace
    netstat_line = delim.join([if_index, "".join([ipv6_r, netmask]), ipv6_r])
    pattern = re.compile(netstat_line)
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
    # Get-NetRoute -AddressFamily IPV6 | select ifIndex, DestinationPrefix, NextHop
    ps = sp.Popen([conf.prog.powershell, 'Get-NetRoute', '-AddressFamily IPV6', '|', 'select ifIndex, DestinationPrefix, NextHop'], stdout = sp.PIPE, universal_newlines = True)
    stdout, stdin = ps.communicate()
    lifaddr = in6_getifaddr()
    for l in stdout.split('\n'):
        match = re.search(pattern,l)
        if match:
            try:
                if_index = match.group(1)
                iface = dev_from_index(if_index)
            except:
                continue

            d = match.group(2)
            dp = int(match.group(3)[1:])
            nh = match.group(4)
            
            cset = [] # candidate set (possible source addresses)
            if iface.name == LOOPBACK_NAME:
                if d == '::':
                    continue
                cset = ['::1']
            else:
                devaddrs = filter(lambda x: x[2] == iface, lifaddr)
                cset = scapy.utils6.construct_source_candidate_set(d, dp, devaddrs, LOOPBACK_NAME)
            # APPEND (DESTINATION, NETMASK, NEXT HOP, IFACE, CANDIDATS)
            routes.append((d, dp, nh, iface, cset))
    return routes




if conf.interactive_shell != 'ipython' and conf.interactive:
    try:
        __IPYTHON__
    except NameError:
        def readLineScapy(prompt):
            result = ""
            end = False
            while not end :
                if not end and result != "":
                    line = readline.rl.readline("... ")
                else:
                    line = readline.rl.readline(prompt)
                if line.strip().endswith(":"):
                    end = False
                elif result == "":
                    end = True
                if line.strip() == "":
                    end = True
                result = result + "\n" + line
            return unicode(result)
        try:
            import readline
            console = readline.GetOutputFile()
        except (ImportError, AttributeError):
            log_loading.info("Could not get readline console. Will not interpret ANSI color codes.") 
        else:
            conf.readfunc = readLineScapy
            orig_stdout = sys.stdout
            sys.stdout = console

def get_working_if():
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        return min(read_routes(), key=lambda x: x[1])[3]
    except ValueError:
        # no route
        return LOOPBACK_NAME

conf.iface = get_working_if()

def route_add_loopback(routes=None, ipv6=False, iflist=None):
    """Add a route to 127.0.0.1 and ::1 to simplify unit tests on Windows"""
    # Add only if some adpaters already exist
    if ipv6:
        if len(conf.route6.routes) == 0:
            return
    else:
        if len(conf.route.routes) == 0:
            return
    data = {}
    data['name'] = LOOPBACK_NAME
    data['description'] = "Loopback"
    data['win_index'] = -1
    data['guid'] = "{0XX00000-X000-0X0X-X00X-00XXXX000XXX}"
    data['invalid'] = True
    adapter = NetworkInterface(data)
    if iflist:
        iflist.append(unicode("\\Device\\NPF_" + adapter.guid))
        return
    # Build the packed network addresses
    loop_net = struct.unpack("!I", socket.inet_aton("127.0.0.0"))[0]
    loop_mask = struct.unpack("!I", socket.inet_aton("255.0.0.0"))[0]
    # Build the fake routes
    loopback_route = (loop_net, loop_mask, "0.0.0.0", adapter, "127.0.0.1")
    loopback_route6 = ('::1', 128, '::', adapter, ["::1"])
    loopback_route6_custom = ("fe80::", 128, "::", adapter, ["::1"])
    if routes == None:
        # Injection
        conf.route6.routes.append(loopback_route6)
        conf.route6.routes.append(loopback_route6_custom)
        conf.route.routes.append(loopback_route)
        # Flush the caches
        conf.route6.invalidate_cache()
        conf.route.invalidate_cache()
    else:
        if ipv6:
            routes.append(loopback_route6)
            routes.append(loopback_route6_custom)
        else:
            routes.append(loopback_route)
