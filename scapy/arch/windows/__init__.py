## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Customizations needed to support Microsoft Windows.
"""
import os, re, sys, socket, time, itertools, platform
import subprocess as sp
from glob import glob
import tempfile

from scapy.config import conf, ConfClass
from scapy.error import Scapy_Exception, log_loading, log_runtime, warning
from scapy.utils import atol, itom, inet_aton, inet_ntoa, PcapReader
from scapy.base_classes import Gen, Net, SetGen
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

conf.use_pcap = False
conf.use_dnet = False
conf.use_winpcapy = True

WINDOWS = (os.name == 'nt')
NEW_RELEASE = None

#hot-patching socket for missing variables on Windows
import socket
if not hasattr(socket, 'IPPROTO_IPIP'):
    socket.IPPROTO_IPIP=4
if not hasattr(socket, 'IPPROTO_AH'):
    socket.IPPROTO_AH=51
if not hasattr(socket, 'IPPROTO_ESP'):
    socket.IPPROTO_ESP=50
if not hasattr(socket, 'IPPROTO_GRE'):
    socket.IPPROTO_GRE=47

from scapy.arch import pcapdnet
from scapy.arch.pcapdnet import *

from scapy.consts import LOOPBACK_NAME

def is_new_release(ignoreVBS=False):
    if NEW_RELEASE and conf.prog.powershell is not None:
        return True
    release = platform.release()
    if conf.prog.powershell is None and not ignoreVBS:
        return False
    try:
         if float(release) >= 8:
             return True
    except ValueError:
        if (release=="post2008Server"):
            return True
    return False

def _encapsulate_admin(cmd):
    """Encapsulate a command with an Administrator flag"""
    # To get admin access, we start a new powershell instance with admin rights, which will execute the command
    return "Start-Process PowerShell -windowstyle hidden -Wait -Verb RunAs -ArgumentList '-command &{%s}'" % cmd

def _exec_query_ps(cmd, fields):
    """Execute a PowerShell query"""
    if not conf.prog.powershell:
        raise OSError("Scapy could not detect powershell !")
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

def _vbs_exec_code(code, split_tag="@"):
    if not conf.prog.cscript:
        raise OSError("Scapy could not detect cscript !")
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
        data = line.replace("\n", "").split(split_tag)
        for l in data:
            yield l
    os.unlink(tmpfile.name)

def _vbs_get_hardware_iface_guid(devid):
    try:
        devid = str(int(devid) + 1)
        guid = iter(_vbs_exec_code("""WScript.Echo CreateObject("WScript.Shell").RegRead("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s\\ServiceName")
""" % devid)).next()
        guid = guid[:-1] if guid.endswith('}\n') else guid
        if guid.startswith('{') and guid.endswith('}'):
            return guid
    except StopIteration:
        return None

# Some names differ between VBS and PS
## None: field will not be returned under VBS
_VBS_WMI_FIELDS = {
    "Win32_NetworkAdapter": {
        "InterfaceDescription": "Description",
        # Note: when using VBS, the GUID is not the same than with Powershell
        # So we use get the device ID instead, then use _vbs_get_hardware_iface_guid
        # To get its real GUID
        "GUID": "DeviceID"
    },
    "*": {
        "Status": "State"
    }
}

_VBS_WMI_REPLACE = {
    "Win32_NetworkAdapterConfiguration": {
        "line.IPAddress": "\"{\" & Join( line.IPAddress, \", \" ) & \"}\"",
    }
}

_VBS_WMI_OUTPUT = {
    "Win32_NetworkAdapter": {
        "DeviceID": _vbs_get_hardware_iface_guid,
    }
}

def _exec_query_vbs(cmd, fields):
    """Execute a query using VBS. Currently Get-WmiObject, Get-Service
    queries are supported.

    """
    if not(len(cmd) == 2 and cmd[0] in ["Get-WmiObject", "Get-Service"]):
        return
    action = cmd[0]
    fields = [_VBS_WMI_FIELDS.get(cmd[1], _VBS_WMI_FIELDS.get("*", {})).get(fld, fld) for fld in fields]
    parsed_command = "WScript.Echo " + " & \" @ \" & ".join("line.%s" % fld for fld in fields
                           if fld is not None)
    # The IPAddress is an array: convert it to a string
    for key,val in _VBS_WMI_REPLACE.get(cmd[1], {}).items():
        parsed_command = parsed_command.replace(key, val)
    if action == "Get-WmiObject":
        values = _vbs_exec_code("""Set wmi = GetObject("winmgmts:")
Set lines = wmi.InstancesOf("%s")
On Error Resume Next
Err.clear
For Each line in lines
  %s
Next
""" % (cmd[1], parsed_command), "@")
    elif action == "Get-Service":
        values = _vbs_exec_code("""serviceName = "%s"
Set wmi = GetObject("winmgmts://./root/cimv2")
Set line = wmi.Get("Win32_Service.Name='" & serviceName & "'")
%s
""" % (cmd[1], parsed_command), "@")

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

def _where(filename, dirs=None, env="PATH"):
    """Find file in current dir, in deep_lookup cache or in system path"""
    if dirs is None:
        dirs = []
    if not isinstance(dirs, list):
        dirs = [dirs]
    if glob(filename):
        return filename
    paths = [os.curdir] + os.environ[env].split(os.path.pathsep) + dirs
    for path in paths:
        for match in glob(os.path.join(path, filename)):
            if match:
                return os.path.normpath(match)
    raise IOError("File not found: %s" % filename)

def win_find_exe(filename, installsubdir=None, env="ProgramFiles"):
    """Find executable in current dir, system path or given ProgramFiles subdir"""
    fns = [filename] if filename.endswith(".exe") else [filename+".exe", filename]
    for fn in fns:
        try:
            if installsubdir is None:
                path = _where(fn)
            else:
                path = _where(fn, dirs=[os.path.join(os.environ[env], installsubdir)])
        except IOError:
            path = None
        else:
            break        
    return path


class WinProgPath(ConfClass):
    _default = "<System default>"
    def __init__(self):
        self._reload()

    def _reload(self):
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
        self.cmd = win_find_exe("cmd", installsubdir="System32",
                               env="SystemRoot")
        if self.wireshark:
            manu_path = load_manuf(os.path.sep.join(self.wireshark.split(os.path.sep)[:-1])+os.path.sep+"manuf")
            scapy.data.MANUFDB = conf.manufdb = MANUFDB = manu_path
        
        self.os_access = (self.powershell is not None) or (self.cscript is not None)

conf.prog = WinProgPath()
if not conf.prog.os_access:
    warning("Scapy did not detect powershell and cscript ! Routes, interfaces and much more won't work !", True)

if conf.prog.tcpdump and conf.use_npcap and conf.prog.os_access:
    def test_windump_npcap():
        """Return wether windump version is correct or not"""
        try:
            p_test_windump = sp.Popen([conf.prog.tcpdump, "-help"], stdout=sp.PIPE, stderr=sp.STDOUT)
            stdout, err = p_test_windump.communicate()
            return "npcap" in stdout.lower()
        except:
            return False
    windump_ok = test_windump_npcap()
    if not windump_ok:
        warning("The installed Windump version does not work with Npcap ! Refer to 'Winpcap/Npcap conflicts' in scapy's doc", True)
    del windump_ok

# Auto-detect release
NEW_RELEASE = is_new_release()

class PcapNameNotFoundError(Scapy_Exception):
    pass    

def is_interface_valid(iface):
    if "guid" in iface and iface["guid"]:
        # Fix '-' instead of ':'
        if "mac" in iface:
            iface["mac"] = iface["mac"].replace("-", ":")
        return True
    return False

def get_windows_if_list():
    """Returns windows interfaces"""
    if not conf.prog.os_access:
        return []
    if is_new_release():
        # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
        # Careful: this is weird, but Get-NetAdaptater works like: (Name isn't the interface name)
        # Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
        # ----                      --------------------                    ------- ------       ----------             ---------
        # Ethernet                  Killer E2200 Gigabit Ethernet Contro...      13 Up           D0-50-99-56-DD-F9         1 Gbps
        query = exec_query(['Get-NetAdapter -Physical'],
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
    return None
        
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
            if not self.ip and self.name == LOOPBACK_NAME:
                self.ip = "127.0.0.1"
            if not self.ip:
                # No IP detected
                self.invalid = True
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

def pcap_service_name():
    """Return the pcap adapter service's name"""
    return "npcap" if conf.use_npcap else "npf"

def pcap_service_status():
    """Returns a tuple (name, description, started) of the windows pcap adapter"""
    for i in exec_query(['Get-Service', 'npcap'], ['Name', 'DisplayName', 'Status']):
        name = i[0]
        description = i[1]
        started = (i[2].lower().strip() == 'running')
        if name == pcap_service_name():
            return (name, description, started)
    return (None, None, None)

def pcap_service_control(action, askadmin=True):
    """Util to run pcap control command"""
    if not conf.prog.powershell:
        return False
    command = action + ' ' + pcap_service_name()
    ps = sp.Popen([conf.prog.powershell, _encapsulate_admin(command) if askadmin else command],
                    stdout=sp.PIPE,
                    universal_newlines=True)
    stdout, stderr = ps.communicate()
    return (not "error" in stdout.lower())

def pcap_service_start(askadmin=True):
    """Starts the pcap adapter. Will ask for admin. Returns True if success"""
    return pcap_service_control('Start-Service', askadmin=askadmin)

def pcap_service_stop(askadmin=True):
    """Stops the pcap adapter. Will ask for admin. Returns True if success"""
    return pcap_service_control('Stop-Service', askadmin=askadmin) 
    
from UserDict import UserDict

class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names""" 
    def load_from_powershell(self):
        if not conf.prog.os_access:
            return
        for i in get_windows_if_list():
            try:
                interface = NetworkInterface(i)
                self.data[interface.guid] = interface
            except (KeyError, PcapNameNotFoundError):
                pass
        
        if len(self.data) == 0 and conf.use_winpcapy:
            _detect = pcap_service_status()
            def _ask_user():
                if not conf.interactive:
                    return False
                while True:
                    _confir = raw_input("Do you want to start it ? (yes/no) [y]: ").lower().strip()
                    if _confir in ["yes", "y", ""]:
                        return True
                    elif _confir in ["no", "n"]:
                        return False
                return False
            _error_msg = "No match between your pcap and windows network interfaces found. "
            if _detect[0] and not _detect[2] and ((hasattr(self, "restarted_adapter") and not self.restarted_adapter)
                                                 or not hasattr(self, "restarted_adapter")):
                warning("Scapy has detected that your pcap service is not running !")
                if not conf.interactive or _ask_user():
                    succeed = pcap_service_start(askadmin=conf.interactive)
                    self.restarted_adapter = True
                    if succeed:
                        log_loading.info("Pcap service started !")
                        self.load_from_powershell()
                        return
                _error_msg = "Could not start the pcap service ! "
            warning(_error_msg +
                    "You probably won't be able to send packets. "
                    "Deactivating unneeded interfaces and restarting Scapy might help. "
                    "Check your winpcap and powershell installation, and access rights.", True)
        else:
            # Loading state: remove invalid interfaces
            self.remove_invalid_ifaces()
            # Replace LOOPBACK_INTERFACE
            try:
                scapy.consts.LOOPBACK_INTERFACE = self.dev_from_name(LOOPBACK_NAME)
            except:
                pass

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
        if str(if_index) == "1":
            # Test if the loopback interface is set up
            if isinstance(scapy.consts.LOOPBACK_INTERFACE, NetworkInterface):
                return scapy.consts.LOOPBACK_INTERFACE
        raise ValueError("Unknown network interface index %r" % if_index)

    def remove_invalid_ifaces(self):
        """Remove all invalid interfaces"""
        for devname, iface in self.items():
            if iface.is_invalid():
                self.data.pop(devname)

    def reload(self):
        """Reload interface list"""
        self.data.clear()
        self.load_from_powershell()

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
    if isinstance(dev, NetworkInterface):
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
    ARPHDR_ETHER, mac2str(IFACES.dev_from_pcapname(pcapname(iface)).mac)
)
get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr

def _read_routes_xp():
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

def _read_routes_7():
    routes=[]
    for line in exec_query(['Get-WmiObject', 'Win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex']):
        try:
            iface = dev_from_index(line[3])
            routes.append((atol(line[0]), atol(line[1]), line[2], iface, iface.ip))
        except ValueError:
            continue
    return routes
        
def read_routes():
    routes = []
    if not conf.prog.os_access:
        return routes
    release = platform.release()
    try:
        if is_new_release():
            routes = _read_routes_post2008()
        elif release == "XP":
            routes = _read_routes_xp()
        else:
            routes = _read_routes_7()
    except Exception as e:    
        warning("Error building scapy IPv4 routing table : %s" % str(e), True)
    else:
        if not routes:
            warning("No default IPv4 routes found. Your Windows release may no be supported and you have to enter your routes manually", True)
    return routes

def _read_routes_post2008():
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
    if is_new_release():
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
    else:
        ret = []
        # Get-WmiObject Win32_NetworkAdapterConfiguration | select InterfaceIndex, IpAddress
        for line in exec_query(['Get-WmiObject', 'Win32_NetworkAdapterConfiguration'], ['InterfaceIndex', 'IPAddress']):
            try:
                iface = dev_from_index(line[0])
            except:
                continue
            _l_addresses = line[1]
            _inline = []
            if _l_addresses:
                _inline = _l_addresses[1:-1].split(",")
                for _address in _inline:
                    _a = _address.strip()
                    if "." not in _a:
                        scope = scapy.utils6.in6_getscope(_a)
                        ret.append((_a, scope, iface)) # (addr,scope,iface)
        return ret

def _append_route6(routes, dpref, dp, nh, iface, lifaddr):
    cset = [] # candidate set (possible source addresses)
    if iface.name == LOOPBACK_NAME:
        if dpref == '::':
            return
        cset = ['::1']
    else:
        devaddrs = filter(lambda x: x[2] == iface, lifaddr)
        cset = scapy.utils6.construct_source_candidate_set(dpref, dp, devaddrs, scapy.consts.LOOPBACK_INTERFACE)
    if len(cset) == 0:
        return
    # APPEND (DESTINATION, NETMASK, NEXT HOP, IFACE, CANDIDATS)
    routes.append((dpref, dp, nh, iface, cset))

def _read_routes6_post2008():
    routes6 = []
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

            dpref = match.group(2)
            dp = int(match.group(3)[1:])
            nh = match.group(4)
            
            _append_route6(routes6, dpref, dp, nh, iface, lifaddr)
    return routes6

def _read_routes6_7():
    # Not supported in powershell, we have to use netsh
    routes = []
    ps = sp.Popen([conf.prog.cmd, '/c', 'netsh interface ipv6 show route level=verbose'], stdout = sp.PIPE, universal_newlines = True)
    stdout, stdin = ps.communicate()
    lifaddr = in6_getifaddr()
    # Define regexes
    r_int = [".*:\s+(\d+)"]
    r_all = ["(.*)"]
    r_ipv6 = [".*:\s+([A-z|0-9|:]+(\/\d+)?)"]
    # Build regex list for each object
    regex_list = r_ipv6*2 + r_int + r_all*3 + r_int + r_all*3
    current_object =  []
    index = 0
    for l in stdout.split('\n'):
        if not l.strip():
            if len(current_object) == 0:
                continue
            
            if len(current_object) == len(regex_list):
                try:
                    if_index = current_object[2]
                    iface = dev_from_index(if_index)
                except:
                    current_object = []
                    index = 0
                    continue
                _ip = current_object[0].split("/")
                dpref = _ip[0]
                dp = int(_ip[1])
                nh = current_object[1].split("/")[0]
                # metric = current_object[6]
                _append_route6(routes, dpref, dp, nh, iface, lifaddr)

            # Reset current object
            current_object = []
            index = 0
        else:
            pattern = re.compile(regex_list[index])
            match = re.search(pattern, l)
            if match:
                current_object.append(match.group(1))
                index = index + 1
    return routes

def read_routes6():
    routes6 = []
    if not conf.prog.os_access:
        return routes6
    try:
        if is_new_release():
            routes6 = _read_routes6_post2008()
        else:
            routes6 = _read_routes6_7()
    except Exception as e:    
        warning("Error building scapy IPv6 routing table : %s" % str(e), True)
    return routes6

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
        return scapy.consts.LOOPBACK_INTERFACE

conf.iface = get_working_if()

def route_add_loopback(routes=None, ipv6=False, iflist=None):
    """Add a route to 127.0.0.1 and ::1 to simplify unit tests on Windows"""
    if not WINDOWS:
        warning("Not available")
        return
    warning("This will completly mess up the routes. Testing purpose only !")
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
    data['mac'] = '00:00:00:00:00:00'
    adapter = NetworkInterface(data)
    if iflist:
        iflist.append(unicode("\\Device\\NPF_" + adapter.guid))
        return
    # Remove all LOOPBACK_NAME routes
    for route in list(conf.route.routes):
        iface = route[3]
        if iface.name == LOOPBACK_NAME:
            conf.route.routes.remove(route)
    # Remove LOOPBACK_NAME interface
    for devname, iface in IFACES.items():
        if iface.name == LOOPBACK_NAME:
            IFACES.pop(devname)
    # Inject interface
    IFACES[data['guid']] = adapter
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
