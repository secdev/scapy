## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Copyright (C) Gabriel Potter <gabriel@potter.fr>
## This program is published under a GPLv2 license

"""
Customizations needed to support Microsoft Windows.
"""
from __future__ import absolute_import
from __future__ import print_function
import os, re, sys, socket, time, itertools, platform
import subprocess as sp
from glob import glob
import tempfile

import scapy
from scapy.config import conf, ConfClass
from scapy.error import Scapy_Exception, log_loading, log_runtime, warning
from scapy.utils import atol, itom, inet_aton, inet_ntoa, PcapReader
from scapy.base_classes import Gen, Net, SetGen
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

import scapy.modules.six as six
from scapy.modules.six.moves import range, zip, input
from scapy.compat import plain_str

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

_WlanHelper = NPCAP_PATH + "\\WlanHelper.exe"

import scapy.consts

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
    tmpfile = tempfile.NamedTemporaryFile(mode="wb", suffix=".vbs", delete=False)
    tmpfile.write(raw(code))
    tmpfile.close()
    ps = sp.Popen([conf.prog.cscript, tmpfile.name],
                  stdout=sp.PIPE, stderr=open(os.devnull),
                  universal_newlines=True)
    for _ in range(3):
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
        guid = next(iter(_vbs_exec_code("""WScript.Echo CreateObject("WScript.Shell").RegRead("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s\\ServiceName")
""" % devid)))
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
                   next(values).strip()
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
            scapy.data.MANUFDB = conf.manufdb = manu_path
        
        self.os_access = (self.powershell is not None) or (self.cscript is not None)

conf.prog = WinProgPath()
if not conf.prog.os_access:
    warning("Scapy did not detect powershell and cscript ! Routes, interfaces and much more won't work !", onlyOnce=True)

if conf.prog.tcpdump and conf.use_npcap and conf.prog.os_access:
    def test_windump_npcap():
        """Return wether windump version is correct or not"""
        try:
            p_test_windump = sp.Popen([conf.prog.tcpdump, "-help"], stdout=sp.PIPE, stderr=sp.STDOUT)
            stdout, err = p_test_windump.communicate()
            _output = stdout.lower()
            return b"npcap" in _output and not b"winpcap" in _output
        except:
            return False
    windump_ok = test_windump_npcap()
    if not windump_ok:
        warning("The installed Windump version does not work with Npcap ! Refer to 'Winpcap/Npcap conflicts' in scapy's doc", onlyOnce=True)
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
    """Returns windows interfaces."""
    if not conf.prog.os_access:
        return []
    if is_new_release():
        # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
        # Careful: this is weird, but Get-NetAdaptater works like: (Name isn't the interface name)
        # Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
        # ----                      --------------------                    ------- ------       ----------             ---------
        # Ethernet                  Killer E2200 Gigabit Ethernet Contro...      13 Up           D0-50-99-56-DD-F9         1 Gbps
        query = exec_query(['Get-NetAdapter'],
                           ['InterfaceDescription', 'InterfaceIndex', 'Name',
                            'InterfaceGuid', 'MacAddress', 'InterfaceAlias']) # It is normal that it is in this order
    else:
        query = exec_query(['Get-WmiObject', 'Win32_NetworkAdapter'],
                           ['Name', 'InterfaceIndex', 'InterfaceDescription',
                            'GUID', 'MacAddress', 'NetConnectionID'])
    return [
        iface for iface in
        (dict(zip(['name', 'win_index', 'description', 'guid', 'mac', 'netid'], line))
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
        self.raw80211 = None
        if data is not None:
            self.update(data)

    def update(self, data):
        """Update info about network interface according to given dnet dictionary"""
        if 'netid' in data and data['netid'] == scapy.consts.LOOPBACK_NAME:
            # Force LOOPBACK_NAME: Some Windows systems overwrite 'name'
            self.name = scapy.consts.LOOPBACK_NAME
        else:
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
            if not self.ip and self.name == scapy.consts.LOOPBACK_NAME:
                self.ip = "127.0.0.1"
            if not self.ip:
                # No IP detected
                self.invalid = True
        except (KeyError, AttributeError, NameError) as e:
            print(e)

        try:
            if self.name == scapy.consts.LOOPBACK_NAME and conf.use_npcap:
                # https://nmap.org/npcap/guide/npcap-devguide.html
                self.mac = "00:00:00:00:00:00"
            else:
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

    def _check_npcap_requirement(self):
        if not conf.use_npcap:
            raise OSError("This operation requires Npcap.")
        if self.raw80211 is None:
            dot11adapters = next(iter(_vbs_exec_code("""WScript.Echo CreateObject("WScript.Shell").RegRead("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\npcap\\Parameters\\Dot11Adapters")""")))
            self.raw80211 = ("\\Device\\" + self.guid).lower() in dot11adapters.lower()
        if not self.raw80211:
            raise Scapy_Exception("This interface does not support raw 802.11")

    def mode(self):
        """Get the interface operation mode.
        Only available with Npcap."""
        self._check_npcap_requirement()
        return sp.Popen([_WlanHelper, self.guid[1:-1], "mode"], stdout=sp.PIPE).communicate()[0].strip()

    def availablemodes(self):
        """Get all available interface modes.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.Popen([_WlanHelper, self.guid[1:-1], "modes"], stdout=sp.PIPE).communicate()[0].strip().split(",")

    def setmode(self, mode):
        """Set the interface mode. It can be:
        - 0 or managed: Managed Mode (aka "Extensible Station Mode")
        - 1 or monitor: Monitor Mode (aka "Network Monitor Mode")
        - 2 or master: Master Mode (aka "Extensible Access Point") (supported from Windows 7 and later)
        - 3 or wfd_device: The Wi-Fi Direct Device operation mode (supported from Windows 8 and later)
        - 4 or wfd_owner: The Wi-Fi Direct Group Owner operation mode (supported from Windows 8 and later)
        - 5 or wfd_client: The Wi-Fi Direct Client operation mode (supported from Windows 8 and later)
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        _modes = {
            0: "managed",
            1: "monitor",
            2: "master",
            3: "wfd_device",
            4: "wfd_owner",
            5: "wfd_client"
        }
        m = _modes.get(mode, "unknown") if isinstance(mode, int) else mode
        return sp.call(_WlanHelper + " " + self.guid[1:-1] + " mode " + m)

    def channel(self):
        """Get the channel of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.Popen([_WlanHelper, self.guid[1:-1], "channel"], stdout=sp.PIPE).communicate()[0].strip().strip()

    def setchannel(self, channel):
        """Set the channel of the interface (1-14):
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.call(_WlanHelper + " " + self.guid[1:-1] + " channel " + str(channel))

    def frequence(self):
        """Get the frequence of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.Popen([_WlanHelper, self.guid[1:-1], "freq"], stdout=sp.PIPE).communicate()[0].strip()

    def setfrequence(self, freq):
        """Set the channel of the interface (1-14):
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.call(_WlanHelper + " " + self.guid[1:-1] + " freq " + str(freq))

    def availablemodulations(self):
        """Get all available 802.11 interface modulations.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.Popen([_WlanHelper, self.guid[1:-1], "modus"], stdout=sp.PIPE).communicate()[0].strip().split(",")

    def modulation(self):
        """Get the 802.11 modulation of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        return sp.Popen([_WlanHelper, self.guid[1:-1], "modu"], stdout=sp.PIPE).communicate()[0].strip()

    def setmodulation(self, modu):
        """Set the interface modulation. It can be:
           - 0: dsss
           - 1: fhss
           - 2: irbaseband
           - 3: ofdm
           - 4: hrdss
           - 5: erp
           - 6: ht
           - 7: vht
           - 8: ihv
           - 9: mimo-ofdm
           - 10: mimo-ofdm
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11
        self._check_npcap_requirement()
        _modus = {
            0: "dsss",
            1: "fhss",
            2: "irbaseband",
            3: "ofdm",
            4: "hrdss",
            5: "erp",
            6: "ht",
            7: "vht",
            8: "ihv",
            9: "mimo-ofdm",
            10: "mimo-ofdm",
        }
        m = _modus.get(modu, "unknown") if isinstance(modu, int) else modu
        return sp.call(_WlanHelper + " " + self.guid[1:-1] + " mode " + m)

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self.name, self.guid)

def pcap_service_name():
    """Return the pcap adapter service's name"""
    return "npcap" if conf.use_npcap else "npf"

def pcap_service_status():
    """Returns a tuple (name, description, started) of the windows pcap adapter"""
    for i in exec_query(['Get-Service', pcap_service_name()], ['Name', 'DisplayName', 'Status']):
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
    
from scapy.modules.six.moves import UserDict

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
        
        if not self.data and conf.use_winpcapy:
            _detect = pcap_service_status()
            def _ask_user():
                if not conf.interactive:
                    return False
                while True:
                    _confir = input("Do you want to start it ? (yes/no) [y]: ").lower().strip()
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
                    "Check your winpcap and powershell installation, and access rights.", onlyOnce=True)
        else:
            # Loading state: remove invalid interfaces
            self.remove_invalid_ifaces()
            # Replace LOOPBACK_INTERFACE
            try:
                scapy.consts.LOOPBACK_INTERFACE = self.dev_from_name(
                    scapy.consts.LOOPBACK_NAME,
                )
            except:
                pass

    def dev_from_name(self, name):
        """Return the first pcap device name for a given Windows
        device name.
        """
        for iface in six.itervalues(self):
            if iface.name == name:
                return iface
        raise ValueError("Unknown network interface %r" % name)

    def dev_from_pcapname(self, pcap_name):
        """Return Windows device name for given pcap device name."""
        for iface in six.itervalues(self):
            if iface.pcap_name == pcap_name:
                return iface
        raise ValueError("Unknown pypcap network interface %r" % pcap_name)

    def dev_from_index(self, if_index):
        """Return interface name from interface index"""
        for devname, iface in six.iteritems(self):
            if iface.win_index == str(if_index):
                return iface
        if str(if_index) == "1":
            # Test if the loopback interface is set up
            if isinstance(scapy.consts.LOOPBACK_INTERFACE, NetworkInterface):
                return scapy.consts.LOOPBACK_INTERFACE
        raise ValueError("Unknown network interface index %r" % if_index)

    def remove_invalid_ifaces(self):
        """Remove all invalid interfaces"""
        for devname in list(self.keys()):
            iface = self.data[devname]
            if iface.is_invalid():
                self.data.pop(devname)

    def reload(self):
        """Reload interface list"""
        self.data.clear()
        self.load_from_powershell()

    def show(self, resolve_mac=True, print_result=True):
        """Print list of available network interfaces in human readable form"""
        res = []
        res.append("%s  %s  %s  %s" % ("INDEX".ljust(5), "IFACE".ljust(35), "IP".ljust(15), "MAC"))
        for iface_name in sorted(self.data):
            dev = self.data[iface_name]
            mac = dev.mac
            if resolve_mac and conf.manufdb:
                mac = conf.manufdb._resolve_MAC(mac)
            res.append("%s  %s  %s  %s" % (str(dev.win_index).ljust(5), str(dev.name).ljust(35), str(dev.ip).ljust(15), mac))
        res = "\n".join(res)
        if print_result:
            print(res)
        else:
            return res

    def __repr__(self):
        return self.show(print_result=False)
            
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
    local_addresses = {iface.ip: iface for iface in six.itervalues(IFACES)}
    iface_indexes = {}
    for line in exec_query(['Get-WmiObject', 'Win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex', 'Metric1']):
        if line[2] in local_addresses:
            iface = local_addresses[line[2]]
            # This gives us an association InterfaceIndex <-> interface
            iface_indexes[line[3]] = iface
            routes.append((atol(line[0]), atol(line[1]), "0.0.0.0", iface,
                           iface.ip, int(line[4])))
        else:
            partial_routes.append((atol(line[0]), atol(line[1]), line[2],
                                   line[3], int(line[4])))
    for dst, mask, gw, ifidx, metric in partial_routes:
        if ifidx in iface_indexes:
            iface = iface_indexes[ifidx]
            routes.append((dst, mask, gw, iface, iface.ip, metric))
    return routes

def _read_routes_7():
    routes=[]
    for line in exec_query(['Get-WmiObject', 'Win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex', 'Metric1']):
        try:
            iface = dev_from_index(line[3])
            ip = "127.0.0.1" if line[3] == "1" else iface.ip # Force loopback on iface 1
            routes.append((atol(line[0]), atol(line[1]), line[2], iface, ip, int(line[4])))
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
        warning("Error building scapy IPv4 routing table : %s", e, onlyOnce=True)
    else:
        if not routes:
            warning("No default IPv4 routes found. Your Windows release may no be supported and you have to enter your routes manually", onlyOnce=True)
    return routes

def _read_routes_post2008():
    routes = []
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
    # Get-NetRoute -AddressFamily IPV4 | select ifIndex, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric | fl
    for line in exec_query(['Get-NetRoute', '-AddressFamily IPV4'], ['ifIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric', 'InterfaceMetric']):
        try:
            iface = dev_from_index(line[0])
            if iface.ip == "0.0.0.0":
                continue
        except:
            continue
        # try:
        #     intf = pcapdnet.dnet.intf().get_dst(pcapdnet.dnet.addr(type=2, addrtxt=dest))
        # except OSError:
        #     log_loading.warning("Building Scapy's routing table: Couldn't get outgoing interface for destination %s", dest)
        #     continue
        dest, mask = line[1].split('/')
        routes.append((atol(dest), itom(int(mask)),
                       line[2], iface, iface.ip, int(line[3])+int(line[4])))
    return routes

############
### IPv6 ###
############

def in6_getifaddr():
    """
    Returns all IPv6 addresses found on the computer
    """
    ifaddrs = []
    for ifaddr in in6_getifaddr_raw():
        try:
            ifaddrs.append((ifaddr[0], ifaddr[1], dev_from_pcapname(ifaddr[2])))
        except ValueError:
            pass
    return ifaddrs

def _append_route6(routes, dpref, dp, nh, iface, lifaddr, metric):
    cset = [] # candidate set (possible source addresses)
    if iface.name == scapy.consts.LOOPBACK_NAME:
        if dpref == '::':
            return
        cset = ['::1']
    else:
        devaddrs = (x for x in lifaddr if x[2] == iface)
        cset = scapy.utils6.construct_source_candidate_set(dpref, dp, devaddrs)
    if not cset:
        return
    # APPEND (DESTINATION, NETMASK, NEXT HOP, IFACE, CANDIDATS, METRIC)
    routes.append((dpref, dp, nh, iface, cset, metric))

def _read_routes6_post2008():
    routes6 = []
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
    # Get-NetRoute -AddressFamily IPV6 | select ifIndex, DestinationPrefix, NextHop | fl
    lifaddr = in6_getifaddr()
    for line in exec_query(['Get-NetRoute', '-AddressFamily IPV6'], ['ifIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric', 'InterfaceMetric']):
        try:
            if_index = line[0]
            iface = dev_from_index(if_index)
        except:
            continue

        dpref, dp = line[1].split('/')
        dp = int(dp)
        nh = line[2]
        metric = int(line[3])+int(line[4])

        _append_route6(routes6, dpref, dp, nh, iface, lifaddr, metric)
    return routes6

def _get_i6_metric(index):
    # Returns the INTERFACE metric from the interface index
    ps = sp.Popen([conf.prog.cmd, '/c', 'netsh interface ipv6 show interfaces level=verbose ' + index], stdout = sp.PIPE)
    stdout, stdin = ps.communicate()
    stdout = stdout.decode("utf8", "ignore")
    metric_line = stdout.split('\n')[6]
    metric = re.search(re.compile(".*:\s+(\d+)"), metric_line).group(1)
    return int(metric)

def _read_routes6_7():
    # Not supported in powershell, we have to use netsh
    routes = []
    ps = sp.Popen([conf.prog.cmd, '/c', 'netsh interface ipv6 show route level=verbose'], stdout = sp.PIPE)
    stdout, stdin = ps.communicate()
    stdout = stdout.decode("utf8", "ignore")
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
            if not current_object:
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
                metric = int(current_object[6]) + _get_i6_metric(if_index)
                _append_route6(routes, dpref, dp, nh, iface, lifaddr, metric)

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
        warning("Error building scapy IPv6 routing table : %s", e, onlyOnce=True)
    return routes6

def get_working_if():
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        return min(read_routes(), key=lambda x: x[1])[3]
    except ValueError:
        # no route
        return scapy.consts.LOOPBACK_INTERFACE

def _get_valid_guid():
    if scapy.consts.LOOPBACK_INTERFACE:
        return scapy.consts.LOOPBACK_INTERFACE.guid
    else:
        for i in six.itervalues(IFACES):
            if not i.is_invalid():
                return i.guid

def route_add_loopback(routes=None, ipv6=False, iflist=None):
    """Add a route to 127.0.0.1 and ::1 to simplify unit tests on Windows"""
    if not WINDOWS:
        warning("Not available")
        return
    warning("This will completly mess up the routes. Testing purpose only !")
    # Add only if some adpaters already exist
    if ipv6:
        if not conf.route6.routes:
            return
    else:
        if not conf.route.routes:
            return
    data = {
        'name': scapy.consts.LOOPBACK_NAME,
        'description': "Loopback",
        'win_index': -1,
        'guid': _get_valid_guid(),
        'invalid': False,
        'mac': '00:00:00:00:00:00',
    }
    data['pcap_name'] = six.text_type("\\Device\\NPF_" + data['guid'])
    adapter = NetworkInterface(data)
    if iflist:
        iflist.append(adapter.pcap_name)
        return
    # Remove all LOOPBACK_NAME routes
    for route in list(conf.route.routes):
        iface = route[3]
        if iface.name == scapy.consts.LOOPBACK_NAME:
            conf.route.routes.remove(route)
    # Remove LOOPBACK_NAME interface
    for devname, iface in list(IFACES.items()):
        if iface.name == scapy.consts.LOOPBACK_NAME:
            IFACES.pop(devname)
    # Inject interface
    IFACES[data['guid']] = adapter
    scapy.consts.LOOPBACK_INTERFACE = adapter
    if isinstance(conf.iface, NetworkInterface):
        if conf.iface.name == LOOPBACK_NAME:
            conf.iface = adapter
    if isinstance(conf.iface6, NetworkInterface):
        if conf.iface6.name == LOOPBACK_NAME:
            conf.iface6 = adapter
    # Build the packed network addresses
    loop_net = struct.unpack("!I", socket.inet_aton("127.0.0.0"))[0]
    loop_mask = struct.unpack("!I", socket.inet_aton("255.0.0.0"))[0]
    # Build the fake routes
    loopback_route = (loop_net, loop_mask, "0.0.0.0", adapter, "127.0.0.1", 1)
    loopback_route6 = ('::1', 128, '::', adapter, ["::1"], 1)
    loopback_route6_custom = ("fe80::", 128, "::", adapter, ["::1"], 1)
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


if not conf.use_winpcapy:

    class NotAvailableSocket(SuperSocket):
        desc = "wpcap.dll missing"
        def __init__(self, *args, **kargs):
            raise RuntimeError("Sniffing and sending packets is not available: "
                               "winpcap is not installed")

    conf.L2socket = NotAvailableSocket
    conf.L2listen = NotAvailableSocket
    conf.L3socket = NotAvailableSocket
