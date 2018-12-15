# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Customizations needed to support Microsoft Windows.
"""

from __future__ import absolute_import
from __future__ import print_function
import os
import re
import sys
import socket
import platform
import subprocess as sp
from glob import glob
import ctypes
from ctypes import wintypes
import tempfile
from threading import Thread, Event
import struct

import scapy
import scapy.consts
from scapy.config import conf, ConfClass
from scapy.error import Scapy_Exception, log_loading, log_runtime, warning
from scapy.utils import atol, itom, pretty_list, mac2str
from scapy.utils6 import construct_source_candidate_set
from scapy.data import ARPHDR_ETHER, load_manuf
import scapy.modules.six as six
from scapy.modules.six.moves import input, winreg, UserDict
from scapy.compat import raw
from scapy.supersocket import SuperSocket

_winapi_SetConsoleTitle = ctypes.windll.kernel32.SetConsoleTitleW
_winapi_SetConsoleTitle.restype = wintypes.BOOL
_winapi_SetConsoleTitle.argtypes = [wintypes.LPWSTR]

_winapi_GetHandleInformation = ctypes.windll.kernel32.GetHandleInformation
_winapi_GetHandleInformation.restype = wintypes.BOOL
_winapi_GetHandleInformation.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]  # noqa: E501

_winapi_SetHandleInformation = ctypes.windll.kernel32.SetHandleInformation
_winapi_SetHandleInformation.restype = wintypes.BOOL
_winapi_SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]  # noqa: E501

conf.use_winpcapy = True
conf.use_pcap = False
conf.use_dnet = False

# These import must appear after setting conf.use_* variables
from scapy.arch import pcapdnet  # noqa: E402
from scapy.arch.pcapdnet import NPCAP_PATH, get_if_raw_addr, \
    get_if_list, in6_getifaddr_raw  # noqa: E402

WINDOWS = (os.name == 'nt')

# hot-patching socket for missing variables on Windows
if not hasattr(socket, 'IPPROTO_IPIP'):
    socket.IPPROTO_IPIP = 4
if not hasattr(socket, 'IPPROTO_AH'):
    socket.IPPROTO_AH = 51
if not hasattr(socket, 'IPPROTO_ESP'):
    socket.IPPROTO_ESP = 50
if not hasattr(socket, 'IPPROTO_GRE'):
    socket.IPPROTO_GRE = 47

_WlanHelper = NPCAP_PATH + "\\WlanHelper.exe"

IS_WINDOWS_XP = platform.release() == "XP"


def is_new_release():
    release = platform.release()
    if conf.prog.powershell is None:
        return False
    try:
        if float(release) >= 8:
            return True
    except ValueError:
        if (release == "post2008Server"):
            return True
    return False


def _encapsulate_admin(cmd):
    """Encapsulate a command with an Administrator flag"""
    # To get admin access, we start a new powershell instance with admin
    # rights, which will execute the command
    return "Start-Process PowerShell -windowstyle hidden -Wait -PassThru -Verb RunAs -ArgumentList '-command &{%s}'" % cmd  # noqa: E501


def _windows_title(title=None):
    """Updates the terminal title with the default one or with `title`
    if provided."""
    if conf.interactive:
        _winapi_SetConsoleTitle(title or "Scapy v{}".format(conf.version))


def _suppress_file_handles_inheritance(r=1000):
    """HACK: python 2.7 file descriptors.

    This magic hack fixes https://bugs.python.org/issue19575
    and https://github.com/secdev/scapy/issues/1136
    by suppressing the HANDLE_FLAG_INHERIT flag to a range of
    already opened file descriptors.
    Bug was fixed on python 3.4+
    """
    if sys.version_info[0:2] >= (3, 4):
        return []

    import stat
    from msvcrt import get_osfhandle

    HANDLE_FLAG_INHERIT = 0x00000001

    handles = []
    for fd in range(r):
        try:
            s = os.fstat(fd)
        except OSError:
            continue
        if stat.S_ISREG(s.st_mode):
            osf_handle = get_osfhandle(fd)
            flags = wintypes.DWORD()
            _winapi_GetHandleInformation(osf_handle, flags)
            if flags.value & HANDLE_FLAG_INHERIT:
                _winapi_SetHandleInformation(osf_handle, HANDLE_FLAG_INHERIT, 0)  # noqa: E501
                handles.append(osf_handle)

    return handles


def _restore_file_handles_inheritance(handles):
    """HACK: python 2.7 file descriptors.

    This magic hack fixes https://bugs.python.org/issue19575
    and https://github.com/secdev/scapy/issues/1136
    by suppressing the HANDLE_FLAG_INHERIT flag to a range of
    already opened file descriptors.
    Bug was fixed on python 3.4+
    """
    if sys.version_info[0:2] >= (3, 4):
        return

    HANDLE_FLAG_INHERIT = 0x00000001

    for osf_handle in handles:
        try:
            _winapi_SetHandleInformation(osf_handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)  # noqa: E501
        except (ctypes.WinError, WindowsError, OSError):
            pass


class _PowershellManager(Thread):
    """Instance used to send multiple commands on the same Powershell process.
    Will be instantiated on loading and automatically stopped.
    """

    def __init__(self):
        opened_handles = _suppress_file_handles_inheritance()
        try:
            # Start & redirect input
            if conf.prog.powershell:
                cmd = [conf.prog.powershell,
                       "-NoLogo", "-NonInteractive",  # Do not print headers
                       "-Command", "-"]  # Listen commands from stdin
            else:  # Fallback on CMD (powershell-only commands will fail, but scapy use the VBS fallback)  # noqa: E501
                cmd = [conf.prog.cmd]
            # Let's hide the window with startup infos
            startupinfo = sp.STARTUPINFO()
            startupinfo.dwFlags |= sp.STARTF_USESHOWWINDOW
            self.process = sp.Popen(cmd, stdout=sp.PIPE, stdin=sp.PIPE, stderr=sp.STDOUT, startupinfo=startupinfo)  # noqa: E501
            self.cmd = not conf.prog.powershell
        finally:
            _restore_file_handles_inheritance(opened_handles)
        self.buffer = []
        self.running = True
        self.query_complete = Event()
        Thread.__init__(self)
        self.daemon = True
        self.start()
        if self.cmd:
            self.query(["echo @off"])  # Remove header
        else:
            self.query(["$FormatEnumerationLimit=-1"])  # Do not crop long IP lists  # noqa: E501
        _windows_title()  # Reset terminal title

    def run(self):
        while self.running:
            read_line = self.process.stdout.readline().strip()
            if read_line == b"scapy_end":
                self.query_complete.set()
            else:
                self.buffer.append(read_line.decode("utf8", "ignore") if six.PY3 else read_line)  # noqa: E501

    def query(self, command, crp=True, rst_t=False):
        self.query_complete.clear()
        if not self.running:
            self.__init__(self)
        # Call powershell query using running process
        self.buffer = []
        # 'scapy_end' is used as a marker of the end of execution
        query = " ".join(command) + ("&" if self.cmd else ";") + " echo scapy_end\n"  # noqa: E501
        self.process.stdin.write(query.encode())
        self.process.stdin.flush()
        self.query_complete.wait()
        if rst_t:
            _windows_title()
        return self.buffer[crp:]  # Crops first line: the command

    def close(self):
        self.running = False
        try:
            self.process.stdin.write(b"exit\n")
        except (ValueError, IOError):
            pass
        finally:
            self.process.terminate()


def _exec_query_ps(cmd, fields):
    """Execute a PowerShell query, using the cmd command,
    and select and parse the provided fields.
    """
    if not conf.prog.powershell:
        raise OSError("Scapy could not detect powershell !")
    # Build query
    query_cmd = cmd + ['|', 'select %s' % ', '.join(fields),  # select fields
                       '|', 'fl',  # print as a list
                       '|', 'out-string', '-Width', '4096']  # do not crop
    lines = []
    # Ask the powershell manager to process the query
    stdout = POWERSHELL_PROCESS.query(query_cmd)
    # Process stdout
    for line in stdout:
        if not line.strip():  # skip empty lines
            continue
        sl = line.split(':', 1)
        if sl[0].strip() not in fields:
            # The previous line was cropped. Let's add the missing part
            lines[-1] += line.strip()
            continue
        else:
            # We put it here to ensure we never return too early,
            # missing some cropped lines
            if len(lines) == len(fields):
                yield lines
                lines = []
            lines.append(sl[1].strip())
    yield lines  # Last buffer won't be returned in the if


def _vbs_exec_code(code, split_tag="@"):
    if not conf.prog.cscript:
        raise OSError("Scapy could not detect cscript !")
    tmpfile = tempfile.NamedTemporaryFile(mode="wb", suffix=".vbs", delete=False)  # noqa: E501
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
    _windows_title()


def _get_hardware_iface_guid(devid):
    """
    Get the hardware interface guid for device with 'devid' number
    or None if such interface does not exist.
    """
    devid = int(devid) + 1

    hkey = winreg.HKEY_LOCAL_MACHINE
    node = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards\{}".format(devid)  # noqa: E501
    try:
        key = winreg.OpenKey(hkey, node)
        guid, _ = winreg.QueryValueEx(key, "ServiceName")
        winreg.CloseKey(key)
    except WindowsError:
        return None
    guid = guid.strip()
    return guid if guid.startswith("{") and guid.endswith("}") else None


def _get_npcap_dot11_adapters():
    """
    Get the npcap 802.11 adapters from the registry or None if npcap
    is not 802.11 enabled.
    """
    hkey = winreg.HKEY_LOCAL_MACHINE
    node = r"SYSTEM\CurrentControlSet\Services\npcap\Parameters"
    try:
        key = winreg.OpenKey(hkey, node)
        dot11_adapters, _ = winreg.QueryValueEx(key, "Dot11Adapters")
        winreg.CloseKey(key)
    except WindowsError:
        return None
    return dot11_adapters


# Some names differ between VBS and PS
# None: field will not be returned under VBS
_VBS_WMI_FIELDS = {
    "Win32_NetworkAdapter": {
        "InterfaceDescription": "Description",
        # Note: when using VBS, the GUID is not the same than with Powershell
        # So we use get the device ID instead, then use _get_hardware_iface_guid  # noqa: E501
        # To get its real GUID
        "GUID": "DeviceID"
    },
    "*": {
        "Status": "State"
    }
}
if IS_WINDOWS_XP:
    # On windows XP, InterfaceIndex does not exist in cscript, and is Index.
    # This is not the case on Windows 7+
    _VBS_WMI_FIELDS["Win32_NetworkAdapter"]["InterfaceIndex"] = "Index"

_VBS_WMI_REPLACE = {
    "Win32_NetworkAdapterConfiguration": {
        "line.IPAddress": "\"{\" & Join( line.IPAddress, \", \" ) & \"}\"",
    }
}

_VBS_WMI_OUTPUT = {
    "Win32_NetworkAdapter": {
        "DeviceID": _get_hardware_iface_guid,
    }
}


def _exec_query_vbs(cmd, fields):
    """Execute a query using VBS. Currently Get-WmiObject, Get-Service
    queries are supported.

    """
    if not(len(cmd) == 2 and cmd[0] in ["Get-WmiObject", "Get-Service"]):
        return
    action = cmd[0]
    fields = [_VBS_WMI_FIELDS.get(cmd[1], _VBS_WMI_FIELDS.get("*", {})).get(fld, fld) for fld in fields]  # noqa: E501
    if IS_WINDOWS_XP:
        # On Windows XP, the Ampersand operator does not exist.
        # Using old method (which does not support missing parameters (e.g. WLAN interfaces))  # noqa: E501
        parsed_command = "\n  ".join("WScript.Echo line.%s" % fld for fld in fields if fld is not None)  # noqa: E501
    else:
        parsed_command = "WScript.Echo " + " & \" @ \" & ".join("line.%s" % fld for fld in fields if fld is not None)  # noqa: E501
    # The IPAddress is an array: convert it to a string
    for key, val in _VBS_WMI_REPLACE.get(cmd[1], {}).items():
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
        try:
            yield [None if fld is None else
                   _VBS_WMI_OUTPUT.get(cmd[1], {}).get(fld, lambda x: x)(
                       next(values).strip()
                   )
                   for fld in fields]
        except (StopIteration, RuntimeError):
            return


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
    try:
        return next(os.path.normpath(match)
                    for path in paths
                    for match in glob(os.path.join(path, filename))
                    if match)
    except (StopIteration, RuntimeError):
        raise IOError("File not found: %s" % filename)


def win_find_exe(filename, installsubdir=None, env="ProgramFiles"):
    """Find executable in current dir, system path or given ProgramFiles subdir"""  # noqa: E501
    fns = [filename] if filename.endswith(".exe") else [filename + ".exe", filename]  # noqa: E501
    for fn in fns:
        try:
            if installsubdir is None:
                path = _where(fn)
            else:
                path = _where(fn, dirs=[os.path.join(os.environ[env], installsubdir)])  # noqa: E501
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
        self.pdfreader = None
        self.psreader = None
        self.svgreader = None
        # We try some magic to find the appropriate executables
        self.dot = win_find_exe("dot")
        self.tcpdump = win_find_exe("windump")
        self.tshark = win_find_exe("tshark")
        self.tcpreplay = win_find_exe("tcpreplay")
        self.display = self._default
        self.hexedit = win_find_exe("hexer")
        self.sox = win_find_exe("sox")
        self.wireshark = win_find_exe("wireshark", "wireshark")
        self.usbpcapcmd = win_find_exe(
            "USBPcapCMD",
            installsubdir="USBPcap",
            env="programfiles"
        )
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
            try:
                manu_path = load_manuf(os.path.sep.join(self.wireshark.split(os.path.sep)[:-1]) + os.path.sep + "manuf")  # noqa: E501
            except (IOError, OSError):  # FileNotFoundError not available on Py2 - using OSError  # noqa: E501
                log_loading.warning("Wireshark is installed, but cannot read manuf !")  # noqa: E501
                manu_path = None
            scapy.data.MANUFDB = conf.manufdb = manu_path

        self.os_access = (self.powershell is not None) or (self.cscript is not None)  # noqa: E501


conf.prog = WinProgPath()
if not conf.prog.os_access:
    warning("Scapy did not detect powershell and cscript ! Routes, interfaces and much more won't work !")  # noqa: E501

if conf.prog.tcpdump and conf.use_npcap and conf.prog.os_access:
    def test_windump_npcap():
        """Return whether windump version is correct or not"""
        try:
            p_test_windump = sp.Popen([conf.prog.tcpdump, "-help"], stdout=sp.PIPE, stderr=sp.STDOUT)  # noqa: E501
            stdout, err = p_test_windump.communicate()
            _windows_title()
            _output = stdout.lower()
            return b"npcap" in _output and b"winpcap" not in _output
        except Exception:
            return False
    windump_ok = test_windump_npcap()
    if not windump_ok:
        warning("The installed Windump version does not work with Npcap ! Refer to 'Winpcap/Npcap conflicts' in scapy's doc")  # noqa: E501
    del windump_ok


class PcapNameNotFoundError(Scapy_Exception):
    pass


def _validate_interface(iface):
    if "guid" in iface and iface["guid"]:
        # Fix '-' instead of ':'
        if "mac" in iface:
            iface["mac"] = iface["mac"].replace("-", ":")
        # Potentially, the default Microsoft KM-TEST would have been translated
        if "name" in iface:
            if "KM-TEST" in iface["name"] and iface["name"] != scapy.consts.LOOPBACK_NAME:  # noqa: E501
                scapy.consts.LOOPBACK_NAME = iface["name"]
        return True
    return False


def get_windows_if_list():
    """Returns windows interfaces."""
    if not conf.prog.os_access:
        return []
    if is_new_release():
        # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed  # noqa: E501
        # Careful: this is weird, but Get-NetAdaptater works like: (Name isn't the interface name)  # noqa: E501
        # Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed  # noqa: E501
        # ----                      --------------------                    ------- ------       ----------             ---------  # noqa: E501
        # Ethernet                  Killer E2200 Gigabit Ethernet Control...      13 Up           D0-50-99-56-DD-F9         1 Gbps  # noqa: E501
        # It is normal that it is in this order
        query = exec_query(['Get-NetAdapter -IncludeHidden'],
                           ['InterfaceDescription', 'InterfaceIndex', 'Name',
                            'InterfaceGuid', 'MacAddress', 'InterfaceAlias'])
    else:
        query = exec_query(['Get-WmiObject', 'Win32_NetworkAdapter'],
                           ['Name', 'InterfaceIndex', 'InterfaceDescription',
                            'GUID', 'MacAddress', 'NetConnectionID'])
    return [
        iface for iface in
        (dict(
            zip(['name', 'win_index', 'description', 'guid', 'mac', 'netid'],
                line))
         for line in query)
        if _validate_interface(iface)
    ]


def get_ips(v6=False):
    """Returns all available IPs matching to interfaces, using the windows system.
    Should only be used as a WinPcapy fallback."""
    res = {}
    for descr, ipaddr in exec_query(['Get-WmiObject',
                                     'Win32_NetworkAdapterConfiguration'],
                                    ['Description', 'IPAddress']):
        if ipaddr.strip():
            # This requires lots of stripping
            ip_string = ipaddr.split(",", 1)[v6].strip('{}').strip()
            res[descr] = [ip.strip() for ip in ip_string.split(",")]
    return res


def get_ip_from_name(ifname, v6=False):
    """Backward compatibility: indirectly calls get_ips
    Deprecated."""
    return get_ips(v6=v6).get(ifname, [""])[0]


class NetworkInterface(object):
    """A network interface of your local host"""

    def __init__(self, data=None):
        self.name = None
        self.ip = None
        self.mac = None
        self.pcap_name = None
        self.description = None
        self.invalid = False
        self.raw80211 = None
        self.cache_mode = None
        if data is not None:
            self.update(data)

    def update(self, data):
        """Update info about network interface according to given dnet dictionary"""  # noqa: E501
        self.data = data
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
            # Npcap loopback interface
            if self.name == scapy.consts.LOOPBACK_NAME and conf.use_npcap:
                # https://nmap.org/npcap/guide/npcap-devguide.html
                self.mac = "00:00:00:00:00:00"
                self.ip = "127.0.0.1"
                conf.cache_ipaddrs[self.pcap_name] = socket.inet_aton(self.ip)
                return
            else:
                self.mac = data['mac']
        except KeyError:
            pass

        try:
            self.ip = socket.inet_ntoa(get_if_raw_addr(self))
        except (TypeError, NameError):
            pass

        try:
            # Windows native loopback interface
            if not self.ip and self.name == scapy.consts.LOOPBACK_NAME:
                self.ip = "127.0.0.1"
                conf.cache_ipaddrs[self.pcap_name] = socket.inet_aton(self.ip)
        except (KeyError, AttributeError, NameError) as e:
            print(e)

    def _update_pcapdata(self):
        if self.is_invalid():
            return
        for i in get_if_list():
            if i.endswith(self.guid):
                self.pcap_name = i
                return

        raise PcapNameNotFoundError

    def is_invalid(self):
        return self.invalid

    def _check_npcap_requirement(self):
        if not conf.use_npcap:
            raise OSError("This operation requires Npcap.")
        if self.raw80211 is None:
            # This checks if npcap has Dot11 enabled and if the interface is compatible,  # noqa: E501
            # by looking for the npcap/Parameters/Dot11Adapters key in the registry.  # noqa: E501
            dot11adapters = _get_npcap_dot11_adapters()
            self.raw80211 = (dot11adapters is not None and
                             (("\\Device\\" + self.guid).lower() in dot11adapters.lower()))  # noqa: E501
        if not self.raw80211:
            raise Scapy_Exception("This interface does not support raw 802.11")

    def mode(self):
        """Get the interface operation mode.
        Only available with Npcap."""
        self._check_npcap_requirement()
        return POWERSHELL_PROCESS.query([_WlanHelper, self.guid[1:-1], "mode"], crp=False, rst_t=True)[0].strip()  # noqa: E501

    def ismonitor(self):
        """Returns True if the interface is in monitor mode.
        Only available with Npcap."""
        if self.cache_mode is not None:
            return self.cache_mode
        try:
            res = (self.mode() == "monitor")
            self.cache_mode = res
            return res
        except Scapy_Exception:
            return False

    def setmonitor(self, enable=True):
        """Alias for setmode('monitor') or setmode('managed')
        Only available with Npcap"""
        # We must reset the monitor cache
        if enable:
            res = self.setmode('monitor')
            self.cache_mode = res
        else:
            res = self.setmode('managed')
            self.cache_mode = not res
        if not res:
            log_runtime.error("Npcap WlanHelper returned with an error code !")
        return res

    def availablemodes(self):
        """Get all available interface modes.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return POWERSHELL_PROCESS.query([_WlanHelper, self.guid[1:-1], "modes"], crp=False, rst_t=True)[0].split(",")  # noqa: E501

    def setmode(self, mode):
        """Set the interface mode. It can be:
        - 0 or managed: Managed Mode (aka "Extensible Station Mode")
        - 1 or monitor: Monitor Mode (aka "Network Monitor Mode")
        - 2 or master: Master Mode (aka "Extensible Access Point") (supported from Windows 7 and later)  # noqa: E501
        - 3 or wfd_device: The Wi-Fi Direct Device operation mode (supported from Windows 8 and later)  # noqa: E501
        - 4 or wfd_owner: The Wi-Fi Direct Group Owner operation mode (supported from Windows 8 and later)  # noqa: E501
        - 5 or wfd_client: The Wi-Fi Direct Client operation mode (supported from Windows 8 and later)  # noqa: E501
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
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
        return not POWERSHELL_PROCESS.query([_encapsulate_admin(_WlanHelper + " " + self.guid[1:-1] + " mode " + m)], rst_t=True)  # noqa: E501

    def channel(self):
        """Get the channel of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        x = POWERSHELL_PROCESS.query([_WlanHelper, self.guid[1:-1], "channel"],
                                     crp=False)[0].strip()
        return int(x)

    def setchannel(self, channel):
        """Set the channel of the interface (1-14):
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return not POWERSHELL_PROCESS.query([_encapsulate_admin(_WlanHelper + " " + self.guid[1:-1] + " channel " + str(channel))],  # noqa: E501
                                            rst_t=True)

    def frequence(self):
        """Get the frequence of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        x = POWERSHELL_PROCESS.query([_WlanHelper, self.guid[1:-1], "freq"], crp=False, rst_t=True)[0].strip()  # noqa: E501
        return int(x)

    def setfrequence(self, freq):
        """Set the channel of the interface (1-14):
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return not POWERSHELL_PROCESS.query([_encapsulate_admin(_WlanHelper + " " + self.guid[1:-1] + " freq " + str(freq))],  # noqa: E501
                                            rst_t=True)

    def availablemodulations(self):
        """Get all available 802.11 interface modulations.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return POWERSHELL_PROCESS.query([_WlanHelper, self.guid[1:-1], "modus"], crp=False, rst_t=True)[0].strip().split(",")  # noqa: E501

    def modulation(self):
        """Get the 802.11 modulation of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return POWERSHELL_PROCESS.query([_WlanHelper, self.guid[1:-1], "modu"], crp=False, rst_t=True)[0].strip()  # noqa: E501

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
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
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
        return not POWERSHELL_PROCESS.query([_encapsulate_admin(_WlanHelper + " " + self.guid[1:-1] + " mode " + m)],  # noqa: E501
                                            rst_t=True)

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self.name, self.guid)


def pcap_service_name():
    """Return the pcap adapter service's name"""
    return "npcap" if conf.use_npcap else "npf"


def pcap_service_status():
    """Returns a tuple (name, description, started) of the windows pcap adapter"""  # noqa: E501
    for i in exec_query(['Get-Service', pcap_service_name()], ['Name', 'DisplayName', 'Status']):  # noqa: E501
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
    stdout = POWERSHELL_PROCESS.query([_encapsulate_admin(command) if askadmin else command])  # noqa: E501
    return "error" not in "".join(stdout).lower()


def pcap_service_start(askadmin=True):
    """Starts the pcap adapter. Will ask for admin. Returns True if success"""
    return pcap_service_control('Start-Service', askadmin=askadmin)


def pcap_service_stop(askadmin=True):
    """Stops the pcap adapter. Will ask for admin. Returns True if success"""
    return pcap_service_control('Stop-Service', askadmin=askadmin)


class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names"""

    def load_from_powershell(self):
        if not conf.prog.os_access:
            return
        ifaces_ips = None
        for i in get_windows_if_list():
            try:
                interface = NetworkInterface(i)
                self.data[interface.guid] = interface
                # If no IP address was detected using winpcap and if
                # the interface is not the loopback one, look for
                # internal windows interfaces
                if not interface.ip:
                    if not ifaces_ips:  # ifaces_ips is used as a cache
                        ifaces_ips = get_ips()
                    # If it exists, retrieve the interface's IP from the cache
                    interface.ip = ifaces_ips.get(interface.name, [""])[0]
            except (KeyError, PcapNameNotFoundError):
                pass

        if not self.data and conf.use_winpcapy:
            _detect = pcap_service_status()

            def _ask_user():
                if not conf.interactive:
                    return False
                while True:
                    _confir = input("Do you want to start it ? (yes/no) [y]: ").lower().strip()  # noqa: E501
                    if _confir in ["yes", "y", ""]:
                        return True
                    elif _confir in ["no", "n"]:
                        return False
                return False
            _error_msg = "No match between your pcap and windows network interfaces found. "  # noqa: E501
            if _detect[0] and not _detect[2] and not (hasattr(self, "restarted_adapter") and self.restarted_adapter):  # noqa: E501
                warning("Scapy has detected that your pcap service is not running !")  # noqa: E501
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
                    "Deactivating unneeded interfaces and restarting Scapy might help. "  # noqa: E501
                    "Check your winpcap and powershell installation, and access rights.")  # noqa: E501
        else:
            # Loading state: remove invalid interfaces
            self.remove_invalid_ifaces()
            # Replace LOOPBACK_INTERFACE
            try:
                scapy.consts.LOOPBACK_INTERFACE = self.dev_from_name(
                    scapy.consts.LOOPBACK_NAME,
                )
            except ValueError:
                pass

    def dev_from_name(self, name):
        """Return the first pcap device name for a given Windows
        device name.
        """
        try:
            return next(iface for iface in six.itervalues(self)
                        if iface.name == name)
        except (StopIteration, RuntimeError):
            raise ValueError("Unknown network interface %r" % name)

    def dev_from_pcapname(self, pcap_name):
        """Return Windows device name for given pcap device name."""
        try:
            return next(iface for iface in six.itervalues(self)
                        if iface.pcap_name == pcap_name)
        except (StopIteration, RuntimeError):
            raise ValueError("Unknown pypcap network interface %r" % pcap_name)

    def dev_from_index(self, if_index):
        """Return interface name from interface index"""
        try:
            return next(iface for iface in six.itervalues(self)
                        if iface.win_index == str(if_index))
        except (StopIteration, RuntimeError):
            if str(if_index) == "1":
                # Test if the loopback interface is set up
                if isinstance(scapy.consts.LOOPBACK_INTERFACE, NetworkInterface):  # noqa: E501
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
        self.restarted_adapter = False
        self.data.clear()
        self.load_from_powershell()

    def show(self, resolve_mac=True, print_result=True):
        """Print list of available network interfaces in human readable form"""
        res = []
        for iface_name in sorted(self.data):
            dev = self.data[iface_name]
            mac = dev.mac
            if resolve_mac and conf.manufdb:
                mac = conf.manufdb._resolve_MAC(mac)
            res.append((str(dev.win_index), str(dev.name), str(dev.ip), mac))

        res = pretty_list(res, [("INDEX", "IFACE", "IP", "MAC")])
        if print_result:
            print(res)
        else:
            return res

    def __repr__(self):
        return self.show(print_result=False)


# Init POWERSHELL_PROCESS
POWERSHELL_PROCESS = _PowershellManager()

IFACES = ifaces = NetworkInterfaceDict()
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


def open_pcap(iface, *args, **kargs):
    """open_pcap: Windows routine for creating a pcap from an interface.
    This function is also responsible for detecting monitor mode.
    """
    iface_pcap_name = pcapname(iface)
    if not isinstance(iface, NetworkInterface) and iface_pcap_name is not None:
        iface = IFACES.dev_from_name(iface)
    if conf.use_npcap and isinstance(iface, NetworkInterface):
        monitored = iface.ismonitor()
        kw_monitor = kargs.get("monitor", None)
        if kw_monitor is None:
            # The monitor param is not specified. Matching it to current state
            kargs["monitor"] = monitored
        elif kw_monitor is not monitored:
            # The monitor param is specified, and not matching the current
            # interface state
            iface.setmonitor(kw_monitor)
    return _orig_open_pcap(iface_pcap_name, *args, **kargs)


pcapdnet.open_pcap = open_pcap

get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr = lambda iface, *args, **kargs: (  # noqa: E501
    ARPHDR_ETHER, mac2str(IFACES.dev_from_pcapname(pcapname(iface)).mac)
)


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
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex', 'Metric1']):  # noqa: E501
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
    routes = []
    for line in exec_query(['Get-WmiObject', 'Win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex', 'Metric1']):  # noqa: E501
        try:
            iface = dev_from_index(line[3])
            ip = "127.0.0.1" if line[3] == "1" else iface.ip  # Force loopback on iface 1  # noqa: E501
            routes.append((atol(line[0]), atol(line[1]), line[2], iface, ip, int(line[4])))  # noqa: E501
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
        warning("Error building scapy IPv4 routing table : %s", e)
    else:
        if not routes:
            warning("No default IPv4 routes found. Your Windows release may no be supported and you have to enter your routes manually")  # noqa: E501
    return routes


def _get_metrics(ipv6=False):
    """Returns a dict containing all IPv4 or IPv6 interfaces' metric,
    ordered by their interface index.
    """
    query_cmd = "netsh interface " + ("ipv6" if ipv6 else "ipv4") + " show interfaces level=verbose"  # noqa: E501
    stdout = POWERSHELL_PROCESS.query([query_cmd])
    res = {}
    _buffer = []
    _pattern = re.compile(r".*:\s+(\d+)")
    for _line in stdout:
        if not _line.strip() and len(_buffer) > 0:
            if_index = re.search(_pattern, _buffer[3]).group(1)
            if_metric = int(re.search(_pattern, _buffer[5]).group(1))
            res[if_index] = if_metric
            _buffer = []
        else:
            _buffer.append(_line)
    return res


def _read_routes_post2008():
    routes = []
    if4_metrics = None
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed  # noqa: E501
    # Get-NetRoute -AddressFamily IPV4 | select ifIndex, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric | fl  # noqa: E501
    for line in exec_query(['Get-NetRoute', '-AddressFamily IPV4'], ['ifIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric', 'InterfaceMetric']):  # noqa: E501
        try:
            iface = dev_from_index(line[0])
            if iface.ip == "0.0.0.0":
                continue
        except ValueError:
            continue
        # try:
        #     intf = pcapdnet.dnet.intf().get_dst(pcapdnet.dnet.addr(type=2, addrtxt=dest))  # noqa: E501
        # except OSError:
        #     log_loading.warning("Building Scapy's routing table: Couldn't get outgoing interface for destination %s", dest)  # noqa: E501
        #     continue
        dest, mask = line[1].split('/')
        ip = "127.0.0.1" if line[0] == "1" else iface.ip  # Force loopback on iface 1  # noqa: E501
        if not line[4].strip():  # InterfaceMetric is not available. Load it from netsh  # noqa: E501
            if not if4_metrics:
                if4_metrics = _get_metrics()
            metric = int(line[3]) + if4_metrics.get(iface.win_index, 0)  # RouteMetric + InterfaceMetric  # noqa: E501
        else:
            metric = int(line[3]) + int(line[4])  # RouteMetric + InterfaceMetric  # noqa: E501
        routes.append((atol(dest), itom(int(mask)),
                       line[2], iface, ip, metric))
    return routes

############
#   IPv6   #
############


def in6_getifaddr():
    """
    Returns all IPv6 addresses found on the computer
    """
    ifaddrs = []
    for ifaddr in in6_getifaddr_raw():
        try:
            ifaddrs.append((ifaddr[0], ifaddr[1], dev_from_pcapname(ifaddr[2])))  # noqa: E501
        except ValueError:
            pass
    # Appends Npcap loopback if available
    if conf.use_npcap and scapy.consts.LOOPBACK_INTERFACE:
        ifaddrs.append(("::1", 0, scapy.consts.LOOPBACK_INTERFACE))
    return ifaddrs


def _append_route6(routes, dpref, dp, nh, iface, lifaddr, metric):
    cset = []  # candidate set (possible source addresses)
    if iface.name == scapy.consts.LOOPBACK_NAME:
        if dpref == '::':
            return
        cset = ['::1']
    else:
        devaddrs = (x for x in lifaddr if x[2] == iface)
        cset = construct_source_candidate_set(dpref, dp, devaddrs)
    if not cset:
        return
    # APPEND (DESTINATION, NETMASK, NEXT HOP, IFACE, CANDIDATS, METRIC)
    routes.append((dpref, dp, nh, iface, cset, metric))


def _read_routes6_post2008():
    routes6 = []
    if6_metrics = None
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed  # noqa: E501
    # Get-NetRoute -AddressFamily IPV6 | select ifIndex, DestinationPrefix, NextHop | fl  # noqa: E501
    lifaddr = in6_getifaddr()
    for line in exec_query(['Get-NetRoute', '-AddressFamily IPV6'], ['ifIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric', 'InterfaceMetric']):  # noqa: E501
        try:
            if_index = line[0]
            iface = dev_from_index(if_index)
        except ValueError:
            continue

        dpref, dp = line[1].split('/')
        dp = int(dp)
        nh = line[2]
        if not line[4].strip():  # InterfaceMetric is not available. Load it from netsh  # noqa: E501
            if not if6_metrics:
                if6_metrics = _get_metrics(ipv6=True)
            metric = int(line[3]) + if6_metrics.get(iface.win_index, 0)  # RouteMetric + InterfaceMetric  # noqa: E501
        else:
            metric = int(line[3]) + int(line[4])  # RouteMetric + InterfaceMetric  # noqa: E501

        _append_route6(routes6, dpref, dp, nh, iface, lifaddr, metric)
    return routes6


def _read_routes6_7():
    # Not supported in powershell, we have to use netsh
    routes = []
    query_cmd = "netsh interface ipv6 show route level=verbose"
    stdout = POWERSHELL_PROCESS.query([query_cmd])
    lifaddr = in6_getifaddr()
    if6_metrics = _get_metrics(ipv6=True)
    # Define regexes
    r_int = [r".*:\s+(\d+)"]
    r_all = [r"(.*)"]
    r_ipv6 = [r".*:\s+([A-z|0-9|:]+(\/\d+)?)"]
    # Build regex list for each object
    regex_list = r_ipv6 * 2 + r_int + r_all * 3 + r_int + r_all * 3
    current_object = []
    index = 0
    for l in stdout:
        if not l.strip():
            if not current_object:
                continue

            if len(current_object) == len(regex_list):
                try:
                    if_index = current_object[2]
                    iface = dev_from_index(if_index)
                except ValueError:
                    current_object = []
                    index = 0
                    continue
                _ip = current_object[0].split("/")
                dpref = _ip[0]
                dp = int(_ip[1])
                _match = re.search(r_ipv6[0], current_object[3])
                nh = "::"
                if _match:  # Detect if Next Hop is specified (if not, it will be the IFName)  # noqa: E501
                    _nhg1 = _match.group(1)
                    nh = _nhg1 if re.match(".*:.*:.*", _nhg1) else "::"
                metric = int(current_object[6]) + if6_metrics.get(if_index, 0)
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
        # Interface metrics have been added to powershell in win10+
        if is_new_release():
            routes6 = _read_routes6_post2008()
        else:
            routes6 = _read_routes6_7()
    except Exception as e:
        warning("Error building scapy IPv6 routing table : %s", e)
    return routes6


def get_working_if():
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        return min(conf.route.routes, key=lambda x: x[1])[3]
    except ValueError:
        # no route
        return scapy.consts.LOOPBACK_INTERFACE


def _get_valid_guid():
    if scapy.consts.LOOPBACK_INTERFACE:
        return scapy.consts.LOOPBACK_INTERFACE.guid
    else:
        return next((i.guid for i in six.itervalues(IFACES)
                     if not i.is_invalid()), None)


def route_add_loopback(routes=None, ipv6=False, iflist=None):
    """Add a route to 127.0.0.1 and ::1 to simplify unit tests on Windows"""
    if not WINDOWS:
        warning("Not available")
        return
    warning("This will completely mess up the routes. Testing purpose only !")
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
        'guid': "{0XX00000-X000-0X0X-X00X-00XXXX000XXX}",
        'invalid': True,
        'mac': '00:00:00:00:00:00',
    }
    adapter = NetworkInterface()
    adapter.pcap_name = "\\Device\\NPF_{0XX00000-X000-0X0X-X00X-00XXXX000XXX}"
    adapter.update(data)
    adapter.invalid = False
    adapter.ip = "127.0.0.1"
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
    IFACES["{0XX00000-X000-0X0X-X00X-00XXXX000XXX}"] = adapter
    scapy.consts.LOOPBACK_INTERFACE = adapter
    if isinstance(conf.iface, NetworkInterface):
        if conf.iface.name == scapy.consts.LOOPBACK_NAME:
            conf.iface = adapter
    if isinstance(conf.iface6, NetworkInterface):
        if conf.iface6.name == scapy.consts.LOOPBACK_NAME:
            conf.iface6 = adapter
    conf.netcache.arp_cache["127.0.0.1"] = "ff:ff:ff:ff:ff:ff"
    conf.netcache.in6_neighbor["::1"] = "ff:ff:ff:ff:ff:ff"
    # Build the packed network addresses
    loop_net = struct.unpack("!I", socket.inet_aton("127.0.0.0"))[0]
    loop_mask = struct.unpack("!I", socket.inet_aton("255.0.0.0"))[0]
    # Build the fake routes
    loopback_route = (loop_net, loop_mask, "0.0.0.0", adapter, "127.0.0.1", 1)
    loopback_route6 = ('::1', 128, '::', adapter, ["::1"], 1)
    loopback_route6_custom = ("fe80::", 128, "::", adapter, ["::1"], 1)
    if routes is None:
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


class _NotAvailableSocket(SuperSocket):
    desc = "wpcap.dll missing"

    def __init__(self, *args, **kargs):
        raise RuntimeError("Sniffing and sending packets is not available: "  # noqa: E501
                           "winpcap is not installed")
