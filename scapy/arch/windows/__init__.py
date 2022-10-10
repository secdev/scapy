# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Customizations needed to support Microsoft Windows.
"""

from glob import glob
import os
import platform as platform_lib
import socket
import struct
import subprocess as sp

import warnings

from scapy.arch.windows.structures import _windows_title, \
    GetAdaptersAddresses, GetIpForwardTable, GetIpForwardTable2, \
    get_service_status
from scapy.consts import WINDOWS, WINDOWS_XP
from scapy.config import conf, ProgPath
from scapy.error import (
    Scapy_Exception,
    log_interactive,
    log_loading,
    log_runtime,
    warning,
)
from scapy.interfaces import NetworkInterface, InterfaceProvider, \
    dev_from_index, resolve_iface, network_name
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils import atol, itom, mac2str, str2mac
from scapy.utils6 import construct_source_candidate_set, in6_getscope
from scapy.data import ARPHDR_ETHER, load_manuf
import scapy.libs.six as six
from scapy.libs.six.moves import input, winreg
from scapy.compat import plain_str
from scapy.supersocket import SuperSocket

# Typing imports
from scapy.compat import (
    cast,
    overload,
    Any,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
)

conf.use_pcap = True

# These import must appear after setting conf.use_* variables
from scapy.arch import libpcap  # noqa: E402
from scapy.arch.libpcap import (  # noqa: E402
    NPCAP_PATH,
    PCAP_IF_UP,
)

# Detection happens after libpcap import (NPcap detection)
NPCAP_LOOPBACK_NAME = r"\Device\NPF_Loopback"
if conf.use_npcap:
    conf.loopback_name = NPCAP_LOOPBACK_NAME
else:
    try:
        if float(platform_lib.release()) >= 8.1:
            conf.loopback_name = "Microsoft KM-TEST Loopback Adapter"
        else:
            conf.loopback_name = "Microsoft Loopback Adapter"
    except ValueError:
        conf.loopback_name = "Microsoft Loopback Adapter"

# hot-patching socket for missing variables on Windows
if not hasattr(socket, 'IPPROTO_IPIP'):
    socket.IPPROTO_IPIP = 4
if not hasattr(socket, 'IP_RECVTTL'):
    socket.IP_RECVTTL = 12  # type: ignore
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # type: ignore
# https://github.com/python/cpython/issues/73701
if not hasattr(socket, 'IPPROTO_IPV6'):
    socket.IPPROTO_IPV6 = 41
if not hasattr(socket, 'SOL_IPV6'):
    socket.SOL_IPV6 = socket.IPPROTO_IPV6  # type: ignore
if not hasattr(socket, 'IPPROTO_GRE'):
    socket.IPPROTO_GRE = 47
if not hasattr(socket, 'IPPROTO_AH'):
    socket.IPPROTO_AH = 51
if not hasattr(socket, 'IPPROTO_ESP'):
    socket.IPPROTO_ESP = 50

_WlanHelper = NPCAP_PATH + "\\WlanHelper.exe"


def _encapsulate_admin(cmd):
    # type: (str) -> str
    """Encapsulate a command with an Administrator flag"""
    # To get admin access, we start a new powershell instance with admin
    # rights, which will execute the command. This needs to be done from a
    # powershell as we run it from a cmd.
    # ! Behold !
    return ("powershell /command \"Start-Process cmd "
            "-windowstyle hidden -Wait -PassThru -Verb RunAs "
            "-ArgumentList '/c %s'\"" % cmd)


def _get_npcap_config(param_key):
    # type: (str) -> Optional[str]
    """
    Get a Npcap parameter matching key in the registry.

    List:
    AdminOnly, DefaultFilterSettings, DltNull, Dot11Adapters, Dot11Support
    LoopbackAdapter, LoopbackSupport, NdisImPlatformBindingOptions, VlanSupport
    WinPcapCompatible
    """
    hkey = winreg.HKEY_LOCAL_MACHINE
    node = r"SYSTEM\CurrentControlSet\Services\npcap\Parameters"
    try:
        key = winreg.OpenKey(hkey, node)
        dot11_adapters, _ = winreg.QueryValueEx(key, param_key)
        winreg.CloseKey(key)
    except WindowsError:
        return None
    return cast(str, dot11_adapters)


def _where(filename, dirs=None, env="PATH"):
    # type: (str, Optional[Any], str) -> str
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
    # type: (str, Optional[Any], str) -> str
    """Find executable in current dir, system path or in the
    given ProgramFiles subdir, and retuen its absolute path.
    """
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
    return path or ""


class WinProgPath(ProgPath):
    def __init__(self):
        # type: () -> None
        self._reload()

    def _reload(self):
        # type: () -> None
        self.pdfreader = ""
        self.psreader = ""
        self.svgreader = ""
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
                new_manuf = load_manuf(
                    os.path.sep.join(
                        self.wireshark.split(os.path.sep)[:-1]
                    ) + os.path.sep + "manuf"
                )
            except (IOError, OSError):  # FileNotFoundError not available on Py2 - using OSError  # noqa: E501
                log_loading.warning("Wireshark is installed, but cannot read manuf !")  # noqa: E501
                new_manuf = None
            if new_manuf:
                # Inject new ManufDB
                conf.manufdb.__dict__.clear()
                conf.manufdb.__dict__.update(new_manuf.__dict__)


def _exec_cmd(command):
    # type: (str) -> Tuple[bytes, int]
    """Call a CMD command and return the output and returncode"""
    proc = sp.Popen(command,
                    stdout=sp.PIPE,
                    shell=True)
    res = proc.communicate()[0]
    return res, proc.returncode


conf.prog = WinProgPath()

if conf.prog.tcpdump and conf.use_npcap:
    def test_windump_npcap():
        # type: () -> bool
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
        log_loading.warning(
            "The installed Windump version does not work with Npcap! "
            "Refer to 'Winpcap/Npcap conflicts' in scapy's installation doc"
        )
    del windump_ok


def get_windows_if_list(extended=False):
    # type: (bool) -> List[Dict[str, Any]]
    """Returns windows interfaces through GetAdaptersAddresses.

    params:
     - extended: include anycast and multicast IPv6 (default False)"""
    # Should work on Windows XP+
    def _get_mac(x):
        # type: (Dict[str, Any]) -> str
        size = x["physical_address_length"]
        if size != 6:
            return ""
        data = bytearray(x["physical_address"])
        return str2mac(bytes(data)[:size])

    def _get_ips(x):
        # type: (Dict[str, Any]) -> List[str]
        unicast = x['first_unicast_address']
        anycast = x['first_anycast_address']
        multicast = x['first_multicast_address']

        def _resolve_ips(y):
            # type: (List[Dict[str, Any]]) -> List[str]
            if not isinstance(y, list):
                return []
            ips = []
            for ip in y:
                addr = ip['address']['address'].contents
                if addr.si_family == socket.AF_INET6:
                    ip_key = "Ipv6"
                    si_key = "sin6_addr"
                else:
                    ip_key = "Ipv4"
                    si_key = "sin_addr"
                data = getattr(addr, ip_key)
                data = getattr(data, si_key)
                data = bytes(bytearray(data.byte))
                # Build IP
                if data:
                    ips.append(inet_ntop(addr.si_family, data))
            return ips

        ips = []
        ips.extend(_resolve_ips(unicast))
        if extended:
            ips.extend(_resolve_ips(anycast))
            ips.extend(_resolve_ips(multicast))
        return ips

    if six.PY2:
        _str_decode = lambda x: x.encode('utf8', errors='ignore')
    else:
        _str_decode = plain_str
    return [
        {
            "name": _str_decode(x["friendly_name"]),
            "index": x["interface_index"],
            "description": _str_decode(x["description"]),
            "guid": _str_decode(x["adapter_name"]),
            "mac": _get_mac(x),
            "ipv4_metric": 0 if WINDOWS_XP else x["ipv4_metric"],
            "ipv6_metric": 0 if WINDOWS_XP else x["ipv6_metric"],
            "ips": _get_ips(x)
        } for x in GetAdaptersAddresses()
    ]


def _pcapname_to_guid(pcap_name):
    # type: (str) -> str
    """Converts a Winpcap/Npcap pcpaname to its guid counterpart.
    e.g. \\DEVICE\\NPF_{...} => {...}
    """
    if "{" in pcap_name:
        return "{" + pcap_name.split("{")[1]
    return pcap_name


class NetworkInterface_Win(NetworkInterface):
    """A network interface of your local host"""

    def __init__(self, provider, data=None):
        # type: (WindowsInterfacesProvider, Optional[Dict[str, Any]]) -> None
        self.cache_mode = None  # type: Optional[bool]
        self.ipv4_metric = None  # type: Optional[int]
        self.ipv6_metric = None  # type: Optional[int]
        self.guid = None  # type: Optional[str]
        self.raw80211 = None  # type: Optional[bool]
        super(NetworkInterface_Win, self).__init__(provider, data)

    def update(self, data):
        # type: (Dict[str, Any]) -> None
        """Update info about a network interface according
        to a given dictionary. Such data is provided by get_windows_if_list
        """
        # Populated early because used below
        self.network_name = data['network_name']
        # Windows specific
        self.guid = data['guid']
        self.ipv4_metric = data['ipv4_metric']
        self.ipv6_metric = data['ipv6_metric']

        try:
            # Npcap loopback interface
            if conf.use_npcap and self.network_name == NPCAP_LOOPBACK_NAME:
                # https://nmap.org/npcap/guide/npcap-devguide.html
                data["mac"] = "00:00:00:00:00:00"
                data["ip"] = "127.0.0.1"
                data["ip6"] = "::1"
                data["ips"] = ["127.0.0.1", "::1"]
        except KeyError:
            pass
        super(NetworkInterface_Win, self).update(data)

    def _check_npcap_requirement(self):
        # type: () -> None
        if not conf.use_npcap:
            raise OSError("This operation requires Npcap.")
        if self.raw80211 is None:
            val = _get_npcap_config("Dot11Support")
            self.raw80211 = bool(int(val)) if val else False
        if not self.raw80211:
            raise Scapy_Exception("Npcap 802.11 support is NOT enabled !")

    def _npcap_set(self, key, val):
        # type: (str, str) -> bool
        """Internal function. Set a [key] parameter to [value]"""
        if self.guid is None:
            raise OSError("Interface not setup")
        res, code = _exec_cmd(_encapsulate_admin(
            " ".join([_WlanHelper, self.guid[1:-1], key, val])
        ))
        _windows_title()  # Reset title of the window
        if code != 0:
            raise OSError(res.decode("utf8", errors="ignore"))
        return True

    def _npcap_get(self, key):
        # type: (str) -> str
        if self.guid is None:
            raise OSError("Interface not setup")
        res, code = _exec_cmd(" ".join([_WlanHelper, self.guid[1:-1], key]))
        _windows_title()  # Reset title of the window
        if code != 0:
            raise OSError(res.decode("utf8", errors="ignore"))
        return plain_str(res.strip())

    def mode(self):
        # type: () -> str
        """Get the interface operation mode.
        Only available with Npcap."""
        self._check_npcap_requirement()
        return self._npcap_get("mode")

    def ismonitor(self):
        # type: () -> bool
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
        # type: (bool) -> bool
        """Alias for setmode('monitor') or setmode('managed')
        Only available with Npcap"""
        # We must reset the monitor cache
        if enable:
            res = self.setmode('monitor')
        else:
            res = self.setmode('managed')
        if not res:
            log_runtime.error("Npcap WlanHelper returned with an error code !")
        self.cache_mode = None
        tmp = self.cache_mode = self.ismonitor()
        return tmp if enable else (not tmp)

    def availablemodes(self):
        # type: () -> List[str]
        """Get all available interface modes.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return self._npcap_get("modes").split(",")

    def setmode(self, mode):
        # type: (Union[str, int]) -> bool
        """Set the interface mode. It can be:
        - 0 or managed: Managed Mode (aka "Extensible Station Mode")
        - 1 or monitor: Monitor Mode (aka "Network Monitor Mode")
        - 2 or master: Master Mode (aka "Extensible Access Point")
              (supported from Windows 7 and later)
        - 3 or wfd_device: The Wi-Fi Direct Device operation mode
              (supported from Windows 8 and later)
        - 4 or wfd_owner: The Wi-Fi Direct Group Owner operation mode
              (supported from Windows 8 and later)
        - 5 or wfd_client: The Wi-Fi Direct Client operation mode
              (supported from Windows 8 and later)
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
        return self._npcap_set("mode", m)

    def channel(self):
        # type: () -> int
        """Get the channel of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return int(self._npcap_get("channel"))

    def setchannel(self, channel):
        # type: (int) -> bool
        """Set the channel of the interface (1-14):
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return self._npcap_set("channel", str(channel))

    def frequence(self):
        # type: () -> int
        """Get the frequence of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return int(self._npcap_get("freq"))

    def setfrequence(self, freq):
        # type: (int) -> bool
        """Set the channel of the interface (1-14):
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return self._npcap_set("freq", str(freq))

    def availablemodulations(self):
        # type: () -> List[str]
        """Get all available 802.11 interface modulations.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return self._npcap_get("modus").split(",")

    def modulation(self):
        # type: () -> str
        """Get the 802.11 modulation of the interface.
        Only available with Npcap."""
        # According to https://nmap.org/npcap/guide/npcap-devguide.html#npcap-feature-dot11  # noqa: E501
        self._check_npcap_requirement()
        return self._npcap_get("modu")

    def setmodulation(self, modu):
        # type: (int) -> bool
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
           - the value directly
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
        return self._npcap_set("modu", str(m))


class WindowsInterfacesProvider(InterfaceProvider):
    name = "libpcap"
    libpcap = True

    def _is_valid(self, dev):
        # type: (NetworkInterface) -> bool
        # Winpcap (and old Npcap) have no support for PCAP_IF_UP :(
        if dev.flags == 0:
            return True
        return bool(dev.flags & PCAP_IF_UP)

    @classmethod
    def _pcap_check(cls):
        # type: () -> None
        """Performs checks/restart pcap adapter"""
        if not conf.use_pcap:
            # Winpcap/Npcap isn't installed
            return

        _detect = pcap_service_status()

        def _ask_user():
            # type: () -> bool
            if not conf.interactive:
                return False
            msg = "Do you want to start it ? (yes/no) [y]: "
            try:
                # Better IPython compatibility
                import IPython
                return cast(bool, IPython.utils.io.ask_yes_no(msg, default='y'))
            except (NameError, ImportError):
                while True:
                    _confir = input(msg)
                    _confir = _confir.lower().strip()
                    if _confir in ["yes", "y", ""]:
                        return True
                    elif _confir in ["no", "n"]:
                        return False
        if _detect:
            # No action needed
            return
        else:
            log_interactive.warning(
                "Scapy has detected that your pcap service is not running !"
            )
            if not conf.interactive or _ask_user():
                succeed = pcap_service_start(askadmin=conf.interactive)
                if succeed:
                    log_loading.info("Pcap service started !")
                    return
        log_loading.warning(
            "Could not start the pcap service! "
            "You probably won't be able to send packets. "
            "Check your winpcap/npcap installation "
            "and access rights."
        )

    def load(self, NetworkInterface_Win=NetworkInterface_Win):
        # type: (type) -> Dict[str, NetworkInterface]
        results = {}
        if not conf.cache_pcapiflist:
            # Try a restart
            WindowsInterfacesProvider._pcap_check()

        windows_interfaces = dict()
        for i in get_windows_if_list():
            # Detect Loopback interface
            if "Loopback" in i['name']:
                i['name'] = conf.loopback_name
            if i['guid']:
                if conf.use_npcap and i['name'] == conf.loopback_name:
                    i['guid'] = NPCAP_LOOPBACK_NAME
                windows_interfaces[i['guid']] = i

        index = 0
        for netw, if_data in six.iteritems(conf.cache_pcapiflist):
            name, ips, flags, _ = if_data
            guid = _pcapname_to_guid(netw)
            data = windows_interfaces.get(guid, None)
            if data:
                # Exists in Windows registry
                data['network_name'] = netw
                data['ips'] = list(set(data['ips'] + ips))
                data['flags'] = flags
            else:
                # Only in [Wi]npcap
                index -= 1
                data = {
                    'name': name,
                    'description': name,
                    'index': index,
                    'guid': guid,
                    'network_name': netw,
                    'mac': '00:00:00:00:00:00',
                    'ipv4_metric': 0,
                    'ipv6_metric': 0,
                    'ips': ips,
                    'flags': flags
                }
            # No KeyError will happen here, as we get it from cache
            results[guid] = NetworkInterface_Win(self, data)
        return results

    def reload(self):
        # type: () -> Dict[str, NetworkInterface]
        """Reload interface list"""
        self.restarted_adapter = False
        if conf.use_pcap:
            # Reload from Winpcapy
            from scapy.arch.libpcap import load_winpcapy
            load_winpcapy()
        return self.load()


# Register provider
conf.ifaces.register_provider(WindowsInterfacesProvider)


def get_ips(v6=False):
    # type: (bool) -> Dict[NetworkInterface, List[str]]
    """Returns all available IPs matching to interfaces, using the windows system.
    Should only be used as a WinPcapy fallback.

    :param v6: IPv6 addresses
    """
    res = {}
    for iface in six.itervalues(conf.ifaces):
        if v6:
            res[iface] = iface.ips[6]
        else:
            res[iface] = iface.ips[4]
    return res


def get_if_raw_addr(iff):
    # type: (Union[NetworkInterface, str]) -> bytes
    """Return the raw IPv4 address of interface"""
    iff = resolve_iface(iff)
    if not iff.ip:
        return b"\x00" * 4
    return inet_pton(socket.AF_INET, iff.ip)


def get_ip_from_name(ifname, v6=False):
    # type: (str, bool) -> str
    """Backward compatibility: indirectly calls get_ips
    Deprecated.
    """
    warnings.warn(
        "get_ip_from_name is deprecated. Use the `ip` attribute of the iface "
        "or use get_ips() to get all ips per interface.",
        DeprecationWarning
    )
    iface = conf.ifaces.dev_from_name(ifname)
    return get_ips(v6=v6).get(iface, [""])[0]


def pcap_service_name():
    # type: () -> str
    """Return the pcap adapter service's name"""
    return "npcap" if conf.use_npcap else "npf"


def pcap_service_status():
    # type: () -> bool
    """Returns whether the windows pcap adapter is running or not"""
    status = get_service_status(pcap_service_name())
    return status["dwCurrentState"] == 4


def _pcap_service_control(action, askadmin=True):
    # type: (str, bool) -> bool
    """Internal util to run pcap control command"""
    command = action + ' ' + pcap_service_name()
    res, code = _exec_cmd(_encapsulate_admin(command) if askadmin else command)
    if code != 0:
        warning(res.decode("utf8", errors="ignore"))
    return (code == 0)


def pcap_service_start(askadmin=True):
    # type: (bool) -> bool
    """Starts the pcap adapter. Will ask for admin. Returns True if success"""
    return _pcap_service_control('sc start', askadmin=askadmin)


def pcap_service_stop(askadmin=True):
    # type: (bool) -> bool
    """Stops the pcap adapter. Will ask for admin. Returns True if success"""
    return _pcap_service_control('sc stop', askadmin=askadmin)


if conf.use_pcap:
    _orig_open_pcap = libpcap.open_pcap

    def open_pcap(iface,  # type: Union[str, NetworkInterface]
                  *args,  # type: Any
                  **kargs  # type: Any
                  ):
        # type: (...) -> libpcap._PcapWrapper_libpcap
        """open_pcap: Windows routine for creating a pcap from an interface.
        This function is also responsible for detecting monitor mode.
        """
        iface = cast(NetworkInterface_Win, resolve_iface(iface))
        iface_network_name = iface.network_name
        if not iface:
            raise Scapy_Exception(
                "Interface is invalid (no pcap match found)!"
            )
        # Only check monitor mode when manually specified.
        # Checking/setting for monitor mode will slow down the process, and the
        # common is case is not to use monitor mode
        kw_monitor = kargs.get("monitor", None)
        if conf.use_npcap and kw_monitor is not None:
            monitored = iface.ismonitor()
            if kw_monitor is not monitored:
                # The monitor param is specified, and not matching the current
                # interface state
                iface.setmonitor(kw_monitor)
        return _orig_open_pcap(iface_network_name, *args, **kargs)
    libpcap.open_pcap = open_pcap  # type: ignore


def get_if_raw_hwaddr(iface):
    # type: (Union[NetworkInterface, str]) -> Tuple[int, bytes]
    _iface = resolve_iface(iface)
    return ARPHDR_ETHER, _iface.mac and mac2str(_iface.mac) or b"\x00" * 6


def _read_routes_c_v1():
    # type: () -> List[Tuple[int, int, str, str, str, int]]
    """Retrieve Windows routes through a GetIpForwardTable call.

    This is compatible with XP but won't get IPv6 routes."""
    def _extract_ip(obj):
        # type: (int) -> str
        return inet_ntop(socket.AF_INET, struct.pack("<I", obj))

    def _proc(ip):
        # type: (int) -> int
        if WINDOWS_XP:
            return struct.unpack("<I", struct.pack(">I", ip))[0]
        return ip
    routes = []
    for route in GetIpForwardTable():
        ifIndex = route['ForwardIfIndex']
        dest = _proc(route['ForwardDest'])
        netmask = _proc(route['ForwardMask'])
        nexthop = _extract_ip(route['ForwardNextHop'])
        metric = route['ForwardMetric1']
        # Build route
        try:
            iface = cast(NetworkInterface_Win, dev_from_index(ifIndex))
            if not iface.ip or iface.ip == "0.0.0.0":
                continue
        except ValueError:
            continue
        ip = iface.ip
        netw = network_name(iface)
        # RouteMetric + InterfaceMetric
        metric = metric + iface.ipv4_metric
        routes.append((dest, netmask, nexthop, netw, ip, metric))
    return routes


@overload
def _read_routes_c(ipv6):  # noqa: F811
    # type: (Literal[True]) -> List[Tuple[str, int, str, str, List[str], int]]
    pass


@overload
def _read_routes_c(ipv6=False):  # noqa: F811
    # type: (Literal[False]) -> List[Tuple[int, int, str, str, str, int]]
    pass


def _read_routes_c(ipv6=False):  # noqa: F811
    # type: (bool) -> Union[List[Tuple[int, int, str, str, str, int]], List[Tuple[str, int, str, str, List[str], int]]]  # noqa: E501
    """Retrieve Windows routes through a GetIpForwardTable2 call.

    This is not available on Windows XP !"""
    af = socket.AF_INET6 if ipv6 else socket.AF_INET
    sock_addr_name = 'Ipv6' if ipv6 else 'Ipv4'
    sin_addr_name = 'sin6_addr' if ipv6 else 'sin_addr'
    metric_name = 'ipv6_metric' if ipv6 else 'ipv4_metric'
    if ipv6:
        lifaddr = in6_getifaddr()
    routes = []  # type: List[Any]

    def _extract_ip(obj):
        # type: (Dict[str, Any]) -> str
        ip = obj[sock_addr_name][sin_addr_name]
        ip = bytes(bytearray(ip['byte']))
        # Build IP
        return inet_ntop(af, ip)

    for route in GetIpForwardTable2(af):
        # Extract data
        ifIndex = route['InterfaceIndex']
        dest = _extract_ip(route['DestinationPrefix']['Prefix'])
        netmask = route['DestinationPrefix']['PrefixLength']
        nexthop = _extract_ip(route['NextHop'])
        metric = route['Metric']
        # Build route
        try:
            iface = dev_from_index(ifIndex)
            if not iface.ip or iface.ip == "0.0.0.0":
                continue
        except ValueError:
            continue
        ip = iface.ip
        netw = network_name(iface)
        # RouteMetric + InterfaceMetric
        metric = metric + getattr(iface, metric_name)
        if ipv6:
            _append_route6(routes, dest, netmask, nexthop,
                           netw, lifaddr, metric)
        else:
            routes.append((atol(dest), itom(int(netmask)),
                           nexthop, netw, ip, metric))
    return routes


def read_routes():
    # type: () -> List[Tuple[int, int, str, str, str, int]]
    routes = []
    try:
        if WINDOWS_XP:
            routes = _read_routes_c_v1()
        else:
            routes = _read_routes_c(ipv6=False)
    except Exception as e:
        log_loading.warning("Error building scapy IPv4 routing table : %s", e)
    return routes


############
#   IPv6   #
############


def in6_getifaddr():
    # type: () -> List[Tuple[str, int, str]]
    """
    Returns all IPv6 addresses found on the computer
    """
    ifaddrs = []  # type: List[Tuple[str, int, str]]
    ip6s = get_ips(v6=True)
    for iface, ips in ip6s.items():
        for ip in ips:
            scope = in6_getscope(ip)
            ifaddrs.append((ip, scope, iface.network_name))
    # Appends Npcap loopback if available
    if conf.use_npcap and conf.loopback_name:
        ifaddrs.append(("::1", 0, conf.loopback_name))
    return ifaddrs


def _append_route6(routes,  # type: List[Tuple[str, int, str, str, List[str], int]]
                   dpref,  # type: str
                   dp,  # type: int
                   nh,  # type: str
                   iface,  # type: str
                   lifaddr,  # type: List[Tuple[str, int, str]]
                   metric,  # type: int
                   ):
    # type: (...) -> None
    cset = []  # candidate set (possible source addresses)
    if iface == conf.loopback_name:
        if dpref == '::':
            return
        cset = ['::1']
    else:
        devaddrs = (x for x in lifaddr if x[2] == iface)
        cset = construct_source_candidate_set(dpref, dp, devaddrs)
    if not cset:
        return
    # APPEND (DESTINATION, NETMASK, NEXT HOP, IFACE, CANDIDATES, METRIC)
    routes.append((dpref, dp, nh, iface, cset, metric))


def read_routes6():
    # type: () -> List[Tuple[str, int, str, str, List[str], int]]
    routes6 = []
    if WINDOWS_XP:
        return routes6
    try:
        routes6 = _read_routes_c(ipv6=True)
    except Exception as e:
        log_loading.warning("Error building scapy IPv6 routing table : %s", e)
    return routes6


def _route_add_loopback(routes=None,  # type: Optional[List[Any]]
                        ipv6=False,  # type: bool
                        iflist=None,  # type: Optional[List[str]]
                        ):
    # type: (...) -> None
    """Add a route to 127.0.0.1 and ::1 to simplify unit tests on Windows"""
    if not WINDOWS:
        warning("Calling _route_add_loopback is only valid on Windows")
        return
    warning("This will completely mess up the routes. Testing purpose only !")
    # Add only if some adapters already exist
    if ipv6:
        if not conf.route6.routes:
            return
    else:
        if not conf.route.routes:
            return
    conf.ifaces._add_fake_iface(conf.loopback_name)
    adapter = conf.ifaces.dev_from_name(conf.loopback_name)
    if iflist:
        iflist.append(adapter.network_name)
        return
    # Remove all conf.loopback_name routes
    for route in list(conf.route.routes):
        iface = route[3]
        if iface == conf.loopback_name:
            conf.route.routes.remove(route)
    # Remove conf.loopback_name interface
    for devname, iface in list(conf.ifaces.items()):
        if iface == conf.loopback_name:
            conf.ifaces.pop(devname)
    # Inject interface
    conf.ifaces["{0XX00000-X000-0X0X-X00X-00XXXX000XXX}"] = adapter
    conf.loopback_name = adapter.network_name
    if isinstance(conf.iface, NetworkInterface):
        if conf.iface.network_name == conf.loopback_name:
            conf.iface = adapter
    conf.netcache.arp_cache["127.0.0.1"] = "ff:ff:ff:ff:ff:ff"  # type: ignore
    conf.netcache.in6_neighbor["::1"] = "ff:ff:ff:ff:ff:ff"  # type: ignore
    # Build the packed network addresses
    loop_net = struct.unpack("!I", socket.inet_aton("127.0.0.0"))[0]
    loop_mask = struct.unpack("!I", socket.inet_aton("255.0.0.0"))[0]
    # Build the fake routes
    loopback_route = (
        loop_net,
        loop_mask,
        "0.0.0.0",
        adapter.network_name,
        "127.0.0.1",
        1
    )
    loopback_route6 = ('::1', 128, '::', adapter.network_name, ["::1"], 1)
    loopback_route6_custom = ("fe80::", 128, "::", adapter.network_name, ["::1"], 1)
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
        # type: (*Any, **Any) -> None
        raise RuntimeError(
            "Sniffing and sending packets is not available at layer 2: "
            "winpcap is not installed. You may use conf.L3socket or"
            "conf.L3socket6 to access layer 3"
        )
