# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

# flake8: noqa E266
# (We keep comment boxes, it's then one-line comments)

"""
C API calls to Windows DLLs
"""

import ctypes
import ctypes.wintypes
from ctypes import Structure, POINTER, byref, create_string_buffer, WINFUNCTYPE

from scapy.config import conf
from scapy.consts import WINDOWS_XP

ANY_SIZE = 65500  # FIXME quite inefficient :/
AF_UNSPEC = 0
NO_ERROR = 0x0

CHAR = ctypes.c_char
DWORD = ctypes.wintypes.DWORD
BOOL = ctypes.wintypes.BOOL
BOOLEAN = ctypes.wintypes.BOOLEAN
ULONG = ctypes.wintypes.ULONG
ULONGLONG = ctypes.c_ulonglong
HANDLE = ctypes.wintypes.HANDLE
LPWSTR = ctypes.wintypes.LPWSTR
VOID = ctypes.c_void_p
INT = ctypes.c_int
UINT = ctypes.wintypes.UINT
UINT8 = ctypes.c_uint8
UINT16 = ctypes.c_uint16
UINT32 = ctypes.c_uint32
UINT64 = ctypes.c_uint64
BYTE = ctypes.c_byte
UCHAR = UBYTE = ctypes.c_ubyte
SHORT = ctypes.c_short
USHORT = ctypes.c_ushort


# UTILS


def _resolve_list(list_obj):
    current = list_obj
    _list = []
    while current and hasattr(current, "contents"):
        _list.append(_struct_to_dict(current.contents))
        current = current.contents.next
    return _list


def _struct_to_dict(struct_obj):
    results = {}
    for fname, ctype in struct_obj.__class__._fields_:
        val = getattr(struct_obj, fname)
        if fname == "next":
            # Already covered by the trick below
            continue
        if issubclass(ctype, (Structure, ctypes.Union)):
            results[fname] = _struct_to_dict(val)
        elif val and hasattr(val, "contents"):
            # Let's resolve recursive pointers
            if hasattr(val.contents, "next"):
                results[fname] = _resolve_list(val)
            else:
                results[fname] = val
        else:
            results[fname] = val
    return results

##############################
####### WinAPI handles #######
##############################

_winapi_SetConsoleTitle = ctypes.windll.kernel32.SetConsoleTitleW
_winapi_SetConsoleTitle.restype = BOOL
_winapi_SetConsoleTitle.argtypes = [LPWSTR]

def _windows_title(title=None):
    """Updates the terminal title with the default one or with `title`
    if provided."""
    if conf.interactive:
        _winapi_SetConsoleTitle(title or "Scapy v{}".format(conf.version))


SC_HANDLE = HANDLE

class SERVICE_STATUS(Structure):
    """https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-_service_status"""  # noqa: E501
    _fields_ = [("dwServiceType", DWORD),
                ("dwCurrentState", DWORD),
                ("dwControlsAccepted", DWORD),
                ("dwWin32ExitCode", DWORD),
                ("dwServiceSpecificExitCode", DWORD),
                ("dwCheckPoint", DWORD),
                ("dwWaitHint", DWORD)]


OpenServiceW = ctypes.windll.Advapi32.OpenServiceW
OpenServiceW.restype = SC_HANDLE
OpenServiceW.argtypes = [SC_HANDLE, LPWSTR, DWORD]

CloseServiceHandle = ctypes.windll.Advapi32.CloseServiceHandle
CloseServiceHandle.restype = BOOL
CloseServiceHandle.argtypes = [SC_HANDLE]

OpenSCManagerW = ctypes.windll.Advapi32.OpenSCManagerW
OpenSCManagerW.restype = SC_HANDLE
OpenSCManagerW.argtypes = [LPWSTR, LPWSTR, DWORD]

QueryServiceStatus = ctypes.windll.Advapi32.QueryServiceStatus
QueryServiceStatus.restype = BOOL
QueryServiceStatus.argtypes = [SC_HANDLE, POINTER(SERVICE_STATUS)]

def get_service_status(service):
    """Returns content of QueryServiceStatus for a service"""
    SERVICE_QUERY_STATUS = 0x0004
    schSCManager = OpenSCManagerW(
        None,  # Local machine
        None,  # SERVICES_ACTIVE_DATABASE
        SERVICE_QUERY_STATUS
    )
    service = OpenServiceW(
        schSCManager,
        service,
        SERVICE_QUERY_STATUS
    )
    status = SERVICE_STATUS()
    QueryServiceStatus(
        service,
        status
    )
    result = _struct_to_dict(status)
    CloseServiceHandle(service)
    CloseServiceHandle(schSCManager)
    return result


##############################
###### Define IPHLPAPI  ######
##############################


iphlpapi = ctypes.windll.iphlpapi

##############################
########### Common ###########
##############################


class in_addr(Structure):
    _fields_ = [("byte", UBYTE * 4)]


class in6_addr(Structure):
    _fields_ = [("byte", UBYTE * 16)]


class sockaddr_in(Structure):
    _fields_ = [("sin_family", SHORT),
                ("sin_port", USHORT),
                ("sin_addr", in_addr),
                ("sin_zero", 8 * CHAR)]


class sockaddr_in6(Structure):
    _fields_ = [("sin6_family", SHORT),
                ("sin6_port", USHORT),
                ("sin6_flowinfo", ULONG),
                ("sin6_addr", in6_addr),
                ("sin6_scope_id", ULONG)]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [("Ipv4", sockaddr_in),
                ("Ipv6", sockaddr_in6),
                ("si_family", USHORT)]

##############################
######### ICMP stats #########
##############################


class MIBICMPSTATS(Structure):
    _fields_ = [("dwMsgs", DWORD),
                ("dwErrors", DWORD),
                ("dwDestUnreachs", DWORD),
                ("dwTimeExcds", DWORD),
                ("dwParmProbs", DWORD),
                ("dwSrcQuenchs", DWORD),
                ("dwRedirects", DWORD),
                ("dwEchos", DWORD),
                ("dwEchoReps", DWORD),
                ("dwTimestamps", DWORD),
                ("dwTimestampReps", DWORD),
                ("dwAddrMasks", DWORD),
                ("dwAddrMaskReps", DWORD)]


class MIBICMPINFO(Structure):
    _fields_ = [("icmpInStats", MIBICMPSTATS),
                ("icmpOutStats", MIBICMPSTATS)]


class MIB_ICMP(Structure):
    _fields_ = [("stats", MIBICMPINFO)]


PMIB_ICMP = POINTER(MIB_ICMP)

# Func

_GetIcmpStatistics = WINFUNCTYPE(ULONG, PMIB_ICMP)(
    ('GetIcmpStatistics', iphlpapi))


def GetIcmpStatistics():
    """Return all Windows ICMP stats from iphlpapi"""
    statistics = MIB_ICMP()
    _GetIcmpStatistics(byref(statistics))
    results = _struct_to_dict(statistics)
    del(statistics)
    return results

##############################
##### Adapters Addresses #####
##############################


# Our GetAdaptersAddresses implementation is inspired by
# @sphaero 's gist: https://gist.github.com/sphaero/f9da6ebb9a7a6f679157
# published under a MPL 2.0 License (GPLv2 compatible)

# from iptypes.h
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130

GAA_FLAG_INCLUDE_PREFIX = 0x0010
GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100
# for now, just use void * for pointers to unused structures
PIP_ADAPTER_WINS_SERVER_ADDRESS_LH = VOID
PIP_ADAPTER_GATEWAY_ADDRESS_LH = VOID
PIP_ADAPTER_DNS_SUFFIX = VOID

IF_OPER_STATUS = UINT
IF_LUID = UINT64

NET_IF_COMPARTMENT_ID = UINT32
GUID = BYTE * 16
NET_IF_NETWORK_GUID = GUID
NET_IF_CONNECTION_TYPE = UINT  # enum
TUNNEL_TYPE = UINT  # enum


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [('address', POINTER(SOCKADDR_INET)),
                ('length', INT)]


class _IP_ADAPTER_ADDRESSES_METRIC(Structure):
    _fields_ = [('length', ULONG),
                ('interface_index', DWORD)]


class IP_ADAPTER_UNICAST_ADDRESS(Structure):
    pass


PIP_ADAPTER_UNICAST_ADDRESS = POINTER(IP_ADAPTER_UNICAST_ADDRESS)
if WINDOWS_XP:
    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("length", ULONG),
        ("flags", DWORD),
        ("next", PIP_ADAPTER_UNICAST_ADDRESS),
        ("address", SOCKET_ADDRESS),
        ("prefix_origin", INT),
        ("suffix_origin", INT),
        ("dad_state", INT),
        ("valid_lifetime", ULONG),
        ("preferred_lifetime", ULONG),
        ("lease_lifetime", ULONG),
    ]
else:
    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("length", ULONG),
        ("flags", DWORD),
        ("next", PIP_ADAPTER_UNICAST_ADDRESS),
        ("address", SOCKET_ADDRESS),
        ("prefix_origin", INT),
        ("suffix_origin", INT),
        ("dad_state", INT),
        ("valid_lifetime", ULONG),
        ("preferred_lifetime", ULONG),
        ("lease_lifetime", ULONG),
        ("on_link_prefix_length", UBYTE)
    ]


class IP_ADAPTER_ANYCAST_ADDRESS(Structure):
    pass


PIP_ADAPTER_ANYCAST_ADDRESS = POINTER(IP_ADAPTER_ANYCAST_ADDRESS)
IP_ADAPTER_ANYCAST_ADDRESS._fields_ = [
    ("length", ULONG),
    ("flags", DWORD),
    ("next", PIP_ADAPTER_ANYCAST_ADDRESS),
    ("address", SOCKET_ADDRESS),
]


class IP_ADAPTER_MULTICAST_ADDRESS(Structure):
    pass


PIP_ADAPTER_MULTICAST_ADDRESS = POINTER(IP_ADAPTER_MULTICAST_ADDRESS)
IP_ADAPTER_MULTICAST_ADDRESS._fields_ = [
    ("length", ULONG),
    ("flags", DWORD),
    ("next", PIP_ADAPTER_MULTICAST_ADDRESS),
    ("address", SOCKET_ADDRESS),
]


class IP_ADAPTER_DNS_SERVER_ADDRESS(Structure):
    pass


PIP_ADAPTER_DNS_SERVER_ADDRESS = POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)
IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
    ("length", ULONG),
    ("flags", DWORD),
    ("next", PIP_ADAPTER_DNS_SERVER_ADDRESS),
    ("address", SOCKET_ADDRESS),
]


class IP_ADAPTER_PREFIX(Structure):
    pass


PIP_ADAPTER_PREFIX = ctypes.POINTER(IP_ADAPTER_PREFIX)
IP_ADAPTER_PREFIX._fields_ = [
    ("alignment", ULONGLONG),
    ("next", PIP_ADAPTER_PREFIX),
    ("address", SOCKET_ADDRESS),
    ("prefix_length", ULONG)
]


class IP_ADAPTER_ADDRESSES(Structure):
    pass


LP_IP_ADAPTER_ADDRESSES = POINTER(IP_ADAPTER_ADDRESSES)

if WINDOWS_XP:
    IP_ADAPTER_ADDRESSES._fields_ = [
        ('length', ULONG),
        ('interface_index', DWORD),
        ('next', LP_IP_ADAPTER_ADDRESSES),
        ('adapter_name', ctypes.c_char_p),
        ('first_unicast_address', PIP_ADAPTER_UNICAST_ADDRESS),
        ('first_anycast_address', PIP_ADAPTER_ANYCAST_ADDRESS),
        ('first_multicast_address', PIP_ADAPTER_MULTICAST_ADDRESS),
        ('first_dns_server_address', PIP_ADAPTER_DNS_SERVER_ADDRESS),
        ('dns_suffix', ctypes.c_wchar_p),
        ('description', ctypes.c_wchar_p),
        ('friendly_name', ctypes.c_wchar_p),
        ('physical_address', BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
        ('physical_address_length', ULONG),
        ('flags', ULONG),
        ('mtu', ULONG),
        ('interface_type', DWORD),
        ('oper_status', IF_OPER_STATUS),
        ('ipv6_interface_index', DWORD),
        ('zone_indices', ULONG * 16),
        ('first_prefix', PIP_ADAPTER_PREFIX),
    ]
else:
    IP_ADAPTER_ADDRESSES._fields_ = [
        ('length', ULONG),
        ('interface_index', DWORD),
        ('next', LP_IP_ADAPTER_ADDRESSES),
        ('adapter_name', ctypes.c_char_p),
        ('first_unicast_address', PIP_ADAPTER_UNICAST_ADDRESS),
        ('first_anycast_address', PIP_ADAPTER_ANYCAST_ADDRESS),
        ('first_multicast_address', PIP_ADAPTER_MULTICAST_ADDRESS),
        ('first_dns_server_address', PIP_ADAPTER_DNS_SERVER_ADDRESS),
        ('dns_suffix', ctypes.c_wchar_p),
        ('description', ctypes.c_wchar_p),
        ('friendly_name', ctypes.c_wchar_p),
        ('physical_address', BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
        ('physical_address_length', ULONG),
        ('flags', ULONG),
        ('mtu', ULONG),
        ('interface_type', DWORD),
        ('oper_status', IF_OPER_STATUS),
        ('ipv6_interface_index', DWORD),
        ('zone_indices', ULONG * 16),
        ('first_prefix', PIP_ADAPTER_PREFIX),
        ('transmit_link_speed', ULONGLONG),
        ('receive_link_speed', ULONGLONG),
        ('first_wins_server_address', PIP_ADAPTER_WINS_SERVER_ADDRESS_LH),
        ('first_gateway_address', PIP_ADAPTER_GATEWAY_ADDRESS_LH),
        ('ipv4_metric', ULONG),
        ('ipv6_metric', ULONG),
        ('luid', IF_LUID),
        ('dhcpv4_server', SOCKET_ADDRESS),
        ('compartment_id', NET_IF_COMPARTMENT_ID),
        ('network_guid', NET_IF_NETWORK_GUID),
        ('connection_type', NET_IF_CONNECTION_TYPE),
        ('tunnel_type', TUNNEL_TYPE),
        ('dhcpv6_server', SOCKET_ADDRESS),
        ('dhcpv6_client_duid', BYTE * MAX_DHCPV6_DUID_LENGTH),
        ('dhcpv6_client_duid_length', ULONG),
        ('dhcpv6_iaid', ULONG),
        ('first_dns_suffix', PIP_ADAPTER_DNS_SUFFIX)]

# Func

_GetAdaptersAddresses = WINFUNCTYPE(ULONG, ULONG, ULONG,
                                    POINTER(VOID),
                                    LP_IP_ADAPTER_ADDRESSES,
                                    POINTER(ULONG))(
                                        ('GetAdaptersAddresses', iphlpapi))


def GetAdaptersAddresses(AF=AF_UNSPEC):
    """Return all Windows Adapters addresses from iphlpapi"""
    # We get the size first
    size = ULONG()
    flags = ULONG(GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_ALL_INTERFACES)
    res = _GetAdaptersAddresses(AF, flags,
                                None, None,
                                byref(size))
    if res != 0x6f:  # BUFFER OVERFLOW -> populate size
        raise RuntimeError("Error getting structure length (%d)" % res)
    # Now let's build our buffer
    pointer_type = POINTER(IP_ADAPTER_ADDRESSES)
    buffer = create_string_buffer(size.value)
    AdapterAddresses = ctypes.cast(buffer, pointer_type)
    # And call GetAdaptersAddresses
    res = _GetAdaptersAddresses(AF, flags,
                                None, AdapterAddresses,
                                byref(size))
    if res != NO_ERROR:
        raise RuntimeError("Error retrieving table (%d)" % res)
    results = _resolve_list(AdapterAddresses)
    del(AdapterAddresses)
    return results

##############################
####### Routing tables #######
##############################

### V1 ###


class MIB_IPFORWARDROW(Structure):
    _fields_ = [('ForwardDest', DWORD),
                ('ForwardMask', DWORD),
                ('ForwardPolicy', DWORD),
                ('ForwardNextHop', DWORD),
                ('ForwardIfIndex', DWORD),
                ('ForwardType', DWORD),
                ('ForwardProto', DWORD),
                ('ForwardAge', DWORD),
                ('ForwardNextHopAS', DWORD),
                ('ForwardMetric1', DWORD),
                ('ForwardMetric2', DWORD),
                ('ForwardMetric3', DWORD),
                ('ForwardMetric4', DWORD),
                ('ForwardMetric5', DWORD)]


class MIB_IPFORWARDTABLE(Structure):
    _fields_ = [('NumEntries', DWORD),
                ('Table', MIB_IPFORWARDROW * ANY_SIZE)]


PMIB_IPFORWARDTABLE = POINTER(MIB_IPFORWARDTABLE)

# Func

_GetIpForwardTable = WINFUNCTYPE(DWORD,
                                 PMIB_IPFORWARDTABLE, POINTER(ULONG), BOOL)(
                                     ('GetIpForwardTable', iphlpapi))


def GetIpForwardTable():
    """Return all Windows routes (IPv4 only) from iphlpapi"""
    # We get the size first
    size = ULONG()
    res = _GetIpForwardTable(None, byref(size), False)
    if res != 0x7a:  # ERROR_INSUFFICIENT_BUFFER -> populate size
        raise RuntimeError("Error getting structure length (%d)" % res)
    # Now let's build our buffer
    pointer_type = PMIB_IPFORWARDTABLE
    buffer = create_string_buffer(size.value)
    pIpForwardTable = ctypes.cast(buffer, pointer_type)
    # And call GetAdaptersAddresses
    res = _GetIpForwardTable(pIpForwardTable, byref(size), True)
    if res != NO_ERROR:
        raise RuntimeError("Error retrieving table (%d)" % res)
    results = []
    for i in range(pIpForwardTable.contents.NumEntries):
        results.append(_struct_to_dict(pIpForwardTable.contents.Table[i]))
    del(pIpForwardTable)
    return results

### V2 ###


NET_IFINDEX = ULONG
NL_ROUTE_PROTOCOL = INT
NL_ROUTE_ORIGIN = INT


class NET_LUID(Structure):
    _fields_ = [("Value", ULONGLONG)]


class IP_ADDRESS_PREFIX(Structure):
    _fields_ = [("Prefix", SOCKADDR_INET),
                ("PrefixLength", UINT8)]


class MIB_IPFORWARD_ROW2(Structure):
    _fields_ = [("InterfaceLuid", NET_LUID),
                ("InterfaceIndex", NET_IFINDEX),
                ("DestinationPrefix", IP_ADDRESS_PREFIX),
                ("NextHop", SOCKADDR_INET),
                ("SitePrefixLength", UCHAR),
                ("ValidLifetime", ULONG),
                ("PreferredLifetime", ULONG),
                ("Metric", ULONG),
                ("Protocol", NL_ROUTE_PROTOCOL),
                ("Loopback", BOOLEAN),
                ("AutoconfigureAddress", BOOLEAN),
                ("Publish", BOOLEAN),
                ("Immortal", BOOLEAN),
                ("Age", ULONG),
                ("Origin", NL_ROUTE_ORIGIN)]


class MIB_IPFORWARD_TABLE2(Structure):
    _fields_ = [("NumEntries", ULONG),
                ("Table", MIB_IPFORWARD_ROW2 * ANY_SIZE)]


PMIB_IPFORWARD_TABLE2 = POINTER(MIB_IPFORWARD_TABLE2)

# Func

if not WINDOWS_XP:
    # GetIpForwardTable2 does not exist under Windows XP
    _GetIpForwardTable2 = WINFUNCTYPE(
        ULONG, USHORT,
        POINTER(PMIB_IPFORWARD_TABLE2))(
            ('GetIpForwardTable2', iphlpapi)
    )
    _FreeMibTable = WINFUNCTYPE(None, PMIB_IPFORWARD_TABLE2)(
        ('FreeMibTable', iphlpapi)
    )


def GetIpForwardTable2(AF=AF_UNSPEC):
    """Return all Windows routes (IPv4/IPv6) from iphlpapi"""
    if WINDOWS_XP:
        raise OSError("Not available on Windows XP !")
    table = PMIB_IPFORWARD_TABLE2()
    res = _GetIpForwardTable2(AF, byref(table))
    if res != NO_ERROR:
        raise RuntimeError("Error retrieving table (%d)" % res)
    results = []
    for i in range(table.contents.NumEntries):
        results.append(_struct_to_dict(table.contents.Table[i]))
    _FreeMibTable(table)
    return results
