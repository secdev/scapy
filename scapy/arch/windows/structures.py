# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
API calls to Windows DLLs
"""

import ctypes
import ctypes.wintypes
from ctypes import Structure, POINTER, byref
import os
import sys

from scapy.config import conf

DWORD = ctypes.wintypes.DWORD
BOOL = ctypes.wintypes.BOOL
ULONG = ctypes.wintypes.ULONG
HANDLE = ctypes.wintypes.HANDLE
LPWSTR = ctypes.wintypes.LPWSTR

_winapi_SetConsoleTitle = ctypes.windll.kernel32.SetConsoleTitleW
_winapi_SetConsoleTitle.restype = BOOL
_winapi_SetConsoleTitle.argtypes = [LPWSTR]

_winapi_GetHandleInformation = ctypes.windll.kernel32.GetHandleInformation
_winapi_GetHandleInformation.restype = BOOL
_winapi_GetHandleInformation.argtypes = [HANDLE, POINTER(DWORD)]

_winapi_SetHandleInformation = ctypes.windll.kernel32.SetHandleInformation
_winapi_SetHandleInformation.restype = BOOL
_winapi_SetHandleInformation.argtypes = [HANDLE, DWORD, DWORD]


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
            flags = DWORD()
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

# UTILS


def _struct_to_dict(struct_obj):
    results = {}
    for fname, ctype in struct_obj.__class__._fields_:
        val = getattr(struct_obj, fname)
        if issubclass(ctype, Structure):
            results[fname] = _struct_to_dict(val)
        else:
            results[fname] = val
    return results

# ICMP STATS


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

# LOAD IPHLPAPI


try:
    system32_path = os.environ["WINDIR"] + "\\System32"

    ctypes.windll.kernel32.SetDllDirectoryW(system32_path)
    iphlpapi = ctypes.windll.LoadLibrary(system32_path + "\\IPHLPAPI.dll")

    iphlpapi.GetIcmpStatistics.restype = ULONG
    iphlpapi.GetIcmpStatistics.argtypes = [POINTER(MIB_ICMP)]
    _iphlpapi_supported = True
except Exception:
    _iphlpapi_supported = False


def _GetIcmpStatistics():
    """Return all Windows ICMP stats from iphlpapi"""
    if not _iphlpapi_supported:
        raise OSError("IPHLPAPI.dll not available !")
    statistics = MIB_ICMP()
    iphlpapi.GetIcmpStatistics(byref(statistics))
    results = _struct_to_dict(statistics)
    del(statistics)
    return results

# XXX The iphlpapi module is a goldmine. TODO: implement and use
#   - GetIfTable
#   - GetAdaptersInfo
#   - GetIpAddrTable
# so that we can replace the Powershell calls.
# XXX Side note: check XP compatibility
