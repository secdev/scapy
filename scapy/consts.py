# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
This file contains constants
"""

from sys import byteorder, platform, maxsize
import platform as platform_lib

__all__ = [
    "LINUX",
    "OPENBSD",
    "FREEBSD",
    "NETBSD",
    "DARWIN",
    "SOLARIS",
    "WINDOWS",
    "WINDOWS_XP",
    "BSD",
    "IS_64BITS",
    "BIG_ENDIAN",
]

LINUX = platform.startswith("linux")
OPENBSD = platform.startswith("openbsd")
FREEBSD = "freebsd" in platform
NETBSD = platform.startswith("netbsd")
DARWIN = platform.startswith("darwin")
SOLARIS = platform.startswith("sunos")
WINDOWS = platform.startswith("win32")
WINDOWS_XP = platform_lib.release() == "XP"
BSD = DARWIN or FREEBSD or OPENBSD or NETBSD
# See https://docs.python.org/3/library/platform.html#cross-platform
IS_64BITS = maxsize > 2**32
BIG_ENDIAN = byteorder == 'big'
# LOOPBACK_NAME moved to conf.loopback_name
