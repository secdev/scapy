# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

import os
from sys import platform, maxsize
import platform as platform_lib

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

if WINDOWS:
    try:
        if float(platform_lib.release()) >= 8.1:
            LOOPBACK_NAME = "Microsoft KM-TEST Loopback Adapter"
        else:
            LOOPBACK_NAME = "Microsoft Loopback Adapter"
    except ValueError:
        LOOPBACK_NAME = "Microsoft Loopback Adapter"
    # Will be different on Windows
    LOOPBACK_INTERFACE = None
else:
    uname = os.uname()
    LOOPBACK_NAME = "lo" if LINUX else "lo0"
    LOOPBACK_INTERFACE = LOOPBACK_NAME
