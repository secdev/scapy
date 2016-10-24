## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os
from sys import platform

LINUX = platform.startswith("linux")
OPENBSD = platform.startswith("openbsd")
FREEBSD = "freebsd" in platform
NETBSD = platform.startswith("netbsd")
DARWIN = platform.startswith("darwin")
SOLARIS = platform.startswith("sunos")
WINDOWS = platform.startswith("win32")
BSD = DARWIN or FREEBSD or OPENBSD or NETBSD

if WINDOWS:
    X86_64 = False
    ARM_64 = False
else:
    uname = os.uname()
    X86_64 = uname[4] == 'x86_64'
    ARM_64 = uname[4] == 'aarch64'

LOOPBACK_NAME = "lo" if LINUX else "lo0"
