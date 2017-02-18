## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os, inspect
from sys import platform, maxsize
import platform as platform_lib
from scapy.error import *

import subprocess

try:
    from matplotlib import get_backend as matplotlib_get_backend
    import matplotlib.pyplot as plt
    MATPLOTLIB = 1
    if "inline" in matplotlib_get_backend():
        MATPLOTLIB_INLINED = 1
    else:
        MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = {"marker": "+"}
# RuntimeError to catch gtk "Cannot open display" error
except (ImportError, RuntimeError):
    plt = None
    MATPLOTLIB = 0
    MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = dict()
    log_loading.info("Can't import matplotlib. Won't be able to plot.")

def test_pyx():
    """Returns if PyX is correctly installed or not"""
    try:
        with open(os.devnull, 'wb') as devnull:
            r = subprocess.check_call(["pdflatex", "--version"], stdout=devnull, stderr=subprocess.STDOUT)
    except:
        return False
    else:
        return r == 0

try:
    import pyx
    if test_pyx():
        PYX = 1
    else:
        log_loading.warning("PyX dependencies are not installed ! Please install TexLive or MikTeX.")
        PYX = 0
except ImportError:
    log_loading.info("Can't import PyX. Won't be able to use psdump() or pdfdump().")
    PYX = 0


LINUX = platform.startswith("linux")
OPENBSD = platform.startswith("openbsd")
FREEBSD = "freebsd" in platform
NETBSD = platform.startswith("netbsd")
DARWIN = platform.startswith("darwin")
SOLARIS = platform.startswith("sunos")
WINDOWS = platform.startswith("win32")
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
else:
    uname = os.uname()
    LOOPBACK_NAME = "lo" if LINUX else "lo0"

def parent_function():
    return inspect.getouterframes(inspect.currentframe())
