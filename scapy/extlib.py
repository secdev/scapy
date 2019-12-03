# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
External link to programs
"""

import os
import subprocess
from scapy.error import log_loading

# Notice: this file must not be called before main.py, if started
# in interactive mode, because it needs to be called after the
# logger has been setup, to be able to print the warning messages

# MATPLOTLIB

try:
    from matplotlib import get_backend as matplotlib_get_backend
    from matplotlib import pyplot as plt
    from matplotlib.lines import Line2D
    MATPLOTLIB = 1
    if "inline" in matplotlib_get_backend():
        MATPLOTLIB_INLINED = 1
    else:
        MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = {"marker": "+"}
# RuntimeError to catch gtk "Cannot open display" error
except (ImportError, RuntimeError):
    plt = None
    Line2D = None
    MATPLOTLIB = 0
    MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = dict()
    log_loading.info("Can't import matplotlib. Won't be able to plot.")

# PYX


def _test_pyx():
    """Returns if PyX is correctly installed or not"""
    try:
        with open(os.devnull, 'wb') as devnull:
            r = subprocess.check_call(["pdflatex", "--version"],
                                      stdout=devnull, stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError):
        return False
    else:
        return r == 0


try:
    import pyx  # noqa: F401
    if _test_pyx():
        PYX = 1
    else:
        log_loading.info("PyX dependencies are not installed ! Please install TexLive or MikTeX.")  # noqa: E501
        PYX = 0
except ImportError:
    log_loading.info("Can't import PyX. Won't be able to use psdump() or pdfdump().")  # noqa: E501
    PYX = 0
