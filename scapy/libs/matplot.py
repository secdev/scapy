# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
External link to matplotlib
"""

from scapy.error import log_loading

# Notice: this file must not be called before main.py, if started
# in interactive mode, because it needs to be called after the
# logger has been setup, to be able to print the warning messages

__all__ = [
    "Line2D",
    "MATPLOTLIB",
    "MATPLOTLIB_DEFAULT_PLOT_KARGS",
    "MATPLOTLIB_INLINED",
    "plt",
]

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
except (ImportError, RuntimeError) as ex:
    plt = None
    Line2D = None
    MATPLOTLIB = 0
    MATPLOTLIB_INLINED = 0
    MATPLOTLIB_DEFAULT_PLOT_KARGS = dict()
    log_loading.info("Can't import matplotlib: %s. Won't be able to plot.", ex)
