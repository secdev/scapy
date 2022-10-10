# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
External link to pyx
"""

import os
import subprocess
from scapy.error import log_loading

# Notice: this file must not be called before main.py, if started
# in interactive mode, because it needs to be called after the
# logger has been setup, to be able to print the warning messages

__all__ = [
    "PYX",
]

# PYX


def _test_pyx():
    # type: () -> bool
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
