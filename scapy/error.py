# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Logging subsystem and basic exception class.
"""

#############################
#     Logging subsystem     #
#############################


import logging
import traceback
import time
import warnings

from scapy.consts import WINDOWS
import scapy.modules.six as six

# Typing imports
from logging import LogRecord
from scapy.compat import (
    Any,
    Dict,
    Tuple,
)


class Scapy_Exception(Exception):
    pass


class ScapyInvalidPlatformException(Scapy_Exception):
    pass


class ScapyNoDstMacException(Scapy_Exception):
    pass


class ScapyFreqFilter(logging.Filter):
    def __init__(self):
        # type: () -> None
        logging.Filter.__init__(self)
        self.warning_table = {}  # type: Dict[int, Tuple[float, int]]  # noqa: E501

    def filter(self, record):
        # type: (LogRecord) -> bool
        from scapy.config import conf
        # Levels below INFO are not covered
        if record.levelno <= logging.INFO:
            return True
        wt = conf.warning_threshold
        if wt > 0:
            stk = traceback.extract_stack()
            caller = 0  # type: int
            for _, l, n, _ in stk:
                if n == 'warning':
                    break
                caller = l
            tm, nb = self.warning_table.get(caller, (0, 0))
            ltm = time.time()
            if ltm - tm > wt:
                tm = ltm
                nb = 0
            else:
                if nb < 2:
                    nb += 1
                    if nb == 2:
                        record.msg = "more " + record.msg
                else:
                    return False
            self.warning_table[caller] = (tm, nb)
        return True


class ScapyColoredFormatter(logging.Formatter):
    """A subclass of logging.Formatter that handles colors."""
    levels_colored = {
        'DEBUG': 'reset',
        'INFO': 'reset',
        'WARNING': 'bold+yellow',
        'ERROR': 'bold+red',
        'CRITICAL': 'bold+white+bg_red'
    }

    def format(self, record):
        # type: (LogRecord) -> str
        message = super(ScapyColoredFormatter, self).format(record)
        from scapy.config import conf
        message = conf.color_theme.format(
            message,
            self.levels_colored[record.levelname]
        )
        return message


if WINDOWS:
    # colorama is bundled within IPython, but
    # logging.StreamHandler will be overwritten when called,
    # so we can't wait for IPython to call it
    try:
        import colorama
        colorama.init()
    except ImportError:
        pass

# get Scapy's master logger
log_scapy = logging.getLogger("scapy")
# override the level if not already set
if log_scapy.level == logging.NOTSET:
    log_scapy.setLevel(logging.WARNING)
# add a custom handler controlled by Scapy's config
_handler = logging.StreamHandler()
_handler.setFormatter(
    ScapyColoredFormatter(
        "%(levelname)s: %(message)s",
    )
)
log_scapy.addHandler(_handler)
# logs at runtime
log_runtime = logging.getLogger("scapy.runtime")
log_runtime.addFilter(ScapyFreqFilter())
# logs in interactive functions
log_interactive = logging.getLogger("scapy.interactive")
log_interactive.setLevel(logging.DEBUG)
# logs when loading Scapy
log_loading = logging.getLogger("scapy.loading")

# Apply warnings filters for python 2
if six.PY2:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cryptography import CryptographyDeprecationWarning
        warnings.filterwarnings("ignore",
                                category=CryptographyDeprecationWarning)
    except ImportError:
        pass


def warning(x, *args, **kargs):
    # type: (str, *Any, **Any) -> None
    """
    Prints a warning during runtime.
    """
    log_runtime.warning(x, *args, **kargs)
