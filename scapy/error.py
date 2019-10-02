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


class Scapy_Exception(Exception):
    pass


class ScapyInvalidPlatformException(Scapy_Exception):
    pass


class ScapyFreqFilter(logging.Filter):
    def __init__(self):
        logging.Filter.__init__(self)
        self.warning_table = {}

    def filter(self, record):
        from scapy.config import conf
        wt = conf.warning_threshold
        if wt > 0:
            stk = traceback.extract_stack()
            caller = None
            for f, l, n, c in stk:
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
                    return 0
            self.warning_table[caller] = (tm, nb)
        return 1


# Inspired from python-colorbg (MIT)
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
        message = super(ScapyColoredFormatter, self).format(record)
        from scapy.config import conf
        message = conf.color_theme.format(
            message,
            self.levels_colored[record.levelname]
        )
        return message


log_scapy = logging.getLogger("scapy")
log_scapy.setLevel(logging.WARNING)
log_scapy.addHandler(logging.NullHandler())
# logs at runtime
log_runtime = logging.getLogger("scapy.runtime")
log_runtime.addFilter(ScapyFreqFilter())
# logs in interactive functions
log_interactive = logging.getLogger("scapy.interactive")
log_interactive.setLevel(logging.DEBUG)
# logs when loading Scapy
log_loading = logging.getLogger("scapy.loading")


def warning(x, *args, **kargs):
    """
    Prints a warning during runtime.
    """
    log_runtime.warning(x, *args, **kargs)
