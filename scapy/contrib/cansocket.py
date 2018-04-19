# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license


"""
CANSocket.
"""

from scapy.error import log_loading
from scapy.consts import LINUX
from scapy.config import conf
import scapy.modules.six as six

PYTHON_CAN = False

try:
    if conf.contribs['CANSocket']['use-python-can']:
        from can import BusABC as can_BusABC    # noqa: F401
        PYTHON_CAN = True
except ImportError:
    log_loading.info("Can't import python-can.")
except KeyError:
    log_loading.info("Specify 'conf.contribs['CANSocket'] = "
                     "{'use-python-can': True}' to enable python-can.")


if PYTHON_CAN:
    from scapy.contrib.cansocket_python_can import (CANSocket,   # noqa: F401
                                                    srcan, CANSocketTimeoutElapsed, CAN_FRAME_SIZE, CAN_INV_FILTER)
elif LINUX and six.PY3:
    log_loading.info("Use native CANSocket. Specify "
                     "'conf.contribs['CANSocket'] = "
                     "{'use-python-can': True}' to enable python-can.")
    from scapy.contrib.cansocket_native import (CANSocket,   # noqa: F401
                                                srcan, CAN_FRAME_SIZE, CAN_INV_FILTER)
else:
    log_loading.info("No CAN support available. Install python-can or "
                     "use Linux and python3.")
