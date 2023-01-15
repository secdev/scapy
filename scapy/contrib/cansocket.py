# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = CANSocket Utils
# scapy.contrib.status = loads

"""
CANSocket.
"""

from scapy.error import log_loading
from scapy.consts import LINUX
from scapy.config import conf

PYTHON_CAN = False

try:
    if conf.contribs['CANSocket']['use-python-can']:
        from can import BusABC as can_BusABC    # noqa: F401
        PYTHON_CAN = True
except ImportError:
    log_loading.info("Can't import python-can.")
except KeyError:
    log_loading.info("Configuration 'conf.contribs['CANSocket'] not found.")


if PYTHON_CAN:
    log_loading.info("Using python-can CANSockets.\nSpecify 'conf.contribs['CANSocket'] = {'use-python-can': False}' to enable native CANSockets.")  # noqa: E501
    from scapy.contrib.cansocket_python_can import (PythonCANSocket, CANSocket)  # noqa: E501 F401

elif LINUX and not conf.use_pypy:
    log_loading.info("Using native CANSockets.\nSpecify 'conf.contribs['CANSocket'] = {'use-python-can': True}' to enable python-can CANSockets.")  # noqa: E501
    from scapy.contrib.cansocket_native import (NativeCANSocket, CANSocket)  # noqa: E501 F401

else:
    log_loading.info("No CAN support available. Install python-can or use Linux and python3.")  # noqa: E501
