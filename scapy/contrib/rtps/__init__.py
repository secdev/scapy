# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2021 Trend Micro Incorporated

"""
Real-Time Publish-Subscribe Protocol (RTPS) dissection
"""

# scapy.contrib.description = Real-Time Publish-Subscribe Protocol (RTPS)
# scapy.contrib.status = loads
# scapy.contrib.name = rtps

from scapy.contrib.rtps.rtps import *  # noqa F403,F401
from scapy.contrib.rtps.pid_types import * # noqa F403,F401
