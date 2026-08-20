# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = DEPRECATED - IGMP
# scapy.contrib.status = deprecated

import warnings

from scapy.layers.igmp import IGMP  # noqa: F401

warnings.warn(
    "scapy.contrib.igmp is deprecated. Please use scapy.layers.igmp instead !",
    DeprecationWarning,
)
