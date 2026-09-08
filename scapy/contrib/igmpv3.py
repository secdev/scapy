# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = DEPRECATED - IGMPv3
# scapy.contrib.status = deprecated

import warnings

from scapy.layers.igmp import (  # noqa: F401
    IGMPv3,
    IGMPv3_MQ,
    IGMPv3_MR_Group,
    IGMPv3_MR,
    IGMPv3_MRA,
)

warnings.warn(
    "scapy.contrib.igmpv3 is deprecated. Please use scapy.layers.igmp instead !",
    DeprecationWarning,
)

# Retro-compatibility

IGMPv3mq = IGMPv3_MQ
IGMPv3gr = IGMPv3_MR_Group
IGMPv3mr = IGMPv3_MR
IGMPv3mra = IGMPv3_MRA
