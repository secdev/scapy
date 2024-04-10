# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = ICMP Extensions (deprecated)
# scapy.contrib.status = deprecated

__all__ = [
    "ICMPExtensionObject",
    "ICMPExtensionHeader",
    "ICMPExtensionInterfaceInformation",
    "ICMPExtensionMPLS",
]

import warnings

from scapy.layers.inet import (
    ICMPExtension_Object as ICMPExtensionObject,
    ICMPExtension_Header as ICMPExtensionHeader,
    ICMPExtension_InterfaceInformation as ICMPExtensionInterfaceInformation,
)
from scapy.contrib.mpls import (
    ICMPExtension_MPLS as ICMPExtensionMPLS,
)

warnings.warn(
    "scapy.contrib.icmp_extensions is deprecated. Behavior has changed ! "
    "Use scapy.layers.inet",
    DeprecationWarning
)
