# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = ETSI ITS V2X ASN.1 messages (UPER)
# scapy.contrib.status = library

"""
ETSI ITS V2X ASN.1 messages (UPER).

Implements CAM, DENM, IVIM, SPATEM and MAPEM from ETSI TS 102 637 / TS 103 301.

Load explicitly::

    load_contrib("automotive.v2x")
"""

from scapy.contrib.automotive.v2x.packets import (
    CAM,
    DENM,
    IVIM,
    MAPEM,
    SPATEM,
)

__all__ = ["CAM", "DENM", "IVIM", "SPATEM", "MAPEM"]
