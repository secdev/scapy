# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = DEPRECATED - IGMPv3
# scapy.contrib.status = deprecated

import warnings

from scapy.layers.igmp import (  # noqa: F401
    IGMPv3 as IGMPv3New,
    IGMPv3_MQ,
    IGMPv3_MR,
    IGMPv3_MR_Group,
    IGMPv3_MRA,
)
from scapy.packet import Packet

warnings.warn(
    "scapy.contrib.igmpv3 is deprecated. Please use scapy.layers.igmp instead !",
    DeprecationWarning,
)

# Retro-compatibility


class IGMPv3(IGMPv3New):
    """Compatibility with the pre-2.8 IGMPv3 header/payload stack."""

    def _stacked_full_message(self, payload):
        """True when payload is already a complete IGMPv3 message.

        contrib.igmpv3 aliases IGMPv3mr to IGMPv3_MR. Code written for 2.7
        still does IGMPv3()/IGMPv3mr(), which used to be one report. IGMPv3_MR
        already includes the header, so keep that message and drop this one.
        """
        return (
            type(self) is IGMPv3
            and isinstance(payload, IGMPv3New)
            and type(payload) not in (IGMPv3, IGMPv3New)
        )

    def add_payload(self, payload):
        # IP()/IGMPv3()/IGMPv3_MR() lands here: IP.add_payload delegates to us.
        if self._stacked_full_message(payload) and self.underlayer is not None:
            under = self.underlayer
            under.remove_payload()
            under.add_payload(payload)
            return
        super(IGMPv3, self).add_payload(payload)

    def __div__(self, other):
        if isinstance(other, Packet) and self._stacked_full_message(other):
            other = other.copy()
            if self.underlayer is not None:
                under = self.underlayer.copy()
                under.remove_payload()
                under.add_payload(other)
                return under
            return other
        return super(IGMPv3, self).__div__(other)

    __truediv__ = __div__


IGMPv3mq = IGMPv3_MQ
IGMPv3gr = IGMPv3_MR_Group
IGMPv3mr = IGMPv3_MR
IGMPv3mra = IGMPv3_MRA
