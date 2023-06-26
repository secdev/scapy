# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
#
# scapy.contrib.description = AltBeacon BLE proximity beacon
# scapy.contrib.status = loads
"""
scapy.contrib.altbeacon - AltBeacon Bluetooth LE proximity beacons.

The AltBeacon specification can be found at: https://github.com/AltBeacon/spec
"""

from scapy.fields import (
    ByteField,
    MayEnd,
    ShortField,
    SignedByteField,
    StrFixedLenField,
)
from scapy.layers.bluetooth import EIR_Hdr, EIR_Manufacturer_Specific_Data, \
    UUIDField, LowEnergyBeaconHelper
from scapy.packet import Packet


# When building beacon frames, one should use their own manufacturer ID.
#
# However, most software (including the AltBeacon SDK) requires explicitly
# registering particular manufacturer IDs to listen to, and the only ID used is
# that of Radius Networks (the developer of the specification).
#
# To maximise compatibility, Scapy's implementation of
# LowEnergyBeaconHelper.build_eir (for constructing frames) uses Radius
# Networks' manufacturer ID.
#
# Scapy's implementation of AltBeacon **does not** require a specific
# manufacturer ID to detect AltBeacons - it uses
# EIR_Manufacturer_Specific_Data.register_magic_payload.
RADIUS_NETWORKS_MFG = 0x0118


class AltBeacon(Packet, LowEnergyBeaconHelper):
    """
    AltBeacon broadcast frame type.

    https://github.com/AltBeacon/spec
    """
    name = "AltBeacon"
    magic = b"\xBE\xAC"
    fields_desc = [
        StrFixedLenField("header", magic, len(magic)),

        # The spec says this is 20 bytes, with >=16 bytes being an
        # organisational unit-specific identifier. However, the Android library
        # treats this as UUID + uint16 + uint16.
        UUIDField("id1", None),

        # Local identifier
        ShortField("id2", None),
        ShortField("id3", None),

        MayEnd(SignedByteField("tx_power", None)),
        ByteField("mfg_reserved", None),
    ]

    @classmethod
    def magic_check(cls, payload):
        """
        Checks if the given payload is for us (starts with our magic string).
        """
        return payload.startswith(cls.magic)

    def build_eir(self):
        """Builds a list of EIR messages to wrap this frame."""

        # Note: Company ID is not required by spec, but most tools only look
        # for manufacturer-specific data with Radius Networks' manufacturer ID.
        return LowEnergyBeaconHelper.base_eir + [
            EIR_Hdr() / EIR_Manufacturer_Specific_Data(
                company_id=RADIUS_NETWORKS_MFG) / self
        ]


EIR_Manufacturer_Specific_Data.register_magic_payload(AltBeacon)
