# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# exposure_notification.py - Apple/Google Exposure Notification System
#
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) 2020 Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license
#
# scapy.contrib.description = Apple/Google Exposure Notification System (ENS)
# scapy.contrib.status = loads
"""
Apple/Google Exposure Notification System (ENS), formerly known as
Privacy-Preserving Contact Tracing Project.

This module parses the Bluetooth Low Energy beacon payloads used by the system.
This does **not** yet implement any cryptographic functionality.

More info:

* `Apple: Privacy-Preserving Contact Tracing`__
* `Google: Exposure Notifications`__
* `Wikipedia: Exposure Notification`__

__ https://www.apple.com/covid19/contacttracing/
__ https://www.google.com/covid19/exposurenotifications/
__ https://en.wikipedia.org/wiki/Exposure_Notification

Bluetooth protocol specifications:

* `v1.1`_ (April 2020)
* `v1.2`_ (April 2020)

.. _v1.1: https://blog.google/documents/58/Contact_Tracing_-_Bluetooth_Specification_v1.1_RYGZbKW.pdf
.. _v1.2: https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ExposureNotification-BluetoothSpecificationv1.2.pdf
"""  # noqa: E501

from scapy.fields import StrFixedLenField
from scapy.layers.bluetooth import EIR_Hdr, EIR_ServiceData16BitUUID, \
    EIR_CompleteList16BitServiceUUIDs, LowEnergyBeaconHelper
from scapy.packet import bind_layers, Packet


EXPOSURE_NOTIFICATION_UUID = 0xFD6F


class Exposure_Notification_Frame(Packet, LowEnergyBeaconHelper):
    """Apple/Google BLE Exposure Notification broadcast frame."""
    name = "Exposure Notification broadcast"

    fields_desc = [
        # Rolling Proximity Identifier
        StrFixedLenField("identifier", None, 16),
        # Associated Encrypted Metadata (added in v1.2)
        StrFixedLenField("metadata", None, 4),
    ]

    def build_eir(self):
        """Builds a list of EIR messages to wrap this frame."""

        return LowEnergyBeaconHelper.base_eir + [
            EIR_Hdr() / EIR_CompleteList16BitServiceUUIDs(svc_uuids=[
                EXPOSURE_NOTIFICATION_UUID]),
            EIR_Hdr() / EIR_ServiceData16BitUUID() / self
        ]


bind_layers(EIR_ServiceData16BitUUID, Exposure_Notification_Frame,
            svc_uuid=EXPOSURE_NOTIFICATION_UUID)
