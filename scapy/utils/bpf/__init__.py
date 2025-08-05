# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
BPF Filter Builder utilities for structured filter creation.

This module provides builder classes for creating BPF filter expressions
in a programmatic, type-safe way instead of manual string concatenation.

Example:
    >>> from scapy.utils.bpf import WiFiBPFBuilder
    >>> builder = WiFiBPFBuilder("aa:bb:cc:dd:ee:ff")
    >>> filter_str = builder.beacon_frames().build()
    >>> print(filter_str)
    wlan addr3 aa:bb:cc:dd:ee:ff and wlan type mgt subtype beacon

    Advanced usage:
    >>> filter_str = (WiFiBPFBuilder("aa:bb:cc:dd:ee:ff")
    ...                .management_frames()
    ...                .multiple_subtypes([ManagementSubtype.BEACON, 
    ...                                  ManagementSubtype.PROBE_RESPONSE])
    ...                .from_ap()
    ...                .build())
"""

from scapy.utils.bpf.wifi import (
    WiFiBPFBuilder,
    FrameType,
    ManagementSubtype,
    ControlSubtype, 
    DataSubtype,
    WiFiField,
    DSFlags,
    WiFiConstants
)

__all__ = [
    'WiFiBPFBuilder', 
    'FrameType', 
    'ManagementSubtype',
    'ControlSubtype',
    'DataSubtype', 
    'WiFiField',
    'DSFlags',
    'WiFiConstants'
]
