# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Shared two's-complement INTEGER helpers (X.690 / X.691 / X.696)."""

from typing import Tuple


def twos_complement_octets(value):
    # type: (int) -> Tuple[int, int]
    """Shortest two's-complement width and unsigned payload.

    A negative value needs one bit less than its magnitude suggests, as
    ``-2**(8n-1)`` still fits in ``n`` octets, hence the increment before
    measuring (X.691 11.4 / X.696 10.4).
    """
    magnitude = value + 1 if value < 0 else value
    number_of_bytes = (magnitude.bit_length() + 8) // 8
    masked = value & ((1 << (8 * number_of_bytes)) - 1)
    return number_of_bytes, masked


def from_twos_complement(masked, number_of_bytes):
    # type: (int, int) -> int
    """Interpret ``masked`` as a ``number_of_bytes``-octet two's complement."""
    sign_bit = 1 << (8 * number_of_bytes - 1)
    if masked & sign_bit:
        return masked - (1 << (8 * number_of_bytes))
    return masked
