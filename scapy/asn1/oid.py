# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Shared OBJECT IDENTIFIER arc handling (X.690 section 8.19.4)."""

from typing import List  # noqa: F401


def oid_decode_first_arc(first):
    # type: (int) -> List[int]
    """Split the first subidentifier into two registration arcs."""
    if first < 40:
        return [0, first]
    if first < 80:
        return [1, first - 40]
    return [2, first - 80]


def oid_subidentifiers_to_dotted(lst):
    # type: (List[int]) -> bytes
    if not lst:
        return b""
    arcs = oid_decode_first_arc(lst[0]) + lst[1:]
    return b".".join(str(k).encode("ascii") for k in arcs)


def oid_dotted_to_subidentifiers(oid):
    # type: (bytes) -> List[int]
    if not oid:
        return []
    parts = [int(x) for x in oid.split(b".")]
    if len(parts) >= 2:
        return [40 * parts[0] + parts[1]] + parts[2:]
    return parts
