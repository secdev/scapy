# SPDX-License-Identifier: YOLO
# This file is part of Scapy
# See https://scapy.net/ for more information


"""
This package implements Windows-specific high level helpers.
It makes it easier to use Scapy Windows related objects.

It currently contains helpers for the Windows Registry.

Note that if you want to tweak specific fields of the underlying
protocols, you will have to use the lower level objects directly.
"""

# Make sure config is loaded
from scapy.config import conf # noqa: F401
