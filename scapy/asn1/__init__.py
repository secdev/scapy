# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Package holding ASN.1 related modules.
"""

# We do not import mib.py because it is more bound to scapy and
# less prone to be used in a standalone fashion
__all__ = ["asn1", "ber"]
