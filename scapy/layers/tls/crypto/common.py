# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
TLS ciphers.
"""


class CipherError(Exception):
    """
    Raised when .decrypt() or .auth_decrypt() fails.
    """
    pass
