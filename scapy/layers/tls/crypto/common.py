# This file is part of Scapy
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
TLS ciphers.
"""


class CipherError(Exception):
    """
    Raised when .decrypt() or .auth_decrypt() fails.
    """
    pass
