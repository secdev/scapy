# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016 Maxence Tury

"""
TLS ciphers.
"""

# in order to avoid circular dependencies.
from scapy.layers.tls.crypto.cipher_aead import _tls_aead_cipher_algs
from scapy.layers.tls.crypto.cipher_block import _tls_block_cipher_algs
from scapy.layers.tls.crypto.cipher_stream import _tls_stream_cipher_algs

_tls_cipher_algs = {}
_tls_cipher_algs.update(_tls_block_cipher_algs)
_tls_cipher_algs.update(_tls_stream_cipher_algs)
_tls_cipher_algs.update(_tls_aead_cipher_algs)
