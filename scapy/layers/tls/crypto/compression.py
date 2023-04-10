# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016 Maxence Tury

"""
TLS compression.
"""

import zlib

from scapy.error import warning


_tls_compression_algs = {}
_tls_compression_algs_cls = {}


class _GenericCompMetaclass(type):
    """
    Compression classes are automatically registered through this metaclass.
    """
    def __new__(cls, name, bases, dct):
        the_class = super(_GenericCompMetaclass, cls).__new__(cls, name,
                                                              bases, dct)
        comp_name = dct.get("name")
        val = dct.get("val")
        if comp_name:
            _tls_compression_algs[val] = comp_name
            _tls_compression_algs_cls[val] = the_class
        return the_class


class _GenericComp(metaclass=_GenericCompMetaclass):
    pass


class Comp_NULL(_GenericComp):
    """
    The default and advised compression method for TLS: doing nothing.
    """
    name = "null"
    val = 0

    def compress(self, s):
        return s

    def decompress(self, s):
        return s


class Comp_Deflate(_GenericComp):
    """
    DEFLATE algorithm, specified for TLS by RFC 3749.
    """
    name = "deflate"
    val = 1

    def compress(self, s):
        tmp = self.compress_state.compress(s)
        tmp += self.compress_state.flush(zlib.Z_FULL_FLUSH)
        return tmp

    def decompress(self, s):
        return self.decompress_state.decompress(s)

    def __init__(self):
        self.compress_state = zlib.compressobj()
        self.decompress_state = zlib.decompressobj()


class Comp_LZS(_GenericComp):
    """
    Lempel-Zic-Stac (LZS) algorithm, specified for TLS by RFC 3943.
    XXX No support for now.
    """
    name = "LZS"
    val = 64

    def compress(self, s):
        warning("LZS Compression algorithm is not implemented yet")
        return s

    def decompress(self, s):
        warning("LZS Compression algorithm is not implemented yet")
        return s
