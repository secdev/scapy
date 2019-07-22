# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Python 2 and 3 link classes.
"""

from __future__ import absolute_import
import base64
import binascii
import gzip
import struct

import scapy.modules.six as six
from typing import Any
from typing import Union
from typing import Callable

###########
# Python3 #
###########


def lambda_tuple_converter(func):
    # type: (Callable) -> Callable
    """
    Converts a Python 2 function as
      lambda (x,y): x + y
    In the Python 3 format:
      lambda x,y : x + y
    """
    if func is not None and func.__code__.co_argcount == 1:
        return lambda *args: func(args[0] if len(args) == 1 else args)
    else:
        return func


if six.PY2:
    bytes_encode = plain_str = str
    chb = lambda x: x if isinstance(x, str) else chr(x)
    orb = ord

    def raw(x):
        """Builds a packet and returns its bytes representation.
        This function is and always be cross-version compatible"""
        if hasattr(x, "__bytes__"):
            return x.__bytes__()
        return bytes(x)
else:
    def raw(x):
        # type: (Any) -> bytes
        """Builds a packet and returns its bytes representation.
        This function is and always be cross-version compatible"""
        return bytes(x)

    def bytes_encode(x):
        # type: (Any) -> bytes
        """Ensure that the given object is bytes.
        If the parameter is a packet, raw() should be preferred.
        """
        if isinstance(x, str):
            return x.encode()
        return bytes(x)

    def plain_str(x):
        # type: (bytes) -> str
        """Convert basic byte objects to str"""
        if isinstance(x, bytes):
            return x.decode(errors="ignore")
        return str(x)

    def chb(x):
        # type: (int) -> bytes
        """Same than chr() but encode as bytes."""
        return struct.pack("!B", x)

    def orb(x):
        # type: (Union[int, str]) -> int
        """Return ord(x) when not already an int."""
        if isinstance(x, int):
            return x
        return ord(x)


def bytes_hex(x):
    # type: (bytes) -> bytes
    """Hexify a str or a bytes object"""
    return binascii.b2a_hex(bytes_encode(x))


def hex_bytes(x):
    # type: (str) -> bytes
    """De-hexify a str or a byte object"""
    return binascii.a2b_hex(bytes_encode(x))


def base64_bytes(x):
    # type: (Union[bytes, str]) -> bytes
    """Turn base64 into bytes"""
    if six.PY2:
        return base64.decodestring(x)
    return base64.decodebytes(bytes_encode(x))


def bytes_base64(x):
    # type: (bytes) -> bytes
    """Turn bytes into base64"""
    if six.PY2:
        return base64.encodestring(x).replace('\n', '')
    return base64.encodebytes(bytes_encode(x)).replace(b'\n', b'')


if six.PY2:
    from StringIO import StringIO

    def gzip_decompress(x):
        """Decompress using gzip"""
        with gzip.GzipFile(fileobj=StringIO(x), mode='rb') as fdesc:
            return fdesc.read()

    def gzip_compress(x):
        """Compress using gzip"""
        buf = StringIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as fdesc:
            fdesc.write(x)
        return buf.getvalue()
else:
    gzip_decompress = gzip.decompress
    gzip_compress = gzip.compress
