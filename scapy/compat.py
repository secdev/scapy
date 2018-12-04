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

import scapy.modules.six as six

###########
# Python3 #
###########


def cmp_to_key(mycmp):
    # TODO remove me once all 'key=cmp_to_key(..)' has been fixed in utils6.py, automaton.py  # noqa: E501
    """Convert a cmp= function into a key= function.
    To use with sort()

    e.g: def stg_cmp(a, b):
            return a == b
    list.sort(key=cmp_to_key(stg_cmp))
    """
    class K(object):
        def __init__(self, obj, *args):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0
    return K


def cmp(a, b):
    """Old Python 2 function"""
    return (a > b) - (a < b)


def lambda_tuple_converter(func):
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


def raw(pkt):
    """Builds a packet.

    params:
     - pkt: the Packet instance to build
    returns: bytes (or string on Python 2) of the built packet

    This function is and will always remain cross-version compatible
    """
    return bytes(pkt)


if six.PY2:
    def orb(x):
        """Return ord(x) when necessary."""
        if isinstance(x, basestring):  # noqa: F821
            return ord(x)
        return x
else:
    def orb(x):
        """Return ord(x) when necessary."""
        if isinstance(x, (bytes, str)):
            return ord(x)
        return x


if six.PY2:
    def plain_str(x):
        """Convert basic byte objects to str"""
        return x if isinstance(x, basestring) else str(x)  # noqa: F821

    def chb(x):
        """Same than chr() but encode as bytes.

        """
        if isinstance(x, bytes):
            return x
        else:
            if hasattr(x, "__int__") and not isinstance(x, int):
                return bytes(chr(int(x)))
            return bytes(chr(x))
else:
    def plain_str(x):
        """Convert basic byte objects to str"""
        if isinstance(x, bytes):
            return x.decode('utf8')
        return x if isinstance(x, str) else str(x)

    def chb(x):
        """Same than chr() but encode as bytes.

        """
        if isinstance(x, bytes):
            return x
        else:
            if hasattr(x, "__int__") and not isinstance(x, int):
                return bytes([int(x)])
            return bytes([x])


def bytes_hex(x):
    """Hexify a str or a bytes object"""
    x = x.encode() if not isinstance(x, bytes) else x
    return binascii.b2a_hex(x)


def hex_bytes(x):
    """De-hexify a str or a byte object"""
    x = x.encode() if not isinstance(x, bytes) else x
    return binascii.a2b_hex(x)


def base64_bytes(x):
    """Turn base64 into bytes"""
    if six.PY2:
        return base64.decodestring(x)
    x = x.encode() if not isinstance(x, bytes) else x
    return base64.decodebytes(x)


def bytes_base64(x):
    """Turn bytes into base64"""
    if six.PY2:
        return base64.encodestring(x).replace('\n', '')
    x = x.encode() if not isinstance(x, bytes) else x
    return base64.encodebytes(x).replace(b'\n', b'')
