## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Copyright (C) Gabriel Potter <gabriel@potter.fr>
## This program is published under a GPLv2 license

"""
Python 2 and 3 link classes.
"""

from __future__ import absolute_import
import codecs

import scapy.modules.six as six

###########
# Python3 #
###########

def cmp_to_key(mycmp):
    # TODO remove me once all 'key=cmp_to_key(..)' has been fixed in utils6.py, automaton.py
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

def orb(x):
    """Return ord(x) when necessary.
    Python 3 compatible.
    
    """
    if isinstance(x, (str, bytes)):
        return ord(x)
    else:
        return x

if six.PY2:
    def raw(x):
        """Convert a str, a packet to bytes"""
        if x is None:
            return None
        if hasattr(x, "__bytes__"):
            return x.__bytes__()
        try:
            return chr(x)
        except (ValueError, TypeError):
            return str(x)

    def plain_str(x):
        """Convert basic byte objects to str"""
        return x

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
    def raw(x):
        """Convert a str, an int, a list of ints, a packet to bytes"""
        try:
            return bytes(x)
        except TypeError:
            return bytes(x, encoding="utf8")

    def plain_str(x):
        """Convert basic byte objects to str"""
        if isinstance(x, bytes):
            return x.decode('utf8')
        return x

    def chb(x):
        """Same than chr() but encode as bytes.

        """
        if isinstance(x, bytes):
            return x
        else:
            if hasattr(x, "__int__") and not isinstance(x, int):
                return bytes([int(x)])
            return bytes([x])

def bytes_codec(x, codec, force_str=False):
    """Encode a str or a bytes object with a codec"""
    if six.PY2:
        return str(x).encode(codec)
    else:
        hex_ = codecs.getencoder(codec)(raw(x))[0]
        if force_str:
            hex_ = hex_.decode('utf8')
        return hex_

def codec_bytes(x, codec):
    """Decode a str or a byte object with a codec"""
    if six.PY2:
        return str(x).decode(codec)
    else:
        return codecs.getdecoder(codec)(x)[0]

def bytes_hex(x, force_str=False):
    """Hexify a str or a bytes object"""
    return bytes_codec(x, "hex", force_str)

def hex_bytes(x):
    """De-hexify a str or a byte object"""
    return codec_bytes(x, "hex")

def base64_bytes(x):
    """Turn base64 into bytes"""
    return codec_bytes(raw(x), "base64")
