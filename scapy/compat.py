## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
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
    """Old python 2 function"""
    return (a > b) - (a < b)

def orb(x):
    """Same than orb() but handle python 3 too
    Even if unnecessary.

    """
    if type(x) is str or type(x) is bytes:
        return ord(x)
    else:
        return x

def chb(x):
    """Same than chr() but handle python 3 too
    Even if unnecessary.

    """
    if type(x) is str or type(x) is bytes:
        return x
    else:
        return chr(x)

if six.PY3:
    def raw(x):
        """Convert a str, an int, a list of ints, a packet to bytes"""
        if x is None:
            return None
        if isinstance(x, list):
            return bytes(x)
        if isinstance(x, int):
             return bytes([x])
        if isinstance(x, bytes):
            return x
        if hasattr(x, "__bytes__"):
            return bytes(x)
        return bytes(x, "utf8")
    def plain_str(x):
        """Convert basic byte objects to str"""
        if isinstance(x, bytes):
            return x.decode('utf8')
        return x
else:
    def raw(x):
        """Convert a str, an int, a list of ints, a packet to bytes"""
        if x is None:
            return None
        if isinstance(x, str):
            return x
        if isinstance(x, int):
            try:
                return chr(x)
            except ValueError:
                # Ignore out of range strings
                pass
        if isinstance(x, list):
            return "".join([chr(y) for y in x])
        if hasattr(x, "__bytes__"):
            return x.__bytes__()
        return str(x)
    def plain_str(x):
        """Convert basic byte objects to str"""
        return x

def bytes_hex(x, force_str=False):
    """Hexify a str or a bytes object"""
    if six.PY2:
        return str(x).encode("hex")
    else:
        hex_ = codecs.getencoder('hex_codec')(raw(x))[0]
        if force_str:
            hex_ = hex_.decode('utf8')
        return hex_

def hex_bytes(x):
    """De-hexify a str or a byte object"""
    if six.PY2:
        return str(x).decode("hex")
    else:
        return codecs.getdecoder('hex_codec')(x)[0]
