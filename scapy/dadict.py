# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Direct Access dictionary.
"""

from __future__ import absolute_import
from __future__ import print_function
from scapy.error import Scapy_Exception
import scapy.modules.six as six
from scapy.compat import plain_str

###############################
#  Direct Access dictionary   #
###############################


def fixname(x):
    """
    Modifies a string to make sure it can be used as an attribute name.
    """
    x = plain_str(x)
    if x and str(x[0]) in "0123456789":
        x = "n_" + x
    return x.translate(
        "________________________________________________"
        "0123456789_______ABCDEFGHIJKLMNOPQRSTUVWXYZ______"
        "abcdefghijklmnopqrstuvwxyz____________________________"
        "______________________________________________________"
        "___________________________________________________"
    )


class DADict_Exception(Scapy_Exception):
    pass


class DADict(object):
    """
    Direct Access Dictionary

    This acts like a dict, but it provides a direct attribute access
    to its keys through its values. This is used to store protocols,
    manuf...

    For instance, scapy fields will use a DADict as an enum::

        ETHER_TYPES[2048] -> IPv4

    Whereas humans can access::

        ETHER_TYPES.IPv4 -> 2048
    """
    def __init__(self, _name="DADict", **kargs):
        self._name = _name
        self.update(kargs)

    def ident(self, v):
        """
        Return value that is used as key for the direct access
        """
        return fixname(v)

    def update(self, *args, **kwargs):
        for k, v in six.iteritems(dict(*args, **kwargs)):
            self[k] = v

    def iterkeys(self):
        for x in six.iterkeys(self.__dict__):
            if not isinstance(x, str) or x[0] != "_":
                yield x

    def keys(self):
        return list(self.iterkeys())

    def __iter__(self):
        return self.iterkeys()

    def itervalues(self):
        return six.itervalues(self.__dict__)

    def values(self):
        return list(self.itervalues())

    def _show(self):
        for k in self.iterkeys():
            print("%10s = %r" % (k, self[k]))

    def __repr__(self):
        return "<%s - %s elements>" % (self._name, len(self))

    def __getitem__(self, attr):
        return self.__dict__[attr]

    def __setitem__(self, attr, val):
        self.__dict__[attr] = val

    def __len__(self):
        return len(self.__dict__)

    def __nonzero__(self):
        # Always has at least its name
        return len(self) > 1
    __bool__ = __nonzero__

    def __getattr__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            for k, v in six.iteritems(self.__dict__):
                if self.ident(v) == attr:
                    return k

    def __dir__(self):
        return [self.ident(x) for x in self.itervalues()]
