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

from typing import Any
from typing import Union
from typing import Optional
from typing import Tuple
from typing import List
from typing import Iterator

###############################
#  Direct Access dictionary   #
###############################


def fixname(x):
    # type: (str) -> str
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


class DADict:
    def __init__(self, _name="DADict", **kargs):
        # type: (str, **Any) -> None
        self._name = _name
        self.update(kargs)

    def fixname(self, val):
        # type: (bytes) -> str
        return fixname(plain_str(val))

    def __contains__(self, val):
        # type: (str) -> bool
        return val in self.__dict__

    def __getitem__(self, attr):
        # type: (str) -> Union[int, str]
        return getattr(self, attr)

    def __setitem__(self, attr, val):
        # type: (bytes, Union[Tuple[str, str], int]) -> Optional[Any]
        return setattr(self, self.fixname(attr), val)

    def __iter__(self):
        return (value for key, value in six.iteritems(self.__dict__)
                if key and key[0] != '_')

    def _show(self):
        for k in self.__dict__:
            if k and k[0] != "_":
                print("%10s = %r" % (k, getattr(self, k)))

    def __repr__(self):
        # type: () -> str
        return "<%s - %s elements>" % (self._name, len(self.__dict__))

    def _branch(self, br, uniq=0):
        if uniq and br._name in self:
            raise DADict_Exception("DADict: [%s] already branched in [%s]" % (br._name, self._name))  # noqa: E501
        self[br._name] = br

    def _my_find(self, *args, **kargs):
        if args and self._name not in args:
            return False
        return all(k in self and self[k] == v for k, v in six.iteritems(kargs))

    def update(self, *args, **kwargs):
        for k, v in six.iteritems(dict(*args, **kwargs)):
            self[k] = v

    def _find(self, *args, **kargs):
        return self._recurs_find((), *args, **kargs)

    def _recurs_find(self, path, *args, **kargs):
        if self in path:
            return None
        if self._my_find(*args, **kargs):
            return self
        for o in self:
            if isinstance(o, DADict):
                p = o._recurs_find(path + (self,), *args, **kargs)
                if p is not None:
                    return p
        return None

    def _find_all(self, *args, **kargs):
        return self._recurs_find_all((), *args, **kargs)

    def _recurs_find_all(self, path, *args, **kargs):
        r = []
        if self in path:
            return r
        if self._my_find(*args, **kargs):
            r.append(self)
        for o in self:
            if isinstance(o, DADict):
                p = o._recurs_find_all(path + (self,), *args, **kargs)
                r += p
        return r

    def keys(self):
        # type: () -> List[str]
        return list(self.iterkeys())

    def iterkeys(self):
        # type: () -> Iterator
        return (x for x in self.__dict__ if x and x[0] != "_")

    def __len__(self):
        # type: () -> int
        return len(self.__dict__)

    def __nonzero__(self):
        # type: () -> bool
        # Always has at least its name
        return len(self.__dict__) > 1
    __bool__ = __nonzero__
