# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Direct Access dictionary.
"""

from scapy.error import log_runtime, Scapy_Exception
from scapy.compat import plain_str

# Typing
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)
from scapy.compat import Self


###############################
#  Direct Access dictionary   #
###############################


def fixname(x):
    # type: (Union[bytes, str]) -> str
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


_K = TypeVar('_K')  # Key type
_V = TypeVar('_V')  # Value type


class DADict(Generic[_K, _V]):
    """
    Direct Access Dictionary

    This acts like a dict, but it provides a direct attribute access
    to its keys through its values. This is used to store protocols,
    manuf...

    For instance, scapy fields will use a DADict as an enum::

        ETHER_TYPES[2048] -> IPv4

    Whereas humans can access::

        ETHER_TYPES.IPv4 -> 2048

    :param lazy_load: optional callable returning a DADict or dict, called on
        first access to the contents. Failed loads are retried on next access.
    """
    __slots__ = ["_name", "_d", "_lazy_load"]

    def __init__(self, _name="DADict", lazy_load=None, **kargs):
        # type: (str, Optional[Callable[[], Union[DADict[_K, _V], Dict[_K, _V]]]], **Any) -> None  # noqa: E501
        self._name = _name
        self._d = {}  # type: Dict[_K, _V]
        self._lazy_load = lazy_load
        self.update(kargs)  # type: ignore

    @property
    def d(self):
        # type: () -> Dict[_K, _V]
        if self._lazy_load is not None:
            log_runtime.debug("Lazy loaded DADict [%s]" % self._name)
            loaded = self._lazy_load()
            if isinstance(loaded, DADict):
                self._d = loaded.d
                self._name = loaded._name
            else:
                self._d = loaded
            self._lazy_load = None
        return self._d

    @d.setter
    def d(self, value):
        # type: (Dict[_K, _V]) -> None
        self._d = value
        self._lazy_load = None

    def ident(self, v):
        # type: (_V) -> str
        """
        Return value that is used as key for the direct access
        """
        if isinstance(v, (str, bytes)):
            return fixname(v)
        return "unknown"

    def update(self, *args, **kwargs):
        # type: (*Dict[_K, _V], **Dict[_K, _V]) -> None
        for k, v in dict(*args, **kwargs).items():
            self[k] = v  # type: ignore

    def iterkeys(self):
        # type: () -> Iterator[_K]
        for x in self.d:
            if not isinstance(x, str) or x[0] != "_":
                yield x

    def keys(self):
        # type: () -> List[_K]
        return list(self.iterkeys())

    def __iter__(self):
        # type: () -> Iterator[_K]
        return self.iterkeys()

    def itervalues(self):
        # type: () -> Iterator[_V]
        return self.d.values()  # type: ignore

    def values(self):
        # type: () -> List[_V]
        return list(self.itervalues())

    def _show(self):
        # type: () -> None
        for k in self.iterkeys():
            print("%10s = %r" % (k, self[k]))

    def __repr__(self):
        # type: () -> str
        return "<%s - %s elements>" % (self._name, len(self))

    def __getitem__(self, attr):
        # type: (_K) -> _V
        return self.d[attr]

    def __setitem__(self, attr, val):
        # type: (_K, _V) -> None
        self.d[attr] = val

    def __len__(self):
        # type: () -> int
        return len(self.d)

    def __nonzero__(self):
        # type: () -> bool
        # Always has at least its name
        return len(self) > 1
    __bool__ = __nonzero__

    def __getattr__(self, attr):
        # type: (str) -> _K
        if attr in ("d", "_d", "_lazy_load"):
            raise AttributeError(attr)
        try:
            return object.__getattribute__(self, attr)  # type: ignore
        except AttributeError:
            for k, v in self.d.items():
                if self.ident(v) == attr:
                    return k
        raise AttributeError

    def __dir__(self):
        # type: () -> List[str]
        return [self.ident(x) for x in self.itervalues()]

    def __reduce__(self):
        # type: () -> Tuple[Type[Self], Tuple[str], Tuple[Dict[_K, _V]]]
        data = self.d
        return (self.__class__, (self._name,), (data,))

    def __setstate__(self, state):
        # type: (Tuple[Dict[_K, _V]]) -> Self
        self.d.update(state[0])
        return self
