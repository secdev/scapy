# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Python 2 and 3 link classes.
"""

import base64
import binascii
import collections
import struct
import sys

# Very important: will issue typing errors otherwise
__all__ = [
    # typing
    'Any',
    'AnyStr',
    'Callable',
    'DefaultDict',
    'Deque',
    'Dict',
    'Generic',
    'IO',
    'Iterable',
    'Iterable',
    'Iterator',
    'List',
    'Literal',
    'NewType',
    'NoReturn',
    'Optional',
    'Pattern',
    'Sequence',
    'Set',
    'Self',
    'Sized',
    'TextIO',
    'Tuple',
    'Type',
    'TypeVar',
    'Union',
    'UserDict',
    'ValuesView',
    'cast',
    'overload',
    'FAKE_TYPING',
    'TYPE_CHECKING',
    # compat
    'base64_bytes',
    'bytes_base64',
    'bytes_encode',
    'bytes_hex',
    'chb',
    'hex_bytes',
    'lambda_tuple_converter',
    'orb',
    'plain_str',
    'raw',
]

# Typing compatibility

# Note:
# supporting typing on multiple python versions is a nightmare.
# Since Python 3.7, Generic is a type instead of a metaclass,
# therefore we can't support both at the same time. Our strategy
# is to only use the typing module if the Python version is >= 3.7
# and use totally fake replacements otherwise.
# HOWEVER, when using the fake ones, to emulate stub Generic
# fields (e.g. _PacketField[str]) we need to add a fake
# __getitem__ to Field_metaclass

try:
    import typing  # noqa: F401
    from typing import TYPE_CHECKING
    if sys.version_info[0:2] <= (3, 6):
        # Generic is messed up before Python 3.7
        # https://github.com/python/typing/issues/449
        raise ImportError
    FAKE_TYPING = False
except ImportError:
    FAKE_TYPING = True
    TYPE_CHECKING = False


# Import or create fake types

def _FakeType(name, cls=object):
    # type: (str, Optional[type]) -> Any
    class _FT(object):
        def __init__(self, name):
            # type: (str) -> None
            self.name = name

        # make the objects subscriptable indefinitely
        def __getitem__(self, item):  # type: ignore
            return cls

        def __call__(self, *args, **kargs):
            # type: (*Any, **Any) -> Any
            if isinstance(args[0], str):
                self.name = args[0]
            return self

        def __repr__(self):
            # type: () -> str
            return "<Fake typing.%s>" % self.name
    return _FT(name)


if not FAKE_TYPING:
    # Only required if using mypy-lang for static typing
    from typing import (
        Any,
        AnyStr,
        Callable,
        DefaultDict,
        Deque,
        Dict,
        Generic,
        IO,
        Iterable,
        Iterator,
        List,
        NewType,
        NoReturn,
        Optional,
        Pattern,
        Sequence,
        Set,
        Sized,
        TextIO,
        Tuple,
        Type,
        TypeVar,
        Union,
        ValuesView,
        cast,
        overload,
    )
else:
    # Let's be creative and make some fake ones.
    def cast(_type, obj):  # type: ignore
        return obj

    Any = _FakeType("Any")
    AnyStr = _FakeType("AnyStr")  # type: ignore
    Callable = _FakeType("Callable")
    DefaultDict = _FakeType("DefaultDict",  # type: ignore
                            collections.defaultdict)
    Deque = _FakeType("Deque")  # type: ignore
    Dict = _FakeType("Dict", dict)  # type: ignore
    IO = _FakeType("IO")  # type: ignore
    Iterable = _FakeType("Iterable")  # type: ignore
    Iterator = _FakeType("Iterator")  # type: ignore
    List = _FakeType("List", list)  # type: ignore
    NewType = _FakeType("NewType")  # type: ignore
    NoReturn = _FakeType("NoReturn")
    Optional = _FakeType("Optional")
    Pattern = _FakeType("Pattern")  # type: ignore
    Sequence = _FakeType("Sequence", list)  # type: ignore
    Set = _FakeType("Set", set)  # type: ignore
    TextIO = _FakeType("TextIO")  # type: ignore
    Tuple = _FakeType("Tuple")
    Type = _FakeType("Type", type)
    TypeVar = _FakeType("TypeVar")  # type: ignore
    Union = _FakeType("Union")
    ValuesView = _FakeType("List", list)  # type: ignore

    class Sized:  # type: ignore
        pass

    overload = lambda x: x


# Python 3.8 Only
if sys.version_info >= (3, 8):
    from typing import Literal
else:
    Literal = _FakeType("Literal")


# Python 3.9 Only
if sys.version_info >= (3, 9):
    from collections import UserDict
else:
    from collections import UserDict as _UserDict
    UserDict = _FakeType("_UserDict", _UserDict)


# Python 3.11 Only
if sys.version_info >= (3, 11):
    from typing import Self
else:
    Self = _FakeType("Self")

###########
# Python3 #
###########

# https://mypy.readthedocs.io/en/stable/generics.html#declaring-decorators
DecoratorCallable = TypeVar("DecoratorCallable", bound=Callable[..., Any])


def lambda_tuple_converter(func):
    # type: (DecoratorCallable) -> DecoratorCallable
    """
    Converts a Python 2 function as
      lambda (x,y): x + y
    In the Python 3 format:
      lambda x,y : x + y
    """
    if func is not None and func.__code__.co_argcount == 1:
        return lambda *args: func(  # type: ignore
            args[0] if len(args) == 1 else args
        )
    else:
        return func


# This is ugly, but we don't want to move raw() out of compat.py
# and it makes it much clearer
if TYPE_CHECKING:
    from scapy.packet import Packet


def raw(x):
    # type: (Union[Packet]) -> bytes
    """
    Builds a packet and returns its bytes representation.
    This function is and will always be cross-version compatible
    """
    return bytes(x)


def bytes_encode(x):
    # type: (Any) -> bytes
    """Ensure that the given object is bytes. If the parameter is a
        packet, raw() should be preferred.

    """
    if isinstance(x, str):
        return x.encode()
    return bytes(x)


def plain_str(x):
    # type: (Any) -> str
    """Convert basic byte objects to str"""
    if isinstance(x, bytes):
        return x.decode(errors="backslashreplace")
    return str(x)


def chb(x):
    # type: (int) -> bytes
    """Same than chr() but encode as bytes."""
    return struct.pack("!B", x)


def orb(x):
    # type: (Union[int, str, bytes]) -> int
    """Return ord(x) when not already an int."""
    if isinstance(x, int):
        return x
    return ord(x)


def bytes_hex(x):
    # type: (AnyStr) -> bytes
    """Hexify a str or a bytes object"""
    return binascii.b2a_hex(bytes_encode(x))


def hex_bytes(x):
    # type: (AnyStr) -> bytes
    """De-hexify a str or a byte object"""
    return binascii.a2b_hex(bytes_encode(x))


def int_bytes(x, size):
    # type: (int, int) -> bytes
    """Convert an int to an arbitrary sized bytes string"""
    return x.to_bytes(size, byteorder='big')


def bytes_int(x):
    # type: (bytes) -> int
    """Convert an arbitrary sized bytes string to an int"""
    return int.from_bytes(x, "big")


def base64_bytes(x):
    # type: (AnyStr) -> bytes
    """Turn base64 into bytes"""
    return base64.decodebytes(bytes_encode(x))


def bytes_base64(x):
    # type: (AnyStr) -> bytes
    """Turn bytes into base64"""
    return base64.encodebytes(bytes_encode(x)).replace(b'\n', b'')
