# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Python 2 and 3 link classes.
"""

import base64
import binascii
import struct
import sys

from typing import (
    Any,
    AnyStr,
    Callable,
    Optional,
    TypeVar,
    TYPE_CHECKING,
    Union,
)

# Very important: will issue typing errors otherwise
__all__ = [
    # typing
    'DecoratorCallable',
    'Literal',
    'Protocol',
    'Self',
    'UserDict',
    # compat
    'base64_bytes',
    'bytes_base64',
    'bytes_encode',
    'bytes_hex',
    'chb',
    'hex_bytes',
    'orb',
    'plain_str',
    'raw',
]

# Typing compatibility

# Note:
# supporting typing on multiple python versions is a nightmare.
# we provide a FakeType class to be able to use types added on
# later Python versions (since we run mypy on 3.12), on older
# ones.


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


# Python 3.8 Only
if sys.version_info >= (3, 8):
    from typing import Literal
    from typing import Protocol
else:
    Literal = _FakeType("Literal")

    class Protocol:
        pass


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


# This is ugly, but we don't want to move raw() out of compat.py
# and it makes it much clearer
if TYPE_CHECKING:
    from scapy.packet import Packet


def raw(x):
    # type: (Packet) -> bytes
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
