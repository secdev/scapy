# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Python 2 and 3 link classes.
"""

from __future__ import absolute_import
import base64
import binascii
import collections
import gzip
import socket
import struct
import sys

import scapy.modules.six as six

# Very important: will issue typing errors otherwise
__all__ = [
    # typing
    'Any',
    'AnyStr',
    'Callable',
    'DefaultDict',
    'Dict',
    'Generic',
    'IO',
    'Iterable',
    'Iterator',
    'List',
    'Literal',
    'NamedTuple',
    'NewType',
    'NoReturn',
    'Optional',
    'Pattern',
    'Sequence',
    'Set',
    'Sized',
    'Tuple',
    'Type',
    'TypeVar',
    'Union',
    'cast',
    'overload',
    'FAKE_TYPING',
    'TYPE_CHECKING',
    # compat
    'AddressFamily',
    'base64_bytes',
    'bytes_base64',
    'bytes_encode',
    'bytes_hex',
    'chb',
    'gzip_compress',
    'gzip_decompress',
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

        # make the objects subscriptable indefinetly
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
        Dict,
        Generic,
        Iterable,
        Iterator,
        IO,
        List,
        NewType,
        NoReturn,
        Optional,
        Pattern,
        Sequence,
        Set,
        Sized,
        Tuple,
        Type,
        TypeVar,
        Union,
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
    Dict = _FakeType("Dict", dict)  # type: ignore
    Generic = _FakeType("Generic")
    Iterable = _FakeType("Iterable")  # type: ignore
    Iterator = _FakeType("Iterator")  # type: ignore
    IO = _FakeType("IO")  # type: ignore
    List = _FakeType("List", list)  # type: ignore
    NewType = _FakeType("NewType")
    NoReturn = _FakeType("NoReturn")  # type: ignore
    Optional = _FakeType("Optional")
    Pattern = _FakeType("Pattern")  # type: ignore
    Sequence = _FakeType("Sequence")  # type: ignore
    Set = _FakeType("Set", set)  # type: ignore
    Sequence = _FakeType("Sequence", list)  # type: ignore
    Tuple = _FakeType("Tuple")
    Type = _FakeType("Type", type)
    TypeVar = _FakeType("TypeVar")  # type: ignore
    Union = _FakeType("Union")

    class Sized(object):  # type: ignore
        pass

    overload = lambda x: x


# Broken < Python 3.7
if sys.version_info >= (3, 7):
    from typing import NamedTuple
else:
    # Hack for Python < 3.7 - Implement NamedTuple pickling
    def _unpickleNamedTuple(name, len_params, *args):
        return collections.namedtuple(
            name,
            args[:len_params]
        )(*args[len_params:])

    def NamedTuple(name, params):
        tup_params = tuple(x[0] for x in params)
        cls = collections.namedtuple(name, tup_params)

        class _NT(cls):
            def __reduce__(self):
                """Used by pickling methods"""
                return (_unpickleNamedTuple,
                        (name, len(tup_params)) + tup_params + tuple(self))
        _NT.__name__ = cls.__name__
        return _NT

# Python 3.8 Only
if sys.version_info >= (3, 8):
    from typing import Literal
else:
    Literal = _FakeType("Literal")

# Python 3.4
if sys.version_info >= (3, 4):
    from socket import AddressFamily
else:
    class AddressFamily:
        AF_INET = socket.AF_INET
        AF_INET6 = socket.AF_INET6


class _Generic_metaclass(type):
    if FAKE_TYPING:
        def __getitem__(self, typ):
            # type: (Any) -> Any
            return self


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


if six.PY2:
    bytes_encode = plain_str = str  # type: Callable[[Any], bytes]
    orb = ord  # type: Callable[[bytes], int]

    def chb(x):
        # type: (int) -> bytes
        if isinstance(x, str):
            return x
        return chr(x)

    def raw(x):
        # type: (Union[Packet]) -> bytes
        """
        Builds a packet and returns its bytes representation.
        This function is and will always be cross-version compatible
        """
        if hasattr(x, "__bytes__"):
            return x.__bytes__()
        return bytes(x)
else:
    def raw(x):
        # type: (Union[Packet]) -> bytes
        """
        Builds a packet and returns its bytes representation.
        This function is and will always be cross-version compatible
        """
        return bytes(x)

    def bytes_encode(x):
        # type: (Any) -> bytes
        """Ensure that the given object is bytes.
        If the parameter is a packet, raw() should be preferred.
        """
        if isinstance(x, str):
            return x.encode()
        return bytes(x)

    if sys.version_info[0:2] <= (3, 4):
        def plain_str(x):
            # type: (AnyStr) -> str
            """Convert basic byte objects to str"""
            if isinstance(x, bytes):
                return x.decode(errors="ignore")
            return str(x)
    else:
        # Python 3.5+
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


def base64_bytes(x):
    # type: (AnyStr) -> bytes
    """Turn base64 into bytes"""
    if six.PY2:
        return base64.decodestring(x)  # type: ignore
    return base64.decodebytes(bytes_encode(x))


def bytes_base64(x):
    # type: (AnyStr) -> bytes
    """Turn bytes into base64"""
    if six.PY2:
        return base64.encodestring(x).replace('\n', '')  # type: ignore
    return base64.encodebytes(bytes_encode(x)).replace(b'\n', b'')


if six.PY2:
    import cgi
    html_escape = cgi.escape
else:
    import html
    html_escape = html.escape


if six.PY2:
    from StringIO import StringIO

    def gzip_decompress(x):
        # type: (AnyStr) -> bytes
        """Decompress using gzip"""
        with gzip.GzipFile(fileobj=StringIO(x), mode='rb') as fdesc:
            return fdesc.read()

    def gzip_compress(x):
        # type: (AnyStr) -> bytes
        """Compress using gzip"""
        buf = StringIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as fdesc:
            fdesc.write(x)
        return buf.getvalue()
else:
    gzip_decompress = gzip.decompress
    gzip_compress = gzip.compress
