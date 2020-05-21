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
import collections
import gzip
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
    'Iterator',
    'List',
    'NoReturn',
    'Optional',
    'Pattern',
    'Set',
    'Sized',
    'Tuple',
    'TypeVar',
    'Union',
    'cast',
    'FAKE_TYPING',
    # compat
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
    if sys.version_info[0:2] <= (3, 6):
        # Generic is messed up before Python 3.7
        # https://github.com/python/typing/issues/449
        raise ImportError
    FAKE_TYPING = False
except ImportError:
    FAKE_TYPING = True

if not FAKE_TYPING:
    # Only required if using mypy-lang for static typing
    from typing import (
        Any,
        AnyStr,
        Callable,
        DefaultDict,
        Dict,
        Generic,
        Iterator,
        List,
        NoReturn,
        Optional,
        Pattern,
        Set,
        Sized,
        Tuple,
        TypeVar,
        Union,
        cast,
    )
else:
    # Let's be creative and make some fake ones.
    def cast(_type, obj):  # type: ignore
        return obj

    def _FakeType(name, cls=object):
        # type: (str, Optional[type]) -> Any
        class _FT(object):
            # make the objects subscriptable indefinetly
            def __getitem__(self, item):  # type: ignore
                return cls
        return _FT()

    Any = _FakeType("Any")
    AnyStr = _FakeType("AnyStr")  # type: ignore
    Callable = _FakeType("Callable")
    DefaultDict = _FakeType("DefaultDict",  # type: ignore
                            collections.defaultdict)
    Dict = _FakeType("Dict", dict)  # type: ignore
    Generic = _FakeType("Generic")
    Iterator = _FakeType("Iterator")  # type: ignore
    List = _FakeType("List", list)  # type: ignore
    NoReturn = _FakeType("NoReturn")  # type: ignore
    Optional = _FakeType("Optional")
    Pattern = _FakeType("Pattern")  # type: ignore
    Set = _FakeType("Set", set)  # type: ignore
    Tuple = _FakeType("Tuple")
    TypeVar = lambda x, *args: _FakeType("TypeVar %s" % x)
    Union = _FakeType("Union")

    class Sized(object):  # type: ignore
        pass


###########
# Python3 #
###########

_CallTupl = TypeVar("_CallTupl", Callable[Ellipsis, Any], None)  # type: ignore


def lambda_tuple_converter(func):
    # type: (_CallTupl) -> _CallTupl
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
    bytes_encode = plain_str = str  # type: Callable[[Any], bytes]
    orb = ord  # type: Callable[[bytes], int]

    def chb(x):
        # type: (int) -> bytes
        if isinstance(x, str):
            return x
        return chr(x)

    def raw(x):
        # type: (Any) -> bytes
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
        # type: (Union[int, bytes]) -> int
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
