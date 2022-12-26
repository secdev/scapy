# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
General utility functions.
"""

from __future__ import absolute_import
from __future__ import print_function

from decimal import Decimal

import array
import collections
import decimal
import difflib
import gzip
import locale
import os
import random
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import warnings

import scapy.libs.six as six
from scapy.libs.six.moves import range, input, zip_longest

from scapy.config import conf
from scapy.consts import DARWIN, OPENBSD, WINDOWS
from scapy.data import MTU, DLT_EN10MB, DLT_RAW
from scapy.compat import orb, plain_str, chb, bytes_base64,\
    base64_bytes, hex_bytes, lambda_tuple_converter, bytes_encode
from scapy.error import log_runtime, Scapy_Exception, warning
from scapy.pton_ntop import inet_pton

# Typing imports
from scapy.compat import (
    cast,
    Any,
    AnyStr,
    Callable,
    Dict,
    IO,
    Iterator,
    List,
    Literal,
    Optional,
    TYPE_CHECKING,
    Tuple,
    Type,
    Union,
    overload,
)

if TYPE_CHECKING:
    from scapy.packet import Packet
    from scapy.plist import _PacketIterable, PacketList
    from scapy.supersocket import SuperSocket
    _SuperSocket = SuperSocket
else:
    _SuperSocket = object

_ByteStream = Union[IO[bytes], gzip.GzipFile]

###########
#  Tools  #
###########


def issubtype(x,  # type: Any
              t,  # type: Union[type, str]
              ):
    # type: (...) -> bool
    """issubtype(C, B) -> bool

    Return whether C is a class and if it is a subclass of class B.
    When using a tuple as the second argument issubtype(X, (A, B, ...)),
    is a shortcut for issubtype(X, A) or issubtype(X, B) or ... (etc.).
    """
    if isinstance(t, str):
        return t in (z.__name__ for z in x.__bases__)
    if isinstance(x, type) and issubclass(x, t):
        return True
    return False


_Decimal = Union[Decimal, int]


class EDecimal(Decimal):
    """Extended Decimal

    This implements arithmetic and comparison with float for
    backward compatibility
    """

    def __add__(self, other, context=None):
        # type: (_Decimal, Any) -> EDecimal
        return EDecimal(Decimal.__add__(self, Decimal(other)))

    def __radd__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__add__(self, Decimal(other)))

    def __sub__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__sub__(self, Decimal(other)))

    def __rsub__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__rsub__(self, Decimal(other)))

    def __mul__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__mul__(self, Decimal(other)))

    def __rmul__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__mul__(self, Decimal(other)))

    def __truediv__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__truediv__(self, Decimal(other)))

    def __floordiv__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__floordiv__(self, Decimal(other)))

    if sys.version_info >= (3,):
        def __divmod__(self, other):
            # type: (_Decimal) -> Tuple[EDecimal, EDecimal]
            r = Decimal.__divmod__(self, Decimal(other))
            return EDecimal(r[0]), EDecimal(r[1])
    else:
        def __div__(self, other):
            # type: (_Decimal) -> EDecimal
            return EDecimal(Decimal.__div__(self, Decimal(other)))

        def __rdiv__(self, other):
            # type: (_Decimal) -> EDecimal
            return EDecimal(Decimal.__rdiv__(self, Decimal(other)))

    def __mod__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__mod__(self, Decimal(other)))

    def __rmod__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__rmod__(self, Decimal(other)))

    def __pow__(self, other, modulo=None):
        # type: (_Decimal, Optional[_Decimal]) -> EDecimal
        return EDecimal(Decimal.__pow__(self, Decimal(other), modulo))

    def __eq__(self, other):
        # type: (Any) -> bool
        return super(EDecimal, self).__eq__(other) or float(self) == other

    def normalize(self, precision):  # type: ignore
        # type: (int) -> EDecimal
        with decimal.localcontext() as ctx:
            ctx.prec = precision
            return EDecimal(super(EDecimal, self).normalize(ctx))


@overload
def get_temp_file(keep, autoext, fd):
    # type: (bool, str, Literal[True]) -> IO[bytes]
    pass


@overload
def get_temp_file(keep=False, autoext="", fd=False):  # noqa: F811
    # type: (bool, str, Literal[False]) -> str
    pass


def get_temp_file(keep=False, autoext="", fd=False):  # noqa: F811
    # type: (bool, str, bool) -> Union[IO[bytes], str]
    """Creates a temporary file.

    :param keep: If False, automatically delete the file when Scapy exits.
    :param autoext: Suffix to add to the generated file name.
    :param fd: If True, this returns a file-like object with the temporary
               file opened. If False (default), this returns a file path.
    """
    f = tempfile.NamedTemporaryFile(prefix="scapy", suffix=autoext,
                                    delete=False)
    if not keep:
        conf.temp_files.append(f.name)

    if fd:
        return f
    else:
        # Close the file so something else can take it.
        f.close()
        return f.name


def get_temp_dir(keep=False):
    # type: (bool) -> str
    """Creates a temporary file, and returns its name.

    :param keep: If False (default), the directory will be recursively
                 deleted when Scapy exits.
    :return: A full path to a temporary directory.
    """

    dname = tempfile.mkdtemp(prefix="scapy")

    if not keep:
        conf.temp_files.append(dname)

    return dname


def sane(x, color=False):
    # type: (AnyStr, bool) -> str
    r = ""
    for i in x:
        j = orb(i)
        if (j < 32) or (j >= 127):
            if color:
                r += conf.color_theme.not_printable(".")
            else:
                r += "."
        else:
            r += chr(j)
    return r


@conf.commands.register
def restart():
    # type: () -> None
    """Restarts scapy"""
    if not conf.interactive or not os.path.isfile(sys.argv[0]):
        raise OSError("Scapy was not started from console")
    if WINDOWS:
        try:
            res_code = subprocess.call([sys.executable] + sys.argv)
        except KeyboardInterrupt:
            res_code = 1
        finally:
            os._exit(res_code)
    os.execv(sys.executable, [sys.executable] + sys.argv)


def lhex(x):
    # type: (Any) -> str
    from scapy.volatile import VolatileValue
    if isinstance(x, VolatileValue):
        return repr(x)
    if isinstance(x, six.integer_types):
        return hex(x)
    if isinstance(x, tuple):
        return "(%s)" % ", ".join(lhex(v) for v in x)
    if isinstance(x, list):
        return "[%s]" % ", ".join(lhex(v) for v in x)
    return str(x)


@conf.commands.register
def hexdump(p, dump=False):
    # type: (Union[Packet, AnyStr], bool) -> Optional[str]
    """Build a tcpdump like hexadecimal view

    :param p: a Packet
    :param dump: define if the result must be printed or returned in a variable
    :return: a String only when dump=True
    """
    s = ""
    x = bytes_encode(p)
    x_len = len(x)
    i = 0
    while i < x_len:
        s += "%04x  " % i
        for j in range(16):
            if i + j < x_len:
                s += "%02X " % orb(x[i + j])
            else:
                s += "   "
        s += " %s\n" % sane(x[i:i + 16], color=True)
        i += 16
    # remove trailing \n
    s = s[:-1] if s.endswith("\n") else s
    if dump:
        return s
    else:
        print(s)
        return None


@conf.commands.register
def linehexdump(p, onlyasc=0, onlyhex=0, dump=False):
    # type: (Union[Packet, AnyStr], int, int, bool) -> Optional[str]
    """Build an equivalent view of hexdump() on a single line

    Note that setting both onlyasc and onlyhex to 1 results in a empty output

    :param p: a Packet
    :param onlyasc: 1 to display only the ascii view
    :param onlyhex: 1 to display only the hexadecimal view
    :param dump: print the view if False
    :return: a String only when dump=True
    """
    s = ""
    s = hexstr(p, onlyasc=onlyasc, onlyhex=onlyhex, color=not dump)
    if dump:
        return s
    else:
        print(s)
        return None


@conf.commands.register
def chexdump(p, dump=False):
    # type: (Union[Packet, AnyStr], bool) -> Optional[str]
    """Build a per byte hexadecimal representation

    Example:
        >>> chexdump(IP())
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x7c, 0xe7, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01  # noqa: E501

    :param p: a Packet
    :param dump: print the view if False
    :return: a String only if dump=True
    """
    x = bytes_encode(p)
    s = ", ".join("%#04x" % orb(x) for x in x)
    if dump:
        return s
    else:
        print(s)
        return None


@conf.commands.register
def hexstr(p, onlyasc=0, onlyhex=0, color=False):
    # type: (Union[Packet, AnyStr], int, int, bool) -> str
    """Build a fancy tcpdump like hex from bytes."""
    x = bytes_encode(p)
    s = []
    if not onlyasc:
        s.append(" ".join("%02X" % orb(b) for b in x))
    if not onlyhex:
        s.append(sane(x, color=color))
    return "  ".join(s)


def repr_hex(s):
    # type: (bytes) -> str
    """ Convert provided bitstring to a simple string of hex digits """
    return "".join("%02x" % orb(x) for x in s)


@conf.commands.register
def hexdiff(a, b, autojunk=False):
    # type: (Union[Packet, AnyStr], Union[Packet, AnyStr], bool) -> None
    """
    Show differences between 2 binary strings, Packets...

    For the autojunk parameter, see
    https://docs.python.org/3.8/library/difflib.html#difflib.SequenceMatcher

    :param a:
    :param b: The binary strings, packets... to compare
    :param autojunk: Setting it to True will likely increase the comparison
        speed a lot on big byte strings, but will reduce accuracy (will tend
        to miss insertion and see replacements instead for instance).
    """

    # Compare the strings using difflib

    xb = bytes_encode(a)
    yb = bytes_encode(b)

    sm = difflib.SequenceMatcher(a=xb, b=yb, autojunk=autojunk)
    xarr = [xb[i:i + 1] for i in range(len(xb))]
    yarr = [yb[i:i + 1] for i in range(len(yb))]

    backtrackx = []
    backtracky = []
    for opcode in sm.get_opcodes():
        typ, x0, x1, y0, y1 = opcode
        if typ == 'delete':
            backtrackx += xarr[x0:x1]
            backtracky += [b''] * (x1 - x0)
        elif typ == 'insert':
            backtrackx += [b''] * (y1 - y0)
            backtracky += yarr[y0:y1]
        elif typ in ['equal', 'replace']:
            backtrackx += xarr[x0:x1]
            backtracky += yarr[y0:y1]

    if autojunk:
        # Some lines may have been considered as junk. Check the sizes
        lbx = len(backtrackx)
        lby = len(backtracky)
        backtrackx += [b''] * (max(lbx, lby) - lbx)
        backtracky += [b''] * (max(lbx, lby) - lby)

    # Print the diff

    x = y = i = 0
    colorize = {0: lambda x: x,
                -1: conf.color_theme.left,
                1: conf.color_theme.right}

    dox = 1
    doy = 0
    btx_len = len(backtrackx)
    while i < btx_len:
        linex = backtrackx[i:i + 16]
        liney = backtracky[i:i + 16]
        xx = sum(len(k) for k in linex)
        yy = sum(len(k) for k in liney)
        if dox and not xx:
            dox = 0
            doy = 1
        if dox and linex == liney:
            doy = 1

        if dox:
            xd = y
            j = 0
            while not linex[j]:
                j += 1
                xd -= 1
            print(colorize[doy - dox]("%04x" % xd), end=' ')
            x += xx
            line = linex
        else:
            print("    ", end=' ')
        if doy:
            yd = y
            j = 0
            while not liney[j]:
                j += 1
                yd -= 1
            print(colorize[doy - dox]("%04x" % yd), end=' ')
            y += yy
            line = liney
        else:
            print("    ", end=' ')

        print(" ", end=' ')

        cl = ""
        for j in range(16):
            if i + j < min(len(backtrackx), len(backtracky)):
                if line[j]:
                    col = colorize[(linex[j] != liney[j]) * (doy - dox)]
                    print(col("%02X" % orb(line[j])), end=' ')
                    if linex[j] == liney[j]:
                        cl += sane(line[j], color=True)
                    else:
                        cl += col(sane(line[j]))
                else:
                    print("  ", end=' ')
                    cl += " "
            else:
                print("  ", end=' ')
            if j == 7:
                print("", end=' ')

        print(" ", cl)

        if doy or not yy:
            doy = 0
            dox = 1
            i += 16
        else:
            if yy:
                dox = 0
                doy = 1
            else:
                i += 16


if struct.pack("H", 1) == b"\x00\x01":  # big endian
    checksum_endian_transform = lambda chk: chk  # type: Callable[[int], int]
else:
    checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | chk << 8


def checksum(pkt):
    # type: (bytes) -> int
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return checksum_endian_transform(s) & 0xffff


def _fletcher16(charbuf):
    # type: (bytes) -> Tuple[int, int]
    # This is based on the GPLed C implementation in Zebra <http://www.zebra.org/>  # noqa: E501
    c0 = c1 = 0
    for char in charbuf:
        c0 += orb(char)
        c1 += c0

    c0 %= 255
    c1 %= 255
    return (c0, c1)


@conf.commands.register
def fletcher16_checksum(binbuf):
    # type: (bytes) -> int
    """Calculates Fletcher-16 checksum of the given buffer.

       Note:
       If the buffer contains the two checkbytes derived from the Fletcher-16 checksum  # noqa: E501
       the result of this function has to be 0. Otherwise the buffer has been corrupted.  # noqa: E501
    """
    (c0, c1) = _fletcher16(binbuf)
    return (c1 << 8) | c0


@conf.commands.register
def fletcher16_checkbytes(binbuf, offset):
    # type: (bytes, int) -> bytes
    """Calculates the Fletcher-16 checkbytes returned as 2 byte binary-string.

       Including the bytes into the buffer (at the position marked by offset) the  # noqa: E501
       global Fletcher-16 checksum of the buffer will be 0. Thus it is easy to verify  # noqa: E501
       the integrity of the buffer on the receiver side.

       For details on the algorithm, see RFC 2328 chapter 12.1.7 and RFC 905 Annex B.  # noqa: E501
    """

    # This is based on the GPLed C implementation in Zebra <http://www.zebra.org/>  # noqa: E501
    if len(binbuf) < offset:
        raise Exception("Packet too short for checkbytes %d" % len(binbuf))

    binbuf = binbuf[:offset] + b"\x00\x00" + binbuf[offset + 2:]
    (c0, c1) = _fletcher16(binbuf)

    x = ((len(binbuf) - offset - 1) * c0 - c1) % 255

    if (x <= 0):
        x += 255

    y = 510 - c0 - x

    if (y > 255):
        y -= 255
    return chb(x) + chb(y)


def mac2str(mac):
    # type: (str) -> bytes
    return b"".join(chb(int(x, 16)) for x in plain_str(mac).split(':'))


def valid_mac(mac):
    # type: (str) -> bool
    try:
        return len(mac2str(mac)) == 6
    except ValueError:
        pass
    return False


def str2mac(s):
    # type: (bytes) -> str
    if isinstance(s, str):
        return ("%02x:" * len(s))[:-1] % tuple(map(ord, s))
    return ("%02x:" * len(s))[:-1] % tuple(s)


def randstring(length):
    # type: (int) -> bytes
    """
    Returns a random string of length (length >= 0)
    """
    return b"".join(struct.pack('B', random.randint(0, 255))
                    for _ in range(length))


def zerofree_randstring(length):
    # type: (int) -> bytes
    """
    Returns a random string of length (length >= 0) without zero in it.
    """
    return b"".join(struct.pack('B', random.randint(1, 255))
                    for _ in range(length))


def strxor(s1, s2):
    # type: (bytes, bytes) -> bytes
    """
    Returns the binary XOR of the 2 provided strings s1 and s2. s1 and s2
    must be of same length.
    """
    return b"".join(map(lambda x, y: chb(orb(x) ^ orb(y)), s1, s2))


def strand(s1, s2):
    # type: (bytes, bytes) -> bytes
    """
    Returns the binary AND of the 2 provided strings s1 and s2. s1 and s2
    must be of same length.
    """
    return b"".join(map(lambda x, y: chb(orb(x) & orb(y)), s1, s2))


# Workaround bug 643005 : https://sourceforge.net/tracker/?func=detail&atid=105470&aid=643005&group_id=5470  # noqa: E501
try:
    socket.inet_aton("255.255.255.255")
except socket.error:
    def inet_aton(ip_string):
        # type: (str) -> bytes
        if ip_string == "255.255.255.255":
            return b"\xff" * 4
        else:
            return socket.inet_aton(ip_string)
else:
    inet_aton = socket.inet_aton  # type: ignore

inet_ntoa = socket.inet_ntoa


def atol(x):
    # type: (str) -> int
    try:
        ip = inet_aton(x)
    except socket.error:
        ip = inet_aton(socket.gethostbyname(x))
    return cast(int, struct.unpack("!I", ip)[0])


def valid_ip(addr):
    # type: (str) -> bool
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    try:
        atol(addr)
    except (OSError, ValueError, socket.error):
        return False
    return True


def valid_net(addr):
    # type: (str) -> bool
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    if '/' in addr:
        ip, mask = addr.split('/', 1)
        return valid_ip(ip) and mask.isdigit() and 0 <= int(mask) <= 32
    return valid_ip(addr)


def valid_ip6(addr):
    # type: (str) -> bool
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    try:
        inet_pton(socket.AF_INET6, addr)
    except socket.error:
        try:
            socket.getaddrinfo(addr, None, socket.AF_INET6)[0][4][0]
        except socket.error:
            return False
    return True


def valid_net6(addr):
    # type: (str) -> bool
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    if '/' in addr:
        ip, mask = addr.split('/', 1)
        return valid_ip6(ip) and mask.isdigit() and 0 <= int(mask) <= 128
    return valid_ip6(addr)


def ltoa(x):
    # type: (int) -> str
    return inet_ntoa(struct.pack("!I", x & 0xffffffff))


def itom(x):
    # type: (int) -> int
    return (0xffffffff00000000 >> x) & 0xffffffff


def decode_locale_str(x):
    # type: (bytes) -> str
    """
    Decode bytes into a string using the system locale.
    Useful on Windows where it can be unusual (e.g. cp1252)
    """
    return x.decode(encoding=locale.getlocale()[1] or "utf-8", errors="replace")


class ContextManagerSubprocess(object):
    """
    Context manager that eases checking for unknown command, without
    crashing.

    Example:
    >>> with ContextManagerSubprocess("tcpdump"):
    >>>     subprocess.Popen(["tcpdump", "--version"])
    ERROR: Could not execute tcpdump, is it installed?

    """

    def __init__(self, prog, suppress=True):
        # type: (str, bool) -> None
        self.prog = prog
        self.suppress = suppress

    def __enter__(self):
        # type: () -> None
        pass

    def __exit__(self,
                 exc_type,  # type: Optional[type]
                 exc_value,  # type: Optional[Exception]
                 traceback,  # type: Optional[Any]
                 ):
        # type: (...) -> Optional[bool]
        if exc_value is None or exc_type is None:
            return None
        # Errored
        if isinstance(exc_value, EnvironmentError):
            msg = "Could not execute %s, is it installed?" % self.prog
        else:
            msg = "%s: execution failed (%s)" % (
                self.prog,
                exc_type.__class__.__name__
            )
        if not self.suppress:
            raise exc_type(msg)
        log_runtime.error(msg, exc_info=True)
        return True  # Suppress the exception


class ContextManagerCaptureOutput(object):
    """
    Context manager that intercept the console's output.

    Example:
    >>> with ContextManagerCaptureOutput() as cmco:
    ...     print("hey")
    ...     assert cmco.get_output() == "hey"
    """

    def __init__(self):
        # type: () -> None
        self.result_export_object = ""
        try:
            import mock  # noqa: F401
        except Exception:
            raise ImportError("The mock module needs to be installed !")

    def __enter__(self):
        # type: () -> ContextManagerCaptureOutput
        import mock

        def write(s, decorator=self):
            # type: (str, ContextManagerCaptureOutput) -> None
            decorator.result_export_object += s
        mock_stdout = mock.Mock()
        mock_stdout.write = write
        self.bck_stdout = sys.stdout
        sys.stdout = mock_stdout
        return self

    def __exit__(self, *exc):
        # type: (*Any) -> Literal[False]
        sys.stdout = self.bck_stdout
        return False

    def get_output(self, eval_bytes=False):
        # type: (bool) -> str
        if self.result_export_object.startswith("b'") and eval_bytes:
            return plain_str(eval(self.result_export_object))
        return self.result_export_object


def do_graph(
    graph,  # type: str
    prog=None,  # type: Optional[str]
    format=None,  # type: Optional[str]
    target=None,  # type: Optional[Union[IO[bytes], str]]
    type=None,  # type: Optional[str]
    string=None,  # type: Optional[bool]
    options=None  # type: Optional[List[str]]
):
    # type: (...) -> Optional[str]
    """Processes graph description using an external software.
    This method is used to convert a graphviz format to an image.

    :param graph: GraphViz graph description
    :param prog: which graphviz program to use
    :param format: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T"
        option
    :param string: if not None, simply return the graph string
    :param target: filename or redirect. Defaults pipe to Imagemagick's
        display program
    :param options: options to be passed to prog
    """

    if format is None:
        format = "svg"
    if string:
        return graph
    if type is not None:
        warnings.warn(
            "type is deprecated, and was renamed format",
            DeprecationWarning
        )
        format = type
    if prog is None:
        prog = conf.prog.dot
    start_viewer = False
    if target is None:
        if WINDOWS:
            target = get_temp_file(autoext="." + format)
            start_viewer = True
        else:
            with ContextManagerSubprocess(conf.prog.display):
                target = subprocess.Popen([conf.prog.display],
                                          stdin=subprocess.PIPE).stdin
    if format is not None:
        format = "-T%s" % format
    if isinstance(target, str):
        if target.startswith('|'):
            target = subprocess.Popen(target[1:].lstrip(), shell=True,
                                      stdin=subprocess.PIPE).stdin
        elif target.startswith('>'):
            target = open(target[1:].lstrip(), "wb")
        else:
            target = open(os.path.abspath(target), "wb")
    target = cast(IO[bytes], target)
    proc = subprocess.Popen(
        "\"%s\" %s %s" % (prog, options or "", format or ""),
        shell=True, stdin=subprocess.PIPE, stdout=target,
        stderr=subprocess.PIPE
    )
    _, stderr = proc.communicate(bytes_encode(graph))
    if proc.returncode != 0:
        raise OSError(
            "GraphViz call failed (is it installed?):\n" +
            plain_str(stderr)
        )
    try:
        target.close()
    except Exception:
        pass
    if start_viewer:
        # Workaround for file not found error: We wait until tempfile is written.  # noqa: E501
        waiting_start = time.time()
        while not os.path.exists(target.name):
            time.sleep(0.1)
            if time.time() - waiting_start > 3:
                warning("Temporary file '%s' could not be written. Graphic will not be displayed.", tempfile)  # noqa: E501
                break
        else:
            if WINDOWS and conf.prog.display == conf.prog._default:
                os.startfile(target.name)
            else:
                with ContextManagerSubprocess(conf.prog.display):
                    subprocess.Popen([conf.prog.display, target.name])
    return None


_TEX_TR = {
    "{": "{\\tt\\char123}",
    "}": "{\\tt\\char125}",
    "\\": "{\\tt\\char92}",
    "^": "\\^{}",
    "$": "\\$",
    "#": "\\#",
    "_": "\\_",
    "&": "\\&",
    "%": "\\%",
    "|": "{\\tt\\char124}",
    "~": "{\\tt\\char126}",
    "<": "{\\tt\\char60}",
    ">": "{\\tt\\char62}",
}


def tex_escape(x):
    # type: (str) -> str
    s = ""
    for c in x:
        s += _TEX_TR.get(c, c)
    return s


def colgen(*lstcol,  # type: Any
           **kargs  # type: Any
           ):
    # type: (...) -> Iterator[Any]
    """Returns a generator that mixes provided quantities forever
    trans: a function to convert the three arguments into a color. lambda x,y,z:(x,y,z) by default"""  # noqa: E501
    if len(lstcol) < 2:
        lstcol *= 2
    trans = kargs.get("trans", lambda x, y, z: (x, y, z))
    while True:
        for i in range(len(lstcol)):
            for j in range(len(lstcol)):
                for k in range(len(lstcol)):
                    if i != j or j != k or k != i:
                        yield trans(lstcol[(i + j) % len(lstcol)], lstcol[(j + k) % len(lstcol)], lstcol[(k + i) % len(lstcol)])  # noqa: E501


def incremental_label(label="tag%05i", start=0):
    # type: (str, int) -> Iterator[str]
    while True:
        yield label % start
        start += 1


def binrepr(val):
    # type: (int) -> str
    return bin(val)[2:]


def long_converter(s):
    # type: (str) -> int
    return int(s.replace('\n', '').replace(' ', ''), 16)

#########################
#    Enum management    #
#########################


class EnumElement:
    def __init__(self, key, value):
        # type: (str, int) -> None
        self._key = key
        self._value = value

    def __repr__(self):
        # type: () -> str
        return "<%s %s[%r]>" % (self.__dict__.get("_name", self.__class__.__name__), self._key, self._value)  # noqa: E501

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self._value, attr)

    def __str__(self):
        # type: () -> str
        return self._key

    def __bytes__(self):
        # type: () -> bytes
        return bytes_encode(self.__str__())

    def __hash__(self):
        # type: () -> int
        return self._value

    def __int__(self):
        # type: () -> int
        return int(self._value)

    def __eq__(self, other):
        # type: (Any) -> bool
        return self._value == int(other)

    def __neq__(self, other):
        # type: (Any) -> bool
        return not self.__eq__(other)


class Enum_metaclass(type):
    element_class = EnumElement

    def __new__(cls, name, bases, dct):
        # type: (Any, str, Any, Dict[str, Any]) -> Any
        rdict = {}
        for k, v in six.iteritems(dct):
            if isinstance(v, int):
                v = cls.element_class(k, v)
                dct[k] = v
                rdict[v] = k
        dct["__rdict__"] = rdict
        return super(Enum_metaclass, cls).__new__(cls, name, bases, dct)

    def __getitem__(self, attr):
        # type: (int) -> Any
        return self.__rdict__[attr]  # type: ignore

    def __contains__(self, val):
        # type: (int) -> bool
        return val in self.__rdict__  # type: ignore

    def get(self, attr, val=None):
        # type: (str, Optional[Any]) -> Any
        return self.__rdict__.get(attr, val)  # type: ignore

    def __repr__(self):
        # type: () -> str
        return "<%s>" % self.__dict__.get("name", self.__name__)


###################
#  Object saving  #
###################


def export_object(obj):
    # type: (Any) -> None
    import zlib
    print(bytes_base64(zlib.compress(six.moves.cPickle.dumps(obj, 2), 9)))


def import_object(obj=None):
    # type: (Optional[str]) -> Any
    import zlib
    if obj is None:
        obj = sys.stdin.read()
    return six.moves.cPickle.loads(zlib.decompress(base64_bytes(obj.strip())))  # noqa: E501


def save_object(fname, obj):
    # type: (str, Any) -> None
    """Pickle a Python object"""

    fd = gzip.open(fname, "wb")
    six.moves.cPickle.dump(obj, fd)
    fd.close()


def load_object(fname):
    # type: (str) -> Any
    """unpickle a Python object"""
    return six.moves.cPickle.load(gzip.open(fname, "rb"))


@conf.commands.register
def corrupt_bytes(data, p=0.01, n=None):
    # type: (str, float, Optional[int]) -> bytes
    """
    Corrupt a given percentage (at least one byte) or number of bytes
    from a string
    """
    s = array.array("B", bytes_encode(data))
    s_len = len(s)
    if n is None:
        n = max(1, int(s_len * p))
    for i in random.sample(range(s_len), n):
        s[i] = (s[i] + random.randint(1, 255)) % 256
    return s.tostring() if six.PY2 else s.tobytes()  # type: ignore


@conf.commands.register
def corrupt_bits(data, p=0.01, n=None):
    # type: (str, float, Optional[int]) -> bytes
    """
    Flip a given percentage (at least one bit) or number of bits
    from a string
    """
    s = array.array("B", bytes_encode(data))
    s_len = len(s) * 8
    if n is None:
        n = max(1, int(s_len * p))
    for i in random.sample(range(s_len), n):
        s[i // 8] ^= 1 << (i % 8)
    return s.tostring() if six.PY2 else s.tobytes()  # type: ignore


#############################
#  pcap capture file stuff  #
#############################

@conf.commands.register
def wrpcap(filename,  # type: Union[IO[bytes], str]
           pkt,  # type: _PacketIterable
           *args,  # type: Any
           **kargs  # type: Any
           ):
    # type: (...) -> None
    """Write a list of packets to a pcap file

    :param filename: the name of the file to write packets to, or an open,
        writable file-like object. The file descriptor will be
        closed at the end of the call, so do not use an object you
        do not want to close (e.g., running wrpcap(sys.stdout, [])
        in interactive mode will crash Scapy).
    :param gz: set to 1 to save a gzipped capture
    :param linktype: force linktype value
    :param endianness: "<" or ">", force endianness
    :param sync: do not bufferize writes to the capture file
    """
    with PcapWriter(filename, *args, **kargs) as fdesc:
        fdesc.write(pkt)


@conf.commands.register
def wrpcapng(filename,  # type: str
             pkt,  # type: _PacketIterable
             ):
    # type: (...) -> None
    """Write a list of packets to a pcapng file

    :param filename: the name of the file to write packets to, or an open,
        writable file-like object. The file descriptor will be
        closed at the end of the call, so do not use an object you
        do not want to close (e.g., running wrpcapng(sys.stdout, [])
        in interactive mode will crash Scapy).
    :param pkt: packets to write
    """
    with PcapNgWriter(filename) as fdesc:
        fdesc.write(pkt)


@conf.commands.register
def rdpcap(filename, count=-1):
    # type: (Union[IO[bytes], str], int) -> PacketList
    """Read a pcap or pcapng file and return a packet list

    :param count: read only <count> packets
    """
    # Rant: Our complicated use of metaclasses and especially the
    # __call__ function is, of course, not supported by MyPy.
    # One day we should simplify this mess and use a much simpler
    # layout that will actually be supported and properly dissected.
    with PcapReader(filename) as fdesc:  # type: ignore
        return fdesc.read_all(count=count)


# NOTE: Type hinting
# Mypy doesn't understand the following metaclass, and thinks each
# constructor (PcapReader...) needs 3 arguments each. To avoid this,
# we add a fake (=None) to the last 2 arguments then force the value
# to not be None in the signature and pack the whole thing in an ignore.
# This allows to not have # type: ignore every time we call those
# constructors.

class PcapReader_metaclass(type):
    """Metaclass for (Raw)Pcap(Ng)Readers"""

    def __new__(cls, name, bases, dct):
        # type: (Any, str, Any, Dict[str, Any]) -> Any
        """The `alternative` class attribute is declared in the PcapNg
        variant, and set here to the Pcap variant.

        """
        newcls = super(PcapReader_metaclass, cls).__new__(
            cls, name, bases, dct
        )
        if 'alternative' in dct:
            dct['alternative'].alternative = newcls
        return newcls

    def __call__(cls, filename):  # type: ignore
        # type: (Union[IO[bytes], str]) -> Any
        """Creates a cls instance, use the `alternative` if that
        fails.

        """
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        filename, fdesc, magic = cls.open(filename)
        if not magic:
            raise Scapy_Exception(
                "No data could be read!"
            )
        try:
            i.__init__(filename, fdesc, magic)
            return i
        except (Scapy_Exception, EOFError):
            pass

        if "alternative" in cls.__dict__:
            cls = cls.__dict__["alternative"]
            i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
            try:
                i.__init__(filename, fdesc, magic)
                return i
            except (Scapy_Exception, EOFError):
                pass

        raise Scapy_Exception("Not a supported capture file")

    @staticmethod
    def open(fname  # type: Union[IO[bytes], str]
             ):
        # type: (...) -> Tuple[str, _ByteStream, bytes]
        """Open (if necessary) filename, and read the magic."""
        if isinstance(fname, str):
            filename = fname
            try:
                fdesc = gzip.open(filename, "rb")  # type: _ByteStream
                magic = fdesc.read(4)
            except IOError:
                fdesc = open(filename, "rb")
                magic = fdesc.read(4)
        else:
            fdesc = fname
            filename = getattr(fdesc, "name", "No name")
            magic = fdesc.read(4)
        return filename, fdesc, magic


@six.add_metaclass(PcapReader_metaclass)
class RawPcapReader:
    """A stateful pcap reader. Each packet is returned as a string"""

    # TODO: use Generics to properly type the various readers.
    # As of right now, RawPcapReader is typed as if it returned packets
    # because all of its child do. Fix that

    nonblocking_socket = True
    PacketMetadata = collections.namedtuple("PacketMetadata",
                                            ["sec", "usec", "wirelen", "caplen"])  # noqa: E501

    def __init__(self, filename, fdesc=None, magic=None):  # type: ignore
        # type: (str, _ByteStream, bytes) -> None
        self.filename = filename
        self.f = fdesc
        if magic == b"\xa1\xb2\xc3\xd4":  # big endian
            self.endian = ">"
            self.nano = False
        elif magic == b"\xd4\xc3\xb2\xa1":  # little endian
            self.endian = "<"
            self.nano = False
        elif magic == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
            self.endian = ">"
            self.nano = True
        elif magic == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision  # noqa: E501
            self.endian = "<"
            self.nano = True
        else:
            raise Scapy_Exception(
                "Not a pcap capture file (bad magic: %r)" % magic
            )
        hdr = self.f.read(20)
        if len(hdr) < 20:
            raise Scapy_Exception("Invalid pcap file (too short)")
        vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(
            self.endian + "HHIIII", hdr
        )
        self.linktype = linktype
        self.snaplen = snaplen

    def __iter__(self):
        # type: () -> RawPcapReader
        return self

    def next(self):
        # type: () -> Packet
        """
        implement the iterator protocol on a set of packets in a pcap file
        """
        try:
            return self._read_packet()  # type: ignore
        except EOFError:
            raise StopIteration

    def __next__(self):
        # type: () -> Packet
        return self.next()

    def _read_packet(self, size=MTU):
        # type: (int) -> Tuple[bytes, RawPcapReader.PacketMetadata]
        """return a single packet read from the file as a tuple containing
        (pkt_data, pkt_metadata)

        raise EOFError when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            raise EOFError
        sec, usec, caplen, wirelen = struct.unpack(self.endian + "IIII", hdr)
        return (self.f.read(caplen)[:size],
                RawPcapReader.PacketMetadata(sec=sec, usec=usec,
                                             wirelen=wirelen, caplen=caplen))

    def read_packet(self, size=MTU):
        # type: (int) -> Packet
        raise Exception(
            "Cannot call read_packet() in RawPcapReader. Use "
            "_read_packet()"
        )

    def dispatch(self,
                 callback  # type: Callable[[Tuple[bytes, RawPcapReader.PacketMetadata]], Any]  # noqa: E501
                 ):
        # type: (...) -> None
        """call the specified callback routine for each packet read

        This is just a convenience function for the main loop
        that allows for easy launching of packet processing in a
        thread.
        """
        for p in self:
            callback(p)

    def _read_all(self, count=-1):
        # type: (int) -> List[Packet]
        """return a list of all packets in the pcap file
        """
        res = []  # type: List[Packet]
        while count != 0:
            count -= 1
            try:
                p = self.read_packet()  # type: Packet
            except EOFError:
                break
            res.append(p)
        return res

    def recv(self, size=MTU):
        # type: (int) -> bytes
        """ Emulate a socket
        """
        return self._read_packet(size=size)[0]

    def fileno(self):
        # type: () -> int
        return -1 if WINDOWS else self.f.fileno()

    def close(self):
        # type: () -> Optional[Any]
        return self.f.close()

    def __exit__(self, exc_type, exc_value, tracback):
        # type: (Optional[Any], Optional[Any], Optional[Any]) -> None
        self.close()

    # emulate SuperSocket
    @staticmethod
    def select(sockets,  # type: List[SuperSocket]
               remain=None,  # type: Optional[float]
               ):
        # type: (...) -> List[SuperSocket]
        return sockets


class PcapReader(RawPcapReader, _SuperSocket):
    def __init__(self, filename, fdesc=None, magic=None):  # type: ignore
        # type: (str, IO[bytes], bytes) -> None
        RawPcapReader.__init__(self, filename, fdesc, magic)
        try:
            self.LLcls = conf.l2types.num2layer[
                self.linktype
            ]  # type: Type[Packet]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype, self.linktype))  # noqa: E501
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            self.LLcls = conf.raw_layer

    def __enter__(self):
        # type: () -> PcapReader
        return self

    def read_packet(self, size=MTU):
        # type: (int) -> Packet
        rp = super(PcapReader, self)._read_packet(size=size)
        if rp is None:
            raise EOFError
        s, pkt_info = rp

        try:
            p = self.LLcls(s)  # type: Packet
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                from scapy.sendrecv import debug
                debug.crashed_on = (self.LLcls, s)
                raise
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            p = conf.raw_layer(s)
        power = Decimal(10) ** Decimal(-9 if self.nano else -6)
        p.time = EDecimal(pkt_info.sec + power * pkt_info.usec)
        p.wirelen = pkt_info.wirelen
        return p

    def recv(self, size=MTU):
        # type: (int) -> Packet
        return self.read_packet(size=size)

    def next(self):
        # type: () -> Packet
        try:
            return self.read_packet()
        except EOFError:
            raise StopIteration

    def read_all(self, count=-1):
        # type: (int) -> PacketList
        res = self._read_all(count)
        from scapy import plist
        return plist.PacketList(res, name=os.path.basename(self.filename))


class RawPcapNgReader(RawPcapReader):
    """A stateful pcapng reader. Each packet is returned as
    bytes.

    """

    alternative = RawPcapReader  # type: Type[Any]

    PacketMetadata = collections.namedtuple("PacketMetadataNg",  # type: ignore
                                            ["linktype", "tsresol",
                                             "tshigh", "tslow", "wirelen",
                                             "comment"])

    def __init__(self, filename, fdesc=None, magic=None):  # type: ignore
        # type: (str, IO[bytes], bytes) -> None
        self.filename = filename
        self.f = fdesc
        # A list of (linktype, snaplen, tsresol); will be populated by IDBs.
        self.interfaces = []  # type: List[Tuple[int, int, int]]
        self.default_options = {
            "tsresol": 1000000
        }
        self.blocktypes = {
            1: self._read_block_idb,
            2: self._read_block_pkt,
            3: self._read_block_spb,
            6: self._read_block_epb,
            10: self._read_block_dsb,
        }
        self.endian = "!"  # Will be overwritten by first SHB

        if magic != b"\x0a\x0d\x0d\x0a":  # PcapNg:
            raise Scapy_Exception(
                "Not a pcapng capture file (bad magic: %r)" % magic
            )

        try:
            self._read_block_shb()
        except EOFError:
            raise Scapy_Exception(
                "The first SHB of the pcapng file is malformed !"
            )

    def _read_block(self, size=MTU):
        # type: (int) -> Optional[Tuple[bytes, RawPcapNgReader.PacketMetadata]]  # noqa: E501
        try:
            blocktype = struct.unpack(self.endian + "I", self.f.read(4))[0]
        except struct.error:
            raise EOFError
        if blocktype == 0x0A0D0D0A:
            # This function updates the endianness based on the block content.
            self._read_block_shb()
            return None
        try:
            blocklen = struct.unpack(self.endian + "I", self.f.read(4))[0]
        except struct.error:
            raise EOFError
        if blocklen < 12:
            warning("Invalid block length !")
            raise EOFError
        block = self.f.read(blocklen - 12)
        self._read_block_tail(blocklen)
        return self.blocktypes.get(
            blocktype,
            lambda block, size: None
        )(block, size)

    def _read_block_tail(self, blocklen):
        # type: (int) -> None
        if blocklen % 4:
            pad = self.f.read(-blocklen % 4)
            warning("PcapNg: bad blocklen %d (MUST be a multiple of 4. "
                    "Ignored padding %r" % (blocklen, pad))
        try:
            if blocklen != struct.unpack(self.endian + 'I',
                                         self.f.read(4))[0]:
                raise EOFError("PcapNg: Invalid pcapng block (bad blocklen)")
        except struct.error:
            raise EOFError

    def _read_block_shb(self):
        # type: () -> None
        _blocklen = self.f.read(4)
        endian = self.f.read(4)
        if endian == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        elif endian == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        else:
            warning("Bad magic in Section Header block (not a pcapng file?)")
            raise EOFError

        blocklen = struct.unpack(self.endian + "I", _blocklen)[0]
        if blocklen < 16:
            warning("Invalid SHB block length!")
            raise EOFError
        options = self.f.read(blocklen - 16)
        self._read_block_tail(blocklen)
        self._read_options(options)

    def _read_packet(self, size=MTU):  # type: ignore
        # type: (int) -> Tuple[bytes, RawPcapNgReader.PacketMetadata]
        """Read blocks until it reaches either EOF or a packet, and
        returns None or (packet, (linktype, sec, usec, wirelen)),
        where packet is a string.

        """
        while True:
            res = self._read_block()
            if res is not None:
                return res

    def _read_options(self, options):
        # type: (bytes) -> Dict[str, Any]
        """Section Header Block"""
        opts = self.default_options.copy()  # type: Dict[str, Any]
        while len(options) >= 4:
            code, length = struct.unpack(self.endian + "HH", options[:4])
            # PCAP Next Generation (pcapng) Capture File Format
            # 4.2. - Interface Description Block
            # http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.2
            if code == 9 and length == 1 and len(options) >= 5:
                tsresol = orb(options[4])
                opts["tsresol"] = (2 if tsresol & 128 else 10) ** (
                    tsresol & 127
                )
            if code == 1 and length >= 1 and 4 + length < len(options):
                comment = options[4:4 + length]
                newline_index = comment.find(b"\n")
                if newline_index == -1:
                    warning("PcapNg: invalid comment option")
                    break
                opts["comment"] = comment[:newline_index]
            if code == 0:
                if length != 0:
                    warning("PcapNg: invalid option length %d for end-of-option" % length)  # noqa: E501
                break
            if length % 4:
                length += (4 - (length % 4))
            options = options[4 + length:]
        return opts

    def _read_block_idb(self, block, _):
        # type: (bytes, int) -> None
        """Interface Description Block"""
        # 2 bytes LinkType + 2 bytes Reserved
        # 4 bytes Snaplen
        options = self._read_options(block[8:-4])
        try:
            interface = struct.unpack(  # type: ignore
                self.endian + "HxxI",
                block[:8]
            ) + (options["tsresol"],)  # type: Tuple[int, int, int]
        except struct.error:
            warning("PcapNg: IDB is too small %d/8 !" % len(block))
            raise EOFError
        self.interfaces.append(interface)

    def _check_interface_id(self, intid):
        # type: (int) -> None
        """Check the interface id value and raise EOFError if invalid."""
        tmp_len = len(self.interfaces)
        if intid >= tmp_len:
            warning("PcapNg: invalid interface id %d/%d" % (intid, tmp_len))
            raise EOFError

    def _read_block_epb(self, block, size):
        # type: (bytes, int) -> Tuple[bytes, RawPcapNgReader.PacketMetadata]
        """Enhanced Packet Block"""
        try:
            intid, tshigh, tslow, caplen, wirelen = struct.unpack(
                self.endian + "5I",
                block[:20],
            )
        except struct.error:
            warning("PcapNg: EPB is too small %d/20 !" % len(block))
            raise EOFError

        # Compute the options offset taking padding into account
        if caplen % 4:
            opt_offset = 20 + caplen + (-caplen) % 4
        else:
            opt_offset = 20 + caplen

        # Parse options
        options = self._read_options(block[opt_offset:])
        comment = options.get("comment", None)

        self._check_interface_id(intid)

        return (block[20:20 + caplen][:size],
                RawPcapNgReader.PacketMetadata(linktype=self.interfaces[intid][0],  # noqa: E501
                                               tsresol=self.interfaces[intid][2],  # noqa: E501
                                               tshigh=tshigh,
                                               tslow=tslow,
                                               wirelen=wirelen,
                                               comment=comment))

    def _read_block_spb(self, block, size):
        # type: (bytes, int) -> Tuple[bytes, RawPcapNgReader.PacketMetadata]
        """Simple Packet Block"""
        # "it MUST be assumed that all the Simple Packet Blocks have
        # been captured on the interface previously specified in the
        # first Interface Description Block."
        intid = 0
        self._check_interface_id(intid)

        try:
            wirelen, = struct.unpack(self.endian + "I", block[:4])
        except struct.error:
            warning("PcapNg: SPB is too small %d/4 !" % len(block))
            raise EOFError

        caplen = min(wirelen, self.interfaces[intid][1])
        return (block[4:4 + caplen][:size],
                RawPcapNgReader.PacketMetadata(linktype=self.interfaces[intid][0],  # noqa: E501
                                               tsresol=self.interfaces[intid][2],  # noqa: E501
                                               tshigh=None,
                                               tslow=None,
                                               wirelen=wirelen,
                                               comment=None))

    def _read_block_pkt(self, block, size):
        # type: (bytes, int) -> Tuple[bytes, RawPcapNgReader.PacketMetadata]
        """(Obsolete) Packet Block"""
        try:
            intid, drops, tshigh, tslow, caplen, wirelen = struct.unpack(
                self.endian + "HH4I",
                block[:20],
            )
        except struct.error:
            warning("PcapNg: PKT is too small %d/20 !" % len(block))
            raise EOFError

        self._check_interface_id(intid)
        return (block[20:20 + caplen][:size],
                RawPcapNgReader.PacketMetadata(linktype=self.interfaces[intid][0],  # noqa: E501
                                               tsresol=self.interfaces[intid][2],  # noqa: E501
                                               tshigh=tshigh,
                                               tslow=tslow,
                                               wirelen=wirelen,
                                               comment=None))

    def _read_block_dsb(self, block, size):
        # type: (bytes, int) -> None
        """Decryption Secrets Block"""

        # Parse the secrets type and length fields
        try:
            secrets_type, secrets_length = struct.unpack(
                self.endian + "II",
                block[:8],
            )
            block = block[8:]
        except struct.error:
            warning("PcapNg: DSB is too small %d!", len(block))
            raise EOFError

        # Compute the secrets length including the padding
        padded_secrets_length = secrets_length + (-secrets_length) % 4
        if len(block) < padded_secrets_length:
            warning("PcapNg: invalid DSB secrets length!")
            raise EOFError

        # Extract secrets data and options
        secrets_data = block[:padded_secrets_length][:secrets_length]
        if block[padded_secrets_length:]:
            warning("PcapNg: DSB options are not supported!")

        # TLS Key Log
        if secrets_type == 0x544c534b:
            if getattr(conf, "tls_nss_keys", False) is False:
                warning("PcapNg: TLS Key Log available, but "
                        "the TLS layer is not loaded! Scapy won't be able "
                        "to decrypt the packets.")
            else:
                from scapy.layers.tls.session import load_nss_keys

                # Write Key Log to a file and parse it
                filename = get_temp_file()
                with open(filename, "wb") as fd:
                    fd.write(secrets_data)
                    fd.close()

                keys = load_nss_keys(filename)
                if not keys:
                    warning("PcapNg: invalid TLS Key Log in DSB!")
                else:
                    # Note: these attributes are only available when the TLS
                    #       layer is loaded.
                    conf.tls_nss_keys = keys  # type: ignore
                    conf.tls_session_enable = True  # type: ignore
        else:
            warning("PcapNg: Unknown DSB secrets type (0x%x)!", secrets_type)


class PcapNgReader(RawPcapNgReader, PcapReader, _SuperSocket):

    alternative = PcapReader

    def __init__(self, filename, fdesc=None, magic=None):  # type: ignore
        # type: (str, IO[bytes], bytes) -> None
        RawPcapNgReader.__init__(self, filename, fdesc, magic)

    def __enter__(self):
        # type: () -> PcapNgReader
        return self

    def read_packet(self, size=MTU):
        # type: (int) -> Packet
        rp = super(PcapNgReader, self)._read_packet(size=size)
        if rp is None:
            raise EOFError
        s, (linktype, tsresol, tshigh, tslow, wirelen, comment) = rp
        try:
            cls = conf.l2types.num2layer[linktype]  # type: Type[Packet]
            p = cls(s)  # type: Packet
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                raise
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            p = conf.raw_layer(s)
        if tshigh is not None:
            p.time = EDecimal((tshigh << 32) + tslow) / tsresol
        p.wirelen = wirelen
        p.comment = comment
        return p

    def recv(self, size=MTU):
        # type: (int) -> Packet
        return self.read_packet()


class GenericPcapWriter(object):
    nano = False
    linktype = None  # type: Optional[int]

    def _write_header(self, pkt):
        # type: (Optional[Union[Packet, bytes]]) -> None
        raise NotImplementedError

    def _write_packet(self,
                      packet,  # type: Union[bytes, Packet]
                      sec=None,  # type: Optional[float]
                      usec=None,  # type: Optional[int]
                      caplen=None,  # type: Optional[int]
                      wirelen=None,  # type: Optional[int]
                      comment=None  # type: Optional[bytes]
                      ):
        # type: (...) -> None
        raise NotImplementedError

    def _get_time(self,
                  packet,  # type: Union[bytes, Packet]
                  sec,  # type: Optional[float]
                  usec  # type: Optional[int]
                  ):
        # type: (...) -> Tuple[float, int]
        if hasattr(packet, "time"):
            if sec is None:
                packet_time = packet.time  # type: ignore
                tmp = int(packet_time)
                usec = int(round((packet_time - tmp) *
                           (1000000000 if self.nano else 1000000)))
                sec = float(packet_time)
        if sec is not None and usec is None:
            usec = 0
        return sec, usec  # type: ignore

    def write_header(self, pkt):
        # type: (Optional[Union[Packet, bytes]]) -> None
        if self.linktype is None:
            try:
                if pkt is None or isinstance(pkt, bytes):
                    # Can't guess LL
                    raise KeyError
                self.linktype = conf.l2types.layer2num[
                    pkt.__class__
                ]
            except KeyError:
                msg = "%s: unknown LL type for %s. Using type 1 (Ethernet)"
                warning(msg, self.__class__.__name__, pkt.__class__.__name__)
                self.linktype = DLT_EN10MB
        self._write_header(pkt)

    def write_packet(self,
                     packet,  # type: Union[bytes, Packet]
                     sec=None,  # type: Optional[float]
                     usec=None,  # type: Optional[int]
                     caplen=None,  # type: Optional[int]
                     wirelen=None,  # type: Optional[int]
                     ):
        # type: (...) -> None
        """
        Writes a single packet to the pcap file.

        :param packet: Packet, or bytes for a single packet
        :type packet: scapy.packet.Packet or bytes
        :param sec: time the packet was captured, in seconds since epoch. If
                    not supplied, defaults to now.
        :type sec: float
        :param usec: If ``nano=True``, then number of nanoseconds after the
                     second that the packet was captured. If ``nano=False``,
                     then the number of microseconds after the second the
                     packet was captured. If ``sec`` is not specified,
                     this value is ignored.
        :type usec: int or long
        :param caplen: The length of the packet in the capture file. If not
                       specified, uses ``len(raw(packet))``.
        :type caplen: int
        :param wirelen: The length of the packet on the wire. If not
                        specified, tries ``packet.wirelen``, otherwise uses
                        ``caplen``.
        :type wirelen: int
        :return: None
        :rtype: None
        """
        f_sec, usec = self._get_time(packet, sec, usec)

        rawpkt = bytes_encode(packet)
        caplen = len(rawpkt) if caplen is None else caplen

        if wirelen is None:
            if hasattr(packet, "wirelen"):
                wirelen = packet.wirelen  # type: ignore
        if wirelen is None:
            wirelen = caplen

        comment = getattr(packet, "comment", None)

        self._write_packet(
            rawpkt,
            sec=f_sec, usec=usec,
            caplen=caplen, wirelen=wirelen,
            comment=comment
        )


class GenericRawPcapWriter(GenericPcapWriter):
    header_present = False
    nano = False
    sync = False
    f = None  # type: Union[IO[bytes], gzip.GzipFile]

    def fileno(self):
        # type: () -> int
        return -1 if WINDOWS else self.f.fileno()

    def flush(self):
        # type: () -> Optional[Any]
        return self.f.flush()

    def close(self):
        # type: () -> Optional[Any]
        if not self.header_present:
            self.write_header(None)
        return self.f.close()

    def __enter__(self):
        # type: () -> GenericRawPcapWriter
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        # type: (Optional[Any], Optional[Any], Optional[Any]) -> None
        self.flush()
        self.close()

    def write(self, pkt):
        # type: (Union[_PacketIterable, bytes]) -> None
        """
        Writes a Packet, a SndRcvList object, or bytes to a pcap file.

        :param pkt: Packet(s) to write (one record for each Packet), or raw
                    bytes to write (as one record).
        :type pkt: iterable[scapy.packet.Packet], scapy.packet.Packet or bytes
        """
        if isinstance(pkt, bytes):
            if not self.header_present:
                self.write_header(pkt)
            self.write_packet(pkt)
        else:
            # Import here to avoid circular dependency
            from scapy.supersocket import IterSocket
            for p in IterSocket(pkt).iter:
                if not self.header_present:
                    self.write_header(p)

                if not isinstance(p, bytes) and \
                        self.linktype != conf.l2types.get(type(p), None):
                    warning("Inconsistent linktypes detected!"
                            " The resulting file might contain"
                            " invalid packets."
                            )

                self.write_packet(p)


class RawPcapWriter(GenericRawPcapWriter):
    """A stream PCAP writer with more control than wrpcap()"""

    def __init__(self,
                 filename,  # type: Union[IO[bytes], str]
                 linktype=None,  # type: Optional[int]
                 gz=False,  # type: bool
                 endianness="",  # type: str
                 append=False,  # type: bool
                 sync=False,  # type: bool
                 nano=False,  # type: bool
                 snaplen=MTU,  # type: int
                 ):
        # type: (...) -> None
        """
        :param filename: the name of the file to write packets to, or an open,
            writable file-like object.
        :param linktype: force linktype to a given value. If None, linktype is
            taken from the first writer packet
        :param gz: compress the capture on the fly
        :param endianness: force an endianness (little:"<", big:">").
            Default is native
        :param append: append packets to the capture file instead of
            truncating it
        :param sync: do not bufferize writes to the capture file
        :param nano: use nanosecond-precision (requires libpcap >= 1.5.0)

        """

        self.linktype = linktype
        self.snaplen = snaplen
        self.append = append
        self.gz = gz
        self.endian = endianness
        self.sync = sync
        self.nano = nano
        bufsz = 4096
        if sync:
            bufsz = 0

        if isinstance(filename, str):
            self.filename = filename
            if gz:
                self.f = cast(_ByteStream, gzip.open(
                    filename, append and "ab" or "wb", 9
                ))
            else:
                self.f = open(filename, append and "ab" or "wb", bufsz)
        else:
            self.f = filename
            self.filename = getattr(filename, "name", "No name")

    def _write_header(self, pkt):
        # type: (Optional[Union[Packet, bytes]]) -> None
        self.header_present = True

        if self.append:
            # Even if prone to race conditions, this seems to be
            # safest way to tell whether the header is already present
            # because we have to handle compressed streams that
            # are not as flexible as basic files
            if self.gz:
                g = gzip.open(self.filename, "rb")  # type: _ByteStream
            else:
                g = open(self.filename, "rb")
            try:
                if g.read(16):
                    return
            finally:
                g.close()

        if self.linktype is None:
            raise ValueError(
                "linktype could not be guessed. "
                "Please pass a linktype while creating the writer"
            )

        self.f.write(struct.pack(self.endian + "IHHIIII", 0xa1b23c4d if self.nano else 0xa1b2c3d4,  # noqa: E501
                                 2, 4, 0, 0, self.snaplen, self.linktype))
        self.f.flush()

    def _write_packet(self,
                      packet,  # type: Union[bytes, Packet]
                      sec=None,  # type: Optional[float]
                      usec=None,  # type: Optional[int]
                      caplen=None,  # type: Optional[int]
                      wirelen=None,  # type: Optional[int]
                      comment=None  # type: Optional[bytes]
                      ):
        # type: (...) -> None
        """
        Writes a single packet to the pcap file.

        :param packet: bytes for a single packet
        :type packet: bytes
        :param sec: time the packet was captured, in seconds since epoch. If
                    not supplied, defaults to now.
        :type sec: float
        :param usec: not used with pcapng
                     packet was captured
        :type usec: int or long
        :param caplen: The length of the packet in the capture file. If not
                       specified, uses ``len(packet)``.
        :type caplen: int
        :param wirelen: The length of the packet on the wire. If not
                        specified, uses ``caplen``.
        :type wirelen: int
        :return: None
        :rtype: None
        """
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        if sec is None or usec is None:
            t = time.time()
            it = int(t)
            if sec is None:
                sec = it
                usec = int(round((t - it) *
                                 (1000000000 if self.nano else 1000000)))
            elif usec is None:
                usec = 0

        self.f.write(struct.pack(self.endian + "IIII",
                                 int(sec), usec, caplen, wirelen))
        self.f.write(packet)
        if self.sync:
            self.f.flush()


class RawPcapNgWriter(GenericRawPcapWriter):
    """A stream pcapng writer with more control than wrpcapng()"""

    def __init__(self,
                 filename,  # type: str
                 ):
        # type: (...) -> None

        self.header_present = False
        self.tsresol = 1000000
        self.linktype = DLT_EN10MB

        # tcpdump only support little-endian in PCAPng files
        self.endian = "<"
        self.endian_magic = b"\x4d\x3c\x2b\x1a"

        self.filename = filename
        self.f = open(filename, "wb", 4096)

    def _get_time(self,
                  packet,  # type: Union[bytes, Packet]
                  sec,  # type: Optional[float]
                  usec  # type: Optional[int]
                  ):
        # type: (...) -> Tuple[float, int]
        if hasattr(packet, "time"):
            if sec is None:
                sec = float(packet.time)  # type: ignore

        if usec is None:
            usec = 0

        return sec, usec  # type: ignore

    def _add_padding(self, raw_data):
        # type: (bytes) -> bytes
        raw_data += ((-len(raw_data)) % 4) * b"\x00"
        return raw_data

    def build_block(self, block_type, block_body, options=None):
        # type: (bytes, bytes, Optional[bytes]) -> bytes

        # Pad Block Body to 32 bits
        block_body = self._add_padding(block_body)

        if options:
            block_body += options

        # An empty block is 12 bytes long
        block_total_length = 12 + len(block_body)

        # Block Type
        block = block_type
        # Block Total Length$
        block += struct.pack(self.endian + "I", block_total_length)
        # Block Body
        block += block_body
        # Block Total Length$
        block += struct.pack(self.endian + "I", block_total_length)

        return block

    def _write_header(self, pkt):
        # type: (Optional[Union[Packet, bytes]]) -> None
        if not self.header_present:
            self.header_present = True
            self._write_block_shb()
            self._write_block_idb()

    def _write_block_shb(self):
        # type: () -> None

        # Block Type
        block_type = b"\x0A\x0D\x0D\x0A"
        # Byte-Order Magic
        block_shb = self.endian_magic
        # Major Version
        block_shb += struct.pack(self.endian + "H", 1)
        # Minor Version
        block_shb += struct.pack(self.endian + "H", 0)
        # Section Length
        block_shb += struct.pack(self.endian + "Q", 0)

        self.f.write(self.build_block(block_type, block_shb))

    def _write_block_idb(self):
        # type: () -> None

        # Block Type
        block_type = struct.pack(self.endian + "I", 1)
        # LinkType
        block_idb = struct.pack(self.endian + "H", self.linktype)
        # Reserved
        block_idb += struct.pack(self.endian + "H", 0)
        # SnapLen
        block_idb += struct.pack(self.endian + "I", 262144)

        self.f.write(self.build_block(block_type, block_idb))

    def _write_block_spb(self, raw_pkt):
        # type: (bytes) -> None

        # Block Type
        block_type = struct.pack(self.endian + "I", 3)
        # Original Packet Length
        block_spb = struct.pack(self.endian + "I", len(raw_pkt))
        # Packet Data
        block_spb += raw_pkt

        self.f.write(self.build_block(block_type, block_spb))

    def _write_block_epb(self,
                         raw_pkt,  # type: bytes
                         timestamp=None,  # type: Optional[Union[EDecimal, float]]  # noqa: E501
                         caplen=None,  # type: Optional[int]
                         orglen=None,  # type: Optional[int]
                         comment=None  # type: Optional[bytes]
                         ):
        # type: (...) -> None

        if timestamp:
            tmp_ts = int(timestamp * self.tsresol)
            ts_high = tmp_ts >> 32
            ts_low = tmp_ts & 0xFFFFFFFF
        else:
            ts_high = ts_low = 0

        if not caplen:
            caplen = len(raw_pkt)

        if not orglen:
            orglen = len(raw_pkt)

        # Block Type
        block_type = struct.pack(self.endian + "I", 6)
        # Interface ID
        block_epb = struct.pack(self.endian + "I", 0)
        # Timestamp (High)
        block_epb += struct.pack(self.endian + "I", ts_high)
        # Timestamp (Low)
        block_epb += struct.pack(self.endian + "I", ts_low)
        # Captured Packet Length
        block_epb += struct.pack(self.endian + "I", caplen)
        # Original Packet Length
        block_epb += struct.pack(self.endian + "I", orglen)
        # Packet Data
        block_epb += raw_pkt

        # Comment option
        comment_opt = None
        if comment:
            comment = bytes_encode(comment)
            if not comment.endswith(b"\n"):
                comment += b"\n"
            comment_opt = struct.pack(self.endian + "HH", 1, len(comment))

            # Pad Option Value to 32 bits
            comment_opt += self._add_padding(bytes_encode(comment))
            comment_opt += struct.pack(self.endian + "HH", 0, 0)

        self.f.write(self.build_block(block_type, block_epb,
                                      options=comment_opt))

    def _write_packet(self,
                      packet,  # type: bytes
                      sec=None,  # type: Optional[float]
                      usec=None,  # type: Optional[int]
                      caplen=None,  # type: Optional[int]
                      wirelen=None,  # type: Optional[int]
                      comment=None  # type: Optional[bytes]
                      ):
        # type: (...) -> None
        """
        Writes a single packet to the pcap file.

        :param packet: bytes for a single packet
        :type packet: bytes
        :param sec: time the packet was captured, in seconds since epoch. If
                    not supplied, defaults to now.
        :type sec: float
        :param caplen: The length of the packet in the capture file. If not
                       specified, uses ``len(packet)``.
        :type caplen: int
        :param wirelen: The length of the packet on the wire. If not
                        specified, uses ``caplen``.
        :type wirelen: int
        :return: None
        :rtype: None
        """
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen

        self._write_block_epb(packet, timestamp=sec, caplen=caplen,
                              orglen=wirelen, comment=comment)
        if self.sync:
            self.f.flush()


class PcapWriter(RawPcapWriter):
    """A stream PCAP writer with more control than wrpcap()"""
    pass


class PcapNgWriter(RawPcapNgWriter):
    """A stream pcapng writer with more control than wrpcapng()"""

    def _get_time(self,
                  packet,  # type: Union[bytes, Packet]
                  sec,  # type: Optional[float]
                  usec  # type: Optional[int]
                  ):
        # type: (...) -> Tuple[float, int]
        if hasattr(packet, "time"):
            if sec is None:
                sec = float(packet.time)  # type: ignore

        if usec is None:
            usec = 0

        return sec, usec  # type: ignore


@conf.commands.register
def rderf(filename, count=-1):
    # type: (Union[IO[bytes], str], int) -> PacketList
    """Read a ERF file and return a packet list

    :param count: read only <count> packets
    """
    with ERFEthernetReader(filename) as fdesc:
        return fdesc.read_all(count=count)


class ERFEthernetReader_metaclass(PcapReader_metaclass):
    def __call__(cls, filename):  # type: ignore
        # type: (Union[IO[bytes], str]) -> Any
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        filename, fdesc = cls.open(filename)
        try:
            i.__init__(filename, fdesc)
            return i
        except (Scapy_Exception, EOFError):
            pass

        if "alternative" in cls.__dict__:
            cls = cls.__dict__["alternative"]
            i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
            try:
                i.__init__(filename, fdesc)
                return i
            except (Scapy_Exception, EOFError):
                pass

        raise Scapy_Exception("Not a supported capture file")

    @staticmethod
    def open(fname  # type: ignore
             ):
        # type: (...) -> Tuple[str, _ByteStream]
        """Open (if necessary) filename"""
        if isinstance(fname, str):
            filename = fname
            try:
                with gzip.open(filename, "rb") as tmp:
                    tmp.read(1)
                fdesc = gzip.open(filename, "rb")  # type: _ByteStream
            except IOError:
                fdesc = open(filename, "rb")

        else:
            fdesc = fname
            filename = getattr(fdesc, "name", "No name")
        return filename, fdesc


@six.add_metaclass(ERFEthernetReader_metaclass)
class ERFEthernetReader(PcapReader):

    def __init__(self, filename, fdesc=None):  # type: ignore
        # type: (Union[IO[bytes], str], IO[bytes]) -> None
        self.filename = filename  # type: ignore
        self.f = fdesc
        self.power = Decimal(10) ** Decimal(-9)

    # time is in 64-bits Endace's format which can be see here:
    # https://www.endace.com/erf-extensible-record-format-types.pdf
    def _convert_erf_timestamp(self, t):
        # type: (int) -> EDecimal
        sec = t >> 32
        frac_sec = t & 0xffffffff
        frac_sec *= 10**9
        frac_sec += (frac_sec & 0x80000000) << 1
        frac_sec >>= 32
        return EDecimal(sec + self.power * frac_sec)

    # The details of ERF Packet format can be see here:
    # https://www.endace.com/erf-extensible-record-format-types.pdf
    def read_packet(self, size=MTU):
        # type: (int) -> Packet

        # General ERF Header have exactly 16 bytes
        hdr = self.f.read(16)
        if len(hdr) < 16:
            raise EOFError

        # The timestamp is in little-endian byte-order.
        time = struct.unpack('<Q', hdr[:8])[0]
        # The rest is in big-endian byte-order.
        # Ignoring flags and lctr (loss counter) since they are ERF specific
        # header fields which Packet object does not support.
        type, _, rlen, _, wlen = struct.unpack('>BBHHH', hdr[8:])
        # Check if the type != 0x02, type Ethernet
        if type & 0x02 == 0:
            raise Scapy_Exception("Invalid ERF Type (Not TYPE_ETH)")

        # If there are extended headers, ignore it because Packet object does
        # not support it. Extended headers size is 8 bytes before the payload.
        if type & 0x80:
            _ = self.f.read(8)
            s = self.f.read(rlen - 24)
        else:
            s = self.f.read(rlen - 16)

        # Ethernet has 2 bytes of padding containing `offset` and `pad`. Both
        # of the fields are disregarded by Endace.
        p = s[2:size]
        from scapy.layers.l2 import Ether
        try:
            p = Ether(p)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                from scapy.sendrecv import debug
                debug.crashed_on = (Ether, s)
                raise
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            p = conf.raw_layer(s)

        p.time = self._convert_erf_timestamp(time)
        p.wirelen = wlen

        return p


@conf.commands.register
def wrerf(filename,  # type: Union[IO[bytes], str]
          pkt,  # type: _PacketIterable
          *args,  # type: Any
          **kargs  # type: Any
          ):
    # type: (...) -> None
    """Write a list of packets to a ERF file

    :param filename: the name of the file to write packets to, or an open,
        writable file-like object. The file descriptor will be
        closed at the end of the call, so do not use an object you
        do not want to close (e.g., running wrerf(sys.stdout, [])
        in interactive mode will crash Scapy).
    :param gz: set to 1 to save a gzipped capture
    :param append: append packets to the capture file instead of
        truncating it
    :param sync: do not bufferize writes to the capture file
    """
    with ERFEthernetWriter(filename, *args, **kargs) as fdesc:
        fdesc.write(pkt)


class ERFEthernetWriter(PcapWriter):
    """A stream ERF Ethernet writer with more control than wrerf()"""

    def __init__(self,
                 filename,  # type: Union[IO[bytes], str]
                 gz=False,  # type: bool
                 append=False,  # type: bool
                 sync=False,  # type: bool
                 ):
        # type: (...) -> None
        """
        :param filename: the name of the file to write packets to, or an open,
            writable file-like object.
        :param gz: compress the capture on the fly
        :param append: append packets to the capture file instead of
            truncating it
        :param sync: do not bufferize writes to the capture file
        """
        super(ERFEthernetWriter, self).__init__(filename,
                                                gz=gz,
                                                append=append,
                                                sync=sync)

    def write(self, pkt):  # type: ignore
        # type: (_PacketIterable) -> None
        """
        Writes a Packet, a SndRcvList object, or bytes to a ERF file.

        :param pkt: Packet(s) to write (one record for each Packet)
        :type pkt: iterable[scapy.packet.Packet], scapy.packet.Packet
        """
        # Import here to avoid circular dependency
        from scapy.supersocket import IterSocket
        for p in IterSocket(pkt).iter:
            self.write_packet(p)

    def write_packet(self, pkt):  # type: ignore
        # type: (Packet) -> None

        if hasattr(pkt, "time"):
            sec = int(pkt.time)
            usec = int((int(round((pkt.time - sec) * 10**9)) << 32) / 10**9)
            t = (sec << 32) + usec
        else:
            t = int(time.time()) << 32

        # There are 16 bytes of headers + 2 bytes of padding before the packets
        # payload.
        rlen = len(pkt) + 18

        if hasattr(pkt, "wirelen"):
            wirelen = pkt.wirelen
        if wirelen is None:
            wirelen = rlen

        self.f.write(struct.pack("<Q", t))
        self.f.write(struct.pack(">BBHHHH", 2, 0, rlen, 0, wirelen, 0))
        self.f.write(bytes(pkt))
        self.f.flush()

    def close(self):
        # type: () -> Optional[Any]
        return self.f.close()


@conf.commands.register
def import_hexcap(input_string=None):
    # type: (Optional[str]) -> bytes
    """Imports a tcpdump like hexadecimal view

    e.g: exported via hexdump() or tcpdump or wireshark's "export as hex"

    :param input_string: String containing the hexdump input to parse. If None,
        read from standard input.
    """
    re_extract_hexcap = re.compile(r"^((0x)?[0-9a-fA-F]{2,}[ :\t]{,3}|) *(([0-9a-fA-F]{2} {,2}){,16})")  # noqa: E501
    p = ""
    try:
        if input_string:
            input_function = six.StringIO(input_string).readline
        else:
            input_function = input
        while True:
            line = input_function().strip()
            if not line:
                break
            try:
                p += re_extract_hexcap.match(line).groups()[2]  # type: ignore
            except Exception:
                warning("Parsing error during hexcap")
                continue
    except EOFError:
        pass

    p = p.replace(" ", "")
    return hex_bytes(p)


@conf.commands.register
def wireshark(pktlist, wait=False, **kwargs):
    # type: (List[Packet], bool, **Any) -> Optional[Any]
    """
    Runs Wireshark on a list of packets.

    See :func:`tcpdump` for more parameter description.

    Note: this defaults to wait=False, to run Wireshark in the background.
    """
    return tcpdump(pktlist, prog=conf.prog.wireshark, wait=wait, **kwargs)


@conf.commands.register
def tdecode(
    pktlist,  # type: Union[IO[bytes], None, str, _PacketIterable]
    args=None,  # type: Optional[List[str]]
    **kwargs  # type: Any
):
    # type: (...) -> Any
    """
    Run tshark on a list of packets.

    :param args: If not specified, defaults to ``tshark -V``.

    See :func:`tcpdump` for more parameters.
    """
    if args is None:
        args = ["-V"]
    return tcpdump(pktlist, prog=conf.prog.tshark, args=args, **kwargs)


def _guess_linktype_name(value):
    # type: (int) -> str
    """Guess the DLT name from its value."""
    from scapy.libs.winpcapy import pcap_datalink_val_to_name
    return cast(bytes, pcap_datalink_val_to_name(value)).decode()


def _guess_linktype_value(name):
    # type: (str) -> int
    """Guess the value of a DLT name."""
    from scapy.libs.winpcapy import pcap_datalink_name_to_val
    val = cast(int, pcap_datalink_name_to_val(name.encode()))
    if val == -1:
        warning("Unknown linktype: %s. Using EN10MB", name)
        return DLT_EN10MB
    return val


@conf.commands.register
def tcpdump(
    pktlist=None,  # type: Union[IO[bytes], None, str, _PacketIterable]
    dump=False,  # type: bool
    getfd=False,  # type: bool
    args=None,  # type: Optional[List[str]]
    flt=None,  # type: Optional[str]
    prog=None,  # type: Optional[Any]
    getproc=False,  # type: bool
    quiet=False,  # type: bool
    use_tempfile=None,  # type: Optional[Any]
    read_stdin_opts=None,  # type: Optional[Any]
    linktype=None,  # type: Optional[Any]
    wait=True,  # type: bool
    _suppress=False  # type: bool
):
    # type: (...) -> Any
    """Run tcpdump or tshark on a list of packets.

    When using ``tcpdump`` on OSX (``prog == conf.prog.tcpdump``), this uses a
    temporary file to store the packets. This works around a bug in Apple's
    version of ``tcpdump``: http://apple.stackexchange.com/questions/152682/

    Otherwise, the packets are passed in stdin.

    This function can be explicitly enabled or disabled with the
    ``use_tempfile`` parameter.

    When using ``wireshark``, it will be called with ``-ki -`` to start
    immediately capturing packets from stdin.

    Otherwise, the command will be run with ``-r -`` (which is correct for
    ``tcpdump`` and ``tshark``).

    This can be overridden with ``read_stdin_opts``. This has no effect when
    ``use_tempfile=True``, or otherwise reading packets from a regular file.

    :param pktlist: a Packet instance, a PacketList instance or a list of
        Packet instances. Can also be a filename (as a string), an open
        file-like object that must be a file format readable by
        tshark (Pcap, PcapNg, etc.) or None (to sniff)
    :param flt: a filter to use with tcpdump
    :param dump:    when set to True, returns a string instead of displaying it.
    :param getfd:   when set to True, returns a file-like object to read data
        from tcpdump or tshark from.
    :param getproc: when set to True, the subprocess.Popen object is returned
    :param args:    arguments (as a list) to pass to tshark (example for tshark:
        args=["-T", "json"]).
    :param prog:    program to use (defaults to tcpdump, will work with tshark)
    :param quiet:   when set to True, the process stderr is discarded
    :param use_tempfile: When set to True, always use a temporary file to store
        packets.
        When set to False, pipe packets through stdin.
        When set to None (default), only use a temporary file with
        ``tcpdump`` on OSX.
    :param read_stdin_opts: When set, a list of arguments needed to capture
        from stdin. Otherwise, attempts to guess.
    :param linktype: A custom DLT value or name, to overwrite the default
        values.
    :param wait: If True (default), waits for the process to terminate before
        returning to Scapy. If False, the process will be detached to the
        background. If dump, getproc or getfd is True, these have the same
        effect as ``wait=False``.

    Examples::

        >>> tcpdump([IP()/TCP(), IP()/UDP()])
        reading from file -, link-type RAW (Raw IP)
        16:46:00.474515 IP 127.0.0.1.20 > 127.0.0.1.80: Flags [S], seq 0, win 8192, length 0  # noqa: E501
        16:46:00.475019 IP 127.0.0.1.53 > 127.0.0.1.53: [|domain]

        >>> tcpdump([IP()/TCP(), IP()/UDP()], prog=conf.prog.tshark)
          1   0.000000    127.0.0.1 -> 127.0.0.1    TCP 40 20->80 [SYN] Seq=0 Win=8192 Len=0  # noqa: E501
          2   0.000459    127.0.0.1 -> 127.0.0.1    UDP 28 53->53 Len=0

    To get a JSON representation of a tshark-parsed PacketList(), one can::

        >>> import json, pprint
        >>> json_data = json.load(tcpdump(IP(src="217.25.178.5",
        ...                                  dst="45.33.32.156"),
        ...                               prog=conf.prog.tshark,
        ...                               args=["-T", "json"],
        ...                               getfd=True))
        >>> pprint.pprint(json_data)
        [{u'_index': u'packets-2016-12-23',
          u'_score': None,
          u'_source': {u'layers': {u'frame': {u'frame.cap_len': u'20',
                                              u'frame.encap_type': u'7',
        [...]
                                              },
                                   u'ip': {u'ip.addr': u'45.33.32.156',
                                           u'ip.checksum': u'0x0000a20d',
        [...]
                                           u'ip.ttl': u'64',
                                           u'ip.version': u'4'},
                                   u'raw': u'Raw packet data'}},
          u'_type': u'pcap_file'}]
        >>> json_data[0]['_source']['layers']['ip']['ip.ttl']
        u'64'
    """
    getfd = getfd or getproc
    if prog is None:
        if not conf.prog.tcpdump:
            raise Scapy_Exception(
                "tcpdump is not available"
            )
        prog = [conf.prog.tcpdump]
    elif isinstance(prog, six.string_types):
        prog = [prog]
    else:
        raise ValueError("prog must be a string")

    if linktype is not None:
        if isinstance(linktype, int):
            # Guess name from value
            try:
                linktype_name = _guess_linktype_name(linktype)
            except StopIteration:
                linktype = -1
        else:
            # Guess value from name
            if linktype.startswith("DLT_"):
                linktype = linktype[4:]
            linktype_name = linktype
            try:
                linktype = _guess_linktype_value(linktype)
            except KeyError:
                linktype = -1
        if linktype == -1:
            raise ValueError(
                "Unknown linktype. Try passing its datalink name instead"
            )
        prog += ["-y", linktype_name]

    # Build Popen arguments
    if args is None:
        args = []
    else:
        # Make a copy of args
        args = list(args)

    if flt is not None:
        # Check the validity of the filter
        if linktype is None and isinstance(pktlist, str):
            # linktype is unknown but required. Read it from file
            with PcapReader(pktlist) as rd:
                if isinstance(rd, PcapNgReader):
                    # Get the linktype from the first packet
                    try:
                        _, metadata = rd._read_packet()
                        linktype = metadata.linktype
                        if OPENBSD and linktype == 228:
                            linktype = DLT_RAW
                    except EOFError:
                        raise ValueError(
                            "Cannot get linktype from a PcapNg packet."
                        )
                else:
                    linktype = rd.linktype
        from scapy.arch.common import compile_filter
        compile_filter(flt, linktype=linktype)
        args.append(flt)

    stdout = subprocess.PIPE if dump or getfd else None
    stderr = open(os.devnull) if quiet else None
    proc = None

    if use_tempfile is None:
        # Apple's tcpdump cannot read from stdin, see:
        # http://apple.stackexchange.com/questions/152682/
        use_tempfile = DARWIN and prog[0] == conf.prog.tcpdump

    if read_stdin_opts is None:
        if prog[0] == conf.prog.wireshark:
            # Start capturing immediately (-k) from stdin (-i -)
            read_stdin_opts = ["-ki", "-"]
        elif prog[0] == conf.prog.tcpdump and not OPENBSD:
            # Capture in packet-buffered mode (-U) from stdin (-r -)
            read_stdin_opts = ["-U", "-r", "-"]
        else:
            read_stdin_opts = ["-r", "-"]
    else:
        # Make a copy of read_stdin_opts
        read_stdin_opts = list(read_stdin_opts)

    if pktlist is None:
        # sniff
        with ContextManagerSubprocess(prog[0], suppress=_suppress):
            proc = subprocess.Popen(
                prog + args,
                stdout=stdout,
                stderr=stderr,
            )
    elif isinstance(pktlist, six.string_types):
        # file
        with ContextManagerSubprocess(prog[0], suppress=_suppress):
            proc = subprocess.Popen(
                prog + ["-r", pktlist] + args,
                stdout=stdout,
                stderr=stderr,
            )
    elif use_tempfile:
        pktlist = cast(Union[IO[bytes], "_PacketIterable"], pktlist)
        tmpfile = get_temp_file(  # type: ignore
            autoext=".pcap",
            fd=True
        )  # type: IO[bytes]
        try:
            tmpfile.writelines(
                iter(lambda: pktlist.read(1048576), b"")  # type: ignore
            )
        except AttributeError:
            pktlist = cast("_PacketIterable", pktlist)
            wrpcap(tmpfile, pktlist, linktype=linktype)
        else:
            tmpfile.close()
        with ContextManagerSubprocess(prog[0], suppress=_suppress):
            proc = subprocess.Popen(
                prog + ["-r", tmpfile.name] + args,
                stdout=stdout,
                stderr=stderr,
            )
    else:
        try:
            pktlist.fileno()  # type: ignore
            # pass the packet stream
            with ContextManagerSubprocess(prog[0], suppress=_suppress):
                proc = subprocess.Popen(
                    prog + read_stdin_opts + args,
                    stdin=pktlist,  # type: ignore
                    stdout=stdout,
                    stderr=stderr,
                )
        except (AttributeError, ValueError):
            # write the packet stream to stdin
            with ContextManagerSubprocess(prog[0], suppress=_suppress):
                proc = subprocess.Popen(
                    prog + read_stdin_opts + args,
                    stdin=subprocess.PIPE,
                    stdout=stdout,
                    stderr=stderr,
                )
            if proc is None:
                # An error has occurred
                return
            try:
                proc.stdin.writelines(  # type: ignore
                    iter(lambda: pktlist.read(1048576), b"")  # type: ignore
                )
            except AttributeError:
                wrpcap(proc.stdin, pktlist, linktype=linktype)  # type: ignore
            except UnboundLocalError:
                # The error was handled by ContextManagerSubprocess
                pass
            else:
                proc.stdin.close()  # type: ignore
    if proc is None:
        # An error has occurred
        return
    if dump:
        data = b"".join(
            iter(lambda: proc.stdout.read(1048576), b"")  # type: ignore
        )
        proc.terminate()
        return data
    if getproc:
        return proc
    if getfd:
        return proc.stdout
    if wait:
        proc.wait()


@conf.commands.register
def hexedit(pktlist):
    # type: (_PacketIterable) -> PacketList
    """Run hexedit on a list of packets, then return the edited packets."""
    f = get_temp_file()
    wrpcap(f, pktlist)
    with ContextManagerSubprocess(conf.prog.hexedit):
        subprocess.call([conf.prog.hexedit, f])
    rpktlist = rdpcap(f)
    os.unlink(f)
    return rpktlist


def get_terminal_width():
    # type: () -> Optional[int]
    """Get terminal width (number of characters) if in a window.

    Notice: this will try several methods in order to
    support as many terminals and OS as possible.
    """
    # Let's first try using the official API
    # (Python 3.3+)
    sizex = None  # type: Optional[int]
    if not six.PY2:
        import shutil
        sizex = shutil.get_terminal_size(fallback=(0, 0))[0]
        if sizex != 0:
            return sizex
    # Backups / Python 2.7
    if WINDOWS:
        from ctypes import windll, create_string_buffer
        # http://code.activestate.com/recipes/440694-determine-size-of-console-window-on-windows/
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
        if res:
            (bufx, bufy, curx, cury, wattr,
             left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)  # noqa: E501
            sizex = right - left + 1
            # sizey = bottom - top + 1
            return sizex
        return sizex
    else:
        # We have various methods
        # COLUMNS is set on some terminals
        try:
            sizex = int(os.environ['COLUMNS'])
        except Exception:
            pass
        if sizex:
            return sizex
        # We can query TIOCGWINSZ
        try:
            import fcntl
            import termios
            s = struct.pack('HHHH', 0, 0, 0, 0)
            x = fcntl.ioctl(1, termios.TIOCGWINSZ, s)
            sizex = struct.unpack('HHHH', x)[1]
        except IOError:
            pass
        return sizex


def pretty_list(rtlst,  # type: List[Tuple[Union[str, List[str]], ...]]
                header,  # type: List[Tuple[str, ...]]
                sortBy=0,  # type: int
                borders=False,  # type: bool
                ):
    # type: (...) -> str
    """
    Pretty list to fit the terminal, and add header.

    :param rtlst: a list of tuples. each tuple contains a value which can
        be either a string or a list of string.
    :param sortBy: the column id (starting with 0) which will be used for
        ordering
    :param borders: whether to put borders on the table or not
    """
    if borders:
        _space = "|"
    else:
        _space = "  "
    cols = len(header[0])
    # Windows has a fat terminal border
    _spacelen = len(_space) * (cols - 1) + int(WINDOWS)
    _croped = False
    # Sort correctly
    rtlst.sort(key=lambda x: x[sortBy])
    # Resolve multi-values
    for i, line in enumerate(rtlst):
        ids = []  # type: List[int]
        values = []  # type: List[Union[str, List[str]]]
        for j, val in enumerate(line):
            if isinstance(val, list):
                ids.append(j)
                values.append(val or " ")
        if values:
            del rtlst[i]
            k = 0
            for ex_vals in zip_longest(*values, fillvalue=" "):
                if k:
                    extra_line = [" "] * cols
                else:
                    extra_line = list(line)  # type: ignore
                for j, h in enumerate(ids):
                    extra_line[h] = ex_vals[j]
                rtlst.insert(i + k, tuple(extra_line))
                k += 1
    rtslst = cast(List[Tuple[str, ...]], rtlst)
    # Append tag
    rtslst = header + rtslst
    # Detect column's width
    colwidth = [max(len(y) for y in x) for x in zip(*rtslst)]
    # Make text fit in box (if required)
    width = get_terminal_width()
    if conf.auto_crop_tables and width:
        width = width - _spacelen
        while sum(colwidth) > width:
            _croped = True
            # Needs to be cropped
            # Get the longest row
            i = colwidth.index(max(colwidth))
            # Get all elements of this row
            row = [len(x[i]) for x in rtslst]
            # Get biggest element of this row: biggest of the array
            j = row.index(max(row))
            # Re-build column tuple with the edited element
            t = list(rtslst[j])
            t[i] = t[i][:-2] + "_"
            rtslst[j] = tuple(t)
            # Update max size
            row[j] = len(t[i])
            colwidth[i] = max(row)
    if _croped:
        log_runtime.info("Table cropped to fit the terminal (conf.auto_crop_tables==True)")  # noqa: E501
    # Generate padding scheme
    fmt = _space.join(["%%-%ds" % x for x in colwidth])
    # Append separation line if needed
    if borders:
        rtslst.insert(1, tuple("-" * x for x in colwidth))
    # Compile
    return "\n".join(fmt % x for x in rtslst)


def __make_table(
    yfmtfunc,  # type: Callable[[int], str]
    fmtfunc,  # type: Callable[[int], str]
    endline,  # type: str
    data,  # type: List[Tuple[Packet, Packet]]
    fxyz,  # type: Callable[[Packet, Packet], Tuple[Any, Any, Any]]
    sortx=None,  # type: Optional[Callable[[str], Tuple[Any, ...]]]
    sorty=None,  # type: Optional[Callable[[str], Tuple[Any, ...]]]
    seplinefunc=None,  # type: Optional[Callable[[int, List[int]], str]]
    dump=False  # type: bool
):
    # type: (...) -> Optional[str]
    """Core function of the make_table suite, which generates the table"""
    vx = {}  # type: Dict[str, int]
    vy = {}  # type: Dict[str, Optional[int]]
    vz = {}  # type: Dict[Tuple[str, str], str]
    vxf = {}  # type: Dict[str, str]

    # Python 2 backward compatibility
    fxyz = lambda_tuple_converter(fxyz)

    tmp_len = 0
    for e in data:
        xx, yy, zz = [str(s) for s in fxyz(*e)]
        tmp_len = max(len(yy), tmp_len)
        vx[xx] = max(vx.get(xx, 0), len(xx), len(zz))
        vy[yy] = None
        vz[(xx, yy)] = zz

    vxk = list(vx)
    vyk = list(vy)
    if sortx:
        vxk.sort(key=sortx)
    else:
        try:
            vxk.sort(key=int)
        except Exception:
            try:
                vxk.sort(key=atol)
            except Exception:
                vxk.sort()
    if sorty:
        vyk.sort(key=sorty)
    else:
        try:
            vyk.sort(key=int)
        except Exception:
            try:
                vyk.sort(key=atol)
            except Exception:
                vyk.sort()

    s = ""
    if seplinefunc:
        sepline = seplinefunc(tmp_len, [vx[x] for x in vxk])
        s += sepline + "\n"

    fmt = yfmtfunc(tmp_len)
    s += fmt % ""
    s += ' '
    for x in vxk:
        vxf[x] = fmtfunc(vx[x])
        s += vxf[x] % x
        s += ' '
    s += endline + "\n"
    if seplinefunc:
        s += sepline + "\n"
    for y in vyk:
        s += fmt % y
        s += ' '
        for x in vxk:
            s += vxf[x] % vz.get((x, y), "-")
            s += ' '
        s += endline + "\n"
    if seplinefunc:
        s += sepline + "\n"

    if dump:
        return s
    else:
        print(s, end="")
        return None


def make_table(*args, **kargs):
    # type: (*Any, **Any) -> Optional[Any]
    return __make_table(
        lambda l: "%%-%is" % l,
        lambda l: "%%-%is" % l,
        "",
        *args,
        **kargs
    )


def make_lined_table(*args, **kargs):
    # type: (*Any, **Any) -> Optional[str]
    return __make_table(  # type: ignore
        lambda l: "%%-%is |" % l,
        lambda l: "%%-%is |" % l,
        "",
        *args,
        seplinefunc=lambda a, x: "+".join(
            '-' * (y + 2) for y in [a - 1] + x + [-2]
        ),
        **kargs
    )


def make_tex_table(*args, **kargs):
    # type: (*Any, **Any) -> Optional[str]
    return __make_table(  # type: ignore
        lambda l: "%s",
        lambda l: "& %s",
        "\\\\",
        *args,
        seplinefunc=lambda a, x: "\\hline",
        **kargs
    )

####################
#   WHOIS CLIENT   #
####################


def whois(ip_address):
    # type: (str) -> bytes
    """Whois client for Python"""
    whois_ip = str(ip_address)
    try:
        query = socket.gethostbyname(whois_ip)
    except Exception:
        query = whois_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.ripe.net", 43))
    s.send(query.encode("utf8") + b"\r\n")
    answer = b""
    while True:
        d = s.recv(4096)
        answer += d
        if not d:
            break
    s.close()
    ignore_tag = b"remarks:"
    # ignore all lines starting with the ignore_tag
    lines = [line for line in answer.split(b"\n") if not line or (line and not line.startswith(ignore_tag))]  # noqa: E501
    # remove empty lines at the bottom
    for i in range(1, len(lines)):
        if not lines[-i].strip():
            del lines[-i]
        else:
            break
    return b"\n".join(lines[3:])

#######################
#   PERIODIC SENDER   #
#######################


class PeriodicSenderThread(threading.Thread):
    def __init__(self, sock, pkt, interval=0.5):
        # type: (Any, _PacketIterable, float) -> None
        """ Thread to send packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet or list of packets to send
            interval: interval between two packets
        """
        if not isinstance(pkt, list):
            self._pkts = [cast("Packet", pkt)]  # type: _PacketIterable
        else:
            self._pkts = pkt
        self._socket = sock
        self._stopped = threading.Event()
        self._interval = interval
        threading.Thread.__init__(self)

    def run(self):
        # type: () -> None
        while not self._stopped.is_set() and not self._socket.closed:
            for p in self._pkts:
                self._socket.send(p)
                time.sleep(self._interval)
                if self._stopped.is_set() or self._socket.closed:
                    break

    def stop(self):
        # type: () -> None
        self._stopped.set()
        self.join(self._interval * 2)


class SingleConversationSocket(object):
    def __init__(self, o):
        # type: (Any) -> None
        self._inner = o
        self._tx_mutex = threading.RLock()

    @property
    def __dict__(self):  # type: ignore
        return self._inner.__dict__

    def __getattr__(self, name):
        # type: (str) -> Any
        return getattr(self._inner, name)

    def sr1(self, *args, **kargs):
        # type: (*Any, **Any) -> Any
        with self._tx_mutex:
            return self._inner.sr1(*args, **kargs)

    def sr(self, *args, **kargs):
        # type: (*Any, **Any) -> Any
        with self._tx_mutex:
            return self._inner.sr(*args, **kargs)

    def send(self, x):
        # type: (Packet) -> Any
        with self._tx_mutex:
            try:
                return self._inner.send(x)
            except (ConnectionError, OSError) as e:
                self._inner.close()
                raise e
