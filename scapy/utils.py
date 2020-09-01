# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
General utility functions.
"""

from __future__ import absolute_import
from __future__ import print_function
from decimal import Decimal

import os
import sys
import socket
import collections
import random
import time
import gzip
import re
import struct
import array
import subprocess
import tempfile
import threading

import scapy.modules.six as six
from scapy.modules.six.moves import range, input

from scapy.config import conf
from scapy.consts import DARWIN, WINDOWS, WINDOWS_XP, OPENBSD
from scapy.data import MTU, DLT_EN10MB
from scapy.compat import orb, raw, plain_str, chb, bytes_base64,\
    base64_bytes, hex_bytes, lambda_tuple_converter, bytes_encode
from scapy.error import log_runtime, Scapy_Exception, warning
from scapy.pton_ntop import inet_pton

###########
#  Tools  #
###########


def issubtype(x, t):
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


class EDecimal(Decimal):
    """Extended Decimal

    This implements arithmetic and comparison with float for
    backward compatibility
    """

    def __add__(self, other, **kwargs):
        return EDecimal(Decimal.__add__(self, Decimal(other), **kwargs))

    def __radd__(self, other, **kwargs):
        return EDecimal(Decimal.__add__(self, Decimal(other), **kwargs))

    def __sub__(self, other, **kwargs):
        return EDecimal(Decimal.__sub__(self, Decimal(other), **kwargs))

    def __rsub__(self, other, **kwargs):
        return EDecimal(Decimal.__rsub__(self, Decimal(other), **kwargs))

    def __mul__(self, other, **kwargs):
        return EDecimal(Decimal.__mul__(self, Decimal(other), **kwargs))

    def __rmul__(self, other, **kwargs):
        return EDecimal(Decimal.__mul__(self, Decimal(other), **kwargs))

    def __truediv__(self, other, **kwargs):
        return EDecimal(Decimal.__truediv__(self, Decimal(other), **kwargs))

    def __floordiv__(self, other, **kwargs):
        return EDecimal(Decimal.__floordiv__(self, Decimal(other), **kwargs))

    def __div__(self, other, **kwargs):
        return EDecimal(Decimal.__div__(self, Decimal(other), **kwargs))

    def __rdiv__(self, other, **kwargs):
        return EDecimal(Decimal.__rdiv__(self, Decimal(other), **kwargs))

    def __mod__(self, other, **kwargs):
        return EDecimal(Decimal.__mod__(self, Decimal(other), **kwargs))

    def __rmod__(self, other, **kwargs):
        return EDecimal(Decimal.__rmod__(self, Decimal(other), **kwargs))

    def __divmod__(self, other, **kwargs):
        return EDecimal(Decimal.__divmod__(self, Decimal(other), **kwargs))

    def __rdivmod__(self, other, **kwargs):
        return EDecimal(Decimal.__rdivmod__(self, Decimal(other), **kwargs))

    def __pow__(self, other, **kwargs):
        return EDecimal(Decimal.__pow__(self, Decimal(other), **kwargs))

    def __rpow__(self, other, **kwargs):
        return EDecimal(Decimal.__rpow__(self, Decimal(other), **kwargs))

    def __eq__(self, other, **kwargs):
        return super(EDecimal, self).__eq__(other) or float(self) == other


def get_temp_file(keep=False, autoext="", fd=False):
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
    """Creates a temporary file, and returns its name.

    :param keep: If False (default), the directory will be recursively
                 deleted when Scapy exits.
    :return: A full path to a temporary directory.
    """

    dname = tempfile.mkdtemp(prefix="scapy")

    if not keep:
        conf.temp_files.append(dname)

    return dname


def sane_color(x):
    r = ""
    for i in x:
        j = orb(i)
        if (j < 32) or (j >= 127):
            r += conf.color_theme.not_printable(".")
        else:
            r += chr(j)
    return r


def sane(x):
    r = ""
    for i in x:
        j = orb(i)
        if (j < 32) or (j >= 127):
            r += "."
        else:
            r += chr(j)
    return r


@conf.commands.register
def restart():
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
    from scapy.volatile import VolatileValue
    if isinstance(x, VolatileValue):
        return repr(x)
    if type(x) in six.integer_types:
        return hex(x)
    elif isinstance(x, tuple):
        return "(%s)" % ", ".join(map(lhex, x))
    elif isinstance(x, list):
        return "[%s]" % ", ".join(map(lhex, x))
    else:
        return x


@conf.commands.register
def hexdump(x, dump=False):
    """Build a tcpdump like hexadecimal view

    :param x: a Packet
    :param dump: define if the result must be printed or returned in a variable
    :return: a String only when dump=True
    """
    s = ""
    x = bytes_encode(x)
    x_len = len(x)
    i = 0
    while i < x_len:
        s += "%04x  " % i
        for j in range(16):
            if i + j < x_len:
                s += "%02X " % orb(x[i + j])
            else:
                s += "   "
        s += " %s\n" % sane_color(x[i:i + 16])
        i += 16
    # remove trailing \n
    s = s[:-1] if s.endswith("\n") else s
    if dump:
        return s
    else:
        print(s)


@conf.commands.register
def linehexdump(x, onlyasc=0, onlyhex=0, dump=False):
    """Build an equivalent view of hexdump() on a single line

    Note that setting both onlyasc and onlyhex to 1 results in a empty output

    :param x: a Packet
    :param onlyasc: 1 to display only the ascii view
    :param onlyhex: 1 to display only the hexadecimal view
    :param dump: print the view if False
    :return: a String only when dump=True
    """
    s = ""
    s = hexstr(x, onlyasc=onlyasc, onlyhex=onlyhex, color=not dump)
    if dump:
        return s
    else:
        print(s)


@conf.commands.register
def chexdump(x, dump=False):
    """Build a per byte hexadecimal representation

    Example:
        >>> chexdump(IP())
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x7c, 0xe7, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01  # noqa: E501

    :param x: a Packet
    :param dump: print the view if False
    :return: a String only if dump=True
    """
    x = bytes_encode(x)
    s = ", ".join("%#04x" % orb(x) for x in x)
    if dump:
        return s
    else:
        print(s)


@conf.commands.register
def hexstr(x, onlyasc=0, onlyhex=0, color=False):
    """Build a fancy tcpdump like hex from bytes."""
    x = bytes_encode(x)
    _sane_func = sane_color if color else sane
    s = []
    if not onlyasc:
        s.append(" ".join("%02X" % orb(b) for b in x))
    if not onlyhex:
        s.append(_sane_func(x))
    return "  ".join(s)


def repr_hex(s):
    """ Convert provided bitstring to a simple string of hex digits """
    return "".join("%02x" % orb(x) for x in s)


@conf.commands.register
def hexdiff(x, y):
    """Show differences between 2 binary strings"""
    x = bytes_encode(x)[::-1]
    y = bytes_encode(y)[::-1]
    SUBST = 1
    INSERT = 1
    d = {(-1, -1): (0, (-1, -1))}
    for j in range(len(y)):
        d[-1, j] = d[-1, j - 1][0] + INSERT, (-1, j - 1)
    for i in range(len(x)):
        d[i, -1] = d[i - 1, -1][0] + INSERT, (i - 1, -1)

    for j in range(len(y)):
        for i in range(len(x)):
            d[i, j] = min((d[i - 1, j - 1][0] + SUBST * (x[i] != y[j]), (i - 1, j - 1)),  # noqa: E501
                          (d[i - 1, j][0] + INSERT, (i - 1, j)),
                          (d[i, j - 1][0] + INSERT, (i, j - 1)))

    backtrackx = []
    backtracky = []
    i = len(x) - 1
    j = len(y) - 1
    while not (i == j == -1):
        i2, j2 = d[i, j][1]
        backtrackx.append(x[i2 + 1:i + 1])
        backtracky.append(y[j2 + 1:j + 1])
        i, j = i2, j2

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
            if i + j < btx_len:
                if line[j]:
                    col = colorize[(linex[j] != liney[j]) * (doy - dox)]
                    print(col("%02X" % orb(line[j])), end=' ')
                    if linex[j] == liney[j]:
                        cl += sane_color(line[j])
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
    checksum_endian_transform = lambda chk: chk
else:
    checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | chk << 8


def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return checksum_endian_transform(s) & 0xffff


def _fletcher16(charbuf):
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
    """Calculates Fletcher-16 checksum of the given buffer.

       Note:
       If the buffer contains the two checkbytes derived from the Fletcher-16 checksum  # noqa: E501
       the result of this function has to be 0. Otherwise the buffer has been corrupted.  # noqa: E501
    """
    (c0, c1) = _fletcher16(binbuf)
    return (c1 << 8) | c0


@conf.commands.register
def fletcher16_checkbytes(binbuf, offset):
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
    return b"".join(chb(int(x, 16)) for x in plain_str(mac).split(':'))


def valid_mac(mac):
    try:
        return len(mac2str(mac)) == 6
    except ValueError:
        pass
    return False


def str2mac(s):
    if isinstance(s, str):
        return ("%02x:" * 6)[:-1] % tuple(map(ord, s))
    return ("%02x:" * 6)[:-1] % tuple(s)


def randstring(length):
    """
    Returns a random string of length (length >= 0)
    """
    return b"".join(struct.pack('B', random.randint(0, 255))
                    for _ in range(length))


def zerofree_randstring(length):
    """
    Returns a random string of length (length >= 0) without zero in it.
    """
    return b"".join(struct.pack('B', random.randint(1, 255))
                    for _ in range(length))


def strxor(s1, s2):
    """
    Returns the binary XOR of the 2 provided strings s1 and s2. s1 and s2
    must be of same length.
    """
    return b"".join(map(lambda x, y: chb(orb(x) ^ orb(y)), s1, s2))


def strand(s1, s2):
    """
    Returns the binary AND of the 2 provided strings s1 and s2. s1 and s2
    must be of same length.
    """
    return b"".join(map(lambda x, y: chb(orb(x) & orb(y)), s1, s2))


# Workaround bug 643005 : https://sourceforge.net/tracker/?func=detail&atid=105470&aid=643005&group_id=5470  # noqa: E501
try:
    socket.inet_aton("255.255.255.255")
except socket.error:
    def inet_aton(x):
        if x == "255.255.255.255":
            return b"\xff" * 4
        else:
            return socket.inet_aton(x)
else:
    inet_aton = socket.inet_aton

inet_ntoa = socket.inet_ntoa


def atol(x):
    try:
        ip = inet_aton(x)
    except socket.error:
        ip = inet_aton(socket.gethostbyname(x))
    return struct.unpack("!I", ip)[0]


def valid_ip(addr):
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
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    if '/' in addr:
        ip, mask = addr.split('/', 1)
        return valid_ip(ip) and mask.isdigit() and 0 <= int(mask) <= 32
    return valid_ip(addr)


def valid_ip6(addr):
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
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    if '/' in addr:
        ip, mask = addr.split('/', 1)
        return valid_ip6(ip) and mask.isdigit() and 0 <= int(mask) <= 128
    return valid_ip6(addr)


if WINDOWS_XP:
    # That is a hell of compatibility :(
    def ltoa(x):
        return inet_ntoa(struct.pack("<I", x & 0xffffffff))
else:
    def ltoa(x):
        return inet_ntoa(struct.pack("!I", x & 0xffffffff))


def itom(x):
    return (0xffffffff00000000 >> x) & 0xffffffff


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
        self.prog = prog
        self.suppress = suppress

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_value is None:
            return
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
        self.result_export_object = ""
        try:
            import mock  # noqa: F401
        except Exception:
            raise ImportError("The mock module needs to be installed !")

    def __enter__(self):
        import mock

        def write(s, decorator=self):
            decorator.result_export_object += s
        mock_stdout = mock.Mock()
        mock_stdout.write = write
        self.bck_stdout = sys.stdout
        sys.stdout = mock_stdout
        return self

    def __exit__(self, *exc):
        sys.stdout = self.bck_stdout
        return False

    def get_output(self, eval_bytes=False):
        if self.result_export_object.startswith("b'") and eval_bytes:
            return plain_str(eval(self.result_export_object))
        return self.result_export_object


def do_graph(graph, prog=None, format=None, target=None, type=None,
             string=None, options=None):
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
        warning("type is deprecated, and was renamed format")
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
            if conf.prog.display == conf.prog._default:
                os.startfile(target.name)
            else:
                with ContextManagerSubprocess(conf.prog.display):
                    subprocess.Popen([conf.prog.display, target.name])


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
    s = ""
    for c in x:
        s += _TEX_TR.get(c, c)
    return s


def colgen(*lstcol, **kargs):
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
    while True:
        yield label % start
        start += 1


def binrepr(val):
    return bin(val)[2:]


def long_converter(s):
    return int(s.replace('\n', '').replace(' ', ''), 16)

#########################
#    Enum management    #
#########################


class EnumElement:
    _value = None

    def __init__(self, key, value):
        self._key = key
        self._value = value

    def __repr__(self):
        return "<%s %s[%r]>" % (self.__dict__.get("_name", self.__class__.__name__), self._key, self._value)  # noqa: E501

    def __getattr__(self, attr):
        return getattr(self._value, attr)

    def __str__(self):
        return self._key

    def __bytes__(self):
        return bytes_encode(self.__str__())

    def __hash__(self):
        return self._value

    def __int__(self):
        return int(self._value)

    def __eq__(self, other):
        return self._value == int(other)

    def __neq__(self, other):
        return not self.__eq__(other)


class Enum_metaclass(type):
    element_class = EnumElement

    def __new__(cls, name, bases, dct):
        rdict = {}
        for k, v in six.iteritems(dct):
            if isinstance(v, int):
                v = cls.element_class(k, v)
                dct[k] = v
                rdict[v] = k
        dct["__rdict__"] = rdict
        return super(Enum_metaclass, cls).__new__(cls, name, bases, dct)

    def __getitem__(self, attr):
        return self.__rdict__[attr]

    def __contains__(self, val):
        return val in self.__rdict__

    def get(self, attr, val=None):
        return self.__rdict__.get(attr, val)

    def __repr__(self):
        return "<%s>" % self.__dict__.get("name", self.__name__)


###################
#  Object saving  #
###################


def export_object(obj):
    print(bytes_base64(gzip.zlib.compress(six.moves.cPickle.dumps(obj, 2), 9)))


def import_object(obj=None):
    if obj is None:
        obj = sys.stdin.read()
    return six.moves.cPickle.loads(gzip.zlib.decompress(base64_bytes(obj.strip())))  # noqa: E501


def save_object(fname, obj):
    """Pickle a Python object"""

    fd = gzip.open(fname, "wb")
    six.moves.cPickle.dump(obj, fd)
    fd.close()


def load_object(fname):
    """unpickle a Python object"""
    return six.moves.cPickle.load(gzip.open(fname, "rb"))


@conf.commands.register
def corrupt_bytes(s, p=0.01, n=None):
    """
    Corrupt a given percentage (at least one byte) or number of bytes
    from a string
    """
    s = array.array("B", bytes_encode(s))
    s_len = len(s)
    if n is None:
        n = max(1, int(s_len * p))
    for i in random.sample(range(s_len), n):
        s[i] = (s[i] + random.randint(1, 255)) % 256
    return s.tostring() if six.PY2 else s.tobytes()


@conf.commands.register
def corrupt_bits(s, p=0.01, n=None):
    """
    Flip a given percentage (at least one bit) or number of bits
    from a string
    """
    s = array.array("B", bytes_encode(s))
    s_len = len(s) * 8
    if n is None:
        n = max(1, int(s_len * p))
    for i in random.sample(range(s_len), n):
        s[i // 8] ^= 1 << (i % 8)
    return s.tostring() if six.PY2 else s.tobytes()


#############################
#  pcap capture file stuff  #
#############################

@conf.commands.register
def wrpcap(filename, pkt, *args, **kargs):
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
def rdpcap(filename, count=-1):
    """Read a pcap or pcapng file and return a packet list

    :param count: read only <count> packets
    """
    with PcapReader(filename) as fdesc:
        return fdesc.read_all(count=count)


class PcapReader_metaclass(type):
    """Metaclass for (Raw)Pcap(Ng)Readers"""

    def __new__(cls, name, bases, dct):
        """The `alternative` class attribute is declared in the PcapNg
        variant, and set here to the Pcap variant.

        """
        newcls = super(PcapReader_metaclass, cls).__new__(cls, name, bases, dct)  # noqa: E501
        if 'alternative' in dct:
            dct['alternative'].alternative = newcls
        return newcls

    def __call__(cls, filename):
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
        except Scapy_Exception:
            if "alternative" in cls.__dict__:
                cls = cls.__dict__["alternative"]
                i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
                try:
                    i.__init__(filename, fdesc, magic)
                except Scapy_Exception:
                    try:
                        i.f.seek(-4, 1)
                    except Exception:
                        pass
                    raise Scapy_Exception("Not a supported capture file")

        return i

    @staticmethod
    def open(filename):
        """Open (if necessary) filename, and read the magic."""
        if isinstance(filename, six.string_types):
            try:
                fdesc = gzip.open(filename, "rb")
                magic = fdesc.read(4)
            except IOError:
                fdesc = open(filename, "rb")
                magic = fdesc.read(4)
        else:
            fdesc = filename
            filename = getattr(fdesc, "name", "No name")
            magic = fdesc.read(4)
        return filename, fdesc, magic


class RawPcapReader(six.with_metaclass(PcapReader_metaclass)):
    """A stateful pcap reader. Each packet is returned as a string"""

    nonblocking_socket = True
    PacketMetadata = collections.namedtuple("PacketMetadata",
                                            ["sec", "usec", "wirelen", "caplen"])  # noqa: E501

    def __init__(self, filename, fdesc, magic):
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
        return self

    def next(self):
        """implement the iterator protocol on a set of packets in a pcap file
        pkt is a tuple (pkt_data, pkt_metadata) as defined in
        RawPcapReader.read_packet()

        """
        try:
            return self.read_packet()
        except EOFError:
            raise StopIteration
    __next__ = next

    def read_packet(self, size=MTU):
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

    def dispatch(self, callback):
        """call the specified callback routine for each packet read

        This is just a convenience function for the main loop
        that allows for easy launching of packet processing in a
        thread.
        """
        for p in self:
            callback(p)

    def read_all(self, count=-1):
        """return a list of all packets in the pcap file
        """
        res = []
        while count != 0:
            count -= 1
            try:
                p = self.read_packet()
            except EOFError:
                break
            res.append(p)
        return res

    def recv(self, size=MTU):
        """ Emulate a socket
        """
        return self.read_packet(size=size)[0]

    def fileno(self):
        return self.f.fileno()

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        self.close()

    # emulate SuperSocket
    @staticmethod
    def select(sockets, remain=None):
        return sockets, None


class PcapReader(RawPcapReader):
    def __init__(self, filename, fdesc, magic):
        RawPcapReader.__init__(self, filename, fdesc, magic)
        try:
            self.LLcls = conf.l2types[self.linktype]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype, self.linktype))  # noqa: E501
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            self.LLcls = conf.raw_layer

    def read_packet(self, size=MTU):
        rp = super(PcapReader, self).read_packet(size=size)
        if rp is None:
            raise EOFError
        s, pkt_info = rp

        try:
            p = self.LLcls(s)
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

    def read_all(self, count=-1):
        res = RawPcapReader.read_all(self, count)
        from scapy import plist
        return plist.PacketList(res, name=os.path.basename(self.filename))

    def recv(self, size=MTU):
        return self.read_packet(size=size)


class RawPcapNgReader(RawPcapReader):
    """A stateful pcapng reader. Each packet is returned as
    bytes.

    """

    alternative = RawPcapReader

    PacketMetadata = collections.namedtuple("PacketMetadata",
                                            ["linktype", "tsresol",
                                             "tshigh", "tslow", "wirelen"])

    def __init__(self, filename, fdesc, magic):
        self.filename = filename
        self.f = fdesc
        # A list of (linktype, snaplen, tsresol); will be populated by IDBs.
        self.interfaces = []
        self.default_options = {
            "tsresol": 1000000
        }
        self.blocktypes = {
            1: self.read_block_idb,
            2: self.read_block_pkt,
            3: self.read_block_spb,
            6: self.read_block_epb,
        }
        if magic != b"\x0a\x0d\x0d\x0a":  # PcapNg:
            raise Scapy_Exception(
                "Not a pcapng capture file (bad magic: %r)" % magic
            )
        # see https://github.com/pcapng/pcapng
        blocklen, magic = self.f.read(4), self.f.read(4)  # noqa: F841
        if magic == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        elif magic == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        else:
            raise Scapy_Exception("Not a pcapng capture file (bad magic)")
        self.f.read(12)
        blocklen = struct.unpack("!I", blocklen)[0]
        # Read default options
        self.default_options = self.read_options(
            self.f.read(blocklen - 24)
        )
        try:
            self.f.seek(0)
        except Exception:
            pass

    def read_packet(self, size=MTU):
        """Read blocks until it reaches either EOF or a packet, and
        returns None or (packet, (linktype, sec, usec, wirelen)),
        where packet is a string.

        """
        while True:
            try:
                blocktype, blocklen = struct.unpack(self.endian + "2I",
                                                    self.f.read(8))
            except struct.error:
                raise EOFError
            block = self.f.read(blocklen - 12)
            if blocklen % 4:
                pad = self.f.read(4 - (blocklen % 4))
                warning("PcapNg: bad blocklen %d (MUST be a multiple of 4. "
                        "Ignored padding %r" % (blocklen, pad))
            try:
                if (blocklen,) != struct.unpack(self.endian + 'I',
                                                self.f.read(4)):
                    warning("PcapNg: Invalid pcapng block (bad blocklen)")
                    raise EOFError
            except struct.error:
                raise EOFError
            res = self.blocktypes.get(blocktype,
                                      lambda block, size: None)(block, size)
            if res is not None:
                return res

    def read_options(self, options):
        """Section Header Block"""
        opts = self.default_options.copy()
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
            if code == 0:
                if length != 0:
                    warning("PcapNg: invalid option length %d for end-of-option" % length)  # noqa: E501
                break
            if length % 4:
                length += (4 - (length % 4))
            options = options[4 + length:]
        return opts

    def read_block_idb(self, block, _):
        """Interface Description Block"""
        options = self.read_options(block[16:])
        self.interfaces.append(struct.unpack(self.endian + "HxxI", block[:8]) +
                               (options["tsresol"],))

    def read_block_epb(self, block, size):
        """Enhanced Packet Block"""
        intid, tshigh, tslow, caplen, wirelen = struct.unpack(
            self.endian + "5I",
            block[:20],
        )
        return (block[20:20 + caplen][:size],
                RawPcapNgReader.PacketMetadata(linktype=self.interfaces[intid][0],  # noqa: E501
                                               tsresol=self.interfaces[intid][2],  # noqa: E501
                                               tshigh=tshigh,
                                               tslow=tslow,
                                               wirelen=wirelen))

    def read_block_spb(self, block, size):
        """Simple Packet Block"""
        # "it MUST be assumed that all the Simple Packet Blocks have
        # been captured on the interface previously specified in the
        # first Interface Description Block."
        intid = 0
        wirelen, = struct.unpack(self.endian + "I", block[:4])
        caplen = min(wirelen, self.interfaces[intid][1])
        return (block[4:4 + caplen][:size],
                RawPcapNgReader.PacketMetadata(linktype=self.interfaces[intid][0],  # noqa: E501
                                               tsresol=self.interfaces[intid][2],  # noqa: E501
                                               tshigh=None,
                                               tslow=None,
                                               wirelen=wirelen))

    def read_block_pkt(self, block, size):
        """(Obsolete) Packet Block"""
        intid, drops, tshigh, tslow, caplen, wirelen = struct.unpack(
            self.endian + "HH4I",
            block[:20],
        )
        return (block[20:20 + caplen][:size],
                RawPcapNgReader.PacketMetadata(linktype=self.interfaces[intid][0],  # noqa: E501
                                               tsresol=self.interfaces[intid][2],  # noqa: E501
                                               tshigh=tshigh,
                                               tslow=tslow,
                                               wirelen=wirelen))


class PcapNgReader(RawPcapNgReader):

    alternative = PcapReader

    def __init__(self, filename, fdesc, magic):
        RawPcapNgReader.__init__(self, filename, fdesc, magic)

    def read_packet(self, size=MTU):
        rp = super(PcapNgReader, self).read_packet(size=size)
        if rp is None:
            raise EOFError
        s, (linktype, tsresol, tshigh, tslow, wirelen) = rp
        try:
            p = conf.l2types[linktype](s)
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
        return p

    def read_all(self, count=-1):
        res = RawPcapNgReader.read_all(self, count)
        from scapy import plist
        return plist.PacketList(res, name=os.path.basename(self.filename))

    def recv(self, size=MTU):
        return self.read_packet()


class RawPcapWriter:
    """A stream PCAP writer with more control than wrpcap()"""

    def __init__(self, filename, linktype=None, gz=False, endianness="",
                 append=False, sync=False, nano=False, snaplen=MTU):
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
        self.header_present = 0
        self.append = append
        self.gz = gz
        self.endian = endianness
        self.sync = sync
        self.nano = nano
        bufsz = 4096
        if sync:
            bufsz = 0

        if isinstance(filename, six.string_types):
            self.filename = filename
            self.f = [open, gzip.open][gz](filename, append and "ab" or "wb", gz and 9 or bufsz)  # noqa: E501
        else:
            self.f = filename
            self.filename = getattr(filename, "name", "No name")

    def fileno(self):
        return self.f.fileno()

    def _write_header(self, pkt):
        self.header_present = 1

        if self.append:
            # Even if prone to race conditions, this seems to be
            # safest way to tell whether the header is already present
            # because we have to handle compressed streams that
            # are not as flexible as basic files
            g = [open, gzip.open][self.gz](self.filename, "rb")
            if g.read(16):
                return

        self.f.write(struct.pack(self.endian + "IHHIIII", 0xa1b23c4d if self.nano else 0xa1b2c3d4,  # noqa: E501
                                 2, 4, 0, 0, self.snaplen, self.linktype))
        self.f.flush()

    def write(self, pkt):
        """
        Writes a Packet, a SndRcvList object, or bytes to a pcap file.

        :param pkt: Packet(s) to write (one record for each Packet), or raw
                    bytes to write (as one record).
        :type pkt: iterable[scapy.packet.Packet], scapy.packet.Packet or bytes
        """
        if isinstance(pkt, bytes):
            if not self.header_present:
                self._write_header(pkt)
            self._write_packet(pkt)
        else:
            # Import here to avoid a circular dependency
            from scapy.plist import SndRcvList
            if isinstance(pkt, SndRcvList):
                def _iter(pkt=pkt):
                    for s, r in pkt:
                        if s.sent_time:
                            s.time = s.sent_time
                        yield s
                        yield r
                pkt = _iter()
            else:
                pkt = pkt.__iter__()
            for p in pkt:

                if not self.header_present:
                    self._write_header(p)

                if self.linktype != conf.l2types.get(type(p), None):
                    warning("Inconsistent linktypes detected!"
                            " The resulting PCAP file might contain"
                            " invalid packets."
                            )

                self._write_packet(p)

    def _write_packet(self, packet, sec=None, usec=None, caplen=None,
                      wirelen=None):
        """
        Writes a single packet to the pcap file.

        :param packet: bytes for a single packet
        :type packet: bytes
        :param sec: time the packet was captured, in seconds since epoch. If
                    not supplied, defaults to now.
        :type sec: int or long
        :param usec: If ``nano=True``, then number of nanoseconds after the
                     second that the packet was captured. If ``nano=False``,
                     then the number of microseconds after the second the
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
                                 sec, usec, caplen, wirelen))
        self.f.write(packet)
        if self.sync:
            self.f.flush()

    def flush(self):
        return self.f.flush()

    def close(self):
        if not self.header_present:
            self._write_header(None)
        return self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        self.flush()
        self.close()


class PcapWriter(RawPcapWriter):
    """A stream PCAP writer with more control than wrpcap()"""

    def _write_header(self, pkt):
        if self.linktype is None:
            try:
                self.linktype = conf.l2types[pkt.__class__]
                # Import here to prevent import loops
                from scapy.layers.inet import IP
                from scapy.layers.inet6 import IPv6
                if OPENBSD and isinstance(pkt, (IP, IPv6)):
                    self.linktype = 14  # DLT_RAW
            except KeyError:
                warning("PcapWriter: unknown LL type for %s. Using type 1 (Ethernet)", pkt.__class__.__name__)  # noqa: E501
                self.linktype = DLT_EN10MB
        RawPcapWriter._write_header(self, pkt)

    def _write_packet(self, packet, sec=None, usec=None, caplen=None,
                      wirelen=None):
        """
        Writes a single packet to the pcap file.

        :param packet: Packet, or bytes for a single packet
        :type packet: scapy.packet.Packet or bytes
        :param sec: time the packet was captured, in seconds since epoch. If
                    not supplied, defaults to now.
        :type sec: int or long
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
        if hasattr(packet, "time"):
            if sec is None:
                sec = int(packet.time)
                usec = int(round((packet.time - sec) *
                                 (1000000000 if self.nano else 1000000)))
        if usec is None:
            usec = 0

        rawpkt = raw(packet)
        caplen = len(rawpkt) if caplen is None else caplen

        if wirelen is None:
            if hasattr(packet, "wirelen"):
                wirelen = packet.wirelen
        if wirelen is None:
            wirelen = caplen

        RawPcapWriter._write_packet(
            self, rawpkt, sec=sec, usec=usec, caplen=caplen, wirelen=wirelen)


@conf.commands.register
def import_hexcap(input_string=None):
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
                p += re_extract_hexcap.match(line).groups()[2]
            except Exception:
                warning("Parsing error during hexcap")
                continue
    except EOFError:
        pass

    p = p.replace(" ", "")
    return hex_bytes(p)


@conf.commands.register
def wireshark(pktlist, wait=False, **kwargs):
    """
    Runs Wireshark on a list of packets.

    See :func:`tcpdump` for more parameter description.

    Note: this defaults to wait=False, to run Wireshark in the background.
    """
    return tcpdump(pktlist, prog=conf.prog.wireshark, wait=wait, **kwargs)


@conf.commands.register
def tdecode(pktlist, args=None, **kwargs):
    """
    Run tshark on a list of packets.

    :param args: If not specified, defaults to ``tshark -V``.

    See :func:`tcpdump` for more parameters.
    """
    if args is None:
        args = ["-V"]
    return tcpdump(pktlist, prog=conf.prog.tshark, args=args, **kwargs)


def _guess_linktype_name(value):
    """Guess the DLT name from its value."""
    import scapy.data
    return next(
        k[4:] for k, v in six.iteritems(scapy.data.__dict__)
        if k.startswith("DLT") and v == value
    )


def _guess_linktype_value(name):
    """Guess the value of a DLT name."""
    import scapy.data
    if not name.startswith("DLT_"):
        name = "DLT_" + name
    return scapy.data.__dict__[name]


@conf.commands.register
def tcpdump(pktlist=None, dump=False, getfd=False, args=None, flt=None,
            prog=None, getproc=False, quiet=False, use_tempfile=None,
            read_stdin_opts=None, linktype=None, wait=True,
            _suppress=False):
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
        # Tcpdump does not support integers in -y (yet)
        # https://github.com/the-tcpdump-group/tcpdump/issues/758
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
        from scapy.arch.common import compile_filter
        compile_filter(flt)
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
        tmpfile = get_temp_file(autoext=".pcap", fd=True)
        try:
            tmpfile.writelines(iter(lambda: pktlist.read(1048576), b""))
        except AttributeError:
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
        # pass the packet stream
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
            proc.stdin.writelines(iter(lambda: pktlist.read(1048576), b""))
        except AttributeError:
            wrpcap(proc.stdin, pktlist, linktype=linktype)
        except UnboundLocalError:
            # The error was handled by ContextManagerSubprocess
            pass
        else:
            proc.stdin.close()
    if proc is None:
        # An error has occurred
        return
    if dump:
        return b"".join(iter(lambda: proc.stdout.read(1048576), b""))
    if getproc:
        return proc
    if getfd:
        return proc.stdout
    if wait:
        proc.wait()


@conf.commands.register
def hexedit(pktlist):
    """Run hexedit on a list of packets, then return the edited packets."""
    f = get_temp_file()
    wrpcap(f, pktlist)
    with ContextManagerSubprocess(conf.prog.hexedit):
        subprocess.call([conf.prog.hexedit, f])
    pktlist = rdpcap(f)
    os.unlink(f)
    return pktlist


def get_terminal_width():
    """Get terminal width (number of characters) if in a window.

    Notice: this will try several methods in order to
    support as many terminals and OS as possible.
    """
    # Let's first try using the official API
    # (Python 3.3+)
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
        return None
    else:
        # We have various methods
        sizex = None
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


def pretty_list(rtlst, header, sortBy=0, borders=False):
    """Pretty list to fit the terminal, and add header"""
    if borders:
        _space = "|"
    else:
        _space = "  "
    # Windows has a fat terminal border
    _spacelen = len(_space) * (len(header) - 1) + (10 if WINDOWS else 0)
    _croped = False
    # Sort correctly
    rtlst.sort(key=lambda x: x[sortBy])
    # Append tag
    rtlst = header + rtlst
    # Detect column's width
    colwidth = [max([len(y) for y in x]) for x in zip(*rtlst)]
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
            row = [len(x[i]) for x in rtlst]
            # Get biggest element of this row: biggest of the array
            j = row.index(max(row))
            # Re-build column tuple with the edited element
            t = list(rtlst[j])
            t[i] = t[i][:-2] + "_"
            rtlst[j] = tuple(t)
            # Update max size
            row[j] = len(t[i])
            colwidth[i] = max(row)
    if _croped:
        log_runtime.info("Table cropped to fit the terminal (conf.auto_crop_tables==True)")  # noqa: E501
    # Generate padding scheme
    fmt = _space.join(["%%-%ds" % x for x in colwidth])
    # Append separation line if needed
    if borders:
        rtlst.insert(1, tuple("-" * x for x in colwidth))
    # Compile
    rt = "\n".join(((fmt % x).strip() for x in rtlst))
    return rt


def __make_table(yfmtfunc, fmtfunc, endline, data, fxyz, sortx=None, sorty=None, seplinefunc=None, dump=False):  # noqa: E501
    """Core function of the make_table suite, which generates the table"""
    vx = {}
    vy = {}
    vz = {}
    vxf = {}

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


def make_table(*args, **kargs):
    return __make_table(lambda l: "%%-%is" % l, lambda l: "%%-%is" % l, "", *args, **kargs)  # noqa: E501


def make_lined_table(*args, **kargs):
    return __make_table(lambda l: "%%-%is |" % l, lambda l: "%%-%is |" % l, "",
                        seplinefunc=lambda a, x: "+".join('-' * (y + 2) for y in [a - 1] + x + [-2]),  # noqa: E501
                        *args, **kargs)


def make_tex_table(*args, **kargs):
    return __make_table(lambda l: "%s", lambda l: "& %s", "\\\\", seplinefunc=lambda a, x: "\\hline", *args, **kargs)  # noqa: E501

####################
#   WHOIS CLIENT   #
####################


def whois(ip_address):
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
        """ Thread to send packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet to send
            interval: interval between two packets
        """
        self._pkt = pkt
        self._socket = sock
        self._stopped = threading.Event()
        self._interval = interval
        threading.Thread.__init__(self)

    def run(self):
        while not self._stopped.is_set():
            self._socket.send(self._pkt)
            time.sleep(self._interval)

    def stop(self):
        self._stopped.set()


class SingleConversationSocket(object):
    def __init__(self, o):
        self._inner = o
        self._tx_mutex = threading.RLock()

    @property
    def __dict__(self):
        return self._inner.__dict__

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def sr1(self, *args, **kargs):
        with self._tx_mutex:
            return self._inner.sr1(*args, **kargs)

    def sr(self, *args, **kargs):
        with self._tx_mutex:
            return self._inner.sr(*args, **kargs)

    def send(self, x):
        with self._tx_mutex:
            return self._inner.send(x)
