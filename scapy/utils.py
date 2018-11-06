# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
General utility functions.
"""

from __future__ import absolute_import
from __future__ import print_function
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

import scapy.modules.six as six
from scapy.modules.six.moves import range

from scapy.config import conf
from scapy.consts import DARWIN, WINDOWS
from scapy.data import MTU, DLT_EN10MB
from scapy.compat import orb, raw, plain_str, chb, bytes_base64,\
    base64_bytes, hex_bytes, lambda_tuple_converter
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
    return isinstance(x, type) and issubclass(x, t)


def get_temp_file(keep=False, autoext=""):
    """Create a temporary file and return its name. When keep is False,
    the file is deleted when scapy exits.

    """
    fname = tempfile.NamedTemporaryFile(prefix="scapy", suffix=autoext,
                                        delete=False).name
    if not keep:
        conf.temp_files.append(fname)
    return fname


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
    :returns: a String only when dump=True
    """
    s = ""
    x = raw(x)
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
    :returns: a String only when dump=True
    """
    s = ""
    s = hexstr(raw(x), onlyasc=onlyasc, onlyhex=onlyhex, color=not dump)
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
    :returns: a String only if dump=True
    """
    x = raw(x)
    s = ", ".join("%#04x" % orb(x) for x in x)
    if dump:
        return s
    else:
        print(s)


@conf.commands.register
def hexstr(x, onlyasc=0, onlyhex=0, color=False):
    """Build a fancy tcpdump like hex from bytes."""
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
    x = raw(x)[::-1]
    y = raw(y)[::-1]
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
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += b"\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += b"\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff


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


def randstring(l):
    """
    Returns a random string of length l (l >= 0)
    """
    return b"".join(struct.pack('B', random.randint(0, 255)) for _ in range(l))


def zerofree_randstring(l):
    """
    Returns a random string of length l (l >= 0) without zero in it.
    """
    return b"".join(struct.pack('B', random.randint(1, 255)) for _ in range(l))


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


def ltoa(x):
    return inet_ntoa(struct.pack("!I", x & 0xffffffff))


def itom(x):
    return (0xffffffff00000000 >> x) & 0xffffffff


class ContextManagerSubprocess(object):
    """
    Context manager that eases checking for unknown command.

    Example:
    >>> with ContextManagerSubprocess("my custom message", "unknown_command"):
    >>>     subprocess.Popen(["unknown_command"])

    """

    def __init__(self, name, prog):
        self.name = name
        self.prog = prog

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        if isinstance(exc_value, (OSError, TypeError)):
            msg = "%s: executing %r failed" % (self.name, self.prog) if self.prog else "Could not execute %s, is it installed ?" % self.name  # noqa: E501
            if not conf.interactive:
                raise OSError(msg)
            else:
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


def do_graph(graph, prog=None, format=None, target=None, type=None, string=None, options=None):  # noqa: E501
    """do_graph(graph, prog=conf.prog.dot, format="svg",
         target="| conf.prog.display", options=None, [string=1]):
    string: if not None, simply return the graph string
    graph: GraphViz graph description
    format: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
    target: filename or redirect. Defaults pipe to Imagemagick's display program  # noqa: E501
    prog: which graphviz program to use
    options: options to be passed to prog"""

    if format is None:
        if WINDOWS:
            format = "png"  # use common format to make sure a viewer is installed  # noqa: E501
        else:
            format = "svg"
    if string:
        return graph
    if type is not None:
        format = type
    if prog is None:
        prog = conf.prog.dot
    start_viewer = False
    if target is None:
        if WINDOWS:
            target = get_temp_file(autoext="." + format)
            start_viewer = True
        else:
            with ContextManagerSubprocess("do_graph()", conf.prog.display):
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
    proc = subprocess.Popen("\"%s\" %s %s" % (prog, options or "", format or ""),  # noqa: E501
                            shell=True, stdin=subprocess.PIPE, stdout=target)
    proc.stdin.write(raw(graph))
    proc.stdin.close()
    proc.wait()
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
                with ContextManagerSubprocess("do_graph()", conf.prog.display):
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
        return raw(self.__str__())

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
    """Corrupt a given percentage or number of bytes from a string"""
    s = array.array("B", raw(s))
    s_len = len(s)
    if n is None:
        n = max(1, int(s_len * p))
    for i in random.sample(range(s_len), n):
        s[i] = (s[i] + random.randint(1, 255)) % 256
    return s.tostring() if six.PY2 else s.tobytes()


@conf.commands.register
def corrupt_bits(s, p=0.01, n=None):
    """Flip a given percentage or number of bits from a string"""
    s = array.array("B", raw(s))
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

filename: the name of the file to write packets to, or an open,
          writable file-like object. The file descriptor will be
          closed at the end of the call, so do not use an object you
          do not want to close (e.g., running wrpcap(sys.stdout, [])
          in interactive mode will crash Scapy).
gz: set to 1 to save a gzipped capture
linktype: force linktype value
endianness: "<" or ">", force endianness
sync: do not bufferize writes to the capture file

    """
    with PcapWriter(filename, *args, **kargs) as fdesc:
        fdesc.write(pkt)


@conf.commands.register
def rdpcap(filename, count=-1):
    """Read a pcap or pcapng file and return a packet list

count: read only <count> packets

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
        try:
            i.__init__(filename, fdesc, magic)
        except Scapy_Exception:
            if "alternative" in cls.__dict__:
                cls = cls.__dict__["alternative"]
                i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
                try:
                    i.__init__(filename, fdesc, magic)
                except Scapy_Exception:
                    raise
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

    read_allowed_exceptions = ()  # emulate SuperSocket
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

    def __iter__(self):
        return self

    def next(self):
        """implement the iterator protocol on a set of packets in a pcap file"""  # noqa: E501
        pkt = self.read_packet()
        if pkt is None:
            raise StopIteration
        return pkt
    __next__ = next

    def read_packet(self, size=MTU):
        """return a single packet read from the file

        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
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
            p = self.read_packet()
            if p is None:
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
            self.LLcls = conf.raw_layer

    def read_packet(self, size=MTU):
        rp = super(PcapReader, self).read_packet(size=size)
        if rp is None:
            return None
        s, pkt_info = rp

        try:
            p = self.LLcls(s)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        p.time = pkt_info.sec + (0.000000001 if self.nano else 0.000001) * pkt_info.usec  # noqa: E501
        p.wirelen = pkt_info.wirelen
        return p

    def read_all(self, count=-1):
        res = RawPcapReader.read_all(self, count)
        from scapy import plist
        return plist.PacketList(res, name=os.path.basename(self.filename))

    def recv(self, size=MTU):
        return self.read_packet(size=size)


class RawPcapNgReader(RawPcapReader):
    """A stateful pcapng reader. Each packet is returned as a
    string.

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
                return None
            block = self.f.read(blocklen - 12)
            if blocklen % 4:
                pad = self.f.read(4 - (blocklen % 4))
                warning("PcapNg: bad blocklen %d (MUST be a multiple of 4. "
                        "Ignored padding %r" % (blocklen, pad))
            try:
                if (blocklen,) != struct.unpack(self.endian + 'I',
                                                self.f.read(4)):
                    warning("PcapNg: Invalid pcapng block (bad blocklen)")
            except struct.error:
                return None
            res = self.blocktypes.get(blocktype,
                                      lambda block, size: None)(block, size)
            if res is not None:
                return res

    def read_block_idb(self, block, _):
        """Interface Description Block"""
        options = block[16:]
        tsresol = 1000000
        while len(options) >= 4:
            code, length = struct.unpack(self.endian + "HH", options[:4])
            # PCAP Next Generation (pcapng) Capture File Format
            # 4.2. - Interface Description Block
            # http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.2
            if code == 9 and length == 1 and len(options) >= 5:
                tsresol = orb(options[4])
                tsresol = (2 if tsresol & 128 else 10) ** (tsresol & 127)
            if code == 0:
                if length != 0:
                    warning("PcapNg: invalid option length %d for end-of-option" % length)  # noqa: E501
                break
            if length % 4:
                length += (4 - (length % 4))
            options = options[4 + length:]
        self.interfaces.append(struct.unpack(self.endian + "HxxI", block[:8]) +
                               (tsresol,))

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
            return None
        s, (linktype, tsresol, tshigh, tslow, wirelen) = rp
        try:
            p = conf.l2types[linktype](s)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        if tshigh is not None:
            p.time = float((tshigh << 32) + tslow) / tsresol
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
                 append=False, sync=False, nano=False):
        """
filename:   the name of the file to write packets to, or an open,
            writable file-like object.
linktype:   force linktype to a given value. If None, linktype is taken
            from the first writer packet
gz:         compress the capture on the fly
endianness: force an endianness (little:"<", big:">"). Default is native
append:     append packets to the capture file instead of truncating it
sync:       do not bufferize writes to the capture file
nano:       use nanosecond-precision (requires libpcap >= 1.5.0)

        """

        self.linktype = linktype
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
                                 2, 4, 0, 0, MTU, self.linktype))
        self.f.flush()

    def write(self, pkt):
        """accepts either a single packet or a list of packets to be
        written to the dumpfile

        """
        if isinstance(pkt, bytes):
            if not self.header_present:
                self._write_header(pkt)
            self._write_packet(pkt)
        else:
            pkt = pkt.__iter__()
            if not self.header_present:
                try:
                    p = next(pkt)
                except (StopIteration, RuntimeError):
                    self._write_header(None)
                    return
                self._write_header(p)
                self._write_packet(p)
            for p in pkt:
                self._write_packet(p)

    def _write_packet(self, packet, sec=None, usec=None, caplen=None, wirelen=None):  # noqa: E501
        """writes a single packet to the pcap file
        """
        if isinstance(packet, tuple):
            for pkt in packet:
                self._write_packet(pkt, sec=sec, usec=usec, caplen=caplen,
                                   wirelen=wirelen)
            return
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        if sec is None or usec is None:
            t = time.time()
            it = int(t)
            if sec is None:
                sec = it
            if usec is None:
                usec = int(round((t - it) * (1000000000 if self.nano else 1000000)))  # noqa: E501
        self.f.write(struct.pack(self.endian + "IIII", sec, usec, caplen, wirelen))  # noqa: E501
        self.f.write(packet)
        if self.sync:
            self.f.flush()

    def flush(self):
        return self.f.flush()

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        self.flush()
        self.close()


class PcapWriter(RawPcapWriter):
    """A stream PCAP writer with more control than wrpcap()"""

    def _write_header(self, pkt):
        if isinstance(pkt, tuple) and pkt:
            pkt = pkt[0]
        if self.linktype is None:
            try:
                self.linktype = conf.l2types[pkt.__class__]
            except KeyError:
                warning("PcapWriter: unknown LL type for %s. Using type 1 (Ethernet)", pkt.__class__.__name__)  # noqa: E501
                self.linktype = DLT_EN10MB
        RawPcapWriter._write_header(self, pkt)

    def _write_packet(self, packet):
        if isinstance(packet, tuple):
            for pkt in packet:
                self._write_packet(pkt)
            return
        sec = int(packet.time)
        usec = int(round((packet.time - sec) * (1000000000 if self.nano else 1000000)))  # noqa: E501
        rawpkt = raw(packet)
        caplen = len(rawpkt)
        RawPcapWriter._write_packet(self, rawpkt, sec=sec, usec=usec, caplen=caplen,  # noqa: E501
                                    wirelen=packet.wirelen or caplen)


@conf.commands.register
def import_hexcap():
    """Imports a tcpdump like hexadecimal view

    e.g: exported via hexdump() or tcpdump
    """
    re_extract_hexcap = re.compile(r"^((0x)?[0-9a-fA-F]{2,}[ :\t]{,3}|) *(([0-9a-fA-F]{2} {,2}){,16})")  # noqa: E501
    p = ""
    try:
        while True:
            line = input().strip()
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
def wireshark(pktlist):
    """Run wireshark on a list of packets"""
    f = get_temp_file()
    wrpcap(f, pktlist)
    with ContextManagerSubprocess("wireshark()", conf.prog.wireshark):
        subprocess.Popen([conf.prog.wireshark, "-r", f])


@conf.commands.register
def tcpdump(pktlist, dump=False, getfd=False, args=None,
            prog=None, getproc=False, quiet=False):
    """Run tcpdump or tshark on a list of packets

pktlist: a Packet instance, a PacketList instance or a list of Packet
         instances. Can also be a filename (as a string) or an open
         file-like object that must be a file format readable by
         tshark (Pcap, PcapNg, etc.)

dump:    when set to True, returns a string instead of displaying it.
getfd:   when set to True, returns a file-like object to read data
         from tcpdump or tshark from.
getproc: when set to True, the subprocess.Popen object is returned
args:    arguments (as a list) to pass to tshark (example for tshark:
         args=["-T", "json"]). Defaults to ["-n"].
prog:    program to use (defaults to tcpdump, will work with tshark)
quiet:   when set to True, the process stderr is discarded

Examples:

>>> tcpdump([IP()/TCP(), IP()/UDP()])
reading from file -, link-type RAW (Raw IP)
16:46:00.474515 IP 127.0.0.1.20 > 127.0.0.1.80: Flags [S], seq 0, win 8192, length 0  # noqa: E501
16:46:00.475019 IP 127.0.0.1.53 > 127.0.0.1.53: [|domain]

>>> tcpdump([IP()/TCP(), IP()/UDP()], prog=conf.prog.tshark)
  1   0.000000    127.0.0.1 -> 127.0.0.1    TCP 40 20->80 [SYN] Seq=0 Win=8192 Len=0  # noqa: E501
  2   0.000459    127.0.0.1 -> 127.0.0.1    UDP 28 53->53 Len=0

To get a JSON representation of a tshark-parsed PacketList(), one can:
>>> import json, pprint
>>> json_data = json.load(tcpdump(IP(src="217.25.178.5", dst="45.33.32.156"),
...                               prog=conf.prog.tshark, args=["-T", "json"],
...                               getfd=True))
>>> pprint.pprint(json_data)
[{u'_index': u'packets-2016-12-23',
  u'_score': None,
  u'_source': {u'layers': {u'frame': {u'frame.cap_len': u'20',
                                      u'frame.encap_type': u'7',
[...]
                                      u'frame.time_relative': u'0.000000000'},
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
        prog = [conf.prog.tcpdump]
    elif isinstance(prog, six.string_types):
        prog = [prog]
    _prog_name = "windump()" if WINDOWS else "tcpdump()"
    if pktlist is None:
        with ContextManagerSubprocess(_prog_name, prog[0]):
            proc = subprocess.Popen(
                prog + (args if args is not None else []),
                stdout=subprocess.PIPE if dump or getfd else None,
                stderr=open(os.devnull) if quiet else None,
            )
    elif isinstance(pktlist, six.string_types):
        with ContextManagerSubprocess(_prog_name, prog[0]):
            proc = subprocess.Popen(
                prog + ["-r", pktlist] + (args if args is not None else []),
                stdout=subprocess.PIPE if dump or getfd else None,
                stderr=open(os.devnull) if quiet else None,
            )
    elif DARWIN:
        # Tcpdump cannot read from stdin, see
        # <http://apple.stackexchange.com/questions/152682/>
        tmpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmpfile.writelines(iter(lambda: pktlist.read(1048576), b""))
        except AttributeError:
            wrpcap(tmpfile, pktlist)
        else:
            tmpfile.close()
        with ContextManagerSubprocess(_prog_name, prog[0]):
            proc = subprocess.Popen(
                prog + ["-r", tmpfile.name] + (args if args is not None else []),  # noqa: E501
                stdout=subprocess.PIPE if dump or getfd else None,
                stderr=open(os.devnull) if quiet else None,
            )
        conf.temp_files.append(tmpfile.name)
    else:
        with ContextManagerSubprocess(_prog_name, prog[0]):
            proc = subprocess.Popen(
                prog + ["-r", "-"] + (args if args is not None else []),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE if dump or getfd else None,
                stderr=open(os.devnull) if quiet else None,
            )
        try:
            proc.stdin.writelines(iter(lambda: pktlist.read(1048576), b""))
        except AttributeError:
            wrpcap(proc.stdin, pktlist)
        except UnboundLocalError:
            raise IOError("%s died unexpectedly !" % prog)
        else:
            proc.stdin.close()
    if dump:
        return b"".join(iter(lambda: proc.stdout.read(1048576), b""))
    if getproc:
        return proc
    if getfd:
        return proc.stdout
    proc.wait()


@conf.commands.register
def hexedit(pktlist):
    """Run hexedit on a list of packets, then return the edited packets."""
    f = get_temp_file()
    wrpcap(f, pktlist)
    with ContextManagerSubprocess("hexedit()", conf.prog.hexedit):
        subprocess.call([conf.prog.hexedit, f])
    pktlist = rdpcap(f)
    os.unlink(f)
    return pktlist


def get_terminal_width():
    """Get terminal width if in a window"""
    if WINDOWS:
        from ctypes import windll, create_string_buffer
        # http://code.activestate.com/recipes/440694-determine-size-of-console-window-on-windows/
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
        if res:
            import struct
            (bufx, bufy, curx, cury, wattr,
             left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)  # noqa: E501
            sizex = right - left + 1
            # sizey = bottom - top + 1
            return sizex
        else:
            return None
    else:
        sizex = 0
        try:
            import struct
            import fcntl
            import termios
            s = struct.pack('HHHH', 0, 0, 0, 0)
            x = fcntl.ioctl(1, termios.TIOCGWINSZ, s)
            sizex = struct.unpack('HHHH', x)[1]
        except IOError:
            pass
        if not sizex:
            try:
                sizex = int(os.environ['COLUMNS'])
            except Exception:
                pass
        if sizex:
            return sizex
        else:
            return None


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


def __make_table(yfmtfunc, fmtfunc, endline, data, fxyz, sortx=None, sorty=None, seplinefunc=None):  # noqa: E501
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

    if seplinefunc:
        sepline = seplinefunc(tmp_len, [vx[x] for x in vxk])
        print(sepline)

    fmt = yfmtfunc(tmp_len)
    print(fmt % "", end=' ')
    for x in vxk:
        vxf[x] = fmtfunc(vx[x])
        print(vxf[x] % x, end=' ')
    print(endline)
    if seplinefunc:
        print(sepline)
    for y in vyk:
        print(fmt % y, end=' ')
        for x in vxk:
            print(vxf[x] % vz.get((x, y), "-"), end=' ')
        print(endline)
    if seplinefunc:
        print(sepline)


def make_table(*args, **kargs):
    __make_table(lambda l: "%%-%is" % l, lambda l: "%%-%is" % l, "", *args, **kargs)  # noqa: E501


def make_lined_table(*args, **kargs):
    __make_table(lambda l: "%%-%is |" % l, lambda l: "%%-%is |" % l, "",
                 seplinefunc=lambda a, x: "+".join('-' * (y + 2) for y in [a - 1] + x + [-2]),  # noqa: E501
                 *args, **kargs)


def make_tex_table(*args, **kargs):
    __make_table(lambda l: "%s", lambda l: "& %s", "\\\\", seplinefunc=lambda a, x: "\\hline", *args, **kargs)  # noqa: E501

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
