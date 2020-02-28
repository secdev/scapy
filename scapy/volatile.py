# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# Copyright (C) Gauthier Sebaux
# This program is published under a GPLv2 license

"""
Fields that hold random numbers.
"""

from __future__ import absolute_import
import copy
import random
import time
import math
import re
import uuid
import struct

from scapy.base_classes import Net
from scapy.compat import bytes_encode, chb, plain_str
from scapy.utils import corrupt_bits, corrupt_bytes
from scapy.modules.six.moves import range

####################
#  Random numbers  #
####################


class RandomEnumeration:
    """iterate through a sequence in random order.
       When all the values have been drawn, if forever=1, the drawing is done again.  # noqa: E501
       If renewkeys=0, the draw will be in the same order, guaranteeing that the same  # noqa: E501
       number will be drawn in not less than the number of integers of the sequence"""  # noqa: E501

    def __init__(self, inf, sup, seed=None, forever=1, renewkeys=0):
        self.forever = forever
        self.renewkeys = renewkeys
        self.inf = inf
        self.rnd = random.Random(seed)
        self.sbox_size = 256

        self.top = sup - inf + 1

        n = 0
        while (1 << n) < self.top:
            n += 1
        self.n = n

        self.fs = min(3, (n + 1) // 2)
        self.fsmask = 2**self.fs - 1
        self.rounds = max(self.n, 3)
        self.turns = 0
        self.i = 0

    def __iter__(self):
        return self

    def next(self):
        while True:
            if self.turns == 0 or (self.i == 0 and self.renewkeys):
                self.cnt_key = self.rnd.randint(0, 2**self.n - 1)
                self.sbox = [self.rnd.randint(0, self.fsmask)
                             for _ in range(self.sbox_size)]
            self.turns += 1
            while self.i < 2**self.n:
                ct = self.i ^ self.cnt_key
                self.i += 1
                for _ in range(self.rounds):  # Unbalanced Feistel Network
                    lsb = ct & self.fsmask
                    ct >>= self.fs
                    lsb ^= self.sbox[ct % self.sbox_size]
                    ct |= lsb << (self.n - self.fs)

                if ct < self.top:
                    return self.inf + ct
            self.i = 0
            if not self.forever:
                raise StopIteration
    __next__ = next


class VolatileValue(object):
    def __repr__(self):
        return "<%s>" % self.__class__.__name__

    def __eq__(self, other):
        x = self._fix()
        y = other._fix() if isinstance(other, VolatileValue) else other
        if not isinstance(x, type(y)):
            return False
        return x == y

    def __ne__(self, other):
        # Python 2.7 compat
        return not self == other

    __hash__ = None

    def __getattr__(self, attr):
        if attr in ["__setstate__", "__getstate__"]:
            raise AttributeError(attr)
        return getattr(self._fix(), attr)

    def __str__(self):
        return str(self._fix())

    def __bytes__(self):
        return bytes_encode(self._fix())

    def __len__(self):
        return len(self._fix())

    def copy(self):
        return copy.copy(self)

    def _fix(self):
        return None


class RandField(VolatileValue):
    pass


class _RandNumeral(RandField):
    """Implements integer management in RandField"""

    def __int__(self):
        return int(self._fix())

    def __index__(self):
        return int(self)

    def __nonzero__(self):
        return bool(self._fix())
    __bool__ = __nonzero__

    def __add__(self, other):
        return self._fix() + other

    def __radd__(self, other):
        return other + self._fix()

    def __sub__(self, other):
        return self._fix() - other

    def __rsub__(self, other):
        return other - self._fix()

    def __mul__(self, other):
        return self._fix() * other

    def __rmul__(self, other):
        return other * self._fix()

    def __floordiv__(self, other):
        return self._fix() / other
    __div__ = __floordiv__

    def __lt__(self, other):
        return self._fix() < other

    def __le__(self, other):
        return self._fix() <= other

    def __ge__(self, other):
        return self._fix() >= other

    def __gt__(self, other):
        return self._fix() > other

    def __lshift__(self, other):
        return self._fix() << other

    def __rshift__(self, other):
        return self._fix() >> other

    def __and__(self, other):
        return self._fix() & other

    def __rand__(self, other):
        return other & self._fix()

    def __or__(self, other):
        return self._fix() | other

    def __ror__(self, other):
        return other | self._fix()


class RandNum(_RandNumeral):
    """Instances evaluate to random integers in selected range"""
    min = 0
    max = 0

    def __init__(self, min, max):
        self.min = min
        self.max = max

    def _fix(self):
        return random.randrange(self.min, self.max + 1)


class RandFloat(RandNum):
    def _fix(self):
        return random.uniform(self.min, self.max)


class RandBinFloat(RandNum):
    def _fix(self):
        return struct.unpack("!f", bytes(RandBin(4)))[0]


class RandNumGamma(_RandNumeral):
    def __init__(self, alpha, beta):
        self.alpha = alpha
        self.beta = beta

    def _fix(self):
        return int(round(random.gammavariate(self.alpha, self.beta)))


class RandNumGauss(_RandNumeral):
    def __init__(self, mu, sigma):
        self.mu = mu
        self.sigma = sigma

    def _fix(self):
        return int(round(random.gauss(self.mu, self.sigma)))


class RandNumExpo(_RandNumeral):
    def __init__(self, lambd, base=0):
        self.lambd = lambd
        self.base = base

    def _fix(self):
        return self.base + int(round(random.expovariate(self.lambd)))


class RandEnum(RandNum):
    """Instances evaluate to integer sampling without replacement from the given interval"""  # noqa: E501

    def __init__(self, min, max, seed=None):
        self.seq = RandomEnumeration(min, max, seed)
        super(RandEnum, self).__init__(min, max)

    def _fix(self):
        return next(self.seq)


class RandByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2**8 - 1)


class RandSByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2**7, 2**7 - 1)


class RandShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2**16 - 1)


class RandSShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2**15, 2**15 - 1)


class RandInt(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2**32 - 1)


class RandSInt(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2**31, 2**31 - 1)


class RandLong(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2**64 - 1)


class RandSLong(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2**63, 2**63 - 1)


class RandEnumByte(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2**8 - 1)


class RandEnumSByte(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2**7, 2**7 - 1)


class RandEnumShort(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2**16 - 1)


class RandEnumSShort(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2**15, 2**15 - 1)


class RandEnumInt(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2**32 - 1)


class RandEnumSInt(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2**31, 2**31 - 1)


class RandEnumLong(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2**64 - 1)


class RandEnumSLong(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2**63, 2**63 - 1)


class RandEnumKeys(RandEnum):
    """Picks a random value from dict keys list. """

    def __init__(self, enum, seed=None):
        self.enum = list(enum)
        RandEnum.__init__(self, 0, len(self.enum) - 1, seed)

    def _fix(self):
        return self.enum[next(self.seq)]


class RandChoice(RandField):
    def __init__(self, *args):
        if not args:
            raise TypeError("RandChoice needs at least one choice")
        self._choice = list(args)

    def _fix(self):
        return random.choice(self._choice)


class RandString(RandField):
    def __init__(self, size=None, chars=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):  # noqa: E501
        if size is None:
            size = RandNumExpo(0.01)
        self.size = size
        self.chars = chars

    def _fix(self):
        s = b""
        for _ in range(self.size):
            rdm_chr = random.choice(self.chars)
            s += rdm_chr if isinstance(rdm_chr, str) else chb(rdm_chr)
        return s

    def __str__(self):
        return plain_str(self._fix())

    def __bytes__(self):
        return bytes_encode(self._fix())

    def __mul__(self, n):
        return self._fix() * n


class RandBin(RandString):
    def __init__(self, size=None):
        super(RandBin, self).__init__(size=size, chars=b"".join(chb(c) for c in range(256)))  # noqa: E501


class RandTermString(RandBin):
    def __init__(self, size, term):
        self.term = bytes_encode(term)
        super(RandTermString, self).__init__(size=size)

    def _fix(self):
        return RandBin._fix(self) + self.term


class RandIP(RandString):
    def __init__(self, iptemplate="0.0.0.0/0"):
        RandString.__init__(self)
        self.ip = Net(iptemplate)

    def _fix(self):
        return self.ip.choice()


class RandMAC(RandString):
    def __init__(self, template="*"):
        RandString.__init__(self)
        template += ":*:*:*:*:*"
        template = template.split(":")
        self.mac = ()
        for i in range(6):
            if template[i] == "*":
                v = RandByte()
            elif "-" in template[i]:
                x, y = template[i].split("-")
                v = RandNum(int(x, 16), int(y, 16))
            else:
                v = int(template[i], 16)
            self.mac += (v,)

    def _fix(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % self.mac


class RandIP6(RandString):
    def __init__(self, ip6template="**"):
        RandString.__init__(self)
        self.tmpl = ip6template
        self.sp = self.tmpl.split(":")
        for i, v in enumerate(self.sp):
            if not v or v == "**":
                continue
            if "-" in v:
                a, b = v.split("-")
            elif v == "*":
                a = b = ""
            else:
                a = b = v

            if not a:
                a = "0"
            if not b:
                b = "ffff"
            if a == b:
                self.sp[i] = int(a, 16)
            else:
                self.sp[i] = RandNum(int(a, 16), int(b, 16))
        self.variable = "" in self.sp
        self.multi = self.sp.count("**")

    def _fix(self):
        nbm = self.multi
        ip = []
        for i, n in enumerate(self.sp):
            if n == "**":
                nbm -= 1
                remain = 8 - (len(self.sp) - i - 1) - len(ip) + nbm
                if "" in self.sp:
                    remain += 1
                if nbm or self.variable:
                    remain = random.randint(0, remain)
                for j in range(remain):
                    ip.append("%04x" % random.randint(0, 65535))
            elif isinstance(n, RandNum):
                ip.append("%04x" % n)
            elif n == 0:
                ip.append("0")
            elif not n:
                ip.append("")
            else:
                ip.append("%04x" % n)
        if len(ip) == 9:
            ip.remove("")
        if ip[-1] == "":
            ip[-1] = "0"
        return ":".join(ip)


class RandOID(RandString):
    def __init__(self, fmt=None, depth=RandNumExpo(0.1), idnum=RandNumExpo(0.01)):  # noqa: E501
        RandString.__init__(self)
        self.ori_fmt = fmt
        if fmt is not None:
            fmt = fmt.split(".")
            for i in range(len(fmt)):
                if "-" in fmt[i]:
                    fmt[i] = tuple(map(int, fmt[i].split("-")))
        self.fmt = fmt
        self.depth = depth
        self.idnum = idnum

    def __repr__(self):
        if self.ori_fmt is None:
            return "<%s>" % self.__class__.__name__
        else:
            return "<%s [%s]>" % (self.__class__.__name__, self.ori_fmt)

    def _fix(self):
        if self.fmt is None:
            return ".".join(str(self.idnum) for _ in range(1 + self.depth))
        else:
            oid = []
            for i in self.fmt:
                if i == "*":
                    oid.append(str(self.idnum))
                elif i == "**":
                    oid += [str(self.idnum) for i in range(1 + self.depth)]
                elif isinstance(i, tuple):
                    oid.append(str(random.randrange(*i)))
                else:
                    oid.append(i)
            return ".".join(oid)


class RandRegExp(RandField):
    def __init__(self, regexp, lambda_=0.3,):
        self._regexp = regexp
        self._lambda = lambda_

    @staticmethod
    def choice_expand(s):  # XXX does not support special sets like (ex ':alnum:')  # noqa: E501
        m = ""
        invert = s and s[0] == "^"
        while True:
            p = s.find("-")
            if p < 0:
                break
            if p == 0 or p == len(s) - 1:
                m = "-"
                if p:
                    s = s[:-1]
                else:
                    s = s[1:]
            else:
                c1 = s[p - 1]
                c2 = s[p + 1]
                rng = "".join(map(chr, range(ord(c1), ord(c2) + 1)))
                s = s[:p - 1] + rng + s[p + 1:]
        res = m + s
        if invert:
            res = "".join(chr(x) for x in range(256) if chr(x) not in res)
        return res

    @staticmethod
    def stack_fix(lst, index):
        r = ""
        mul = 1
        for e in lst:
            if isinstance(e, list):
                if mul != 1:
                    mul = mul - 1
                    r += RandRegExp.stack_fix(e[1:] * mul, index)
                # only the last iteration should be kept for back reference
                f = RandRegExp.stack_fix(e[1:], index)
                for i, idx in enumerate(index):
                    if e is idx:
                        index[i] = f
                r += f
                mul = 1
            elif isinstance(e, tuple):
                kind, val = e
                if kind == "cite":
                    r += index[val - 1]
                elif kind == "repeat":
                    mul = val

                elif kind == "choice":
                    if mul == 1:
                        c = random.choice(val)
                        r += RandRegExp.stack_fix(c[1:], index)
                    else:
                        r += RandRegExp.stack_fix([e] * mul, index)
                        mul = 1
            else:
                if mul != 1:
                    r += RandRegExp.stack_fix([e] * mul, index)
                    mul = 1
                else:
                    r += str(e)
        return r

    def _fix(self):
        stack = [None]
        index = []
        current = stack
        i = 0
        ln = len(self._regexp)
        interp = True
        while i < ln:
            c = self._regexp[i]
            i += 1

            if c == '(':
                current = [current]
                current[0].append(current)
            elif c == '|':
                p = current[0]
                ch = p[-1]
                if not isinstance(ch, tuple):
                    ch = ("choice", [current])
                    p[-1] = ch
                else:
                    ch[1].append(current)
                current = [p]
            elif c == ')':
                ch = current[0][-1]
                if isinstance(ch, tuple):
                    ch[1].append(current)
                index.append(current)
                current = current[0]
            elif c == '[' or c == '{':
                current = [current]
                current[0].append(current)
                interp = False
            elif c == ']':
                current = current[0]
                choice = RandRegExp.choice_expand("".join(current.pop()[1:]))
                current.append(RandChoice(*list(choice)))
                interp = True
            elif c == '}':
                current = current[0]
                num = "".join(current.pop()[1:])
                e = current.pop()
                if "," not in num:
                    n = int(num)
                    current.append([current] + [e] * n)
                else:
                    num_min, num_max = num.split(",")
                    if not num_min:
                        num_min = "0"
                    if num_max:
                        n = RandNum(int(num_min), int(num_max))
                    else:
                        n = RandNumExpo(self._lambda, base=int(num_min))
                    current.append(("repeat", n))
                    current.append(e)
                interp = True
            elif c == '\\':
                c = self._regexp[i]
                if c == "s":
                    c = RandChoice(" ", "\t")
                elif c in "0123456789":
                    c = ("cite", ord(c) - 0x30)
                current.append(c)
                i += 1
            elif not interp:
                current.append(c)
            elif c == '+':
                e = current.pop()
                current.append([current] + [e] * (int(random.expovariate(self._lambda)) + 1))  # noqa: E501
            elif c == '*':
                e = current.pop()
                current.append([current] + [e] * int(random.expovariate(self._lambda)))  # noqa: E501
            elif c == '?':
                if random.randint(0, 1):
                    current.pop()
            elif c == '.':
                current.append(RandChoice(*[chr(x) for x in range(256)]))
            elif c == '$' or c == '^':
                pass
            else:
                current.append(c)

        return RandRegExp.stack_fix(stack[1:], index)

    def __repr__(self):
        return "<%s [%r]>" % (self.__class__.__name__, self._regexp)


class RandSingularity(RandChoice):
    pass


class RandSingNum(RandSingularity):
    @staticmethod
    def make_power_of_two(end):
        sign = 1
        if end == 0:
            end = 1
        if end < 0:
            end = -end
            sign = -1
        end_n = int(math.log(end) / math.log(2)) + 1
        return {sign * 2**i for i in range(end_n)}

    def __init__(self, mn, mx):
        sing = {0, mn, mx, int((mn + mx) / 2)}
        sing |= self.make_power_of_two(mn)
        sing |= self.make_power_of_two(mx)
        for i in sing.copy():
            sing.add(i + 1)
            sing.add(i - 1)
        for i in sing.copy():
            if not mn <= i <= mx:
                sing.remove(i)
        super(RandSingNum, self).__init__(*sing)
        self._choice.sort()


class RandSingByte(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2**8 - 1)


class RandSingSByte(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2**7, 2**7 - 1)


class RandSingShort(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2**16 - 1)


class RandSingSShort(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2**15, 2**15 - 1)


class RandSingInt(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2**32 - 1)


class RandSingSInt(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2**31, 2**31 - 1)


class RandSingLong(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2**64 - 1)


class RandSingSLong(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2**63, 2**63 - 1)


class RandSingString(RandSingularity):
    def __init__(self):
        choices_list = ["",
                        "%x",
                        "%%",
                        "%s",
                        "%i",
                        "%n",
                        "%x%x%x%x%x%x%x%x%x",
                        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                        "%",
                        "%%%",
                        "A" * 4096,
                        b"\x00" * 4096,
                        b"\xff" * 4096,
                        b"\x7f" * 4096,
                        b"\x80" * 4096,
                        " " * 4096,
                        "\\" * 4096,
                        "(" * 4096,
                        "../" * 1024,
                        "/" * 1024,
                        "${HOME}" * 512,
                        " or 1=1 --",
                        "' or 1=1 --",
                        '" or 1=1 --',
                        " or 1=1; #",
                        "' or 1=1; #",
                        '" or 1=1; #',
                        ";reboot;",
                        "$(reboot)",
                        "`reboot`",
                        "index.php%00",
                        b"\x00",
                        "%00",
                        "\\",
                        "../../../../../../../../../../../../../../../../../etc/passwd",  # noqa: E501
                        "%2e%2e%2f" * 20 + "etc/passwd",
                        "%252e%252e%252f" * 20 + "boot.ini",
                        "..%c0%af" * 20 + "etc/passwd",
                        "..%c0%af" * 20 + "boot.ini",
                        "//etc/passwd",
                        r"..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\boot.ini",  # noqa: E501
                        "AUX:",
                        "CLOCK$",
                        "COM:",
                        "CON:",
                        "LPT:",
                        "LST:",
                        "NUL:",
                        "CON:",
                        r"C:\CON\CON",
                        r"C:\boot.ini",
                        r"\\myserver\share",
                        "foo.exe:",
                        "foo.exe\\", ]
        super(RandSingString, self).__init__(*choices_list)

    def __str__(self):
        return str(self._fix())

    def __bytes__(self):
        return bytes_encode(self._fix())


class RandPool(RandField):
    def __init__(self, *args):
        """Each parameter is a volatile object or a couple (volatile object, weight)"""  # noqa: E501
        pool = []
        for p in args:
            w = 1
            if isinstance(p, tuple):
                p, w = p
            pool += [p] * w
        self._pool = pool

    def _fix(self):
        r = random.choice(self._pool)
        return r._fix()


class RandUUID(RandField):
    """Generates a random UUID.

    By default, this generates a RFC 4122 version 4 UUID (totally random).

    See Python's ``uuid`` module documentation for more information.

    Args:
        template (optional): A template to build the UUID from. Not valid with
                             any other option.
        node (optional): A 48-bit Host ID. Only valid for version 1 (where it
                         is optional).
        clock_seq (optional): An integer of up to 14-bits for the sequence
                              number. Only valid for version 1 (where it is
                              optional).
        namespace: A namespace identifier, which is also a UUID. Required for
                   versions 3 and 5, must be omitted otherwise.
        name: string, required for versions 3 and 5, must be omitted otherwise.
        version: Version of UUID to use (1, 3, 4 or 5). If omitted, attempts to
                 guess which version to generate, defaulting to version 4
                 (totally random).

    Raises:
        ValueError: on invalid constructor arguments
    """
    # This was originally scapy.contrib.dce_rpc.RandUUID.

    _BASE = "([0-9a-f]{{{0}}}|\\*|[0-9a-f]{{{0}}}:[0-9a-f]{{{0}}})"
    _REG = re.compile(
        r"^{0}-?{1}-?{1}-?{2}{2}-?{2}{2}{2}{2}{2}{2}$".format(
            _BASE.format(8), _BASE.format(4), _BASE.format(2)
        ),
        re.I
    )
    VERSIONS = [1, 3, 4, 5]

    def __init__(self, template=None, node=None, clock_seq=None,
                 namespace=None, name=None, version=None):
        self.uuid_template = None
        self.node = None
        self.clock_seq = None
        self.namespace = None
        self.node = None
        self.version = None

        if template:
            if node or clock_seq or namespace or name or version:
                raise ValueError("UUID template must be the only parameter, "
                                 "if specified")
            tmp = RandUUID._REG.match(template)
            if tmp:
                template = tmp.groups()
            else:
                # Invalid template
                raise ValueError("UUID template is invalid")

            rnd_f = [RandInt] + [RandShort] * 2 + [RandByte] * 8
            uuid_template = []
            for i, t in enumerate(template):
                if t == "*":
                    val = rnd_f[i]()
                elif ":" in t:
                    mini, maxi = t.split(":")
                    val = RandNum(int(mini, 16), int(maxi, 16))
                else:
                    val = int(t, 16)
                uuid_template.append(val)

            self.uuid_template = tuple(uuid_template)
        else:
            if version:
                if version not in RandUUID.VERSIONS:
                    raise ValueError("version is not supported")
                else:
                    self.version = version
            else:
                # No version specified, try to guess...
                # This could be wrong, and cause an error later!
                if node or clock_seq:
                    self.version = 1
                elif namespace and name:
                    self.version = 5
                else:
                    # Don't know, random!
                    self.version = 4

            # We have a version, now do things...
            if self.version == 1:
                if namespace or name:
                    raise ValueError("namespace and name may not be used with "
                                     "version 1")
                self.node = node
                self.clock_seq = clock_seq
            elif self.version in (3, 5):
                if node or clock_seq:
                    raise ValueError("node and clock_seq may not be used with "
                                     "version {}".format(self.version))

                self.namespace = namespace
                self.name = name
            elif self.version == 4:
                if namespace or name or node or clock_seq:
                    raise ValueError("node, clock_seq, node and clock_seq may "
                                     "not be used with version 4. If you "
                                     "did not specify version, you need to "
                                     "specify it explicitly.")

    def _fix(self):
        if self.uuid_template:
            return uuid.UUID(("%08x%04x%04x" + ("%02x" * 8))
                             % self.uuid_template)
        elif self.version == 1:
            return uuid.uuid1(self.node, self.clock_seq)
        elif self.version == 3:
            return uuid.uuid3(self.namespace, self.name)
        elif self.version == 4:
            return uuid.uuid4()
        elif self.version == 5:
            return uuid.uuid5(self.namespace, self.name)
        else:
            raise ValueError("Unhandled version")


# Automatic timestamp


class AutoTime(_RandNumeral):
    def __init__(self, base=None, diff=None):
        if diff is not None:
            self.diff = diff
        elif base is None:
            self.diff = 0
        else:
            self.diff = time.time() - base

    def _fix(self):
        return time.time() - self.diff


class IntAutoTime(AutoTime):
    def _fix(self):
        return int(time.time() - self.diff)


class ZuluTime(AutoTime):
    def __init__(self, diff=0):
        super(ZuluTime, self).__init__(diff=diff)

    def _fix(self):
        return time.strftime("%y%m%d%H%M%SZ",
                             time.gmtime(time.time() + self.diff))


class GeneralizedTime(AutoTime):
    def __init__(self, diff=0):
        super(GeneralizedTime, self).__init__(diff=diff)

    def _fix(self):
        return time.strftime("%Y%m%d%H%M%SZ",
                             time.gmtime(time.time() + self.diff))


class DelayedEval(VolatileValue):
    """ Example of usage: DelayedEval("time.time()") """

    def __init__(self, expr):
        self.expr = expr

    def _fix(self):
        return eval(self.expr)


class IncrementalValue(VolatileValue):
    def __init__(self, start=0, step=1, restart=-1):
        self.start = self.val = start
        self.step = step
        self.restart = restart

    def _fix(self):
        v = self.val
        if self.val == self.restart:
            self.val = self.start
        else:
            self.val += self.step
        return v


class CorruptedBytes(VolatileValue):
    def __init__(self, s, p=0.01, n=None):
        self.s = s
        self.p = p
        self.n = n

    def _fix(self):
        return corrupt_bytes(self.s, self.p, self.n)


class CorruptedBits(CorruptedBytes):
    def _fix(self):
        return corrupt_bits(self.s, self.p, self.n)
