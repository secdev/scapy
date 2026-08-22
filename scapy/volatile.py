# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# Copyright (C) Gauthier Sebaux

"""
Fields that hold random numbers.
"""

import copy
import random
import time
import math
import re
import uuid
import struct
import string

from scapy.base_classes import Net
from scapy.compat import bytes_encode, chb, plain_str
from scapy.utils import corrupt_bits, corrupt_bytes

from typing import (
    List,
    TypeVar,
    Generic,
    Set,
    Union,
    Any,
    Dict,
    Optional,
    Tuple,
    cast,
)

####################
#  Random numbers  #
####################

# Classic off-by-one/overflow boundaries, in value space. Anything a fuzzed
# field should be made to carry regardless of how its walk happens to be
# strided: signed/unsigned limits and their immediate neighbours at every
# common width. Used by Packet._boundary_checkpoints() for the integer walk
# and by _EnumField._enum_walk_edges() for the enum walk, which want the
# same set for the same reason.
MAGIC_BOUNDARIES = (
    0, 1,
    0x7f, 0x80, 0xff,
    0x7fff, 0x8000, 0xffff,
    0x7fffffff, 0x80000000, 0xffffffff,
)


class RandomEnumeration:
    """iterate through a sequence in random order.
       When all the values have been drawn, if forever=1, the drawing is done again.  # noqa: E501
       If renewkeys=0, the draw will be in the same order, guaranteeing that the same  # noqa: E501
       number will be drawn in not less than the number of integers of the sequence"""  # noqa: E501

    def __init__(self, inf, sup, seed=None, forever=1, renewkeys=0):
        # type: (int, int, Optional[int], int, int) -> None
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
        # type: () -> RandomEnumeration
        return self

    def next(self):
        # type: () -> int
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


_T = TypeVar('_T')


class VolatileValue(Generic[_T]):
    def __repr__(self):
        # type: () -> str
        return "<%s>" % self.__class__.__name__

    def _command_args(self):
        # type: () -> str
        return ''

    def command(self, json=False):
        # type: (bool) -> Union[Dict[str, str], str]
        if json:
            return {"type": self.__class__.__name__, "value": self._command_args()}
        else:
            return "%s(%s)" % (self.__class__.__name__, self._command_args())

    def __eq__(self, other):
        # type: (Any) -> bool
        x = self._fix()
        y = other._fix() if isinstance(other, VolatileValue) else other
        if not isinstance(x, type(y)):
            return False
        return bool(x == y)

    def __ne__(self, other):
        # type: (Any) -> bool
        # Python 2.7 compat
        return not self == other

    __hash__ = None  # type: ignore

    def __getattr__(self, attr):
        # type: (str) -> Any
        if attr in ["__setstate__", "__getstate__"]:
            raise AttributeError(attr)
        return getattr(self._fix(), attr)

    def __str__(self):
        # type: () -> str
        return str(self._fix())

    def __bytes__(self):
        # type: () -> bytes
        return bytes_encode(self._fix())

    def __len__(self):
        # type: () -> int
        # Does not work for some types (int?)
        return len(self._fix())  # type: ignore

    def copy(self):
        # type: () -> Any
        return copy.copy(self)

    def _fix(self):
        # type: () -> _T
        return cast(_T, None)


class RandField(VolatileValue[_T], Generic[_T]):
    pass


_I = TypeVar("_I", int, float)


class _RandNumeral(RandField[_I]):
    """Implements integer management in RandField"""

    def __int__(self):
        # type: () -> int
        return int(self._fix())

    def __index__(self):
        # type: () -> int
        return int(self)

    def __nonzero__(self):
        # type: () -> bool
        return bool(self._fix())
    __bool__ = __nonzero__

    def __add__(self, other):
        # type: (_I) -> _I
        return self._fix() + other

    def __radd__(self, other):
        # type: (_I) -> _I
        return other + self._fix()

    def __sub__(self, other):
        # type: (_I) -> _I
        return self._fix() - other

    def __rsub__(self, other):
        # type: (_I) -> _I
        return other - self._fix()

    def __mul__(self, other):
        # type: (_I) -> _I
        return self._fix() * other

    def __rmul__(self, other):
        # type: (_I) -> _I
        return other * self._fix()

    def __floordiv__(self, other):
        # type: (_I) -> float
        return self._fix() / other
    __div__ = __floordiv__

    def __lt__(self, other):
        # type: (_I) -> bool
        return self._fix() < other

    def __le__(self, other):
        # type: (_I) -> bool
        return self._fix() <= other

    def __ge__(self, other):
        # type: (_I) -> bool
        return self._fix() >= other

    def __gt__(self, other):
        # type: (_I) -> bool
        return self._fix() > other


class RandNum(_RandNumeral[int]):
    """Instances evaluate to random integers in selected range"""
    min = 0
    max = 0
    state_pos = None

    def __init__(self, min, max):
        # type: (int, int) -> None
        self.min = min
        self.max = max

    def _command_args(self):
        # type: () -> str
        if self.__class__.__name__ == 'RandNum':
            return "min=%r, max=%r" % (self.min, self.max)
        return super(RandNum, self)._command_args()

    def _fix(self):
        # type: () -> int

        # Old code:
        # return random.randrange(self.min, self.max + 1)

        # New code:
        if self.state_pos is None:
            if 'default' in self.__dict__:
                # If the 'default' exists, use it rather than min
                # 'min' is '0' causing:
                #    new_default_fields = {
                #      key: (val._fix() if isinstance(val, VolatileValue) else val)
                #      for key, val in six.iteritems(new_default_fields)
                #    }
                # To fix the value to '0' rather than use the value that was set by the
                #   packet generator, for example for ARP(), 'hwtype' will be set to 0
                #   rather than Ethernet (10Mb)
                return self.default

            return self.min

        if 'default' in self.__dict__ and isinstance(self.default, tuple):
            # if the default value is a tuple, we modify the first item
            if not isinstance(self.default[0], int):
                raise ValueError("We expected the first value to be a 'int' in the 'tuple'")

            return (self.state_pos, self.default[1])

        if isinstance(self, RandInt):
            if 'expecting_unsigned_short' in self.__dict__ and self.expecting_unsigned_short:
                return (self.state_pos % 65535) # needs to be between 0 <= val <= 65535

        if isinstance(self, RandShort):
            if 'expecting_unsigned_byte' in self.__dict__ and self.expecting_unsigned_byte:
                return [self.state_pos % 255]

        if isinstance(self, RandByte):
            # Plain ByteField/XByteField/ByteEnumField all feed this straight into
            # struct.pack("B", val) via Field.i2m/addfield, which requires an int -
            # same contract as RandShort/RandInt above. Returning bytes here breaks
            # every scalar byte field (IP.tos, IP.ttl, ...) as soon as it's fuzzed.
            return self.state_pos

        return self.state_pos

    def __lshift__(self, other):
        # type: (int) -> int
        return self._fix() << other

    def __rshift__(self, other):
        # type: (int) -> int
        return self._fix() >> other

    def __and__(self, other):
        # type: (int) -> int
        return self._fix() & other

    def __rand__(self, other):
        # type: (int) -> int
        return other & self._fix()

    def __or__(self, other):
        # type: (int) -> int
        return self._fix() | other

    def __ror__(self, other):
        # type: (int) -> int
        return other | self._fix()


class RandFloat(_RandNumeral[float]):
    # Kept in line with RandNum/RandBin/RandString: forward() reads
    # field_obj.state_pos unconditionally on any VolatileValue it's handed,
    # and without a class-level default here that falls through
    # VolatileValue.__getattr__ (-> _fix() -> AttributeError on the
    # resulting float, uncaught).
    state_pos = None

    def __init__(self, min, max):
        # type: (int, int) -> None
        self.min = min
        self.max = max

    def _fix(self):
        # type: () -> float
        return random.uniform(self.min, self.max)


class RandBinFloat(RandFloat):
    def _fix(self):
        # type: () -> float
        return cast(
            float,
            struct.unpack("!f", bytes(RandBin(4)))[0]
        )


class RandNumGamma(RandNum):
    def __init__(self, alpha, beta):
        # type: (int, int) -> None
        self.alpha = alpha
        self.beta = beta

    def _command_args(self):
        # type: () -> str
        return "alpha=%r, beta=%r" % (self.alpha, self.beta)

    def _fix(self):
        # type: () -> int
        return int(round(random.gammavariate(self.alpha, self.beta)))


class RandNumGauss(RandNum):
    def __init__(self, mu, sigma):
        # type: (int, int) -> None
        self.mu = mu
        self.sigma = sigma

    def _command_args(self):
        # type: () -> str
        return "mu=%r, sigma=%r" % (self.mu, self.sigma)

    def _fix(self):
        # type: () -> int
        return int(round(random.gauss(self.mu, self.sigma)))


class RandNumExpo(RandNum):
    def __init__(self, lambd, base=0):
        # type: (float, int) -> None
        self.lambd = lambd
        self.base = base

    def _command_args(self):
        # type: () -> str
        ret = "lambd=%r" % self.lambd
        if self.base != 0:
            ret += ", base=%r" % self.base
        return ret

    def _fix(self):
        # type: () -> int
        return self.base + int(round(random.expovariate(self.lambd)))


class RandEnum(RandNum):
    """Instances evaluate to integer sampling without replacement from the given interval"""  # noqa: E501

    def __init__(self, min, max, seed=None):
        # type: (int, int, Optional[int]) -> None
        self._seed = seed
        self.seq = RandomEnumeration(min, max, seed)
        super(RandEnum, self).__init__(min, max)

    def _command_args(self):
        # type: () -> str
        ret = "min=%r, max=%r" % (self.min, self.max)
        if self._seed:
            ret += ", seed=%r" % self._seed
        return ret

    def _fix(self):
        # type: () -> int
        return next(self.seq)


class RandByte(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, 0, 2**8 - 1)


class RandSByte(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, -2**7, 2**7 - 1)


class RandShort(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, 0, 2**16 - 1)


class RandSShort(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, -2**15, 2**15 - 1)


class RandInt(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, 0, 2**32 - 1)


class RandSInt(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, -2**31, 2**31 - 1)


class RandLong(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, 0, 2**64 - 1)


class RandSLong(RandNum):
    def __init__(self):
        # type: () -> None
        RandNum.__init__(self, -2**63, 2**63 - 1)


class RandEnumByte(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, 0, 2**8 - 1)


class RandEnumSByte(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, -2**7, 2**7 - 1)


class RandEnumShort(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, 0, 2**16 - 1)


class RandEnumSShort(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, -2**15, 2**15 - 1)


class RandEnumInt(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, 0, 2**32 - 1)


class RandEnumSInt(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, -2**31, 2**31 - 1)


class RandEnumLong(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, 0, 2**64 - 1)


class RandEnumSLong(RandEnum):
    def __init__(self):
        # type: () -> None
        RandEnum.__init__(self, -2**63, 2**63 - 1)


class RandEnumKeys(RandEnum):
    """Picks a random value from dict keys list. """

    def __init__(self, enum, seed=None):
        # type: (Dict[Any, Any], Optional[int]) -> None
        self.enum = list(enum)
        RandEnum.__init__(self, 0, len(self.enum) - 1, seed)

    def _command_args(self):
        # type: () -> str
        # Note: only outputs the list of keys, but values are irrelevant anyway
        ret = "enum=%r" % self.enum
        if self._seed:
            ret += ", seed=%r" % self._seed
        return ret

    def _fix(self):
        # type: () -> Any
        return self.enum[next(self.seq)]


class RandEnumWalk(RandNum):
    """State-driven walk over an enum field's own declared values, then the rest

    ``Field.randval()`` dispatches on the struct format character alone, so an
    ``EnumField`` used to be handed a plain ``RandByte``/``RandShort``/... and
    the ``i2s`` dict sitting on the very same field object was never consulted.
    The field was then walked as an integer, and at the default
    ``max_samples_per_field=128`` a byte field is sampled at 128 of its 256
    points - every *other* value, and never ``min`` itself - so the values a
    protocol actually defines were the ones least likely to be sent, and a
    ``{0: "off", 1: "on"}`` enum could send neither of them.

    The list is built in three blocks, and the order is the whole design:

    1. **the declared keys**, in declared order, so a run cut short has covered
       the protocol's own vocabulary before spending anything else;
    2. **the guaranteed edges** - 0, the field's maximum, one past the highest
       declared key, and the ``MAGIC_BOUNDARIES`` that fit (see
       ``_EnumField._enum_walk_edges()``);
    3. **undefined values filling the rest of the sampling budget**, spread
       across whatever the enum leaves unused.

    Blocks 1 and 2 are sent whatever the budget; block 3 is what
    ``max_samples_per_field`` bounds (see ``plan_budget()``). That split is what
    keeps both halves of the coverage: an unhandled enum value is its own bug
    class, and it is most of what the integer sweep provided by accident, so a
    walk that sent *only* the declared values would trade one blind spot for
    another - a byte enum field went from 114 undefined values per field to 6.

    Unlike the rest of the ``Rand*`` family, ``state_pos`` here is an *index*
    into ``values`` rather than the value itself, so ``min``/``max`` bound the
    list and not the field's integer width.
    """

    # Packet._advance_state_pos() reads this: the value list is already sized to
    # the sampling budget, so it must be stepped one at a time. Striding it -
    # which is what max_samples_per_field means for an integer field - would
    # sample away the declared values this exists to send.
    exhaustive = True

    # Above this span, listing the not-yet-used values costs more than it buys:
    # 'used' is sparse in a 16-bit-or-wider range, so proportional striding
    # lands on distinct values without enumerating anything.
    _ENUMERABLE_SPAN = 1024

    def __init__(self, declared, guaranteed, low, high, budget=128):
        # type: (List[int], List[int], int, int, int) -> None
        if not declared:
            raise TypeError("RandEnumWalk needs at least one declared value")
        self.declared = list(declared)
        self.guaranteed = list(guaranteed)
        self.low = low
        self.high = high
        self.values = []  # type: List[Any]
        self._field_default = self.declared[0]  # type: Any
        self._default_index = 0
        self._budget = None  # type: Optional[int]
        self.plan_budget(budget)

    def plan_budget(self, budget):
        # type: (int) -> None
        """Size the value list to a max_samples_per_field budget

        Called by ``Packet.initialize_volatile_field()`` with the budget the
        state carries, which is what makes the density knob mean something for
        an enum field again: at 128 a byte enum sends its declared values, the
        guaranteed edges and about a hundred of the remaining range; at 512 it
        sends all 256. Without this the walk sent the same handful of cases at
        every density, so a caller stepping 128 -> 512 -> 1024 got identical
        work out of every enum field.

        Idempotent for a given budget, since a field shared across several
        pair-states is re-initialized once per pair.
        """
        if budget == self._budget:
            return
        self._budget = budget

        self.values = self.declared + self.guaranteed
        self.values.extend(self._undefined_fill(budget))
        # Indexes the value list directly: 0 .. len(values) - 1. This used to
        # start at -1, because Packet.forward() advanced a field before
        # reading it and so emitted min + 1 .. max, never min - which would
        # have made values[0], the first declared value, unreachable.
        # Packet._advance_state_pos() now emits a cycle's own starting
        # position first, for plain integer fields as much as for this one,
        # so the extra index below the list is no longer needed. _fix()
        # still clamps, so a read before the first advance renders
        # values[0] rather than raising.
        RandNum.__init__(self, 0, len(self.values) - 1)
        # Re-resolve the field default against the new list.
        self.default = self._field_default

    def _undefined_fill(self, budget):
        # type: (int) -> List[int]
        """Undefined values spread over whatever the enum leaves unused

        Spread rather than clustered at the edges: for an enum whose keys are
        0..40, 90 is as likely to matter as 254. Deterministic in ``state_pos``,
        which the state-based walk requires - no randomness anywhere here.
        """
        used = set(self.values)
        room = budget - len(self.values)
        if room <= 0:
            # A wide enum can exceed the budget on its own (IP.proto declares
            # 138 against a default 128). The declared block wins.
            return []

        span = self.high - self.low + 1
        unused_count = span - len(used)
        if unused_count <= room:
            # The whole value space fits in the budget - send all of it, which
            # is what a density of 512 on a byte field should mean.
            return [v for v in range(self.low, self.high + 1) if v not in used]

        if span <= self._ENUMERABLE_SPAN:
            unused = [v for v in range(self.low, self.high + 1) if v not in used]
            return [unused[(i * len(unused)) // room] for i in range(room)]

        # Too wide to enumerate: step proportionally through the range and walk
        # forward off the rare collision with a declared or guaranteed value.
        filled = []  # type: List[int]
        for i in range(room):
            candidate = self.low + (i * span) // room
            while candidate <= self.high and candidate in used:
                candidate += 1
            if candidate > self.high:
                break
            used.add(candidate)
            filled.append(candidate)
        return filled

    # Everywhere else in this module 'default' is the field's own default
    # value, and fuzz() assigns it that way ('rnd.default = f.default'). But
    # Packet.forward() also assigns 'default' straight into 'state_pos' when it
    # resets an exhausted field, and here state_pos is an index into 'values',
    # not a value. Keep both meanings: the setter records the real default, the
    # getter hands the walk machinery the matching index.
    @property
    def default(self):
        # type: () -> int
        return self._default_index

    @default.setter
    def default(self, value):
        # type: (Any) -> None
        self._field_default = value
        try:
            self._default_index = self.values.index(value)
        except (ValueError, TypeError):
            # A default the enum doesn't declare (or that got filtered out for
            # not fitting the field's width) - start the walk at the top of the
            # list instead, which is the first declared value.
            self._default_index = 0

    def _command_args(self):
        # type: () -> str
        return "declared=%r, guaranteed=%r, low=%r, high=%r" % (
            self.declared, self.guaranteed, self.low, self.high,
        )

    def _fix(self):
        # type: () -> Any
        if self.state_pos is None:
            # Not the field being fuzzed right now - same contract as
            # RandNum._fix(): build with the value the packet would have had.
            return self._field_default

        # 'max' is len(values) - 1 and Packet.forward() stops a field as soon
        # as state_pos passes max, so an out-of-range index is a bug rather
        # than something to wrap around into an unrelated enum entry.
        return self.values[min(max(self.state_pos, 0), len(self.values) - 1)]


class RandChoice(RandField[Any]):
    def __init__(self, *args):
        # type: (*Any) -> None
        if not args:
            raise TypeError("RandChoice needs at least one choice")
        self._choice = list(args)

    def _command_args(self):
        # type: () -> str
        return ", ".join(self._choice)

    def _fix(self):
        # type: () -> Any
        return random.choice(self._choice)


_S = TypeVar("_S", bytes, str)


class _RandString(RandField[_S], Generic[_S]):
    def __str__(self):
        # type: () -> str
        return plain_str(self._fix())

    def __bytes__(self):
        # type: () -> bytes
        return bytes_encode(self._fix())

    def __mul__(self, n):
        # type: (int) -> _S
        return self._fix() * n


class RandString(_RandString[str]):
    _DEFAULT_CHARS = (string.ascii_uppercase + string.ascii_lowercase +
                      string.digits).encode("utf-8")
    min = 0
    max = 0
    state_pos = None

    def __init__(self, size=None, chars=_DEFAULT_CHARS):
        # type: (Optional[Union[int, RandNum]], str) -> None
        if size is None:
            size = RandNumExpo(0.01)
        self.size = size
        self.chars = chars
        self.max = len(chars)

    def __getitem__(self, start, stop=None, step=None):
        # Missing subscriptable (needed by BOOTP while show calls it, maybe others?)
        #  due to i2repr being called/implemented
        if stop is not None and step is None:
            return self.chars[start:stop]
        
        if stop is not None and step is not None:
            return self.chars[start:stop:step]
        
        return self.chars[start]

    def _command_args(self):
        # type: () -> str
        ret = ""
        if isinstance(self.size, VolatileValue):
            if self.size.lambd != 0.01 or self.size.base != 0:
                ret += "size=%r" % self.size.command()
        else:
            ret += "size=%r" % self.size

        if self.chars != self._DEFAULT_CHARS:
            ret += ", chars=%r" % self.chars
        return ret

    def _fix(self):
        # type: () -> bytes

        # Old code:
        # s = b""
        # for _ in range(int(self.size)):
        #     rdm_chr = random.choice(self.chars)
        #     s += rdm_chr if isinstance(rdm_chr, str) else chb(rdm_chr)
        # return s

        # State aware code:
        if self.state_pos is None:
            # Not the field currently being fuzzed - render its actual
            # (un-fuzzed) default rather than a fixed-size slice of the
            # whole charset. fuzz() sets '.default' to the field's original
            # value; without it (e.g. a fresh MultipleTypeField randval that
            # hasn't gone through forward()'s init yet), fall back to empty -
            # self.chars[:self.max] used to be returned unconditionally here,
            # which for the default 256-byte charset silently inflated every
            # not-yet-active string/bin field to up to 256 bytes.
            if 'default' in self.__dict__:
                return bytes_encode(self.default)

            return b""

        if len(self.chars) == 0:
            # If no value was given, don't divide it...
            return bytes_encode(self.chars)

        pos_adjusted = self.state_pos % len(self.chars)
        s = bytes_encode(self.chars[0:pos_adjusted]) # Make it change by state_pos

        return s


class RandBin(_RandString[bytes]):
    _DEFAULT_CHARS = b"".join(chb(c) for c in range(256))

    min = 0
    max = 0
    state_pos = None

    def __init__(self, size=None, chars=_DEFAULT_CHARS):
        # type: (Optional[Union[int, RandNum]], bytes) -> None
        if size is None:
            size = RandNumExpo(0.01)
        self.size = size
        self.chars = chars
        self.max = len(chars)

    def __getitem__(self, start, stop=None, step=None):
        # Missing subscriptable (needed by BOOTP while show calls it, maybe others?)
        #  due to i2repr being called/implemented
        if stop is not None and step is None:
            return self.chars[start:stop]

        if stop is not None and step is not None:
            return self.chars[start:stop:step]

        return self.chars[start]

    def _command_args(self):
        # type: () -> str
        ret = ""
        if isinstance(self.size, VolatileValue):
            if self.size.lambd != 0.01 or self.size.base != 0:
                ret += "size=%r" % self.size.command()
        else:
            ret += "size=%r" % self.size

        if self.chars != self._DEFAULT_CHARS:
            ret += ", chars=%r" % self.chars
        return ret

    def _fix(self):
        # type: () -> bytes

        # Old code:
        # s = b""
        # for _ in range(int(self.size)):
        #   s += struct.pack("!B", random.choice(self.chars))
        # return s

        # State aware code:
        if self.state_pos is None:
            # Not the field currently being fuzzed - render its actual
            # (un-fuzzed) default rather than a fixed-size slice of the
            # whole charset. fuzz() sets '.default' to the field's original
            # value; without it (e.g. a fresh MultipleTypeField randval that
            # hasn't gone through forward()'s init yet), fall back to empty -
            # self.chars[:self.max] used to be returned unconditionally here,
            # which for the default 256-byte charset silently inflated every
            # not-yet-active string/bin field to up to 256 bytes.
            if 'default' in self.__dict__:
                return bytes_encode(self.default)

            return b""

        if len(self.chars) == 0:
            # If no value was given, don't divide it...
            return bytes_encode(self.chars)

        pos_adjusted = self.state_pos % len(self.chars)
        s = bytes_encode(self.chars[0:pos_adjusted]) # Make it change by state_pos

        return s


class RandTermString(RandBin):
    def __init__(self, size, term):
        # type: (Union[int, RandNum], bytes) -> None
        self.term = bytes_encode(term)
        super(RandTermString, self).__init__(size=size)
        self.chars = self.chars.replace(self.term, b"")

    def _command_args(self):
        # type: () -> str
        return ", ".join((super(RandTermString, self)._command_args(),
                          "term=%r" % self.term))

    def _fix(self):
        # type: () -> bytes
        return RandBin._fix(self) + self.term


class RandIP(_RandString[str]):
    _DEFAULT_IPTEMPLATE = "0.0.0.0/0"

    _COMBINATIONS = [
        '0.0.0.0', '127.0.0.1', '255.255.255.255',
        '10.0.0.0', '172.16.0.0', '192.168.0.0',
        '169.254.0.0', '254.254.254.254',
        '192.0.2.1', '198.51.100.0', '203.0.113.0',
        '224.0.0.0', '239.255.255.255']
    min = 0
    max = len(_COMBINATIONS)
    state_pos = None

    def __init__(self, iptemplate=_DEFAULT_IPTEMPLATE):
        # type: (str) -> None
        super(RandIP, self).__init__()
        self.ip = Net(iptemplate)

    def _command_args(self):
        # type: () -> str
        rep = "%s/%s" % (self.ip.net, self.ip.mask)
        if rep == self._DEFAULT_IPTEMPLATE:
            return ""
        return "iptemplate=%r" % rep

    def _fix(self):
        # type: () -> str

        # Old:
        # return self.ip.choice()

        # New:
        if self.state_pos is None:
            # Not the field being fuzzed right now - same contract as
            # RandNum._fix()/RandString._fix(): build with the value the
            # packet would have had. Without this every IP-typed field that
            # isn't the active one both built and rendered as
            # _COMBINATIONS[0], 0.0.0.0, instead of its own default
            # (OSPF_Hdr.src is 1.1.1.1 until the layer is fuzzed).
            if 'default' in self.__dict__ and self.default is not None:
                return self.default

            return self._COMBINATIONS[0]

        # No 'state_pos > 0' guard: index 0 is a value of the list like any
        # other, and skipping it made _COMBINATIONS[0] unreachable the same
        # way min used to be for an integer field.
        return self._COMBINATIONS[self.state_pos % len(self._COMBINATIONS)]


class RandMAC(_RandString[str]):
    # https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
    _COMBINATIONS = [
        '00:00:00:00:00:00',
        'FF:FF:FF:FF:FF:FF', # Broadcast
        '00:00:5E:00:00:00', # Reserved
        '00:00:5E:00:01:00', # VRRP
        '00:00:5E:00:02:01', # VRRP IPv6
        '00:00:5E:00:03:00', # Unassigned
        '01:00:5E:00:00:00', # Multicast
        '01:00:5E:80:00:00', # MPLS Multicast
    ]
    min = 0
    max = len(_COMBINATIONS)
    state_pos = None

    def __init__(self, _template="*"):
        # type: (str) -> None
        super(RandMAC, self).__init__()
        self._template = _template
        _template += ":*:*:*:*:*"
        template = _template.split(":")
        self.mac = ()  # type: Tuple[Union[int, RandNum], ...]
        for i in range(6):
            v = 0  # type: Union[int, RandNum]
            if template[i] == "*":
                v = RandByte()
            elif "-" in template[i]:
                x, y = template[i].split("-")
                v = RandNum(int(x, 16), int(y, 16))
            else:
                v = int(template[i], 16)
            self.mac += (v,)

    def _command_args(self):
        # type: () -> str
        if self._template == "*":
            return ""
        return "template=%r" % self._template

    def _fix(self):
        # type: () -> str

        # Old:
        # return "%02x:%02x:%02x:%02x:%02x:%02x" % self.mac  # type: ignore

        # New: same contract as RandNum._fix()/RandIP._fix() - render the
        # field's own default when this isn't the field being fuzzed, and
        # treat index 0 as a value like any other rather than as a stand-in
        # for "not fuzzed" (which made _COMBINATIONS[0] unreachable and made
        # every MAC field that isn't the active one build as 00:00:00:00:00:00
        # instead of the address it carries).
        if self.state_pos is None:
            if 'default' in self.__dict__ and self.default is not None:
                return self.default

            return self._COMBINATIONS[0]

        return self._COMBINATIONS[self.state_pos % len(self._COMBINATIONS)]



class RandIP6(_RandString[str]):
    _DEFAULT_IPTEMPLATE = "**"

    _COMBINATIONS = [
        '::', '::1', '::ffff:192.0.2.1',
        'fc00::1', 'fe80::abcd:ef12', 'fd00::', 'fd80::1',
        'fe80::1', '::ffff:FEEF:FEEF', 'ff00::1', 'ff02::1',
        '2001:db8:85a3:0:0:8a2e:370:7334', '2001:db8::1', '2001:db8:1234:113::',
        'ff02::1', 'ff02::255', 'ff0e::1', 'fd12:3456:789a::1',
        'fec0::1', '::255.255.255.255', '2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ]
    min = 0
    max = len(_COMBINATIONS)
    state_pos = None

    def __init__(self, ip6template=_DEFAULT_IPTEMPLATE):
        # type: (str) -> None
        super(RandIP6, self).__init__()
        self.tmpl = ip6template
        self.sp = []  # type: List[Union[int, RandNum, str]]
        for v in self.tmpl.split(":"):
            if not v or v == self._DEFAULT_IPTEMPLATE:
                self.sp.append(v)
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
                self.sp.append(int(a, 16))
            else:
                self.sp.append(RandNum(int(a, 16), int(b, 16)))
        self.variable = "" in self.sp
        self.multi = self.sp.count("**")

    def _command_args(self):
        # type: () -> str
        if self.tmpl == "**":
            return ""
        return "ip6template=%r" % self.tmpl

    def _fix(self):
        # type: () -> str

        # Old
        # nbm = self.multi
        # ip = []  # type: List[str]
        # for i, n in enumerate(self.sp):
        #     if n == "**":
        #         nbm -= 1
        #         remain = 8 - (len(self.sp) - i - 1) - len(ip) + nbm
        #         if "" in self.sp:
        #             remain += 1
        #         if nbm or self.variable:
        #             remain = random.randint(0, remain)
        #         for j in range(remain):
        #             ip.append("%04x" % random.randint(0, 65535))
        #     elif isinstance(n, RandNum):
        #         ip.append("%04x" % int(n))
        #     elif n == 0:
        #         ip.append("0")
        #     elif not n:
        #         ip.append("")
        #     else:
        #         ip.append("%04x" % int(n))
        # if len(ip) == 9:
        #     ip.remove("")
        # if ip[-1] == "":
        #     ip[-1] = "0"
        # return ":".join(ip)

        # New: see RandIP._fix() - the field's own default when this isn't
        # the field being fuzzed, and index 0 reachable like any other.
        if self.state_pos is None:
            if 'default' in self.__dict__ and self.default is not None:
                return self.default

            return self._COMBINATIONS[0]

        return self._COMBINATIONS[self.state_pos % len(self._COMBINATIONS)]


class RandOID(_RandString[str]):
    def __init__(self, fmt=None, depth=RandNumExpo(0.1), idnum=RandNumExpo(0.01)):  # noqa: E501
        # type: (Optional[str], RandNumExpo, RandNumExpo) -> None
        super(RandOID, self).__init__()
        self.ori_fmt = fmt
        self.fmt = None  # type: Optional[List[Union[str, Tuple[int, ...]]]]
        if fmt is not None:
            self.fmt = [
                tuple(map(int, x.split("-"))) if "-" in x else x
                for x in fmt.split(".")
            ]
        self.depth = depth
        self.idnum = idnum

    def _command_args(self):
        # type: () -> str
        ret = []
        if self.fmt:
            ret.append("fmt=%r" % self.ori_fmt)

        if not isinstance(self.depth, VolatileValue):
            ret.append("depth=%r" % self.depth)
        elif not isinstance(self.depth, RandNumExpo) or \
                self.depth.lambd != 0.1 or self.depth.base != 0:
            ret.append("depth=%s" % self.depth.command())

        if not isinstance(self.idnum, VolatileValue):
            ret.append("idnum=%r" % self.idnum)
        elif not isinstance(self.idnum, RandNumExpo) or \
                self.idnum.lambd != 0.01 or self.idnum.base != 0:
            ret.append("idnum=%s" % self.idnum.command())

        return ", ".join(ret)

    def __repr__(self):
        # type: () -> str
        if self.ori_fmt is None:
            return "<%s>" % self.__class__.__name__
        else:
            return "<%s [%s]>" % (self.__class__.__name__, self.ori_fmt)

    def _fix(self):
        # type: () -> str
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


class RandRegExp(RandField[str]):
    def __init__(self, regexp, lambda_=0.3):
        # type: (str, float) -> None
        self._regexp = regexp
        self._lambda = lambda_

    def _command_args(self):
        # type: () -> str
        ret = "regexp=%r" % self._regexp
        if self._lambda != 0.3:
            ret += ", lambda_=%r" % self._lambda
        return ret

    special_sets = {
        "[:alnum:]": "[a-zA-Z0-9]",
        "[:alpha:]": "[a-zA-Z]",
        "[:ascii:]": "[\x00-\x7F]",
        "[:blank:]": "[ \t]",
        "[:cntrl:]": "[\x00-\x1F\x7F]",
        "[:digit:]": "[0-9]",
        "[:graph:]": "[\x21-\x7E]",
        "[:lower:]": "[a-z]",
        "[:print:]": "[\x20-\x7E]",
        "[:punct:]": "[!\"\\#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_{|}~]",
        "[:space:]": "[ \t\r\n\v\f]",
        "[:upper:]": "[A-Z]",
        "[:word:]": "[A-Za-z0-9_]",
        "[:xdigit:]": "[A-Fa-f0-9]",
    }

    @staticmethod
    def choice_expand(s):
        # type: (str) -> str
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
        # type: (List[Any], List[Any]) -> str
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
        # type: () -> str
        stack = [None]
        index = []
        # Give up on typing this
        current = stack  # type: Any
        i = 0
        regexp = self._regexp
        for k, v in self.special_sets.items():
            regexp = regexp.replace(k, v)
        ln = len(regexp)
        interp = True
        while i < ln:
            c = regexp[i]
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
                    current.append([current] + [e] * int(num))
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
                c = regexp[i]
                if c == "s":
                    current.append(RandChoice(" ", "\t"))
                elif c in "0123456789":
                    current.append("cite", ord(c) - 0x30)
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
        # type: () -> str
        return "<%s [%r]>" % (self.__class__.__name__, self._regexp)


class RandSingularity(RandChoice):
    pass


class RandSingNum(RandSingularity):
    @staticmethod
    def make_power_of_two(end):
        # type: (int) -> Set[int]
        sign = 1
        if end == 0:
            end = 1
        if end < 0:
            end = -end
            sign = -1
        end_n = int(math.log(end) / math.log(2)) + 1
        return {sign * 2**i for i in range(end_n)}

    def __init__(self, mn, mx):
        # type: (int, int) -> None
        self._mn = mn
        self._mx = mx
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

    def _command_args(self):
        # type: () -> str
        if self.__class__.__name__ == 'RandSingNum':
            return "mn=%r, mx=%r" % (self._mn, self._mx)
        return super(RandSingNum, self)._command_args()


class RandSingByte(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, 0, 2**8 - 1)


class RandSingSByte(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, -2**7, 2**7 - 1)


class RandSingShort(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, 0, 2**16 - 1)


class RandSingSShort(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, -2**15, 2**15 - 1)


class RandSingInt(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, 0, 2**32 - 1)


class RandSingSInt(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, -2**31, 2**31 - 1)


class RandSingLong(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, 0, 2**64 - 1)


class RandSingSLong(RandSingNum):
    def __init__(self):
        # type: () -> None
        RandSingNum.__init__(self, -2**63, 2**63 - 1)


class RandSingString(RandSingularity):
    def __init__(self):
        # type: () -> None
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

    def _command_args(self):
        # type: () -> str
        return ""

    def __str__(self):
        # type: () -> str
        return str(self._fix())

    def __bytes__(self):
        # type: () -> bytes
        return bytes_encode(self._fix())


class RandPool(RandField[VolatileValue[Any]]):
    def __init__(self, *args):
        # type: (*Tuple[VolatileValue[Any], int]) -> None
        """Each parameter is a volatile object or a couple (volatile object, weight)"""  # noqa: E501
        self._args = args
        pool = []  # type: List[VolatileValue[Any]]
        for p in args:
            w = 1
            if isinstance(p, tuple):
                p, w = p  # type: ignore
            pool += [cast(VolatileValue[Any], p)] * w
        self._pool = pool

    def _command_args(self):
        # type: () -> str
        ret = []
        for p in self._args:
            if isinstance(p, tuple):
                ret.append("(%s, %r)" % (p[0].command(), p[1]))
            else:
                ret.append(p.command())
        return ", ".join(ret)

    def _fix(self):
        # type: () -> Any
        r = random.choice(self._pool)
        return r._fix()


class RandUUID(RandField[uuid.UUID]):
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

    def __init__(self,
                 template=None,  # type: Optional[Any]
                 node=None,  # type: Optional[int]
                 clock_seq=None,  # type: Optional[int]
                 namespace=None,  # type: Optional[uuid.UUID]
                 name=None,  # type: Optional[str]
                 version=None,  # type: Optional[Any]
                 ):
        # type: (...) -> None
        self._template = template
        self._ori_version = version

        self.uuid_template = None
        self.clock_seq = None
        self.namespace = None
        self.name = None
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
            uuid_template = []  # type: List[Union[int, RandNum]]
            for i, t in enumerate(template):
                if t == "*":
                    uuid_template.append(rnd_f[i]())
                elif ":" in t:
                    mini, maxi = t.split(":")
                    uuid_template.append(
                        RandNum(int(mini, 16), int(maxi, 16))
                    )
                else:
                    uuid_template.append(int(t, 16))

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

    def _command_args(self):
        # type: () -> str
        ret = []
        if self._template:
            ret.append("template=%r" % self._template)
        if self.node:
            ret.append("node=%r" % self.node)
        if self.clock_seq:
            ret.append("clock_seq=%r" % self.clock_seq)
        if self.namespace:
            ret.append("namespace=%r" % self.namespace)
        if self.name:
            ret.append("name=%r" % self.name)
        if self._ori_version:
            ret.append("version=%r" % self._ori_version)
        return ", ".join(ret)

    def _fix(self):
        # type: () -> uuid.UUID
        if self.uuid_template:
            return uuid.UUID(("%08x%04x%04x" + ("%02x" * 8))
                             % self.uuid_template)
        elif self.version == 1:
            return uuid.uuid1(self.node, self.clock_seq)
        elif self.version == 3:
            if not self.namespace or not self.name:
                raise ValueError("Missing namespace or name")
            return uuid.uuid3(self.namespace, self.name)
        elif self.version == 4:
            return uuid.uuid4()
        elif self.version == 5:
            if not self.namespace or not self.name:
                raise ValueError("Missing namespace or name")
            return uuid.uuid5(self.namespace, self.name)
        else:
            raise ValueError("Unhandled version")


# Automatic timestamp


class _AutoTime(_RandNumeral[_T],  # type: ignore
                Generic[_T]):
    def __init__(self, base=None, diff=None):
        # type: (Optional[int], Optional[float]) -> None
        self._base = base
        self._ori_diff = diff

        if diff is not None:
            self.diff = diff
        elif base is None:
            self.diff = 0.
        else:
            self.diff = time.time() - base

    def _command_args(self):
        # type: () -> str
        ret = []
        if self._base:
            ret.append("base=%r" % self._base)
        if self._ori_diff:
            ret.append("diff=%r" % self._ori_diff)
        return ", ".join(ret)


class AutoTime(_AutoTime[float]):
    def _fix(self):
        # type: () -> float
        return time.time() - self.diff


class IntAutoTime(_AutoTime[int]):
    def _fix(self):
        # type: () -> int
        return int(time.time() - self.diff)


class ZuluTime(_AutoTime[str]):
    def __init__(self, diff=0):
        # type: (int) -> None
        super(ZuluTime, self).__init__(diff=diff)

    def _fix(self):
        # type: () -> str
        return time.strftime("%y%m%d%H%M%SZ",
                             time.gmtime(time.time() + self.diff))


class GeneralizedTime(_AutoTime[str]):
    def __init__(self, diff=0):
        # type: (int) -> None
        super(GeneralizedTime, self).__init__(diff=diff)

    def _fix(self):
        # type: () -> str
        return time.strftime("%Y%m%d%H%M%SZ",
                             time.gmtime(time.time() + self.diff))


class DelayedEval(VolatileValue[Any]):
    """ Example of usage: DelayedEval("time.time()") """

    def __init__(self, expr):
        # type: (str) -> None
        self.expr = expr

    def _command_args(self):
        # type: () -> str
        return "expr=%r" % self.expr

    def _fix(self):
        # type: () -> Any
        return eval(self.expr)


class IncrementalValue(VolatileValue[int]):
    def __init__(self, start=0, step=1, restart=-1):
        # type: (int, int, int) -> None
        self.start = self.val = start
        self.step = step
        self.restart = restart

    def _command_args(self):
        # type: () -> str
        ret = []
        if self.start:
            ret.append("start=%r" % self.start)
        if self.step != 1:
            ret.append("step=%r" % self.step)
        if self.restart != -1:
            ret.append("restart=%r" % self.restart)
        return ", ".join(ret)

    def _fix(self):
        # type: () -> int
        v = self.val
        if self.val == self.restart:
            self.val = self.start
        else:
            self.val += self.step
        return v


class CorruptedBytes(VolatileValue[bytes]):
    def __init__(self, s, p=0.01, n=None):
        # type: (str, float, Optional[Any]) -> None
        self.s = s
        self.p = p
        self.n = n

    def _command_args(self):
        # type: () -> str
        ret = []
        ret.append("s=%r" % self.s)
        if self.p != 0.01:
            ret.append("p=%r" % self.p)
        if self.n:
            ret.append("n=%r" % self.n)
        return ", ".join(ret)

    def _fix(self):
        # type: () -> bytes
        return corrupt_bytes(self.s, self.p, self.n)


class CorruptedBits(CorruptedBytes):
    def _fix(self):
        # type: () -> bytes
        return corrupt_bits(self.s, self.p, self.n)
