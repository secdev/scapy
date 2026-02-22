# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

from functools import lru_cache
from collections import defaultdict
import itertools
from typing import Set, List, Tuple, Any


# Taken from https://en.wikipedia.org/wiki/Cyclic_redundancy_check
# Only direct representation. Reversed, reciprocal,
# reversed reciprocal polynoms can be deduced.
WELL_KNOWN_POLY = {
    16: [0x1021, 0x8005, 0xa02b, 0x2f15, 0xc867, 0x0589, 0x8bb7, 0x3d65,
         0x5935, 0x755b, 0x1dcf],
    32: [0x04c11db7, 0x1edc6f41, 0x741b8cd7, 0x32583499, 0x814141ab, 0xf4acfb13]
}


class CRCParam:
    MISC = ["name", "test_vectors"]
    PARAMETERS = ["poly", "size", "init_crc", "xor",
                  "reflect_input", "reflect_output"]
    OPTIONS = ["header", "trailer"]
    FMT = {"size": "", "reflect_input": "", "reflect_output": ""}

    def __init__(self, **args):
        # type: (Any) -> None
        self.remain = set(args) - set(self.PARAMETERS + self.OPTIONS + self.MISC)

        self.param = dict(header=b"", trailer=b"", test_vectors=[],
                          reflect_input=False, reflect_output=False)
        try:
            self.param.update({n: args[n] for n in self.PARAMETERS})
        except KeyError as e:
            raise Exception(f"CRC parameter {e} is mandatory")

        self.param.update({n: args[n] for n in self.OPTIONS + self.MISC if n in args})
        self.__dict__.update(self.param)
        if "name" not in self.param or self.param["name"] is None:
            self.name = self.param["name"] = f"CRCsig_{self.signature()}"

    def copy(self):
        # type: () -> CRCParam
        return self.__class__(**self.param)

    def param_repr(self):
        # type: () -> str
        s = [f"{k}={getattr(self, k): {self.FMT.get(k, '#x')}}"
             for k in self.PARAMETERS]
        s += [f"+{k}" for k in self.OPTIONS if getattr(self, k)]
        return ", ".join(s)

    def __repr__(self):
        # type: () -> str
        name = self.name if hasattr(self, "name") else "CRC param"
        s = self.param_repr()
        return f"<Param for {name} {s}>"

    def __eq__(self, other):
        # type: (object) -> bool
        return all(getattr(self, k) == getattr(other, k)
                   for k in self.PARAMETERS + self.OPTIONS)

    def __hash__(self):
        # type: () -> int
        return hash(tuple(getattr(self, k) for k in self.PARAMETERS + self.OPTIONS))

    def __iter__(self):
        for k in self.PARAMETERS + self.MISC + self.OPTIONS:
            yield (k, getattr(self, k))

    def signature(self):
        # type: () -> str
        sig_end = ((self.reflect_input << 3) | (self.reflect_output << 2)
                   | (bool(self.header) << 1) | bool(self.trailer))
        return f"{self.poly:0{self.size // 4}x}_{self.init_crc:x}_{self.xor:x}_{sig_end:x}"  # noqa: E231,E501


class _CRC_metaclass(type):
    REGISTRY = set()  # type: Set[CRC]

    def __new__(cls, name, bases, dct):
        newcls = super(_CRC_metaclass, cls).__new__(cls, name, bases, dct)
        if not hasattr(newcls, "name"):
            newcls.name = newcls.__name__
        if bases:  # exclude parent class because it is virtual
            newcls.param = CRCParam(**dct)
            newcls.precal_table = (
                cls._precalc_table_reflect
                if newcls.reflect_input
                else cls._precalc_table
            )
            newcls.table = newcls.precal_table(newcls.poly, newcls.size)
            if not getattr(newcls, "do_not_register", False):
                newcls.REGISTRY.add(newcls)
            newcls.mask = (1 << newcls.size) - 1
        else:
            newcls.param = None
        return newcls

    @staticmethod
    @lru_cache(maxsize=128)
    def _precalc_table_reflect(crcpoly, sz):
        # type: (int, int) -> List[int]
        revpoly = CRC._reverse_bits(crcpoly, sz)
        t = []
        for i in range(256):
            crc = i
            for j in range(8):
                b0 = crc & 1
                crc >>= 1
                if b0:
                    crc ^= revpoly
            t.append(crc)
        return t

    @staticmethod
    @lru_cache(maxsize=128)
    def _precalc_table(crcpoly, sz):
        # type: (int, int) -> List[int]
        t = []
        hbmsk = (1 << (sz - 1))
        msk = (1 << sz) - 1
        for i in range(256):
            crc = i << (sz - 8)
            for j in range(8):
                bsz = crc & hbmsk
                crc <<= 1
                if bsz:
                    crc ^= crcpoly
            t.append(crc & msk)
        return t

    @staticmethod
    def _reverse_bits(x, sz):
        # type: (int, int) -> int
        y = 0
        for i in range(sz):
            y <<= 1
            y |= x & 1
            x >>= 1
        return y

    def from_parameters(self, crc_param=None, name=None,
                        do_not_register=False, **kargs):
        if crc_param is None:
            crc_param = CRCParam(name=name, **kargs)
        p = dict(crc_param)
        if name is not None:
            p["name"] = name
        p["do_not_register"] = do_not_register
        cls = type(self).__new__(type(self), p["name"], (self,), p)
        return cls

    def create_context(self):
        # type: () -> CRC
        i = self.__new__(self)
        i.__init__()
        return i

    def _init(self):
        # type: () -> int
        return self._update(self.param.init_crc, self.param.header)

    def _update(self, crc, msg):
        # type: (int, bytes) -> int
        if self.param.reflect_input:
            for c in msg:
                idx = (crc & 0xff) ^ c
                crc >>= 8
                crc ^= self.table[idx]
        else:
            for c in msg:
                idx = (crc >> (self.param.size - 8)) ^ c
                crc <<= 8
                crc &= self.mask
                crc ^= self.table[idx]
        return crc

    def _finish(self, crc):
        # type: (int) -> int
        crc = self._update(crc, self.param.trailer)
        crc = (crc ^ self.param.xor) & self.mask
        if self.param.reflect_input ^ self.param.reflect_output:
            crc = self._reverse_bits(crc, self.param.size)
        return crc

    def __call__(self, msg):
        # type: (bytes) -> int
        assert type(msg) is bytes, "type of input is bytes"
        crc = self._init()
        crc = self._update(crc, msg)
        return self._finish(crc)

    def test(self):
        # type: () -> bool
        ok = True
        for (tvin, tvout) in self.param.test_vectors:
            out = self(tvin)
            ok &= (out == tvout)
            print(f"{self.name}\t({tvin.hex()})\t = {out:#0{self.size // 4}x}\t{'ok' if out == tvout else f'FAILED. Expected {tvout:#0{self.size // 4}x}'}".expandtabs(32))  # noqa: E501,E231
        return ok

    def __eq__(self, other):
        # type: (object) -> bool
        return hasattr(other, "param") and (self.param == other.param)

    def __hash__(self):
        # type: () -> int
        return hash(self.param)  # if hasattr(self, "param") else 0)

    def __repr__(self):
        # type: () -> str
        repr = self.param.param_repr() if self.param else "-"
        return f"<{self.name} {repr}>"

    def autotest(self):
        # type: () -> bool
        ok = 0
        n = len(self.REGISTRY)
        ok = sum(c.test() for c in self.REGISTRY)
        print(f"TOTAL: {ok}/{n} CRC test passed")
        return ok == n

    def lookup(self, crc):
        param = crc.param if isinstance(crc, self.__class__) else crc
        for c in self.REGISTRY:
            if c.param == param:
                return c

    def find_substring_from_crc(self, s, *target_crc):
        # type: (bytes, List[int]) -> List[Tuple[Tuple[int,int],int]]
        l = len(s)  # noqa: E741
        i = 0
        res = []
        while i < l:
            j = i
            c = self.create_context()
            c.init()
            while j < l:
                c.update(s[j:j + 1])
                crc = c.finish()
                if crc in target_crc:
                    res.append(((i, j), crc))
                j += 1
            i += 1
        return res

    def find_crc_from_string(self, s, *target_crc):
        # type: (bytes, List[int]) -> List[Tuple[int, CRC]]
        res = []
        for crc in self.REGISTRY:
            c = crc(s)
            if c in target_crc:
                res.append((c, crc))
        return res

    def search(self, s, min_substring_len=4, only_registry=False):
        # type: (bytes, int, bool) -> List[Tuple[Tuple[int,int],int,type(CRC)]]

        if only_registry:
            crc_list = self.REGISTRY
        else:
            crc_list = set()
            for sz, poly_lst in WELL_KNOWN_POLY.items():
                msk = (1 << sz) - 1
                poly_lst_and_rev = (
                    poly_lst +
                    [self._reverse_bits(p, sz) for p in poly_lst]
                )
                crc_list |= {
                    self.from_parameters(
                        do_not_register=True,
                        poly=poly, size=sz, init_crc=init & msk, xor=xor & msk,
                        reflect_input=r_in, reflect_output=r_out)
                    for poly, init, xor, r_in, r_out
                    in itertools.product(poly_lst_and_rev, [0, -1], [0, -1],
                                         [False, True], [False, True])
                }

        l = len(s)  # noqa: E741
        sizes = set(c.size // 8 for c in crc_list)
        targets = defaultdict(set)
        for sz in sizes:
            i = 0
            while i <= l - sz:
                ss = s[i:i + sz]
                targets[sz].add(int.from_bytes(ss, "little"))
                targets[sz].add(int.from_bytes(ss, "big"))
                i += 1

        crcs = defaultdict(list)
        for c in crc_list:
            crcs[c.size].append(c)

        res = []

        i = 0
        ctx = {k // 8: [c.create_context() for c in v] for k, v in crcs.items()}
        while i < l:
            for clst in ctx.values():
                for c in clst:
                    c.init()
            j = i
            while j < l:
                for sz in sizes:
                    for c in ctx[sz]:
                        c.update(s[j:j + 1])
                        if j - i + 1 >= min_substring_len:
                            crc = c.finish()
                            if crc in targets[sz]:
                                res.append(((i, j + 1), crc, c.__class__))
                j += 1
            i += 1
        return res


class CRC(metaclass=_CRC_metaclass):
    def __init__(self):
        self.init()

    # Context API: init()/update()/finish()
    # finish() does not change state, so update()/finish() can be called again

    def init(self):
        # type: () -> None
        self.crc = self.__class__._init()

    def update(self, msg):
        # type: (bytes) -> None
        self.crc = self.__class__._update(self.crc, msg)

    def finish(self):
        # type: () -> int
        return self.__class__._finish(self.crc)

    def __repr__(self):
        # type: () -> str
        return f"<{self.name} CTX>"


class CRC_16(CRC):
    name = "CRC-16"
    size = 16
    poly = 0x8005
    init_crc = 0
    xor = 0
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"123456789", 0xbb3d)]


class CRC_32(CRC):
    name = "CRC-32"
    size = 32
    poly = 0x4c11db7
    init_crc = 0xffffffff
    xor = 0xffffffff
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"123456789", 0xcbf43926)]


class CRC_16_CCITT(CRC):
    "aka KERMIT CRC"
    name = "CRC16 CCITT"
    size = 16
    poly = 0x1021
    init_crc = 0
    xor = 0
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"\xcb\x37", 0x6b3e)]


class CRC_32_AUTOSAR(CRC):
    name = "CRC32 AUTOSAR"
    size = 32
    poly = 0xf4acfb13
    init_crc = 0xffffffff
    xor = 0xffffffff
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"\0\0\0\0", 0x6fb32240),
                    (b"\x33\x22\x55\xAA\xBB\xCC\xDD\xEE\xFF", 0xa65a343d), ]
