# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Answering machines.
"""

########################
#  Answering machines  #
########################

from __future__ import absolute_import
from __future__ import print_function

import warnings

from scapy.config import conf
from scapy.sendrecv import send, sniff
from scapy.packet import Packet
from scapy.plist import PacketList

import scapy.modules.six as six

from scapy.compat import (
    Any,
    Dict,
    Generic,
    _Generic_metaclass,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

_T = TypeVar("_T", Packet, PacketList)


class ReferenceAM(type):
    def __new__(cls,  # type: ignore
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['AnsweringMachine[_T]']
        obj = super(ReferenceAM, cls).__new__(cls, name, bases, dct)
        if obj.function_name:  # type: ignore
            globals()[obj.function_name] = lambda obj=obj, *args, **kargs: obj(*args, **kargs)()  # type: ignore  # noqa: E501
        return obj


@six.add_metaclass(_Generic_metaclass)
@six.add_metaclass(ReferenceAM)
class AnsweringMachine(Generic[_T]):
    function_name = ""
    filter = None  # type: Optional[str]
    sniff_options = {"store": 0}  # type: Dict[str, Any]
    sniff_options_list = ["store", "iface", "count", "promisc", "filter",
                          "type", "prn", "stop_filter", "opened_socket"]
    send_options = {"verbose": 0}  # type: Dict[str, Any]
    send_options_list = ["iface", "inter", "loop", "verbose", "socket"]
    send_function = staticmethod(send)

    def __init__(self, **kargs):
        # type: (Any) -> None
        self.mode = 0
        self.verbose = kargs.get("verbose", conf.verb >= 0)
        if self.filter:
            kargs.setdefault("filter", self.filter)
        kargs.setdefault("prn", self.reply)
        self.optam1 = {}  # type: Dict[str, Any]
        self.optam2 = {}  # type: Dict[str, Any]
        self.optam0 = {}  # type: Dict[str, Any]
        doptsend, doptsniff = self.parse_all_options(1, kargs)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend = {}   # type: Dict[str, Any]
        self.optsniff = {}   # type: Dict[str, Any]

    def __getattr__(self, attr):
        # type: (str) -> Any
        for dct in [self.optam2, self.optam1]:
            if attr in dct:
                return dct[attr]
        raise AttributeError(attr)

    def __setattr__(self, attr, val):
        # type: (str, Any) -> None
        mode = self.__dict__.get("mode", 0)
        if mode == 0:
            self.__dict__[attr] = val
        else:
            [self.optam1, self.optam2][mode - 1][attr] = val

    def parse_options(self):
        # type: () -> None
        pass

    def parse_all_options(self, mode, kargs):
        # type: (int, Any) -> Tuple[Dict[str, Any], Dict[str, Any]]
        sniffopt = {}  # type: Dict[str, Any]
        sendopt = {}  # type: Dict[str, Any]
        for k in list(kargs):  # use list(): kargs is modified in the loop
            if k in self.sniff_options_list:
                sniffopt[k] = kargs[k]
            if k in self.send_options_list:
                sendopt[k] = kargs[k]
            if k in self.sniff_options_list + self.send_options_list:
                del kargs[k]
        if mode != 2 or kargs:
            if mode == 1:
                self.optam0 = kargs
            elif mode == 2 and kargs:
                k = self.optam0.copy()
                k.update(kargs)
                self.parse_options(**k)  # type: ignore
                kargs = k
            omode = self.__dict__.get("mode", 0)
            self.__dict__["mode"] = mode
            self.parse_options(**kargs)  # type: ignore
            self.__dict__["mode"] = omode
        return sendopt, sniffopt

    def is_request(self, req):
        # type: (Packet) -> int
        return 1

    def make_reply(self, req):
        # type: (Packet) -> _T
        return req

    def send_reply(self, reply):
        # type: (_T) -> None
        self.send_function(reply, **self.optsend)

    def print_reply(self, req, reply):
        # type: (Packet, _T) -> None
        if isinstance(reply, PacketList):
            print("%s ==> %s" % (req.summary(),
                                 [res.summary() for res in reply]))
        else:
            print("%s ==> %s" % (req.summary(), reply.summary()))

    def reply(self, pkt):
        # type: (Packet) -> None
        if not self.is_request(pkt):
            return
        reply = self.make_reply(pkt)
        self.send_reply(reply)
        if self.verbose:
            self.print_reply(pkt, reply)

    def run(self, *args, **kargs):
        # type: (Any, Any) -> None
        warnings.warn(
            "run() method deprecated. The instance is now callable",
            DeprecationWarning
        )
        self(*args, **kargs)

    def __call__(self, *args, **kargs):
        # type: (Any, Any) -> None
        optsend, optsniff = self.parse_all_options(2, kargs)
        self.optsend = self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff = self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        try:
            self.sniff()
        except KeyboardInterrupt:
            print("Interrupted by user")

    def sniff(self):
        # type: () -> None
        sniff(**self.optsniff)
