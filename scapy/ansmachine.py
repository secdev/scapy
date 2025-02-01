# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Answering machines.
"""

########################
#  Answering machines  #
########################

from __future__ import annotations

import abc
import functools
import threading
import socket
import warnings

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.sendrecv import sendp, sniff, AsyncSniffer
from scapy.packet import Packet
from scapy.plist import PacketList

from typing import (
    Any,
    Callable,
    Generic,
    Optional,
    Type,
    TypeVar,
    cast,
)

_T = TypeVar("_T", Packet, PacketList)


class ReferenceAM(type):
    def __new__(cls, name: str,
                bases: tuple[type, ...],
                dct: dict[str, Any]
                ) -> type[AnsweringMachine[_T]]:
        obj = cast('Type[AnsweringMachine[_T]]',
                   super(ReferenceAM, cls).__new__(cls, name, bases, dct))
        try:
            import inspect
            obj.__signature__ = inspect.signature(  # type: ignore
                obj.parse_options
            )
        except (ImportError, AttributeError):
            pass
        if obj.function_name:
            func = lambda obj=obj, *args, **kargs: obj(*args, **kargs)()  # type: ignore  # noqa: E501
            # Inject signature
            func.__name__ = func.__qualname__ = obj.function_name
            func.__doc__ = obj.__doc__ or obj.parse_options.__doc__
            try:
                func.__signature__ = obj.__signature__  # type: ignore
            except (AttributeError):
                pass
            globals()[obj.function_name] = func
        return obj


class AnsweringMachine(Generic[_T], metaclass=ReferenceAM):
    function_name = ""
    filter: str | None = None
    sniff_options: dict[str, Any] = {"store": 0}
    sniff_options_list = ["store", "iface", "count", "promisc", "filter",
                          "type", "prn", "stop_filter", "opened_socket"]
    send_options: dict[str, Any] = {"verbose": 0}
    send_options_list = ["iface", "inter", "loop", "verbose", "socket"]
    send_function = staticmethod(sendp)

    def __init__(self, **kargs: Any) -> None:
        self.mode = 0
        self.verbose = kargs.get("verbose", conf.verb >= 0)
        if self.filter:
            kargs.setdefault("filter", self.filter)
        kargs.setdefault("prn", self.reply)
        self.optam1: dict[str, Any] = {}
        self.optam2: dict[str, Any] = {}
        self.optam0: dict[str, Any] = {}
        doptsend, doptsniff = self.parse_all_options(1, kargs)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend: dict[str, Any] = {}
        self.optsniff: dict[str, Any] = {}

    def __getattr__(self, attr: str) -> Any:
        for dct in [self.optam2, self.optam1]:
            if attr in dct:
                return dct[attr]
        raise AttributeError(attr)

    def __setattr__(self, attr: str, val: Any) -> None:
        mode = self.__dict__.get("mode", 0)
        if mode == 0:
            self.__dict__[attr] = val
        else:
            [self.optam1, self.optam2][mode - 1][attr] = val

    def parse_options(self) -> None:
        pass

    def parse_all_options(
            self, mode: int, kargs: Any
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        sniffopt: dict[str, Any] = {}
        sendopt: dict[str, Any] = {}
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
                self.parse_options(**k)
                kargs = k
            omode = self.__dict__.get("mode", 0)
            self.__dict__["mode"] = mode
            self.parse_options(**kargs)
            self.__dict__["mode"] = omode
        return sendopt, sniffopt

    def is_request(self, req: Packet) -> int:
        return 1

    @abc.abstractmethod
    def make_reply(self, req: Packet) -> _T:
        pass

    def send_reply(
            self, reply: _T, send_function: Callable[..., None] | None = None
    ) -> None:
        if send_function:
            send_function(reply)
        else:
            self.send_function(reply, **self.optsend)

    def print_reply(self, req: Packet, reply: _T) -> None:
        if isinstance(reply, PacketList):
            print("%s ==> %s" % (req.summary(),
                                 [res.summary() for res in reply]))
        else:
            print("%s ==> %s" % (req.summary(), reply.summary()))

    def reply(
            self,
            pkt: Packet,
            send_function: Callable[..., None] | None = None,
            address: Any | None = None
    ) -> None:
        if not self.is_request(pkt):
            return
        if address:
            # Only on AnsweringMachineTCP
            reply = self.make_reply(pkt, address=address)  # type: ignore
        else:
            reply = self.make_reply(pkt)
        if not reply:
            return
        if send_function:
            self.send_reply(reply, send_function=send_function)
        else:
            # Retro-compability. Remove this if eventually
            self.send_reply(reply)
        if self.verbose:
            self.print_reply(pkt, reply)

    def run(self, *args: Any, **kargs: Any) -> None:
        warnings.warn(
            "run() method deprecated. The instance is now callable",
            DeprecationWarning
        )
        self(*args, **kargs)

    def bg(self, *args: Any, **kwargs: Any) -> AsyncSniffer:
        kwargs.setdefault("bg", True)
        self(*args, **kwargs)
        return self.sniffer

    def __call__(self, *args: Any, **kargs: Any) -> None:
        bg = kargs.pop("bg", False)
        optsend, optsniff = self.parse_all_options(2, kargs)
        self.optsend = self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff = self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        if bg:
            self.sniff_bg()
        else:
            try:
                self.sniff()
            except KeyboardInterrupt:
                print("Interrupted by user")

    def sniff(self) -> None:
        sniff(**self.optsniff)

    def sniff_bg(self) -> None:
        self.sniffer = AsyncSniffer(**self.optsniff)
        self.sniffer.start()


class AnsweringMachineTCP(AnsweringMachine[Packet]):
    """
    An answering machine that use the classic socket.socket to
    answer multiple TCP clients
    """
    TYPE = socket.SOCK_STREAM

    def parse_options(self, port: int = 80, cls: type[Packet] = conf.raw_layer) -> None:
        self.port = port
        self.cls = cls

    def close(self) -> None:
        pass

    def sniff(self) -> None:
        from scapy.supersocket import StreamSocket
        ssock = socket.socket(socket.AF_INET, self.TYPE)
        try:
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        ssock.bind(
            (get_if_addr(self.optsniff.get("iface", conf.iface)), self.port))
        ssock.listen()
        sniffers = []
        try:
            while True:
                clientsocket, address = ssock.accept()
                print("%s connected" % repr(address))
                sock = StreamSocket(clientsocket, self.cls)
                optsniff = self.optsniff.copy()
                optsniff["prn"] = functools.partial(self.reply,
                                                    send_function=sock.send,
                                                    address=address)
                del optsniff["iface"]
                sniffer = AsyncSniffer(opened_socket=sock, **optsniff)
                sniffer.start()
                sniffers.append((sniffer, sock))
        finally:
            for (sniffer, sock) in sniffers:
                try:
                    sniffer.stop()
                except Exception:
                    pass
                sock.close()
            self.close()
            ssock.close()

    def sniff_bg(self) -> None:
        self.sniffer = threading.Thread(target=self.sniff)  # type: ignore
        self.sniffer.start()

    def make_reply(self, req: Packet, address: Any | None = None) -> Packet:
        return req


class AnsweringMachineUDP(AnsweringMachineTCP):
    """
    An answering machine that use the classic socket.socket to
    answer multiple UDP clients
    """
    TYPE = socket.SOCK_DGRAM
