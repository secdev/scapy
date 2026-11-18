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

import abc
import enum
import functools
import threading
import socket
import warnings

from scapy.arch import get_if_addr
from scapy.data import MTU
from scapy.config import conf
from scapy.error import log_runtime
from scapy.sendrecv import sendp, sniff, AsyncSniffer
from scapy.packet import Packet
from scapy.plist import PacketList

from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Optional,
    Tuple,
    Type,
    TypeVar,
    cast,
)

_T = TypeVar("_T", Packet, PacketList)


class ReferenceAM(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['AnsweringMachine[_T]']
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
    """
    This class acts as a template of a small server that answers stimuli.

    The following classes should be extended:

        - parse_options -> store / process a parameter
        - make_reply -> called with a request to make a reply
        - is_request -> acts as a filter for requests

    By default, it listens on a RAW socket, but it can be configured to run
    on a normal socket (UDP, TCP, ...) if necessary, through the ansmode param.

    In RAW mode, set a "filter" class attribute to use a BPF filter.

    Provide a "function_name" class attribute to register the answering machine
    as a command.
    """
    function_name = ""
    filter = None  # type: Optional[str]
    sniff_options = {"store": 0}  # type: Dict[str, Any]
    sniff_options_list = ["store", "iface", "count", "promisc", "filter",
                          "type", "prn", "stop_filter", "opened_socket"]
    send_options = {"verbose": 0}  # type: Dict[str, Any]
    send_options_list = ["iface", "inter", "loop", "verbose", "socket"]
    send_function = staticmethod(sendp)

    class MODE(enum.IntEnum):
        RAW = socket.SOCK_RAW
        TCP = socket.SOCK_STREAM
        UDP = socket.SOCK_DGRAM

    def __init__(self, **kargs):
        # type: (Any) -> None
        self.mode = kargs.pop("ansmode", self.MODE.RAW)
        self.verbose = kargs.get("verbose", conf.verb >= 0)
        self.port = kargs.get("port", 0)
        self.cls = kargs.get("cls", conf.raw_layer)
        if self.filter:
            kargs.setdefault("filter", self.filter)
        kargs.setdefault("prn", self.reply)
        doptsend, doptsniff, defoptuser = self.split_all_options(kargs)
        self.defoptuser = defoptuser
        self.parse_options(**defoptuser)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend = {}   # type: Dict[str, Any]
        self.optsniff = {}   # type: Dict[str, Any]

    def parse_options(self):
        # type: () -> None
        pass

    def split_all_options(self, kargs):
        # type: (Any) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]
        sniffopt = {}  # type: Dict[str, Any]
        sendopt = {}  # type: Dict[str, Any]
        for k in list(kargs):  # use list(): kargs is modified in the loop
            if k in self.sniff_options_list:
                sniffopt[k] = kargs[k]
            if k in self.send_options_list:
                sendopt[k] = kargs[k]
            if k in self.sniff_options_list + self.send_options_list:
                del kargs[k]
        return sendopt, sniffopt, kargs

    def is_request(self, req):
        # type: (Packet) -> int
        return 1

    @abc.abstractmethod
    def make_reply(self, req: Packet, address: Optional[Any] = None) -> _T:
        pass

    def send_reply(self, reply, send_function=None):
        # type: (_T, Optional[Callable[..., Any]]) -> None
        if send_function:
            send_function(reply)
        else:
            self.send_function(reply, **self.optsend)

    def print_reply(self, req, reply):
        # type: (Packet, _T) -> None
        if isinstance(reply, PacketList):
            print("%s ==> %s" % (req.summary(),
                                 [res.summary() for res in reply]))
        else:
            print("%s ==> %s" % (req.summary(), reply.summary()))

    def reply(self, pkt, send_function=None, address=None):
        # type: (Packet, Optional[Callable[..., None]], Optional[Any]) -> None
        if not self.is_request(pkt):
            return
        if address:
            reply = self.make_reply(pkt, address)
        else:
            # For backwards compatibility, we don't pass address if undefined (RAW)
            # since the 'address' parameter is new
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

    def run(self, *args, **kargs):
        # type: (Any, Any) -> None
        warnings.warn(
            "run() method deprecated. The instance is now callable",
            DeprecationWarning
        )
        self(*args, **kargs)

    def bg(self, *args, **kwargs):
        # type: (Any, Any) -> AsyncSniffer
        kwargs.setdefault("bg", True)
        self(*args, **kwargs)
        return self.sniffer

    def __call__(self, *args, **kargs):
        # type: (Any, Any) -> None
        bg = kargs.pop("bg", False)

        # Separate the kargs in the send/sniff/user
        optsend, optsniff, optuser = self.split_all_options(kargs)
        self.optsend = self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff = self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        # Finally call the AnsweringMachine's parse_options with user
        # provided arguments.
        kargs = self.defoptuser.copy()
        kargs.update(optuser)
        self.parse_options(**kargs)

        if bg:
            self.sniff_bg()
        else:
            try:
                self.sniff()
            except KeyboardInterrupt:
                print("Interrupted by user")

    def sniff(self) -> None:
        """
        Start sniffing. This is blocking
        """
        if self.mode == self.MODE.RAW:
            # Sniff using RAW method.
            sniff(**self.optsniff)
        elif self.mode in [self.MODE.TCP, self.MODE.UDP]:
            # Sniff using a normal socket
            from scapy.supersocket import StreamSocket
            ssock = socket.socket(socket.AF_INET, self.mode)
            try:
                ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            ssock.bind(
                (
                    get_if_addr(self.optsniff.get("iface", conf.iface)),
                    self.port
                )
            )
            if self.mode == self.MODE.TCP:
                # TCP
                ssock.listen(5)
                sniffers = []
                try:
                    while True:
                        clientsocket, address = ssock.accept()
                        print("%s connected (TCP)" % repr(address))
                        sock = StreamSocket(clientsocket, self.cls)
                        optsniff = self.optsniff.copy()
                        optsniff["prn"] = functools.partial(self.reply,
                                                            send_function=sock.send,
                                                            address=address)
                        optsniff.pop("iface", None)
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
                    ssock.close()
            else:
                # UDP
                try:
                    while True:
                        rpkt, address = ssock.recvfrom(MTU)
                        print("%s received (UDP)" % repr(address))
                        try:
                            pkt = self.cls(rpkt)
                        except Exception as ex:
                            log_runtime.warning(str(ex))
                            continue
                        self.reply(
                            pkt,
                            send_function=lambda x: ssock.sendto(bytes(x), address),  # type: ignore
                            address=address,
                        )
                finally:
                    ssock.close()
        else:
            raise ValueError

    def sniff_bg(self):
        # type: () -> None
        if self.mode == self.MODE.RAW:
            self.sniffer = AsyncSniffer(**self.optsniff)
            self.sniffer.start()
        elif self.mode in [self.MODE.TCP, self.MODE.UDP]:
            # Sniff using a normal socket
            self.sniffer = threading.Thread(target=self.sniff)  # type: ignore
            self.sniffer.start()
        else:
            raise ValueError
