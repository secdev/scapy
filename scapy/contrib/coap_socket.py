# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 eHonnef <contact@honnef.net>

# scapy.contrib.description = CoAP Socket Library / RFC 7252
# scapy.contrib.status = library

import logging
import random
import socket
import time

# Typing imports
from typing import (
    Optional,
    Union,
    Tuple,
    cast,
    Type
)

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.contrib.coap import CoAP, coap_options, coap_codes, EMPTY_MESSAGE, GET, \
    POST, PUT, DELETE, COAP_REQ_CODES, CONTENT_205, NOT_FOUND_404, NOT_ALLOWED_405, \
    CF_TEXT_PLAIN, CF_APP_LINK_FORMAT, PAYMARK, URI_PATH, CONTENT_FORMAT, CON, NON, ACK
from scapy.contrib.isotp.isotp_soft_socket import TimeoutScheduler
from scapy.data import MTU
from scapy.utils import EDecimal
from scapy.automaton import ObjectPipe, select_objects
from scapy.layers.inet import UDP, IP
from scapy.supersocket import SuperSocket, SimpleSocket

log_coap_sock = logging.getLogger("scapy.contrib.coap_socket")


class CoAPSocket(SuperSocket):
    """
    CoAP socket with client and server capabilities.

    General and defaults timeouts for the protocol - RFC 7252 @ section-4.8.2

    Client example:
    >>> with CoAPSocket("127.0.0.1", 1234) as coap_client:
    >>>     req = CoAPSocket.make_coap_req_packet(
    >>>                 method=GET, uri="endpoint-uri", payload=b"")
    >>>     coap_client.send(IP(dst="192.168.1.1") / UDP(dport=1234) / req)
    >>>     # Careful, this will block until the coap_client receives something
    >>>     res = coap_client.recv()

    Server without specifying resources:
    >>> with CoAPSocket("127.0.0.1", 5683) as coap_server:
    >>>     while True:
    >>>         pkg = coap_server.recv()
    >>>         handle_package(pkg)

    Server with custom resources:
    >>> class DummyResource(CoAPResource):
    >>>     def get(self, payload, options, token, sa_ll):
    >>>         return {"type": ACK, "code": CONTENT_205,
    >>>                 "options": [(CONTENT_FORMAT, CF_TEXT_PLAIN)],
    >>>                 "payload": b'dummy response'}
    >>>
    >>> class DelayedResource(CoAPResource):
    >>>     def __init__(self, url):
    >>>         CoAPResource.__init__(self, url=url)
    >>>         self.delayed_tokens = []
    >>>     def delayed_message(self):
    >>>         token, address = self.delayed_tokens.pop(0)
    >>>         pkt = CoAPSocket.make_delayed_resp_packet(token,
    >>>                  [(CONTENT_FORMAT, CF_TEXT_PLAIN)], b"delayed payload")
    >>>         self._send_separate_response(pkt, address)
    >>>     def get(self, payload, options, token, sa_ll):
    >>>         # We know that this can take a while, so we return an empty ACK now
    >>>         # and wait for whatever resource to be available.
    >>>         TimeoutScheduler.schedule(1, self.delayed_message)
    >>>         self.delayed_tokens.append((token, sa_ll))
    >>>         return CoAPSocket.empty_ack_params()
    >>> # Doesn't matter if it starts with "/dummy" or "dummy",
    >>> # but it is an error if it is in the end
    >>> lst_resources = [DummyResource("dummy"), DelayedResource("/delayed")].
    >>> with CoAPSocket("127.0.0.1", 5683, lst_resources=lst_resources) as coap_socket:
    >>>     while True:
    >>>         pkg = coap_socket.recv()
    >>>         # You can handle the packages inside your resources,
    >>>         # here will only be the "unhandled" ones.

    :param ip: ip address to bind udp socket to.
    :param port: port to bind udp socket to.
    :param ack_timeout: the time, in ms, that we should wait for the acknowledgment
                        after sending a request.
    :param retries: amount of retransmissions before giving up on the request.
    :param duplication_response_timeout: Timeout, in fractions of seconds, that we will
                                        keep the response in case a response get lost.
    :param lst_resources: optional, list of registered resources.
    :param sock: optional, a socket instance to transmit,
                 if None, a classic UDP socket will be open and bound to ip/port.
    :param close_on_timeout: Will try to close the socket if the retries is exceeded
    """

    def __init__(self,
                 ip="",  # type: str
                 port=5683,  # type: int
                 ack_timeout=500,  # type: int
                 retries=3,  # type: int
                 duplication_response_timeout=1.00,  # type: float
                 lst_resources=None,  # type: Optional[list[CoAPResource]]
                 sock=None,  # type: Optional[SuperSocket]
                 close_on_timeout=False  # type: bool
                 ):
        self.impl = CoAPSocketImpl(ip, port, ack_timeout, retries,
                                   duplication_response_timeout, lst_resources, sock,
                                   close_on_timeout)

        self.ins = cast(socket.socket, self.impl)
        self.outs = cast(socket.socket, self.impl)
        self.basecls = CoAP

    def recv_raw(self, x=0xffff):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]
        if not self.closed:
            tup = self.impl.recv()
            if tup is not None:
                return IP, tup[0], float(tup[1])
        return IP, None, None

    def close(self):
        # type: () -> None
        if not self.closed:
            self.closed = True
            self.impl.close()

    def send(self, x):
        # type: (Packet) -> int
        """
        Send the packet using this socket.
        Should be a CoAP packet with IP and UDP data.

        Example:
        >>> IP(dst="192.168.1.1") / UDP(dport=1234) / CoAP()
        >>> IP(dst="192.168.1.1") / UDP(dport=1234) / CoAPSocket.make_coap_req_packet()

        :param x: Concatenated packet with IP / UDP / CoAP
        :return: The length of x, which is the amount of bytes sent
        """
        return self.impl.send(x)

    def sr(self, pkt, *args, **kargs):
        pkt[UDP].sport = self.impl.port
        return super(CoAPSocket, self).sr(pkt, *args, **kargs)

    def sr1(self, pkt, *args, **kargs):
        pkt[UDP].sport = self.impl.port
        return super(CoAPSocket, self).sr1(pkt, *args, **kargs)

    @staticmethod
    def select(sockets, remain=None):
        # type: (list[SuperSocket], Optional[float]) -> list[SuperSocket]
        """
        This function is called during sendrecv() routine to wait for
        sockets to be ready to receive.
        """
        obj_pipes = [x.impl.rx_queue for x in sockets if
                     isinstance(x, CoAPSocket) and not x.closed]

        ready_pipes = select_objects(obj_pipes, 0)

        return [x for x in sockets if isinstance(x, CoAPSocket) and
                not x.closed and x.impl.rx_queue in ready_pipes]

    @staticmethod
    def make_coap_req_packet(method=GET, uri="", options=None, payload=b""):
        # type: (int, str, list[tuple], bytes) -> Packet
        """
        Create a CoAP request packet

        :param method: The target method, one of: GET, POST, PUT, DELETE
        :param uri: The destination uri
        :param options: The options, should be a list of tuples.
                        You must specify here the payload type.
                        Example: options = [(CONTENT_FORMAT, CF_APP_XML)]
        :param payload: The payload to send, should be a byte array
        :return: The CoAP packet.
        """
        return CoAPSocketImpl.make_coap_req_packet(method, uri, options, payload)

    @staticmethod
    def make_coap_resp_packet(coap_type, code, token, message_id, options=None,
                              payload=b""):
        # type: (int, int, bytes, int, list[tuple], bytes) -> Packet
        """
        Create a CoAP response packet

        :param coap_type: Message type, one of: CON, NON, ACK, RST
        :param code: Response code, one of: EMPTY_ACK, CONTENT_205, NOT_FOUND_404,
                     NOT_ALLOWED_405, NOT_IMPLEMENTED_501
        :param token: The token from the request
        :param message_id: The message id from the request
        :param options: The options, should be a list of tuples.
                        You must specify here the payload type. If applicable.
                        Example: options = [(CONTENT_FORMAT, CF_APP_XML)]
        :param payload: The payload to send, should be a byte array.
        :return: The CoAP packet.
        """
        return CoAPSocketImpl.make_coap_resp_packet(coap_type, code, token, message_id,
                                                    options, payload)

    @staticmethod
    def empty_ack_params():
        # type: () -> dict
        """
        A dictionary containing the base parameters for the empty ACK response.
        Later, you should also add the request msg_id.

        :return: A dictionary containing the parameters necessary to build a
                 CoAP package for an empty ACK response.
        """
        # {"type": ACK, "code": EMPTY_MESSAGE, "tkl": 0, "token": b'', "options": []}
        return CoAPSocketImpl.empty_ack_params()

    @staticmethod
    def make_delayed_resp_packet(token, options, payload):
        # type: (int|bytes, list[tuple], bytes) -> Packet
        """
        This will create a CoAP packet that contains all the correct parameters
        for the delayed response.
        The msg_id is not necessary to be specified, it will be random generated.
        After all, this is similar to a new request.

        :param token: The original request token
        :param options: The options, should be a list of tuples.
                        You must specify here the payload type. If applicable.
                        Example: options = [(CONTENT_FORMAT, CF_APP_XML)]
        :param payload: The payload to send, should be a byte array.
        :return: The CoAP packet.
        """
        return CoAPSocketImpl.make_delayed_resp_packet(token, options, payload)


class CoAPResource:
    """
    User should implement this class if he wants an answering machine for the CoAPSocket

    :param url: the resource URL
    :param content_format: the default content format, this can be overridden by
                specifying the CF in the method's return value. RFC 7252 @ section-7.2.1
    :param title: A human-readable title for this resource. RFC 5988 @ section 5.4.
    :param description: One can think of this as describing verbs usable on a resource.
                        RFC 6690 @ section-3.1
    :param resource_type: One can think of this as a noun describing the resource.
                        RFC 6690 @ section-3.2
    """

    def __init__(self,
                 url,  # type: str
                 content_format=CF_TEXT_PLAIN,  # type: bytes
                 title="",  # type: str
                 description="",  # type: str
                 resource_type="",  # type: str
                 ):
        # type: (...) -> None
        self.url = url
        if self.url[0] != "/":
            self.url = "/" + self.url
        self.description = description  # if
        self.content_format = content_format  # ct
        self.resource_type = resource_type  # rt
        self.title = title  # title
        self._coap_socket = None
        self._duplication_dict = {}  # type: dict[str, tuple[dict, float]]

    def get_CORE_string(self):
        # type: () -> str
        """
        Will return a CORE formatted string as specified in
        RFC 6690 + RFC 7252 @ section-7.2.1
        """
        fmt_str = "<%s>;" % self.url
        if self.description:
            fmt_str += "if=\"%s\";" % self.description
        if self.resource_type:
            fmt_str += "rt=\"%s\";" % self.resource_type
        if self.title:
            fmt_str += "title=\"%s\"" % self.title
        fmt_str += "ct=%d" % int().from_bytes(self.content_format, "big")
        return fmt_str

    def get(self, payload, options, token, sa_ll):
        # type: (bytes, list[tuple], int, tuple[str, int]) -> dict

        """
        Implementation of the get method for this resource.
        User should return a dictionary containing, at least these keys:

        - type: one of the CoAP message type
        - code: one of the CoAP message response codes (RFC 7252 @ section-12.1.2)
        - options: a list of tuples with the options for the response
                   (RFC 7252 @ section-5.10).
                   Should have at least the pair CONTENT_FORMAT
        - payload: optional, byte encoded payload
        - token: the request token, in case you need to implement a delayed message
        - sa_ll: the sender ip/port pair,
                 in case you need to implement a delayed message

        RFC 7252 @ section-5.8.1
        """
        return {"type": ACK, "code": NOT_ALLOWED_405,
                "options": [(CONTENT_FORMAT, CF_TEXT_PLAIN)],
                "payload": coap_codes[NOT_ALLOWED_405].encode("utf8")}

    def put(self, payload, options, token, sa_ll):
        # type: (bytes, list[tuple], int, tuple[str, int]) -> dict

        """
        Implementation of the put method for this resource.
        User should return a dictionary containing, at least these keys:

        - type: one of the CoAP message type
        - code: one of the CoAP message response codes (RFC 7252 @ section-12.1.2)
        - options: a list of tuples with the options for the response
                    (RFC 7252 @ section-5.10).
                    Should have at least the pair CONTENT_FORMAT
        - payload: optional, byte encoded payload
        - token: the request token, in case you need to implement a delayed message
        - sa_ll: the sender ip/port pair,
                 in case you need to implement a delayed message

        RFC 7252 @ section-5.8.3
        """
        return {"type": ACK, "code": NOT_ALLOWED_405,
                "options": [(CONTENT_FORMAT, CF_TEXT_PLAIN)],
                "payload": coap_codes[NOT_ALLOWED_405].encode("utf8")}

    def check_duplicated(self, message_id, token):
        # type: (int, int) -> bool
        """Returns true if (message_id, token) duplicated."""
        return (message_id, token) in self._duplication_dict.keys()

    def _set_coap_socket(self, coap_socket):
        # type: (CoAPSocketImpl) -> None
        """Will set the CoAP socket internally, this will be called by CoAPSocketImpl"""
        self._coap_socket = coap_socket

    def _register_request_response(self, message_id, token, response):
        # type: (int, int, dict) -> None
        """Registers a response in case it get lost"""
        if (message_id, token) not in self._duplication_dict.keys():
            self._duplication_dict[(message_id, token)] = (response, time.monotonic())

    def _get_response(self, message_id, token):
        # type: (int, int) -> dict
        """Returns the already sent message"""
        return self._duplication_dict[(message_id, token)][0]

    def _duplicates_cleanup(self, timeout):
        # type: (float) -> None
        """
        Will clean up the duplication dictionary if response timestamp
        + timeout is less than now
        """
        now = time.monotonic()
        deletion_list = [key for key, value in self._duplication_dict.items() if
                         (value[1] + timeout) <= now]
        for key in deletion_list:
            log_coap_sock.debug("Removing response: MessageID=%s; Token=0x%x", key[0],
                                key[1])
            del self._duplication_dict[key]

    def _send_separate_response(self, pkt, sa_ll):
        # type: (CoAP, tuple[str, int]) -> None
        """
        Will create a separate response, that will be treated as a
        new request by the CoAPSocket.
        :param pkt: The built packet.
        :param sa_ll: The ip/port pair to the target machine.
        """
        request = CoAPSocketImpl.CoAPRequest(sa_ll[0], sa_ll[1],
                                             self._coap_socket.retries,
                                             self._coap_socket.ack_timeout,
                                             pkt)
        self._coap_socket.tx_queue.send(request)


class CoAPSocketImpl:
    """
    Implementation of a CoAP socket with client and server capabilities.

    :param ip: ip address to bind udp socket to.
    :param port: port to bind udp socket to.
    :param ack_timeout: the time, in ms, that we should wait for the acknowledgment
                        after sending a request.
    :param retries: amount of retransmissions before giving up on the request.
    :param duplication_response_timeout: Timeout, in fractions of seconds,
                            that we will keep the response in case a response get lost.
    :param lst_resources: optional, list of registered resources.
    :param sock: optional, a socket instance to transmit,
                 if None, a classic UDP socket will be open and bound to ip/port.
    :param close_on_timeout: Will try to close the socket if the retries is exceeded
    """

    def __init__(self,
                 ip="",  # type: str
                 port=5683,  # type: int
                 ack_timeout=500,  # type: int
                 retries=3,  # type: int
                 duplication_response_timeout=1.00,  # type: float
                 lst_resources=None,  # type: Optional[None, list["CoAPResource"]]
                 sock=None,  # type: Optional[None, SuperSocket, any]
                 close_on_timeout=False  # type: bool
                 ):
        # type: (...) -> None

        self.ip = ip
        self.port = port
        self.ack_timeout = ack_timeout
        self.duplication_response_timeout = duplication_response_timeout
        self.retries = retries
        self.close_on_timeout = close_on_timeout

        # For development: set this to True, so it will drop rx/tx packages on purpose,
        # this way it is possible to test the retransmission mechanism
        self._enable_debug = False
        self._debug_drop_package_number = 1  # Will drop the first received package
        self._debug_drop_package_counter = 0

        if lst_resources is not None:
            self.resources = {}  # type: dict[str, CoAPResource]
            for res in lst_resources:
                if res.url not in self.resources.keys():
                    self.resources[res.url] = res
                    res._set_coap_socket(self)
                else:
                    log_coap_sock.error(
                        "Duplicated URL for different resources:\nURL=%s", res.url)

            # Only creates the well-known resource if we have some answering machine
            self.resources["/.well-known/core"] = CoAPSocketImpl.WellKnownResource(
                lst_resources)
        else:
            self.resources = None

        if sock is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind((self.ip, self.port))
            self.sock = SimpleSocket(s)
        else:
            self.sock = SimpleSocket(sock)

        self.poll_rate = 0.005
        self.closed = False

        self.rx_queue = ObjectPipe[Tuple[bytes, Union[float, EDecimal]]]()
        self.tx_queue = ObjectPipe[CoAPSocketImpl.CoAPRequest]()

        self.rx_handle = TimeoutScheduler.schedule(self.poll_rate, self._recv)
        self.tx_handle = TimeoutScheduler.schedule(self.poll_rate, self._send)

        # type: dict[tuple[int,int], CoAPSocketImpl.CoAPRequest]
        self.pending_requests = {}

    def __del__(self):
        self.close()

    def recv(self, timeout=None):
        # type: (Optional[int]) -> Optional[Tuple[bytes, Union[float, EDecimal]]]
        return self.rx_queue.recv(timeout)

    def send(self, x):
        # type: (CoAP) -> int
        self.tx_queue.send(
            CoAPSocketImpl.CoAPRequest(x.dst, x.dport, self.retries, self.ack_timeout,
                                       x[CoAP]))
        return len(x)

    def close(self):
        # type: () -> None
        try:
            if select_objects([self.tx_queue], 0):
                log_coap_sock.warning("TX queue not empty")
                time.sleep(0.1)
        except OSError:
            pass

        try:
            if select_objects([self.rx_queue], 0):
                log_coap_sock.warning("RX queue not empty")
        except OSError:
            pass

        self.closed = True
        try:
            self.sock.close()
        except Scapy_Exception:
            pass
        try:
            self.rx_handle.cancel()
        except Scapy_Exception:
            pass
        try:
            self.tx_handle.cancel()
        except Scapy_Exception:
            pass

    @staticmethod
    def make_coap_req_packet(method=GET, uri="", options=None, payload=b""):
        # type: (int, str, Optional[list[tuple]], bytes) -> Packet
        """Check CoAPSocket for the documentation"""

        # Parse the uri as options
        if uri[0] == "/":
            uri = uri[1:]
        parsed_opt = [(URI_PATH, x) for x in uri.split("/")]

        if options is not None:
            parsed_opt.extend(options)

        msg_id, token = CoAPSocketImpl.generate_msgId_token()
        coap_packet = CoAP(type=CON, code=method, options=parsed_opt, msg_id=msg_id,
                           tkl=len(token), token=token)
        if payload:
            coap_packet.paymark = PAYMARK
            coap_packet.add_payload(payload)

        return coap_packet

    @staticmethod
    def make_coap_resp_packet(coap_type, code, token, message_id, options, payload):
        # type: (int, int, bytes, int, list[tuple], bytes) -> Packet
        """Check CoAPSocket for the documentation"""
        pkt_params = {
            "type": coap_type, "code": code, "options": options, "msg_id": message_id,
            "tkl": len(token), "token": token
        }
        if payload != b'':
            pkt_params["paymark"] = PAYMARK

        pkt = CoAP(**pkt_params)

        if payload != b'':
            pkt.add_payload(payload)
        return pkt

    @staticmethod
    def empty_ack_params():
        # type: () -> dict
        return {"type": ACK, "code": EMPTY_MESSAGE, "tkl": 0, "token": b'',
                "options": []}

    @staticmethod
    def make_delayed_resp_packet(token, options, payload):
        # type: (int|bytes, list[tuple], bytes) -> Packet
        """Check CoAPSocket for the documentation"""
        t = token
        if isinstance(token, int):
            t = token.to_bytes((token.bit_length() + 7) // 8, 'big')
        return CoAPSocketImpl.make_coap_resp_packet(CON, CONTENT_205, t,
                                                    random.randint(0, 0xffff),
                                                    options, payload)

    @staticmethod
    def generate_msgId_token():
        # type: () -> tuple[int, bytes]
        """
        Will generate a pair of (msgId, token) with message
        id in the range of [0, 0xffff] and a random token with size from 1 to 8 bytes
        :return: msgId and token tuple
        """

        def _randbytes():
            return bytes([random.randint(1, 255)
                          for _ in range(random.randint(1, 8))])

        return random.randint(0, 0xffff), _randbytes()

    def fileno(self):
        return self.sock.fileno()

    def _recv(self):
        # type: () -> None
        """
        Method called periodically to poll the real socket for messages.
        Also, this method will do periodic cleanups in the resources.
        """
        # Do a cleanup in the resources
        if self.resources is not None:
            for _, resource in self.resources.items():
                resource._duplicates_cleanup(self.duplication_response_timeout)

        if self.sock.select([self.sock], 0):
            pkt, sa_ll = self.sock.ins.recvfrom(MTU)
            pkt = (IP(src=sa_ll[0], dst=self.ip) /
                   UDP(sport=sa_ll[1], dport=self.port) /
                   CoAP(bytes(pkt)))
            if pkt:
                if not self._debug_drop_package():
                    self._on_pkt_recv(pkt, sa_ll)
                    self._debug_drop_package_counter = 0
                else:
                    self._debug_drop_package_counter += 1

        if not self.closed and not self.sock.closed:
            if self.sock.select([self.sock], 0):
                poll_time = 0.0
            else:
                poll_time = self.poll_rate
            self.rx_handle = TimeoutScheduler.schedule(poll_time, self._recv)
        else:
            try:
                self.rx_handle.cancel()
            except Scapy_Exception:
                pass

    def _on_pkt_recv(self, pkt, sa_ll):
        # type: (CoAP, tuple[str, int]) -> None
        """Handles a received package"""
        # Request codes
        if pkt.code in COAP_REQ_CODES:
            if self.resources is None:
                # No answering machine registered, user will handle it individually
                self.rx_queue.send((pkt.build(), pkt.time))
            else:
                self._handle_rcv_request(pkt, sa_ll)
        else:
            # Response, check pending requests and process internally
            self._handle_request_response(pkt, sa_ll)

    def _post(self):
        # type: () -> dict
        """
        Creates a new resource.
        @todo: handle resource POST: RFC 7252 @ section-5.8.2
        """
        return {"type": ACK, "code": NOT_ALLOWED_405,
                "options": [(CONTENT_FORMAT, CF_TEXT_PLAIN)],
                "payload": coap_codes[NOT_ALLOWED_405].encode("utf8")}

    def _delete(self, resource):
        # type: (CoAPResource) -> dict
        """
        Will remove resource from the server.
        @todo: handle resource DELETE: RFC 7252 @ section-5.8.4
        """
        return {"type": ACK, "code": NOT_ALLOWED_405,
                "options": [(CONTENT_FORMAT, CF_TEXT_PLAIN)],
                "payload": coap_codes[NOT_ALLOWED_405].encode("utf8")}

    def _handle_rcv_request(self, pkt, sa_ll):
        # type: (CoAP, tuple[str, int]) -> None
        """Process a received request"""
        coap_pkt = pkt[CoAP]
        req_uri = "/"
        token = int.from_bytes(coap_pkt.token, "big")  # Can be up to 8 bytes
        message_id = coap_pkt.msg_id
        lst_options = []
        response = {"type": ACK, "code": NOT_FOUND_404,
                    "options": [(CONTENT_FORMAT, CF_TEXT_PLAIN)],
                    "payload": coap_codes[NOT_FOUND_404].encode("utf8")}

        for option in coap_pkt.options:
            option_type_id = coap_options[1].get(option[0], -1)
            option_value = option[1]

            if option_type_id == -1:
                log_coap_sock.warning("Invalid option ID, ignoring: "
                                      "ID=%s; Value=%s;",
                                      option[0], option[1])
            elif option_type_id == URI_PATH:
                req_uri += option_value.decode("ascii").casefold()
                req_uri += "/"
            else:
                lst_options.append(option)

        # Special case: if we are requesting the root resource
        if req_uri != "/":
            req_uri = req_uri[:-1]  # remove the extra "/" in the end

        resource = self.resources.get(req_uri, None)
        if resource is not None:
            if not resource.check_duplicated(message_id, token):
                if coap_pkt.code == GET:
                    response = resource.get(coap_pkt.payload, lst_options, token, sa_ll)
                elif coap_pkt.code == POST:
                    # @todo: handle existing resource POST: RFC 7252 @ section-5.8.2
                    pass
                elif coap_pkt.code == PUT:
                    response = resource.put(coap_pkt.payload, lst_options, token, sa_ll)
                elif coap_pkt.code == DELETE:
                    response = self._delete(resource)

                resource._register_request_response(message_id, token, response)
            else:
                response = resource._get_response(message_id, token)
                log_coap_sock.debug(
                    "Received duplicated request: "
                    "URI=%s; MessageID=%s; Token=0x%x",
                    req_uri,
                    message_id, token)
        else:
            if coap_pkt.code == POST:
                response = self._post()
            else:
                log_coap_sock.warning("Unknown resource: URI=%s", req_uri)

        response["tkl"] = coap_pkt.tkl
        response["token"] = coap_pkt.token
        response["msg_id"] = message_id

        if coap_pkt.type == NON:
            response["type"] = NON

        # Add paymark (separator between options and payload)
        if "paymark" not in response.keys():
            response["paymark"] = PAYMARK

        # Remove useless fields for the empty ACK
        if response["code"] == EMPTY_MESSAGE and response["type"] == ACK:
            response["tkl"] = 0
            response["token"] = b""
            response.pop("paymark", None)

        # Assign payload to packet
        pl = response.pop("payload", None)
        p = CoAP(**response)
        if pl is not None:
            p.add_payload(pl)

        self._sock_send(sa_ll, p)

    def _start_new_client_request(self, request):
        # type: (CoAPSocketImpl.CoAPRequest) -> None
        """
        Starts a new client interaction. This function is meant to be called internally.
        :param request: a CoAPRequest instance.
        """
        if request.indexing() not in self.pending_requests:
            log_coap_sock.debug("New client request: msg_id=%s; token=0x%x",
                                request.message_id, request.token)
            self.pending_requests[request.indexing()] = request
            self._sock_send((request.ip, request.port), request.get_pkt_and_mark())
        else:
            log_coap_sock.warning(
                "Duplicated request, will not be sent: msg_id=%s; token=0x%x",
                request.message_id,
                request.token)

    def _handle_pending_client_request(self, request):
        # type: (CoAPSocketImpl.CoAPRequest) -> bool
        """
        Will check the pending request and trigger a retransmission or deletion
        of the request.
        :param request:  a CoAPRequest instance.
        :return: Will return True if we should delete the request instance.
        """
        result = False
        if request.should_give_up():
            if not request.empty_ack_fulfilled:  # To avoid misleading logs
                log_coap_sock.warning(
                    "Expired number of retries, giving up: msg_id=%s; token=0x%x",
                    request.message_id,
                    request.token)
            result = True
        elif request.should_resend():
            self._sock_send((request.ip, request.port), request.get_pkt_and_mark())

        return result

    def _handle_request_response(self, pkt, sa_ll):
        # type: (CoAP, tuple[str, int]) -> None
        """
        Handles a received response. Will check if there is the valid request.
        Otherwise, it will put in the rx_queue for the user to handle it
        via the recv() function.
        :param coap_pkt: The CoAP packet to be processed
        :param sa_ll: The ip/port tuple of the sender
        """
        coap_pkt = pkt[CoAP]
        token = int.from_bytes(coap_pkt.token, "big")
        index = (coap_pkt.msg_id, token)
        request = self.pending_requests.get(index, None)
        if (request is None and
                (coap_pkt.type == ACK or coap_pkt.type == CON or coap_pkt.type == NON)):
            for key in self.pending_requests.keys():
                if index[0] == key[0] or index[1] == key[1]:
                    log_coap_sock.info("Found request by using %s",
                                       "token" if index[1] == key[1]
                                       else "message_id")
                    request = self.pending_requests[key]
                    index = key
                    break

        if request is None:
            log_coap_sock.warning(
                "Request for received response not found: msg_id=%s; token=0x%x",
                coap_pkt.msg_id, token)
            return

        if coap_pkt.type == ACK and coap_pkt.code != EMPTY_MESSAGE:
            log_coap_sock.debug("Request fulfilled: msg_id=%s; token=0x%x; code=%s",
                                index[0], index[1],
                                coap_codes[coap_pkt.code])
            pkt.sport = self.pending_requests[index].port
            del self.pending_requests[index]
            self.rx_queue.send((pkt.build(), coap_pkt.time))
        elif coap_pkt.type == ACK and coap_pkt.code == EMPTY_MESSAGE:
            log_coap_sock.debug(
                "Server sent an empty ack, request will be fulfilled later: "
                "msg_id=%s; token=0x%x; code=%s",
                index[0], index[1], coap_codes[coap_pkt.code])
            request.empty_ack_set()
        elif coap_pkt.type == CON and coap_pkt.code == CONTENT_205:
            log_coap_sock.debug(
                "Received a delayed content for a previous request: msg_id=%s; "
                "token=0x%x; code=%s",
                index[0], index[1], coap_codes[coap_pkt.code])

            # We need to respond with an empty ACK
            request.empty_ack_fulfilled = True
            response = CoAPSocketImpl.empty_ack_params()
            response["msg_id"] = coap_pkt.msg_id
            self._sock_send(sa_ll, CoAP(**response))
            pkt.sport = request.port
            self.rx_queue.send((pkt.build(), coap_pkt.time))
        else:
            log_coap_sock.info("Not handled message: "
                               "type=%s; code=%s;",
                               coap_pkt.type, coap_codes[coap_pkt.code])
            self.rx_queue.send((pkt.build(), coap_pkt.time))

    def _sock_send(self, address, pl):
        # type: (tuple[str, int], Packet) -> None
        self.sock.outs.sendto(pl.build(), address)

    def _send(self):
        # type: () -> None
        """
        Periodically checks the pending requests for either retransmitting or removing,
        depends on the result of _handle_pending_client_request().
        """
        lst_remove = []
        for key, request in self.pending_requests.items():
            if self._handle_pending_client_request(request):
                lst_remove.append(key)

        for key in lst_remove:
            del self.pending_requests[key]

        if select_objects([self.tx_queue], 0):
            request = self.tx_queue.recv()
            if request:
                self._start_new_client_request(request)

        if self.close_on_timeout and len(self.pending_requests) == 0:
            self.close()

        if not self.closed:
            self.tx_handle = TimeoutScheduler.schedule(self.poll_rate, self._send)
        else:
            try:
                self.tx_handle.cancel()
            except Scapy_Exception:
                pass

    def _debug_drop_package(self):
        # type: () -> bool
        """
        Debug function where it will return if we should drop the
        package to test the retransmission mechanism
        """
        return (self._enable_debug and
                self._debug_drop_package_counter < self._debug_drop_package_number)

    class WellKnownResource(CoAPResource):
        """
        This is a default resource that will return information about all the registered
        resources in the server.
        Described at RFC 7252 @ section 7.2 and RFC 6690

        :param lst_resources: List of CoAPResource.
        """

        def __init__(self,
                     lst_resources  # type: list[CoAPResource]
                     ):
            # type: (...) -> None
            CoAPResource.__init__(self, url=".well-known/core",
                                  content_format=CF_APP_LINK_FORMAT)
            self.lst_resources = lst_resources

        def get(self, payload, options, token, sa_ll):
            # type: (bytes, list[tuple], int, tuple[str, int]) -> dict
            str_resources = ",".join([x.get_CORE_string() for x in self.lst_resources])
            return {"type": ACK, "code": CONTENT_205,
                    "options": [(CONTENT_FORMAT, CF_APP_LINK_FORMAT)],
                    "payload": str_resources.encode("ascii")}

    class CoAPRequest:
        """
        Class to control a client request.

        :param ip: The remote server's ip address.
        :param port: The remote server's port.
        :param max_retries: Number of retransmissions before giving up.
        :param retry_timeout: ACK timeout for retransmission.
        :param pkt: The CoAP package to be sent.
        """

        def __init__(self,
                     ip,  # type: str
                     port,  # type: int
                     max_retries,  # type: int
                     retry_timeout,  # type: float
                     pkt,  # type: CoAP
                     resource=None  # type: Optional[CoAPResource]
                     ):
            # type: (...) -> None
            self.ip = ip
            self.port = port
            self.package = pkt

            self.message_id = pkt.msg_id
            self.token = int.from_bytes(pkt.token, "big")

            self.tries = 0
            self.max_retries = max_retries
            self.last_try_timestamp = 0.0
            self.base_retry_timeout = retry_timeout
            self.retry_timeout = self.base_retry_timeout

            # Set this flag if an empty ack was received
            self.received_empty_ack = False
            self.empty_ack_timeout = 0
            self.empty_ack_fulfilled = False
            self.resource = resource

        def get_pkt_and_mark(self):
            # type: () -> Packet
            """
            Returns the already sent packet for retransmission and sets
            a new timeout for retry.
            :return: A CoAP packet for retransmission.
            """
            self.tries += 1
            self.last_try_timestamp = time.monotonic()
            self.retry_timeout = self.base_retry_timeout * self.tries

            # Clear the empty ack flags
            self.empty_ack_timeout = 0
            self.received_empty_ack = False

            return self.package

        def should_give_up(self):
            # type: () -> bool
            """
            Checks if we should give up on retransmission of this request.
            :return: True if we should give up.
            """
            return self.tries > self.max_retries

        def should_resend(self):
            # type: () -> bool
            """
            Checks if it is time to resend this request.
            :return: True if we should resend.
            """
            if self.received_empty_ack:
                return ((self.last_try_timestamp + self.retry_timeout) <=
                        time.monotonic())
            else:
                if self.empty_ack_fulfilled:
                    # This way, eventually, this request will be removed by the timer.
                    # It is to avoid late retransmissions.
                    self.tries += 1
                return ((not self.empty_ack_fulfilled) and
                        self.empty_ack_timeout <= time.monotonic())

        def indexing(self):
            # type: () -> tuple[int, int]
            """
            Returns the indexing of this request.
            :return: A tuple containing the message_id and token of this request.
            """
            return self.message_id, self.token

        def empty_ack_set(self):
            # type: () -> None
            """
            Set the empty ack flag and will set the timeout.
            After the timeout, it will resend the request until should_give_up()
            is triggered.
            """
            self.tries = 0
            self.received_empty_ack = True
            self.empty_ack_timeout = time.monotonic() + 15
