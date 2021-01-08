#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Helper class for tracking ECU states (ECU)
# scapy.contrib.status = loads

import time
import random

from collections import defaultdict

from scapy.packet import Raw, Packet
from scapy.plist import PacketList
from scapy.error import Scapy_Exception
from scapy.sessions import DefaultSession
from scapy.ansmachine import AnsweringMachine
from scapy.config import conf

__all__ = ["ECU_State", "ECU", "ECUResponse", "ECUSession", "ECU_am"]


class ECU_State(object):
    def __init__(self, session=1, tester_present=False, security_level=0,
                 communication_control=0, **kwargs):
        self.session = session
        self.security_level = security_level
        self.communication_control = communication_control
        self._tp = tester_present
        self.misc = kwargs

    def reset(self):
        self.session = 1
        self.security_level = 0
        self.communication_control = 0
        self._tp = False
        self.misc = dict()

    @property
    def tp(self):
        return self._tp or self.session > 1

    def __eq__(self, other):
        return other.session == self.session and other.tp == self.tp and \
            other.misc == self.misc and \
            self.security_level == other.security_level

    def __ne__(self, other):
        return not other == self

    def __lt__(self, other):
        if self.session == other.session:
            return len(self.misc) < len(other.misc)
        return self.session < other.session

    def __hash__(self):
        return hash(repr(self))

    def __repr__(self):
        tps = "_TP" if self.tp else ""
        sl = "_SL%d" % self.security_level if self.security_level else ""
        ks = "_" + "_".join(self.misc.keys()) if len(self.misc) else ""
        return "%d%s%s%s" % (self.session, tps, sl, ks)


class ECU(object):
    """A ECU object can be used to
            - track the states of an ECU.
            - to log all modification to an ECU
            - to extract supported responses of a real ECU

           Usage:
           >>> print("This ecu logs, tracks and creates supported responses")
           >>> my_virtual_ecu = ECU()
           >>> my_virtual_ecu.update(PacketList([...]))
           >>> my_virtual_ecu.supported_responses
           >>> print("Another ecu just tracks")
           >>> my_tracking_ecu = ECU(logging=False, store_supported_responses=False)  # noqa: E501
           >>> my_tracking_ecu.update(PacketList([...]))
           >>> print("Another ecu just logs all modifications to it")
           >>> my_logging_ecu = ECU(verbose=False, store_supported_responses=False)  # noqa: E501
           >>> my_logging_ecu.update(PacketList([...]))
           >>> my_logging_ecu.log
           >>> print("Another ecu just creates supported responses")
           >>> my_response_ecu = ECU(verbose=False, logging=False)
           >>> my_response_ecu.update(PacketList([...]))
           >>> my_response_ecu.supported_responses
       """
    def __init__(self, init_session=None, init_security_level=None,
                 init_communication_control=None, logging=True, verbose=True,
                 store_supported_responses=True):
        """
        Initialize an ECU object

        :param init_session: An initial session
        :param init_security_level: An initial security level
        :param init_communication_control: An initial communication control
                                           setting
        :param logging: Turn logging on or off. Default is on.
        :param verbose: Turn tracking on or off. Default is on.
        :param store_supported_responses: Turn creation of supported responses
                                          on or off. Default is on.
        """
        self.state = ECU_State(
            session=init_session or 1, security_level=init_security_level or 0,
            communication_control=init_communication_control or 0)
        self.verbose = verbose
        self.logging = logging
        self.store_supported_responses = store_supported_responses
        self.log = defaultdict(list)
        self._supported_responses = list()
        self._unanswered_packets = PacketList()

    @property
    def current_session(self):
        return self.state.session

    @current_session.setter
    def current_session(self, ses):
        self.state.session = ses

    @property
    def current_security_level(self):
        return self.state.security_level

    @current_security_level.setter
    def current_security_level(self, sec):
        self.state.security_level = sec

    @property
    def communication_control(self):
        return self.state.communication_control

    @communication_control.setter
    def communication_control(self, cc):
        self.state.communication_control = cc

    def reset(self):
        self.state.reset()

    def update(self, p):
        if isinstance(p, PacketList):
            for pkt in p:
                self._update(pkt)
        elif not isinstance(p, Packet):
            raise Scapy_Exception("Provide a Packet object for an update")
        else:
            self._update(p)

    def _update(self, pkt):
        if self.verbose:
            print(repr(self), repr(pkt))
        if self.store_supported_responses:
            self._update_supported_responses(pkt)
        if self.logging:
            self._update_log(pkt)
        self._update_internal_state(pkt)

    def _update_log(self, pkt):
        for layer in pkt.layers():
            if hasattr(layer, "get_log"):
                log_key, log_value = layer.get_log(pkt)
                self.log[log_key].append((pkt.time, log_value))

    def _update_internal_state(self, pkt):
        for layer in pkt.layers():
            if hasattr(layer, "modifies_ecu_state"):
                layer.modifies_ecu_state(pkt, self)

    def _update_supported_responses(self, pkt):
        self._unanswered_packets += PacketList([pkt])
        answered, unanswered = self._unanswered_packets.sr()
        for _, resp in answered:
            ecu_resp = ECUResponse(session=self.current_session,
                                   security_level=self.current_security_level,
                                   responses=resp)

            if ecu_resp not in self._supported_responses:
                if self.verbose:
                    print("[+] ", repr(ecu_resp))
                self._supported_responses.append(ecu_resp)
            else:
                if self.verbose:
                    print("[-] ", repr(ecu_resp))
        self._unanswered_packets = unanswered

    @property
    def supported_responses(self):
        # This sorts responses in the following order:
        # 1. Positive responses first
        # 2. Lower ServiceID first
        # 3. Longer (more specific) responses first
        self._supported_responses.sort(
            key=lambda x: (x.responses[0].service == 0x7f,
                           x.responses[0].service,
                           0xffffffff - len(x.responses[0])))
        return self._supported_responses

    @property
    def unanswered_packets(self):
        return self._unanswered_packets

    def __repr__(self):
        return "ses: %03d  sec: %03d  cc: %d" % (self.current_session,
                                                 self.current_security_level,
                                                 self.communication_control)


class ECUSession(DefaultSession):
    """Tracks modification to an ECU 'on-the-flow'.

    Usage:
    >>> sniff(session=ECUSession)
    """

    def __init__(self, *args, **kwargs):
        DefaultSession.__init__(self, *args, **kwargs)
        self.ecu = ECU(init_session=kwargs.pop("init_session", None),
                       init_security_level=kwargs.pop("init_security_level", None),  # noqa: E501
                       init_communication_control=kwargs.pop("init_communication_control", None),  # noqa: E501
                       logging=kwargs.pop("logging", True),
                       verbose=kwargs.pop("verbose", True),
                       store_supported_responses=kwargs.pop("store_supported_responses", True))  # noqa: E501

    def on_packet_received(self, pkt):
        if not pkt:
            return
        if isinstance(pkt, list):
            for p in pkt:
                ECUSession.on_packet_received(self, p)
            return
        self.ecu.update(pkt)
        DefaultSession.on_packet_received(self, pkt)


class ECUResponse:
    """Encapsulates a response and the according ECU state.
    A list of this objects can be used to configure a ECU Answering Machine.
    This is useful, if you want to clone the behaviour of a real ECU on a bus.

        Usage:
        >>> print("Generates a ECUResponse which answers on UDS()/UDS_RDBI(identifiers=[2]) if ECU is in session 2 and has security_level 2")  # noqa: E501
        >>> ECUResponse(session=2,                     security_level=2,                responses=UDS()/UDS_RDBIPR(dataIdentifier=2)/Raw(b"deadbeef1"))  # noqa: E501
        >>> print("Further examples")
        >>> ECUResponse(session=range(3,5),            security_level=[3,4],            responses=UDS()/UDS_RDBIPR(dataIdentifier=3)/Raw(b"deadbeef2"))  # noqa: E501
        >>> ECUResponse(session=[5,6,7],               security_level=range(5,7),       responses=UDS()/UDS_RDBIPR(dataIdentifier=5)/Raw(b"deadbeef3"))  # noqa: E501
        >>> ECUResponse(session=lambda x: 8 < x <= 10, security_level=lambda x: x > 10, responses=UDS()/UDS_RDBIPR(dataIdentifier=9)/Raw(b"deadbeef4"))  # noqa: E501
    """
    def __init__(self, session=1, security_level=0,
                 responses=Raw(b"\x7f\x10"),
                 answers=None):
        """
        Initialize an ECUResponse capsule

        :param session: Defines the session in which this response is valid.
                        A integer, a callable or any iterable object can be
                        provided.
        :param security_level: Defines the security_level in which this
                               response is valid. A integer, a callable or any
                               iterable object can be provided.
        :param responses: A Packet or a list of Packet objects. By default the
                          last packet is asked if it answers a incoming packet.
                          This allows to send for example
                          `requestCorrectlyReceived-ResponsePending` packets.
        :param answers: Optional argument to provide a custom answer here:
                        `lambda resp, req: return resp.answers(req)`
                        This allows the modification of a response depending
                        on a request. Custom SecurityAccess mechanisms can
                        be implemented in this way or generic NegativeResponse
                        messages which answers to everything can be realized
                        in this way.
        """
        self.__session = session \
            if hasattr(session, "__iter__") or callable(session) else [session]
        self.__security_level = security_level \
            if hasattr(security_level, "__iter__") or callable(security_level)\
            else [security_level]
        if isinstance(responses, PacketList):
            self.responses = responses
        elif isinstance(responses, Packet):
            self.responses = PacketList([responses])
        elif hasattr(responses, "__iter__"):
            self.responses = PacketList(responses)
        else:
            self.responses = PacketList([responses])

        self.__custom_answers = answers

    def in_correct_session(self, current_session):
        if callable(self.__session):
            return self.__session(current_session)
        else:
            return current_session in self.__session

    def has_security_access(self, current_security_level):
        if callable(self.__security_level):
            return self.__security_level(current_security_level)
        else:
            return current_security_level in self.__security_level

    def answers(self, other):
        if self.__custom_answers is not None:
            return self.__custom_answers(self.responses[-1], other)
        else:
            return self.responses[-1].answers(other)

    def __repr__(self):
        return "session=%s, security_level=%s, responses=%s" % \
               (self.__session, self.__security_level,
                [resp.summary() for resp in self.responses])

    def __eq__(self, other):
        return \
            self.__class__ == other.__class__ and \
            self.__session == other.__session and \
            self.__security_level == other.__security_level and \
            len(self.responses) == len(other.responses) and \
            all(bytes(x) == bytes(y) for x, y in zip(self.responses,
                                                     other.responses))

    def __ne__(self, other):
        # Python 2.7 compat
        return not self == other

    __hash__ = None


conf.contribs['ECU_am'] = {'send_delay': 0}


class ECU_am(AnsweringMachine):
    """AnsweringMachine which emulates the basic behaviour of a real world ECU.
    Provide a list of ``ECUResponse`` objects to configure the behaviour of this
    AnsweringMachine.

        :param supported_responses: List of ``ECUResponse`` objects to define
                                    the behaviour. The default response is
                                    ``generalReject``.
        :param main_socket: Defines the object of the socket to send
                            and receive packets.
        :param broadcast_socket: Defines the object of the broadcast socket.
                                 Listen-only, responds with the main_socket.
                                 `None` to disable broadcast capabilities.
        :param basecls: Provide a basecls of the used protocol

           Usage:
           >>> resp = ECUResponse(session=range(0,255), security_level=0, responses=UDS() / UDS_NR(negativeResponseCode=0x7f, requestServiceId=0x10))  # noqa: E501
           >>> sock = ISOTPSocket(can_iface, sid=0x700, did=0x600, basecls=UDS)  # noqa: E501
           >>> answering_machine = ECU_am(supported_responses=[resp], main_socket=sock, basecls=UDS)  # noqa: E501
           >>> sim = threading.Thread(target=answering_machine, kwargs={'count': 4, 'timeout':5})  # noqa: E501
           >>> sim.start()
       """
    function_name = "ECU_am"
    sniff_options_list = ["store", "opened_socket", "count", "filter", "prn", "stop_filter", "timeout"]  # noqa: E501

    def parse_options(self, supported_responses=None,
                      main_socket=None, broadcast_socket=None, basecls=Raw,
                      timeout=None):
        self.main_socket = main_socket
        self.sockets = [self.main_socket]

        if broadcast_socket is not None:
            self.sockets.append(broadcast_socket)

        self.ecu_state = ECU(logging=False, verbose=False,
                             store_supported_responses=False)
        self.basecls = basecls
        self.supported_responses = supported_responses

        self.sniff_options["timeout"] = timeout
        self.sniff_options["opened_socket"] = self.sockets

    def is_request(self, req):
        return req.__class__ == self.basecls

    def print_reply(self, req, reply):
        print("%s ==> %s" % (req.summary(), [res.summary() for res in reply]))

    def make_reply(self, req):
        if self.supported_responses is not None:
            for resp in self.supported_responses:
                if not isinstance(resp, ECUResponse):
                    raise Scapy_Exception("Unsupported type for response. "
                                          "Please use `ECUResponse` objects. ")

                if not resp.in_correct_session(self.ecu_state.current_session):
                    continue

                if not resp.has_security_access(
                        self.ecu_state.current_security_level):
                    continue

                if not resp.answers(req):
                    continue

                for r in resp.responses:
                    for layer in r.layers():
                        if hasattr(layer, "modifies_ecu_state"):
                            layer.modifies_ecu_state(r, self.ecu_state)

                return resp.responses

        return PacketList([self.basecls(b"\x7f" + bytes(req)[0:1] + b"\x10")])

    def send_reply(self, reply):
        for p in reply:
            time.sleep(conf.contribs['ECU_am']['send_delay'])
            if len(reply) > 1:
                time.sleep(random.uniform(0.01, 0.5))
            self.main_socket.send(p)
