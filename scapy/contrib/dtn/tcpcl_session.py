# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = TCP Convergence Layer version 4 (TCPCLv4)
# scapy.contrib.status = loads

# These classes support unit testing of the TCPCL scapy layer
# (scapy.contrib.dtn.tcpcl) and illustrate how the protocol messages may
# be used to emulate a TCPCL session.

from scapy.all import Raw, raw, TCP, Packet, bind_layers, split_layers
import scapy.contrib.dtn.tcpcl as TCPCL
from typing import List


class Session:
    """
    TCPCL messages are conventionally, but not necessarily, sent on port 4556.
    Since this cannot be relied upon, especially on a localhost session, the best
    way to bind TCP packets to TCPCL message is to track the state of a TCPCL session.
    Once Contact Headers are successfully exchanged, TCP packets can be assumed to
    carry payloads of TCPCL messages until the session ends.
    """

    def __init__(self):
        self.contact_init = False
        self.contact_ack = False
        self.is_active = False
        self.term_begun = False
        self.sport = 0
        self.dport = 0

    @staticmethod
    def bind_messages(sport, dport):
        bind_layers(TCP, TCPCL.MsgHeader, sport=sport, dport=dport)
        bind_layers(TCP, TCPCL.MsgHeader, sport=dport, dport=sport)

    @staticmethod
    def split_messages(sport, dport):
        split_layers(TCP, TCPCL.MsgHeader, sport=sport, dport=dport)
        split_layers(TCP, TCPCL.MsgHeader, sport=dport, dport=sport)

    def activate(self):
        if not (self.contact_init and self.contact_ack):
            raise Exception(
                "tried to activate a session before initialization and acknowledgement"
            )

        self.is_active = self.contact_init and self.contact_ack

        Session.bind_messages(self.sport, self.dport)

    def terminate(self):
        if not (self.contact_init and self.contact_ack):
            raise Exception("tried to terminate a session while none was active")

        self.is_active = self.contact_ack = self.contact_init = False

        Session.split_messages(self.sport, self.dport)

    def init_contact(self, sport, dport):
        self.contact_init = True
        self.sport = sport
        self.dport = dport

    def init_timeout(self):
        self.contact_init = False

    def proc_ack(self):
        self.contact_ack = True
        self.activate()

    def proc_term(self):
        self.term_begun = True

    def proc_term_ack(self):
        self.terminate()


class TestTcpcl:

    @staticmethod
    def check_pkt(pkt: Packet, options: List[Packet]):
        """Asserts that pkt is equal to one of the packets in options
        (according to the raw representation)"""
        for opt in options:
            assert raw(pkt) in list(
                map(raw, options)
            ), "Failed to build a properly formatted TCPCL message"

    @staticmethod
    def make_prn():
        """Define a function for processing packets that closes over a new Session.
        Return it for use in Scapy.sniff."""

        sess = Session()

        def process(pkt):
            # Manage session initialization
            if not sess.is_active:
                try:  # try to find a Contact Header
                    pay = pkt[Raw].load
                    contact = TCPCL.ContactHeader(
                        pay
                    )  # should raise unhandled error if
                    # the TCP payload does not fit ContactHeader
                    # replace pkt's raw payload with a ContactHeader formatted payload
                    pkt[TCP].remove_payload()
                    pkt = pkt / contact

                    # process ContactHeader
                    if (
                        sess.contact_init
                    ):  # session already initialized, Header is an ack
                        sess.proc_ack()
                        print("BEGIN TCPCL SESSION")
                    else:
                        sess.init_contact(pkt[TCP].sport, pkt[TCP].dport)
                except IndexError:  # no TCP payload to process
                    pass
            else:  # currently in an active session
                if TCPCL.SessTerm in pkt:
                    # process SessTerm
                    if sess.term_begun:
                        sess.proc_term_ack()
                        print("END TCPCL SESSION")
                    else:
                        sess.proc_term()

            return pkt  # end of process

        return process  # end of make_prn
