## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##               2015, 2016, 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
The _TLSAutomaton class provides methods common to both TLS client and server.
"""

import struct

from scapy.automaton import Automaton
from scapy.error import log_interactive
from scapy.packet import Raw
from scapy.layers.tls.basefields import _tls_type
from scapy.layers.tls.cert import Cert, PrivKey
from scapy.layers.tls.record import TLS
from scapy.layers.tls.record_sslv2 import SSLv2
from scapy.layers.tls.record_tls13 import TLS13


class _TLSAutomaton(Automaton):
    """
    SSLv3 and TLS 1.0-1.2 typically need a 2-RTT handshake:

    Client        Server
      | --------->>> |    C1 - ClientHello
      | <<<--------- |    S1 - ServerHello
      | <<<--------- |    S1 - Certificate
      | <<<--------- |    S1 - ServerKeyExchange
      | <<<--------- |    S1 - ServerHelloDone
      | --------->>> |    C2 - ClientKeyExchange
      | --------->>> |    C2 - ChangeCipherSpec
      | --------->>> |    C2 - Finished [encrypted]
      | <<<--------- |    S2 - ChangeCipherSpec
      | <<<--------- |    S2 - Finished [encrypted]

    We call these successive groups of messages:
    ClientFlight1, ServerFlight1, ClientFlight2 and ServerFlight2.

    We want to send our messages from the same flight all at once through the
    socket. This is achieved by managing a list of records in 'buffer_out'.
    We may put several messages (i.e. what RFC 5246 calls the record fragments)
    in the same record when possible, but we may need several records for the
    same flight, as with ClientFlight2.

    However, note that the flights from the opposite side may be spread wildly
    accross TLS records and TCP packets. This is why we use a 'get_next_msg'
    method for feeding a list of received messages, 'buffer_in'. Raw data
    which has not yet been interpreted as a TLS record is kept in 'remain_in'.
    """
    def parse_args(self, mycert=None, mykey=None, **kargs):

        super(_TLSAutomaton, self).parse_args(**kargs)

        self.socket = None
        self.remain_in = b""
        self.buffer_in = []         # these are 'fragments' inside records
        self.buffer_out = []        # these are records

        self.cur_session = None
        self.cur_pkt = None         # this is usually the latest parsed packet

        if mycert:
            self.mycert = Cert(mycert)
        else:
            self.mycert = None

        if mykey:
            self.mykey = PrivKey(mykey)
        else:
            self.mykey = None

        self.verbose = kargs.get("verbose", True)


    def get_next_msg(self, socket_timeout=2, retry=2):
        """
        The purpose of the function is to make next message(s) available in
        self.buffer_in. If the list is not empty, nothing is done. If not, in
        order to fill it, the function uses the data already available in
        self.remain_in from a previous call and waits till there are enough to
        dissect a TLS packet. Once dissected, the content of the TLS packet
        (carried messages, or 'fragments') is appended to self.buffer_in.

        We have to grab enough data to dissect a TLS packet. We start by
        reading the first 2 bytes. Unless we get anything different from
        \\x14\\x03, \\x15\\x03, \\x16\\x03 or \\x17\\x03 (which might indicate
        an SSLv2 record, whose first 2 bytes encode the length), we retrieve
        3 more bytes in order to get the length of the TLS record, and
        finally we can retrieve the remaining of the record.
        """
        if self.buffer_in:
            # A message is already available.
            return

        self.socket.settimeout(socket_timeout)
        is_sslv2_msg = False
        still_getting_len = True
        grablen = 2
        while retry and (still_getting_len or len(self.remain_in) < grablen):
            if not is_sslv2_msg and grablen == 5 and len(self.remain_in) >= 5:
                grablen = struct.unpack('!H', self.remain_in[3:5])[0] + 5
                still_getting_len = False
            elif grablen == 2 and len(self.remain_in) >= 2:
                byte0 = struct.unpack("B", self.remain_in[:1])[0]
                byte1 = struct.unpack("B", self.remain_in[1:2])[0]
                if (byte0 in _tls_type) and (byte1 == 3):
                    # Retry following TLS scheme. This will cause failure
                    # for SSLv2 packets with length 0x1{4-7}03.
                    grablen = 5
                else:
                    # Extract the SSLv2 length.
                    is_sslv2_msg = True
                    still_getting_len = False
                    if byte0 & 0x80:
                        grablen = 2 + 0 + ((byte0 & 0x7f) << 8) + byte1
                    else:
                        grablen = 2 + 1 + ((byte0 & 0x3f) << 8) + byte1
            elif not is_sslv2_msg and grablen == 5 and len(self.remain_in) >= 5:
                grablen = struct.unpack('!H', self.remain_in[3:5])[0] + 5

            if grablen == len(self.remain_in):
                break

            try:
                tmp = self.socket.recv(grablen - len(self.remain_in))
                if not tmp:
                    retry -= 1
                else:
                    self.remain_in += tmp
            except:
                self.vprint("Could not join host ! Retrying...")
                retry -= 1

        if len(self.remain_in) < 2 or len(self.remain_in) != grablen:
            # Remote peer is not willing to respond
            return

        p = TLS(self.remain_in, tls_session=self.cur_session)
        self.cur_session = p.tls_session
        self.remain_in = b""
        if isinstance(p, SSLv2) and not p.msg:
            p.msg = Raw("")
        if self.cur_session.tls_version is None or \
           self.cur_session.tls_version < 0x0304:
            self.buffer_in += p.msg
        else:
            if isinstance(p, TLS13):
                self.buffer_in += p.inner.msg
            else:
                # should be TLS13ServerHello only
                self.buffer_in += p.msg

        while p.payload:
            if isinstance(p.payload, Raw):
                self.remain_in += p.payload.load
                p = p.payload
            elif isinstance(p.payload, TLS):
                p = p.payload
                if self.cur_session.tls_version is None or \
                   self.cur_session.tls_version < 0x0304:
                    self.buffer_in += p.msg
                else:
                    self.buffer_in += p.inner.msg

    def raise_on_packet(self, pkt_cls, state, get_next_msg=True):
        """
        If the next message to be processed has type 'pkt_cls', raise 'state'.
        If there is no message waiting to be processed, we try to get one with
        the default 'get_next_msg' parameters.
        """
        # Maybe we already parsed the expected packet, maybe not.
        if get_next_msg:
            self.get_next_msg()
        if (not self.buffer_in or
            not isinstance(self.buffer_in[0], pkt_cls)):
            return
        self.cur_pkt = self.buffer_in[0]
        self.buffer_in = self.buffer_in[1:]
        raise state()

    def add_record(self, is_sslv2=None, is_tls13=None):
        """
        Add a new TLS or SSLv2 or TLS 1.3 record to the packets buffered out.
        """
        if is_sslv2 is None and is_tls13 is None:
            v = (self.cur_session.tls_version or
                 self.cur_session.advertised_tls_version)
            if v in [0x0200, 0x0002]:
                is_sslv2 = True
            elif v >= 0x0304:
                is_tls13 = True
        if is_sslv2:
            self.buffer_out.append(SSLv2(tls_session=self.cur_session))
        elif is_tls13:
            self.buffer_out.append(TLS13(tls_session=self.cur_session))
        else:
            self.buffer_out.append(TLS(tls_session=self.cur_session))

    def add_msg(self, pkt):
        """
        Add a TLS message (e.g. TLSClientHello or TLSApplicationData)
        inside the latest record to be sent through the socket.
        We believe a good automaton should not use the first test.
        """
        if not self.buffer_out:
            self.add_record()
        r = self.buffer_out[-1]
        if isinstance(r, TLS13):
            self.buffer_out[-1].inner.msg.append(pkt)
        else:
            self.buffer_out[-1].msg.append(pkt)

    def flush_records(self):
        """
        Send all buffered records and update the session accordingly.
        """
        s = b"".join(p.raw_stateful() for p in self.buffer_out)
        self.socket.send(s)
        self.buffer_out = []

    def vprint(self, s=""):
        if self.verbose:
            log_interactive.info("> %s", s)

