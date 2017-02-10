## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS automatons. This makes for a primitive TLS stack.
SSLv3 is not guaranteed, and SSLv2 is not supported.
Obviously you need rights for network access.


Launch a server on tcp/4433:

from scapy.all import *
t = TLSServerAutomaton(mycert='<cert.pem>', mykey='<key.pem>')
t.run()


Launch a client to tcp/50000 with one cipher suite of your choice:

from scapy.all import *
ch = TLSClientHello(ciphers=<int code of the cipher suite>)
t = TLSClientAutomaton(dport=50000, client_hello=ch)
t.run()
"""

import socket
import struct

from scapy.error import warning
from scapy.automaton import Automaton, ATMT
from scapy.layers.tls.cert import Cert, PrivKey, PrivKeyRSA, PrivKeyECDSA
from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.session import tlsSession
from scapy.layers.tls.handshake import *
from scapy.layers.tls.record import (TLS, TLSAlert, TLSChangeCipherSpec,
                                     TLSApplicationData)
from scapy.layers.tls.crypto.suites import (_tls_cipher_suites_cls,
                                            _tls_cipher_suites,
                                            get_usable_ciphersuites)


###############################################################################
### Client automaton                                                        ###
###############################################################################

class TLSClientAutomaton(Automaton):
    """
    The TLS client automaton.

    - server : default value is '127.0.0.1';
    - dport : default value is 4433;
    - server_name : default value is None;
    - mycert : optional when there is no client authentication;
    - mykey : optional when there is no client authentication;
    - client_hello : optional definition of the ClientHello to be sent to the
      server, this is faster than automaton overloading and enables quick
      cipher suite choice (make sure it is usable, though);
    - data : optional application_data to be sent after the handshake, if this
      is not defined we send a simple GET request.
    """

    def parse_args(self, server="127.0.0.1", dport=4433,
                   server_name=None, mycert=None, mykey=None,
                   client_hello=None, data=None, **kargs):
        Automaton.parse_args(self, **kargs)

        tmp = socket.getaddrinfo(server, dport)
        self.remote_name = None
        try:
            if ':' in server:
                socket.inet_pton(socket.AF_INET6, server)
            else:
                socket.inet_pton(socket.AF_INET, server)
        except:
            self.remote_name = socket.getfqdn(server)
            if self.remote_name != server:
                tmp = socket.getaddrinfo(self.remote_name, dport)

        if server_name:
            self.remote_name = server_name
        self.remote_family = tmp[0][0]
        self.remote_ip = tmp[0][4][0]
        self.remote_port = dport
        self.local_ip = None
        self.local_port = None

        self.cur_pkt = None
        self.cur_session = None
        self.msg_list = []

        self.remain = ""

        self.socket = None

        self.cert_req = None

        self.client_hello = client_hello
        self.data = data

        if mycert and mykey:
            self.mycert = Cert(mycert)
            self.mykey  = PrivKey(mykey)
        else:
            self.mycert = None
            self.mykey  = None


    def get_next_msg(self, socket_timeout=5, retry=5):
        """
        The purpose of the function is to make next message(s) available in
        self.msg_list. If the list is not empty, nothing is done. If not, in
        order to fill it, the function uses the data already available in
        self.remain from a previous call and waits till there are enough to
        dissect a TLS packet (expected length is in the 5 first bytes of the
        packet). Once dissected, the content of the TLS packet (carried
        messages) is appended to self.msg_list.

        We have to grab enough data to dissect a TLS packet, i.e. at least
        5 bytes in order to access the expected length of the TLS packet.
        """

        if self.msg_list:       # a message is already available
            return

        self.socket.settimeout(socket_timeout)
        grablen = 5
        while retry and (grablen == 5 or len(self.remain) < grablen):
            if grablen == 5 and len(self.remain) >= 5:
                grablen = struct.unpack('!H', self.remain[3:5])[0] + 5

            if grablen == len(self.remain):
                break

            try:
                tmp = self.socket.recv(grablen - len(self.remain))
                if not tmp:
                    retry -= 1
                else:
                    self.remain += tmp
            except:
                retry -= 1

        if self.remain < 5 or len(self.remain) != grablen:
            # Remote peer is not willing to respond
            return

        # Instantiate the TLS packet (record header only, at this point)
        p = TLS(self.remain, tls_session=self.cur_session)
        self.cur_session = p.tls_session
        self.remain = ""
        self.msg_list += p.msg

        while p.payload:
            if isinstance(p.payload, Raw):
                self.remain += p.payload.load
                p = p.payload
            elif isinstance(p.payload, TLS):
                p = p.payload
                self.msg_list += p.msg


    @ATMT.state(initial=True)
    def INITIAL(self):
        raise self.INIT_TLS_SESSION()

    @ATMT.state()
    def INIT_TLS_SESSION(self):
        self.cur_session = tlsSession()
        self.cur_session.client_certs = self.mycert
        self.cur_session.client_key = self.mykey
        raise self.CONNECT()

    @ATMT.state()
    def CONNECT(self):
        s = socket.socket(self.remote_family, socket.SOCK_STREAM)
        s.connect((self.remote_ip, self.remote_port))
        self.socket = s
        self.local_ip, self.local_port = self.socket.getsockname()[:2]
        raise self.PREPARE_FIRST_PKT()

    @ATMT.state()
    def PREPARE_FIRST_PKT(self):
        self.cur_pkt = TLS(tls_session=self.cur_session)

    @ATMT.condition(PREPARE_FIRST_PKT)
    def should_add_ClientHello(self):
        raise self.ADDED_ClientHello()

    @ATMT.action(should_add_ClientHello, prio=1)
    def add_ClientHello(self):
        """
        Default TLSClientHello() offers only TLS_DHE_RSA_WITH_AES_128_CBC_SHA.

        For fast server testing, typical alternatives (DHE only, RSAkx with CBC
        only, ECDHE with appropriate extensions) may be found in tls.uts,
        and then brought here through the client_hello argument.
        """
        p = self.client_hello or TLSClientHello()
        self.cur_pkt.msg.append(p)

    @ATMT.state()
    def ADDED_ClientHello(self):
        pass

    @ATMT.condition(ADDED_ClientHello)
    def should_send_ClientHello(self):
        raise self.SENT_ClientHello()

    @ATMT.action(should_send_ClientHello, prio=1)
    def send_ClientHello(self):
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None

    @ATMT.state()
    def SENT_ClientHello(self):
        raise self.WAITING_FOR_ServerHello()

    @ATMT.state()
    def WAITING_FOR_ServerHello(self):
        self.get_next_msg()
        raise self.PREPROCESS_ServerHello()

    @ATMT.state()
    def PREPROCESS_ServerHello(self):
        pass

    @ATMT.condition(PREPROCESS_ServerHello, prio=1)
    def should_HANDLE_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSServerHello)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_SH()

    @ATMT.state()
    def HANDLE_SH(self):
        pass

    @ATMT.condition(PREPROCESS_ServerHello, prio=2)
    def missing_server_hello(self):
        raise self.MISSING_SH()

    @ATMT.state(final=True)
    def MISSING_SH(self):
        print "Missing TLS Server Hello message"

    @ATMT.condition(HANDLE_SH, prio=1)
    def should_HANDLE_CERT(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSCertificate)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_CERT()

    @ATMT.state()
    def HANDLE_CERT(self):
        pass

    @ATMT.condition(HANDLE_SH, prio=2)
    def missing_certificate(self):
        raise self.MISSING_CERT()

    @ATMT.state(final=True)
    def MISSING_CERT(self):
        print "Missing TLS Certificate message"

    @ATMT.state()
    def HANDLE_CERT_REQ(self):
        pass

    @ATMT.condition(HANDLE_CERT, prio=1)
    def should_HANDLE_SKE_from_CERT(self):
        """
        XXX We should check the ServerKeyExchange attributes for discrepancies
        with our own ClientHello, along with the ServerHello and Certificate.
        """
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSServerKeyExchange)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_SKE()

    @ATMT.state(final=True)
    def MISSING_SKE(self):
        pass

    @ATMT.condition(HANDLE_CERT, prio=2)
    def expected_server_key_exchange(self):
        if self.cur_session.prcs.key_exchange.server_kx_msg_cls:
            # Should have received a SKE
            raise self.MISSING_SKE()

    @ATMT.state()
    def HANDLE_SKE(self):
        # XXX Move that refill code somewhere else
        self.get_next_msg()

    @ATMT.condition(HANDLE_SKE, prio=2)
    def should_HANDLE_CERT_REQ_from_SKE(self):
        self.get_next_msg()
        """
        XXX We should check the CertificateRequest attributes for discrepancies
        with the cipher suite, etc.
        """
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSCertificateRequest)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        self.cert_req = p
        raise self.HANDLE_CERT_REQ()

    @ATMT.condition(HANDLE_CERT, prio=3)
    def should_HANDLE_CERT_REQ(self):
        """
        XXX We should check the CertificateRequest attributes for discrepancies
        with the cipher suite, etc.
        """
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSCertificateRequest)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        self.cert_req = p
        raise self.HANDLE_CERT_REQ()

    @ATMT.condition(HANDLE_SKE, prio=1)
    def should_HANDLE_SHD(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSServerHelloDone)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_SHD()

    @ATMT.condition(HANDLE_CERT_REQ, prio=4)
    def should_HANDLE_SHD_from_CERT_REQ(self):
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSServerHelloDone)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_SHD()

    @ATMT.condition(HANDLE_CERT)
    def should_HANDLE_SHD_from_CERT(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSServerHelloDone)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_SHD()

    @ATMT.state()
    def HANDLE_SHD(self):
        raise self.PREPARE_PKT2()

    # Second packet sent by us
    @ATMT.state()
    def PREPARE_PKT2(self):
        pass

    @ATMT.condition(PREPARE_PKT2, prio=1)
    def should_ADD_CLIENT_CERT(self):
        """
        If the server sent a CertificateRequest, we send a Certificate message.
        If no certificate is available, an empty Certificate message is sent:
        - this is a SHOULD in RFC 4346 (Section 7.4.6)
        - this is a MUST in RFC 5246 (Section 7.4.6)

        XXX We may want to add a complete chain.
        """
        if not self.cert_req:
            return
        certs = []
        if self.mycert:
            certs = [self.mycert]
        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[])
        p = TLSCertificate(certs=certs)
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_CLIENT_CERT()

    @ATMT.state()
    def ADD_CLIENT_CERT(self):
        pass

    @ATMT.condition(PREPARE_PKT2, prio=2)
    def should_ADD_CKE_from_PREPARE_PKT2(self):
        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[])
        p = TLSClientKeyExchange()
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_CKE()

    @ATMT.condition(ADD_CLIENT_CERT, prio=2)
    def should_ADD_CKE_from_ADD_CLIENT_CERT(self):
        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[])
        p = TLSClientKeyExchange()
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_CKE()

    @ATMT.state()
    def ADD_CKE(self):
        pass

    @ATMT.condition(ADD_CKE, prio=1)
    def should_ADD_CV_from_ADD_CKE(self):
        """
        XXX Section 7.4.7.1 of RFC 5246 states that the CertificateVerify
        message is only sent following a client certificate that has signing
        capability (i.e. not those containing fixed DH params).
        We should verify that before adding the message. We should also handle
        the case when the Certificate message was empty.
        """
        if (not self.cert_req or
            self.mycert is None or
            self.mykey is None):
            return
        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[])
        p = TLSCertificateVerify()
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_CV()

    @ATMT.state()
    def ADD_CV(self):
        pass

    @ATMT.condition(ADD_CV)
    def should_ADD_CCS_from_ADD_CV(self):
        self.cur_pkt = TLS(type=20, tls_session=self.cur_session, msg=[])
        p = TLSChangeCipherSpec()
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_CCS()

    @ATMT.condition(ADD_CKE, prio=2)
    def should_ADD_CCS_from_ADD_CKE(self):
        self.cur_pkt = TLS(type=20, tls_session=self.cur_session, msg=[])
        p = TLSChangeCipherSpec()
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_CCS()

    @ATMT.state()
    def ADD_CCS(self):
        pass

    @ATMT.condition(ADD_CCS)
    def should_ADD_FINISHED(self):
        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[])
        p = TLSFinished()
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.ADD_FINISHED()

    @ATMT.state()
    def ADD_FINISHED(self):
        pass

    @ATMT.condition(ADD_FINISHED)
    def should_SEND_SECOND_PKT(self):
        raise self.SEND_SECOND_PKT()

    @ATMT.state()
    def SEND_SECOND_PKT(self):
        raise self.WAIT_FOR_RESP2()

    @ATMT.state()
    def WAIT_FOR_RESP2(self):
        self.socket.settimeout(10)
        s = self.socket.recv(100000)
        p = TLS(s, tls_session=self.cur_session)
        self.msg_list = p.msg
        while p.payload:
            if isinstance(p.payload, Raw):
                self.remain += p.payload.load
                p = p.payload
            elif isinstance(p.payload, TLS):
                p = p.payload
                self.msg_list += p.msg
        raise self.PREPROCESS_RESP2()

    # Second response from the server
    @ATMT.state()
    def PREPROCESS_RESP2(self):
        pass

    @ATMT.condition(PREPROCESS_RESP2)
    def should_HANDLE_CCS(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSChangeCipherSpec)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_CCS()

    @ATMT.state()
    def HANDLE_CCS(self):
        pass

    @ATMT.condition(HANDLE_CCS)
    def should_HANDLE_FINISHED(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSFinished)):
            return
        p = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_FINISHED()

    @ATMT.state()
    def HANDLE_FINISHED(self):
        pass

    @ATMT.condition(HANDLE_FINISHED)
    def should_test_connection(self):
        raise self.TESTED_CONNECTION()

    @ATMT.action(should_test_connection, prio=1)
    def send_recv_data(self):
        """
        XXX No live input from the user ; one unique send for now.
        XXX We might want not to send any ApplicationData message.
        XXX We do not wait very long for server answer.
        """
        txt = self.data or "GET /\r\n\r\n"  # GET HTTP/1.1\r\n\r\n"
        p = TLS(type=23, tls_session=self.cur_session, msg=[Raw(load=txt)])
        self.socket.send(str(p))
        print "Sent to server: \n%r" % txt

        self.get_next_msg(1, 0)
        if self.msg_list:
            p = self.msg_list[0]
            self.msg_list = self.msg_list[1:]
            if isinstance(p, Raw):
                print "Received from server: \n%s" % p.load
            else:
                print "Received from server: \n%s" % p

    @ATMT.state()
    def TESTED_CONNECTION(self):
        pass

    @ATMT.condition(TESTED_CONNECTION)
    def should_close_session(self):
        raise self.CLOSED_TLS_SESSION()

    @ATMT.action(should_close_session, prio=1)
    def close_session(self):
        """
        We end the session properly after 2 seconds,
        with a TLS Alert (warning, close_notify).
        """
        time.sleep(2)
        self.cur_pkt = TLS(type=21, msg=[], tls_session=self.cur_session)
        p = TLSAlert(level=1, descr=0)
        self.cur_pkt.msg.append(p)
        try:
            self.socket.send(str(self.cur_pkt))
        except:
            print "Could not send termination Alert (maybe the server stopped)"
        self.cur_pkt = None

    @ATMT.state()
    def CLOSED_TLS_SESSION(self):
        raise self.FINAL()

    @ATMT.state(final=True)
    def FINAL(self):
        """
        We might call shutdown, but it may happen that the server
        did not wait for us to shutdown after answering our data query.
        #self.socket.shutdown(1)
        """
        self.socket.close()


###############################################################################
### Server automaton                                                        ###
###############################################################################

class TLSServerAutomaton(Automaton):
    """
    The TLS client automaton.

    - server : default value is '127.0.0.1';
    - sport : default value is 4433;
    - mycert : optional when there is no client authentication;
    - mykey : optional when there is no client authentication;
    - preferred_ciphersuite : optional cipher suite to be selected should the
      client offer it through its ClientHello.
    """

    def parse_args(self, server="127.0.0.1", sport=4433,
                   mycert=None, mykey=None,
                   preferred_ciphersuite=None, **kargs):
        Automaton.parse_args(self, **kargs)

        self.mycert = Cert(mycert)
        self.mykey  = PrivKey(mykey)

        try:
            if ':' in server:
                socket.inet_pton(socket.AF_INET6, server)
            else:
                socket.inet_pton(socket.AF_INET, server)
            tmp = socket.getaddrinfo(server, sport)
        except:
            tmp = socket.getaddrinfo(socket.getfqdn(server), sport)

        self.ip_family = tmp[0][0]
        self.local_ip = tmp[0][4][0]
        self.local_port = sport
        self.remote_ip = None
        self.remote_port = None

        self.cur_pkt = None
        self.cur_session = None
        self.msg_list = []

        self.remain = ""

        self.socket = None

        self.cert_req = None

        self.preferred_ciphersuite = preferred_ciphersuite


    def get_next_msg(self):
        """
        The purpose of the function is to make next message(s) available
        in self.msg_list. If the list is not empty, nothing is done. If
        not, in order to fill it, the function uses the data already
        available in self.remain from a previous call and waits till there
        are enough to dissect a TLS packet (expected length is in the 5
        first bytes of the packet). Once dissected, the content of the
        TLS packet (carried messages) is appended to self.msg_list.

        We have to grab enough data to dissect a TLS packet, i.e. at least
        5 bytes in order to access the expected length of the TLS packet.
        """

        if self.msg_list:       # a message is already available
            return

        self.socket.settimeout(5)
        retry = 5
        grablen = 5
        while retry and (grablen == 5 or len(self.remain) < grablen):
            if grablen == 5 and len(self.remain) >= 5:
                grablen = struct.unpack('!H', self.remain[3:5])[0] + 5
            if grablen == len(self.remain):
                break

            try:
                tmp = self.socket.recv(grablen - len(self.remain))
                if not tmp:
                    retry -= 1
                else:
                    self.remain += tmp
            except:
                retry -= 1

        if self.remain < 5 or len(self.remain) != grablen:
            # Remote peer is not willing to respond
            return

        # Instantiate TLS packet (record header only, at this point)
        p = TLS(self.remain, tls_session=self.cur_session)
        self.cur_session = p.tls_session
        self.remain = ""
        self.msg_list += p.msg

        while p.payload:
            if isinstance(p.payload, Raw):
                self.remain += p.payload.load
                p = p.payload
            elif isinstance(p.payload, TLS):
                p = p.payload
                self.msg_list += p.msg

    @ATMT.state(initial=True)
    def INITIAL(self):
        raise self.INIT_TLS_SESSION()

    @ATMT.state()
    def INIT_TLS_SESSION(self):
        """
        XXX We should offer the right key according to the client's suites. For
        now server_rsa_key is only used for RSAkx, but we should try to replace
        every server_key with both server_rsa_key and server_ecdsa_key.
        """
        self.cur_session = tlsSession(connection_end="server")
        self.cur_session.server_certs = [self.mycert]
        self.cur_session.server_key = self.mykey
        if isinstance(self.mykey, PrivKeyRSA):
            self.cur_session.server_rsa_key = self.mykey
        #elif isinstance(self.mykey, PrivKeyECDSA):
        #    self.cur_session.server_ecdsa_key = self.mykey
        raise self.BIND_AND_WAIT()

    @ATMT.state()
    def BIND_AND_WAIT(self):
        s = socket.socket(self.ip_family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.local_ip, self.local_port))
            s.listen(1)
        except:
            print "Unable to bind on address %s and port %d" % (self.local_ip,
                                                                self.local_port)
            return
        self.socket, addr = s.accept()
        if not isinstance(addr, tuple):
            addr = self.socket.getpeername()
        if len(addr) > 2:
            addr = (addr[0], addr[1])
        self.remote_ip, self.remote_port = addr

        raise self.WAITING_FOR_ClientHello()

    @ATMT.state()
    def WAITING_FOR_ClientHello(self):
        self.get_next_msg()

        raise self.PREPROCESS_ClientHello()

    @ATMT.state()
    def PREPROCESS_ClientHello(self):
        pass

    @ATMT.condition(PREPROCESS_ClientHello, prio=1)
    def should_HANDLE_ClientHello(self):
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSClientHello)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_CH()

    @ATMT.state()
    def HANDLE_CH(self):
        pass

    @ATMT.condition(HANDLE_CH, prio=1)
    def should_NO_USABLE_CIPHERSUITE(self):
        """
        We extract cipher suites candidates from the client's proposition.
        """
        l = self.cur_pkt.ciphers

        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        l = get_usable_ciphersuites(l, kx)

        if l:
            return

        raise self.NO_USABLE_CIPHERSUITE()

    @ATMT.state(final=True)
    def NO_USABLE_CIPHERSUITE(self):
        """
        If there is no available cipher suite, close the session with an Alert.
        """
        print "No usable cipher suite, closing connection"
        self.cur_pkt = TLS(type=21, msg=[], tls_session=self.cur_session)
        p = TLSAlert(level=1, descr=0)
        self.cur_pkt.msg.append(p)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None

    @ATMT.condition(PREPROCESS_ClientHello, prio=2)
    def missing_client_hello(self):
        raise self.MISSING_CH()

    @ATMT.state(final=True)
    def MISSING_CH(self):
        print "Missing TLS Client Hello message"

    @ATMT.condition(HANDLE_CH, prio=2)
    def should_REPLY_TO_CH(self):
        """
        XXX Several enhancements needed here.

        Selecting a cipher suite should be no trouble as we already caught the
        None case previously. However, regarding the protocol version, we
        might want to try resending a ClientHello when the advertised
        version is not deemed satisfying.

        Then, the sending of ServerHello, Certificate, ServerKeyExchange and
        ServerHelloDone should be split into multiple states, in order for the
        user to overload only the ones he's interested in.

        Also, we do not manage extensions at all.
        """
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
        c = usable_suites[0]
        if self.preferred_ciphersuite in usable_suites:
            c = self.preferred_ciphersuite

        comp = 0
        if self.cur_pkt.comp and 1 in self.cur_pkt.comp:
            comp = 1

        self.cur_session.advertised_tls_version = self.cur_pkt.version
        self.cur_session.tls_version = self.cur_pkt.version
        #XXX there should be some checks on this version from the ClientHello
        v = self.cur_session.tls_version
        print "\nVersion: " + _tls_version[v]
        print "Cipher suite: " + _tls_cipher_suites[c]

        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[])

        p = TLSServerHello(cipher=c, comp=[comp])
        self.cur_pkt.msg.append(p)

        p = TLSCertificate(certs=self.cur_session.server_certs)
        self.cur_pkt.msg.append(p)

        if not _tls_cipher_suites_cls[c].kx_alg.no_ske:
            p = TLSServerKeyExchange()
            self.cur_pkt.msg.append(p)

        p = TLSServerHelloDone()
        self.cur_pkt.msg.append(p)

        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.SENT_SH()

    @ATMT.state()
    def SENT_SH(self):
        pass

    @ATMT.condition(SENT_SH, prio=1)
    def should_HANDLE_CKE(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSClientKeyExchange)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_CKE()

    @ATMT.state()
    def HANDLE_CKE(self):
        pass

    @ATMT.condition(SENT_SH, prio=2)
    def should_HANDLE_ALERT_INSTEAD_OF_CKE(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSAlert)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_ALERT_INSTEAD_OF_CKE()

    @ATMT.state()
    def HANDLE_ALERT_INSTEAD_OF_CKE(self):
        print "Received Alert message instead of CKE"

    @ATMT.condition(SENT_SH, prio=3)
    def should_HANDLE_MISSING_CKE(self):
        raise self.HANDLE_MISSING_CKE()

    @ATMT.state()
    def HANDLE_MISSING_CKE(self):
        print "Missing CKE in client's reply"


    @ATMT.condition(HANDLE_CKE, prio=1)
    def should_HANDLE_CCS(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSChangeCipherSpec)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_CCS()

    @ATMT.state()
    def HANDLE_CCS(self):
        pass

    @ATMT.condition(HANDLE_CKE, prio=2)
    def should_HANDLE_ALERT_INSTEAD_OF_CCS(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSAlert)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]

        raise self.HANDLE_ALERT_INSTEAD_OF_CCS()

    @ATMT.state()
    def HANDLE_ALERT_INSTEAD_OF_CCS(self):
        print "Received Alert message instead of CCS"

    @ATMT.condition(HANDLE_CKE, prio=3)
    def should_HANDLE_MISSING_CCS(self):
        raise self.HANDLE_MISSING_CCS()

    @ATMT.state()
    def HANDLE_MISSING_CCS(self):
        print "Missing CCS in client's reply"

    @ATMT.condition(HANDLE_CCS, prio=1)
    def should_HANDLE_Finished(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSFinished)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_FINISHED()

    @ATMT.state()
    def HANDLE_FINISHED(self):
        pass

    @ATMT.condition(HANDLE_CCS, prio=2)
    def should_HANDLE_ALERT_INSTEAD_OF_Finished(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSAlert)):
            return
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        raise self.HANDLE_ALERT_INSTEAD_OF_FINISHED()

    @ATMT.state()
    def HANDLE_ALERT_INSTEAD_OF_FINISHED(self):
        print "Received Alert message instead of Finished"

    @ATMT.condition(HANDLE_CCS, prio=3)
    def should_HANDLE_MISSING_FINISHED(self):
        raise self.HANDLE_MISSING_FINISHED()

    @ATMT.state()
    def HANDLE_MISSING_FINISHED(self):
        print "Missing Finished in client's reply"

    @ATMT.condition(HANDLE_FINISHED, prio=1)
    def should_SEND_CCS(self):
        ccs = TLSChangeCipherSpec()
        self.cur_pkt = TLS(type=20, msg=[ccs], tls_session=self.cur_session)
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.SEND_CCS()

    @ATMT.state()
    def SEND_CCS(self):
        pass

    @ATMT.condition(SEND_CCS, prio=2)
    def should_SEND_FINISHED(self):
        p = TLSFinished()
        self.cur_pkt = TLS(tls_session=self.cur_session, msg=[p])
        self.socket.send(str(self.cur_pkt))
        self.cur_pkt = None
        raise self.FINISHED_SENT()

    @ATMT.state()
    def FINISHED_SENT(self):
        pass

    @ATMT.condition(FINISHED_SENT, prio=0)
    def should_HANDLE_NO_CLIENT(self):
        self.get_next_msg()
        if self.msg_list:
            return
        print "Client left. Closing connection..."
        raise self.FINAL()

    @ATMT.condition(FINISHED_SENT, prio=1)
    def should_HANDLE_ALERT_FROM_FINISHED(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSAlert)):
            return
        raise self.HANDLE_ALERT_FROM_FINISHED_SENT()

    @ATMT.state()
    def HANDLE_ALERT_FROM_FINISHED_SENT(self):
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]
        print "Received Alert Message after sending Finished"
        print "Closing connection"
        #XXX no support for new connections, for now
        raise self.FINAL()

    @ATMT.condition(FINISHED_SENT, prio=2)
    def should_WAIT_DATA(self):
        self.get_next_msg()
        if self.msg_list:
            return
        # Client did not send anything, let's wait
        raise self.FINISHED_SENT()

    @ATMT.condition(FINISHED_SENT, prio=3)
    def should_PROCESS_DATA(self):
        self.get_next_msg()
        if (not self.msg_list or
            not isinstance(self.msg_list[0], TLSApplicationData)):
            return
        raise self.PROCESS_DATA()

    @ATMT.state()
    def PROCESS_DATA(self):
        """
        In the beginning, we return a small page with useful information.
        Then, we act as an echo server.
        """
        self.cur_pkt = self.msg_list[0]
        self.msg_list = self.msg_list[1:]

        recv_data = self.cur_pkt.data
        print "Received %s" % repr(recv_data)

        if recv_data.startswith("GET / HTTP/1."):
            header  = "HTTP/1.1 200 OK\r\n"
            header += "Server: Scapy TLS Extension\r\n"
            header += "Content-type: text/html\r\n"
            header += "Content-length: %d\r\n\r\n"
            s  = "Information on current TLS session:\n\n"
            s += "Local end      : %s:%d\n" % (self.local_ip, self.local_port)
            s += "Remote end     : %s:%d\n" % (self.remote_ip, self.remote_port)
            v = self.cur_session.advertised_tls_version
            v = "%s (0x%04x)" % (_tls_version[v], v)
            s += "TLS version    : %s\n" % v
            s += repr(self.cur_session.wcs)
            body = "<html><body><pre>%s</pre></body></html>\r\n\r\n" % s
            page = (header+body) % len(body)
        else:
            page = recv_data

        p = Raw(load=page)
        self.cur_pkt = TLS(type=23, msg=[p], tls_session=self.cur_session)
        self.socket.send(str(self.cur_pkt))
        raise self.FINISHED_SENT()

    @ATMT.state(final=True)
    def FINAL(self):
        """
        We might call shutdown, but unit tests with s_client fail with this.
        #self.socket.shutdown(1)
        """
        self.socket.close()

