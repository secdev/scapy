## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##               2015, 2016, 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS server automaton. This makes for a primitive TLS stack.
Obviously you need rights for network access.

We support versions SSLv2 to TLS 1.2, along with many features.
There is no session resumption mechanism for now.

In order to run a server listening on tcp/4433:
> from scapy.all import *
> t = TLSServerAutomaton(mycert='<cert.pem>', mykey='<key.pem>')
> t.run()
"""

from __future__ import print_function
import socket

from scapy.pton_ntop import inet_pton
from scapy.utils import randstring, repr_hex
from scapy.automaton import ATMT
from scapy.layers.tls.automaton import _TLSAutomaton
from scapy.layers.tls.cert import PrivKeyRSA, PrivKeyECDSA
from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.session import tlsSession
from scapy.layers.tls.handshake import *
from scapy.layers.tls.handshake_sslv2 import *
from scapy.layers.tls.record import (TLS, TLSAlert, TLSChangeCipherSpec,
                                     TLSApplicationData)
from scapy.layers.tls.crypto.suites import (_tls_cipher_suites_cls,
                                            get_usable_ciphersuites)


class TLSServerAutomaton(_TLSAutomaton):
    """
    A simple TLS test server automaton. Try to overload some states or
    conditions and see what happens on the other side.

    Because of socket and automaton limitations, for now, the best way to
    interrupt the server is by sending him 'stop_server'. Interruptions with
    Ctrl-Z should work, but this might leave a loose listening socket behind.

    In case the server receives a TLSAlert (whatever its type), or a 'goodbye'
    message in a SSLv2 version, he will close the client session with a
    similar message, and start waiting for new client connections.

    _'mycert' and 'mykey' may be provided as filenames. They are needed for any
    server authenticated handshake.
    _'preferred_ciphersuite' allows the automaton to choose a cipher suite when
    offered in the ClientHello. If absent, another one will be chosen.
    _'client_auth' means the client has to provide a certificate.
    _'is_echo_server' means that everything received will be sent back.
    _'max_client_idle_time' is the maximum silence duration from the client.
    Once this limit has been reached, the client (if still here) is dropped,
    and we wait for a new connection.
    """
    def parse_args(self, server="127.0.0.1", sport=4433,
                         mycert=None, mykey=None,
                         preferred_ciphersuite=None,
                         client_auth=False,
                         is_echo_server=True,
                         max_client_idle_time=60,
                         **kargs):

        super(TLSServerAutomaton, self).parse_args(mycert=mycert,
                                                   mykey=mykey,
                                                   **kargs)
        try:
            if ':' in server:
                inet_pton(socket.AF_INET6, server)
            else:
                inet_pton(socket.AF_INET, server)
            tmp = socket.getaddrinfo(server, sport)
        except:
            tmp = socket.getaddrinfo(socket.getfqdn(server), sport)

        self.serversocket = None
        self.ip_family = tmp[0][0]
        self.local_ip = tmp[0][4][0]
        self.local_port = sport
        self.remote_ip = None
        self.remote_port = None

        self.preferred_ciphersuite = preferred_ciphersuite
        self.client_auth = client_auth
        self.is_echo_server = is_echo_server
        self.max_client_idle_time = max_client_idle_time


    def vprint_sessioninfo(self):
        if self.verbose:
            s = self.cur_session
            v = _tls_version[s.tls_version]
            self.vprint("Version       : %s" % v)
            cs = s.wcs.ciphersuite.name
            self.vprint("Cipher suite  : %s" % cs)
            ms = s.master_secret
            self.vprint("Master secret : %s" % repr_hex(ms))
            if s.client_certs:
                self.vprint("Client certificate chain: %r" % s.client_certs)
            self.vprint()

    def http_sessioninfo(self):
        header  = "HTTP/1.1 200 OK\r\n"
        header += "Server: Scapy TLS Extension\r\n"
        header += "Content-type: text/html\r\n"
        header += "Content-length: %d\r\n\r\n"
        s = "----- Scapy TLS Server Automaton -----\n\n"
        s += "Information on current TLS session:\n\n"
        s += "Local end     : %s:%d\n" % (self.local_ip, self.local_port)
        s += "Remote end    : %s:%d\n" % (self.remote_ip, self.remote_port)
        v = _tls_version[self.cur_session.tls_version]
        s += "Version       : %s\n" % v
        cs = self.cur_session.wcs.ciphersuite.name
        s += "Cipher suite  : %s\n" % cs
        ms = self.cur_session.master_secret
        s += "Master secret : %s\n" % repr_hex(ms)
        body = "<html><body><pre>%s</pre></body></html>\r\n\r\n" % s
        answer = (header+body) % len(body)
        return answer


    @ATMT.state(initial=True)
    def INITIAL(self):
        self.vprint("Starting TLS server automaton.")
        self.vprint("Receiving 'stop_server' will cause a graceful exit.")
        self.vprint("Interrupting with Ctrl-Z might leave a loose socket hanging.")
        raise self.BIND()

    @ATMT.state()
    def BIND(self):
        s = socket.socket(self.ip_family, socket.SOCK_STREAM)
        self.serversocket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.local_ip, self.local_port))
            s.listen(1)
        except:
            m = "Unable to bind on %s:%d!" % (self.local_ip, self.local_port)
            self.vprint()
            self.vprint(m)
            self.vprint("Maybe some server is already listening there?")
            self.vprint()
            raise self.FINAL()
        raise self.WAITING_CLIENT()

    @ATMT.state()
    def WAITING_CLIENT(self):
        self.vprint()
        self.vprint("Waiting for a new client on %s:%d" % (self.local_ip,
                                                           self.local_port))
        self.socket, addr = self.serversocket.accept()
        if not isinstance(addr, tuple):
            addr = self.socket.getpeername()
        if len(addr) > 2:
            addr = (addr[0], addr[1])
        self.remote_ip, self.remote_port = addr
        self.vprint("Accepted connection from %s:%d" % (self.remote_ip,
                                                        self.remote_port))
        self.vprint()
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
        raise self.WAITING_CLIENTFLIGHT1()

    @ATMT.state()
    def WAITING_CLIENTFLIGHT1(self):
        self.get_next_msg()
        raise self.RECEIVED_CLIENTFLIGHT1()

    @ATMT.state()
    def RECEIVED_CLIENTFLIGHT1(self):
        pass

    ########################### TLS handshake #################################

    @ATMT.condition(RECEIVED_CLIENTFLIGHT1, prio=1)
    def should_handle_ClientHello(self):
        self.raise_on_packet(TLSClientHello,
                             self.HANDLED_CLIENTHELLO)

    @ATMT.state()
    def HANDLED_CLIENTHELLO(self):
        raise self.PREPARE_SERVERFLIGHT1()

    @ATMT.condition(HANDLED_CLIENTHELLO)
    def should_check_ciphersuites(self):
        """
        We extract cipher suites candidates from the client's proposition.
        """
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        if get_usable_ciphersuites(self.cur_pkt.ciphers, kx):
            return
        raise self.NO_USABLE_CIPHERSUITE()

    @ATMT.state()
    def NO_USABLE_CIPHERSUITE(self):
        self.vprint("No usable cipher suite!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(RECEIVED_CLIENTFLIGHT1, prio=3)
    def missing_ClientHello(self):
        raise self.MISSING_CLIENTHELLO()

    @ATMT.state(final=True)
    def MISSING_CLIENTHELLO(self):
        self.vprint("Missing ClientHello message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def PREPARE_SERVERFLIGHT1(self):
        self.add_record()

    @ATMT.condition(PREPARE_SERVERFLIGHT1)
    def should_add_ServerHello(self):
        """
        Selecting a cipher suite should be no trouble as we already caught
        the None case previously.

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
        self.add_msg(TLSServerHello(cipher=c))
        raise self.ADDED_SERVERHELLO()

    @ATMT.state()
    def ADDED_SERVERHELLO(self):
        pass

    @ATMT.condition(ADDED_SERVERHELLO)
    def should_add_Certificate(self):
        c = self.buffer_out[-1].msg[0].cipher
        if not _tls_cipher_suites_cls[c].kx_alg.anonymous:
            self.add_msg(TLSCertificate(certs=self.cur_session.server_certs))
        raise self.ADDED_CERTIFICATE()

    @ATMT.state()
    def ADDED_CERTIFICATE(self):
        pass

    @ATMT.condition(ADDED_CERTIFICATE)
    def should_add_ServerKeyExchange(self):
        c = self.buffer_out[-1].msg[0].cipher
        if not _tls_cipher_suites_cls[c].kx_alg.no_ske:
            self.add_msg(TLSServerKeyExchange())
        raise self.ADDED_SERVERKEYEXCHANGE()

    @ATMT.state()
    def ADDED_SERVERKEYEXCHANGE(self):
        pass

    @ATMT.condition(ADDED_SERVERKEYEXCHANGE)
    def should_add_CertificateRequest(self):
        if self.client_auth:
            self.add_msg(TLSCertificateRequest())
        raise self.ADDED_CERTIFICATEREQUEST()

    @ATMT.state()
    def ADDED_CERTIFICATEREQUEST(self):
        pass

    @ATMT.condition(ADDED_CERTIFICATEREQUEST)
    def should_add_ServerHelloDone(self):
        self.add_msg(TLSServerHelloDone())
        raise self.ADDED_SERVERHELLODONE()

    @ATMT.state()
    def ADDED_SERVERHELLODONE(self):
        pass

    @ATMT.condition(ADDED_SERVERHELLODONE)
    def should_send_ServerFlight1(self):
        self.flush_records()
        raise self.WAITING_CLIENTFLIGHT2()

    @ATMT.state()
    def WAITING_CLIENTFLIGHT2(self):
        self.get_next_msg()
        raise self.RECEIVED_CLIENTFLIGHT2()

    @ATMT.state()
    def RECEIVED_CLIENTFLIGHT2(self):
        pass

    @ATMT.condition(RECEIVED_CLIENTFLIGHT2, prio=1)
    def should_handle_ClientCertificate(self):
        self.raise_on_packet(TLSCertificate,
                             self.HANDLED_CLIENTCERTIFICATE)

    @ATMT.condition(RECEIVED_CLIENTFLIGHT2, prio=2)
    def no_ClientCertificate(self):
        if self.client_auth:
            raise self.MISSING_CLIENTCERTIFICATE()
        raise self.HANDLED_CLIENTCERTIFICATE()

    @ATMT.state()
    def MISSING_CLIENTCERTIFICATE(self):
        self.vprint("Missing ClientCertificate!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def HANDLED_CLIENTCERTIFICATE(self):
        if self.client_auth:
            self.vprint("Received client certificate chain...")

    @ATMT.condition(HANDLED_CLIENTCERTIFICATE, prio=1)
    def should_handle_ClientKeyExchange(self):
        self.raise_on_packet(TLSClientKeyExchange,
                             self.HANDLED_CLIENTKEYEXCHANGE)

    @ATMT.state()
    def HANDLED_CLIENTKEYEXCHANGE(self):
        pass

    @ATMT.condition(HANDLED_CLIENTCERTIFICATE, prio=2)
    def should_handle_Alert_from_ClientCertificate(self):
        self.raise_on_packet(TLSAlert,
                             self.HANDLED_ALERT_FROM_CLIENTCERTIFICATE)

    @ATMT.state()
    def HANDLED_ALERT_FROM_CLIENTCERTIFICATE(self):
        self.vprint("Received Alert message instead of ClientKeyExchange!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_CLIENTCERTIFICATE, prio=3)
    def missing_ClientKeyExchange(self):
        raise self.MISSING_CLIENTKEYEXCHANGE()

    @ATMT.state()
    def MISSING_CLIENTKEYEXCHANGE(self):
        self.vprint("Missing ClientKeyExchange!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_CLIENTKEYEXCHANGE, prio=1)
    def should_handle_CertificateVerify(self):
        self.raise_on_packet(TLSCertificateVerify,
                             self.HANDLED_CERTIFICATEVERIFY)

    @ATMT.condition(HANDLED_CLIENTKEYEXCHANGE, prio=2)
    def no_CertificateVerify(self):
        if self.client_auth:
            raise self.MISSING_CERTIFICATEVERIFY()
        raise self.HANDLED_CERTIFICATEVERIFY()

    @ATMT.state()
    def MISSING_CERTIFICATEVERIFY(self):
        self.vprint("Missing CertificateVerify!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def HANDLED_CERTIFICATEVERIFY(self):
        pass

    @ATMT.condition(HANDLED_CERTIFICATEVERIFY, prio=1)
    def should_handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec,
                             self.HANDLED_CHANGECIPHERSPEC)

    @ATMT.state()
    def HANDLED_CHANGECIPHERSPEC(self):
        pass

    @ATMT.condition(HANDLED_CERTIFICATEVERIFY, prio=2)
    def should_handle_Alert_from_ClientKeyExchange(self):
        self.raise_on_packet(TLSAlert,
                             self.HANDLED_ALERT_FROM_CLIENTKEYEXCHANGE)

    @ATMT.state()
    def HANDLED_ALERT_FROM_CLIENTKEYEXCHANGE(self):
        self.vprint("Received Alert message instead of ChangeCipherSpec!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_CERTIFICATEVERIFY, prio=3)
    def missing_ChangeCipherSpec(self):
        raise self.MISSING_CHANGECIPHERSPEC()

    @ATMT.state()
    def MISSING_CHANGECIPHERSPEC(self):
        self.vprint("Missing ChangeCipherSpec!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_CHANGECIPHERSPEC, prio=1)
    def should_handle_ClientFinished(self):
        self.raise_on_packet(TLSFinished,
                             self.HANDLED_CLIENTFINISHED)

    @ATMT.state()
    def HANDLED_CLIENTFINISHED(self):
        raise self.PREPARE_SERVERFLIGHT2()

    @ATMT.condition(HANDLED_CHANGECIPHERSPEC, prio=2)
    def should_handle_Alert_from_ClientFinished(self):
        self.raise_on_packet(TLSAlert,
                             self.HANDLED_ALERT_FROM_CHANGECIPHERSPEC)

    @ATMT.state()
    def HANDLED_ALERT_FROM_CHANGECIPHERSPEC(self):
        self.vprint("Received Alert message instead of Finished!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_CHANGECIPHERSPEC, prio=3)
    def missing_ClientFinished(self):
        raise self.MISSING_CLIENTFINISHED()

    @ATMT.state()
    def MISSING_CLIENTFINISHED(self):
        self.vprint("Missing Finished!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def PREPARE_SERVERFLIGHT2(self):
        self.add_record()

    @ATMT.condition(PREPARE_SERVERFLIGHT2)
    def should_add_ChangeCipherSpec(self):
        self.add_msg(TLSChangeCipherSpec())
        raise self.ADDED_CHANGECIPHERSPEC()

    @ATMT.state()
    def ADDED_CHANGECIPHERSPEC(self):
        pass

    @ATMT.condition(ADDED_CHANGECIPHERSPEC)
    def should_add_ServerFinished(self):
        self.add_record()
        self.add_msg(TLSFinished())
        raise self.ADDED_SERVERFINISHED()

    @ATMT.state()
    def ADDED_SERVERFINISHED(self):
        pass

    @ATMT.condition(ADDED_SERVERFINISHED)
    def should_send_ServerFlight2(self):
        self.flush_records()
        raise self.SENT_SERVERFLIGHT2()

    @ATMT.state()
    def SENT_SERVERFLIGHT2(self):
        self.vprint("TLS handshake completed!")
        self.vprint_sessioninfo()
        if self.is_echo_server:
            self.vprint("Will now act as a simple echo server.")
        raise self.WAITING_CLIENTDATA()

    ####################### end of TLS handshake ##############################

    @ATMT.state()
    def WAITING_CLIENTDATA(self):
        self.get_next_msg(self.max_client_idle_time, 1)
        raise self.RECEIVED_CLIENTDATA()

    @ATMT.state()
    def RECEIVED_CLIENTDATA(self):
        pass

    @ATMT.condition(RECEIVED_CLIENTDATA)
    def should_handle_ClientData(self):
        if not self.buffer_in:
            self.vprint("Client idle time maxed out.")
            raise self.CLOSE_NOTIFY()
        p = self.buffer_in[0]
        self.buffer_in = self.buffer_in[1:]

        recv_data = b""
        if isinstance(p, TLSApplicationData):
            print("> Received: %r" % p.data)
            recv_data = p.data
            lines = recv_data.split(b"\n")
            for l in lines:
                if l.startswith(b"stop_server"):
                    raise self.CLOSE_NOTIFY_FINAL()
        elif isinstance(p, TLSAlert):
            print("> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        else:
            print("> Received: %r" % p)

        if recv_data.startswith(b"GET / HTTP/1.1"):
            p = TLSApplicationData(data=self.http_sessioninfo())

        if self.is_echo_server or recv_data.startswith(b"GET / HTTP/1.1"):
            self.add_record()
            self.add_msg(p)
            raise self.ADDED_SERVERDATA()

        raise self.HANDLED_CLIENTDATA()

    @ATMT.state()
    def HANDLED_CLIENTDATA(self):
        raise self.WAITING_CLIENTDATA()

    @ATMT.state()
    def ADDED_SERVERDATA(self):
        pass

    @ATMT.condition(ADDED_SERVERDATA)
    def should_send_ServerData(self):
        self.flush_records()
        raise self.SENT_SERVERDATA()

    @ATMT.state()
    def SENT_SERVERDATA(self):
        raise self.WAITING_CLIENTDATA()

    @ATMT.state()
    def CLOSE_NOTIFY(self):
        self.vprint()
        self.vprint("Sending a TLSAlert to the client...")

    @ATMT.condition(CLOSE_NOTIFY)
    def close_session(self):
        self.add_record()
        self.add_msg(TLSAlert(level=1, descr=0))
        try:
            self.flush_records()
        except:
            self.vprint("Could not send termination Alert, maybe the client left?")
            self.buffer_out = []
        self.socket.close()
        raise self.WAITING_CLIENT()

    @ATMT.state()
    def CLOSE_NOTIFY_FINAL(self):
        self.vprint()
        self.vprint("Sending a TLSAlert to the client...")

    @ATMT.condition(CLOSE_NOTIFY_FINAL)
    def close_session_final(self):
        self.add_record()
        self.add_msg(TLSAlert(level=1, descr=0))
        try:
            self.flush_records()
        except:
            self.vprint("Could not send termination Alert, maybe the client left?")
        # We might call shutdown, but unit tests with s_client fail with this.
        #self.socket.shutdown(1)
        self.socket.close()
        raise self.FINAL()

    ########################## SSLv2 handshake ################################

    @ATMT.condition(RECEIVED_CLIENTFLIGHT1, prio=2)
    def sslv2_should_handle_ClientHello(self):
        self.raise_on_packet(SSLv2ClientHello,
                             self.SSLv2_HANDLED_CLIENTHELLO)

    @ATMT.state()
    def SSLv2_HANDLED_CLIENTHELLO(self):
        pass

    @ATMT.condition(SSLv2_HANDLED_CLIENTHELLO)
    def sslv2_should_add_ServerHello(self):
        self.add_record(is_sslv2=True)
        cert = self.mycert
        ciphers = [0x010080, 0x020080, 0x030080, 0x040080,
                   0x050080, 0x060040, 0x0700C0]
        connection_id = randstring(16)
        p = SSLv2ServerHello(cert=cert,
                             ciphers=ciphers,
                             connection_id=connection_id)
        self.add_msg(p)
        raise self.SSLv2_ADDED_SERVERHELLO()

    @ATMT.state()
    def SSLv2_ADDED_SERVERHELLO(self):
        pass

    @ATMT.condition(SSLv2_ADDED_SERVERHELLO)
    def sslv2_should_send_ServerHello(self):
        self.flush_records()
        raise self.SSLv2_SENT_SERVERHELLO()

    @ATMT.state()
    def SSLv2_SENT_SERVERHELLO(self):
        raise self.SSLv2_WAITING_CLIENTMASTERKEY()

    @ATMT.state()
    def SSLv2_WAITING_CLIENTMASTERKEY(self):
        self.get_next_msg()
        raise self.SSLv2_RECEIVED_CLIENTMASTERKEY()

    @ATMT.state()
    def SSLv2_RECEIVED_CLIENTMASTERKEY(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_CLIENTMASTERKEY, prio=1)
    def sslv2_should_handle_ClientMasterKey(self):
        self.raise_on_packet(SSLv2ClientMasterKey,
                             self.SSLv2_HANDLED_CLIENTMASTERKEY)

    @ATMT.condition(SSLv2_RECEIVED_CLIENTMASTERKEY, prio=2)
    def missing_ClientMasterKey(self):
        raise self.SSLv2_MISSING_CLIENTMASTERKEY()

    @ATMT.state()
    def SSLv2_MISSING_CLIENTMASTERKEY(self):
        self.vprint("Missing SSLv2 ClientMasterKey!")
        raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.state()
    def SSLv2_HANDLED_CLIENTMASTERKEY(self):
        raise self.SSLv2_RECEIVED_CLIENTFINISHED()

    @ATMT.state()
    def SSLv2_RECEIVED_CLIENTFINISHED(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_CLIENTFINISHED, prio=1)
    def sslv2_should_handle_ClientFinished(self):
        self.raise_on_packet(SSLv2ClientFinished,
                             self.SSLv2_HANDLED_CLIENTFINISHED)

    @ATMT.state()
    def SSLv2_HANDLED_CLIENTFINISHED(self):
        pass

    @ATMT.condition(SSLv2_HANDLED_CLIENTFINISHED, prio=1)
    def sslv2_should_add_ServerVerify_from_ClientFinished(self):
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if SSLv2ServerVerify in hs_msg:
            return
        self.add_record(is_sslv2=True)
        p = SSLv2ServerVerify(challenge=self.cur_session.sslv2_challenge)
        self.add_msg(p)
        raise self.SSLv2_ADDED_SERVERVERIFY()

    @ATMT.condition(SSLv2_RECEIVED_CLIENTFINISHED, prio=2)
    def sslv2_should_add_ServerVerify_from_NoClientFinished(self):
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if SSLv2ServerVerify in hs_msg:
            return
        self.add_record(is_sslv2=True)
        p = SSLv2ServerVerify(challenge=self.cur_session.sslv2_challenge)
        self.add_msg(p)
        raise self.SSLv2_ADDED_SERVERVERIFY()

    @ATMT.condition(SSLv2_RECEIVED_CLIENTFINISHED, prio=3)
    def sslv2_missing_ClientFinished(self):
        raise self.SSLv2_MISSING_CLIENTFINISHED()

    @ATMT.state()
    def SSLv2_MISSING_CLIENTFINISHED(self):
        self.vprint("Missing SSLv2 ClientFinished!")
        raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.state()
    def SSLv2_ADDED_SERVERVERIFY(self):
        pass

    @ATMT.condition(SSLv2_ADDED_SERVERVERIFY)
    def sslv2_should_send_ServerVerify(self):
        self.flush_records()
        raise self.SSLv2_SENT_SERVERVERIFY()

    @ATMT.state()
    def SSLv2_SENT_SERVERVERIFY(self):
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if SSLv2ClientFinished in hs_msg:
            raise self.SSLv2_HANDLED_CLIENTFINISHED()
        else:
            raise self.SSLv2_RECEIVED_CLIENTFINISHED()

    ####################### SSLv2 client authentication #######################

    @ATMT.condition(SSLv2_HANDLED_CLIENTFINISHED, prio=2)
    def sslv2_should_add_RequestCertificate(self):
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if not self.client_auth or SSLv2RequestCertificate in hs_msg:
            return
        self.add_record(is_sslv2=True)
        self.add_msg(SSLv2RequestCertificate(challenge=randstring(16)))
        raise self.SSLv2_ADDED_REQUESTCERTIFICATE()

    @ATMT.state()
    def SSLv2_ADDED_REQUESTCERTIFICATE(self):
        pass

    @ATMT.condition(SSLv2_ADDED_REQUESTCERTIFICATE)
    def sslv2_should_send_RequestCertificate(self):
        self.flush_records()
        raise self.SSLv2_SENT_REQUESTCERTIFICATE()

    @ATMT.state()
    def SSLv2_SENT_REQUESTCERTIFICATE(self):
        raise self.SSLv2_WAITING_CLIENTCERTIFICATE()

    @ATMT.state()
    def SSLv2_WAITING_CLIENTCERTIFICATE(self):
        self.get_next_msg()
        raise self.SSLv2_RECEIVED_CLIENTCERTIFICATE()

    @ATMT.state()
    def SSLv2_RECEIVED_CLIENTCERTIFICATE(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_CLIENTCERTIFICATE, prio=1)
    def sslv2_should_handle_ClientCertificate(self):
        self.raise_on_packet(SSLv2ClientCertificate,
                             self.SSLv2_HANDLED_CLIENTCERTIFICATE)

    @ATMT.condition(SSLv2_RECEIVED_CLIENTCERTIFICATE, prio=2)
    def sslv2_missing_ClientCertificate(self):
        raise self.SSLv2_MISSING_CLIENTCERTIFICATE()

    @ATMT.state()
    def SSLv2_MISSING_CLIENTCERTIFICATE(self):
        self.vprint("Missing SSLv2 ClientCertificate!")
        raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.state()
    def SSLv2_HANDLED_CLIENTCERTIFICATE(self):
        selv.vprint("Received client certificate...")
        # We could care about the client CA, but we don't.
        raise self.SSLv2_HANDLED_CLIENTFINISHED()

    ################### end of SSLv2 client authentication ####################

    @ATMT.condition(SSLv2_HANDLED_CLIENTFINISHED, prio=3)
    def sslv2_should_add_ServerFinished(self):
        self.add_record(is_sslv2=True)
        self.add_msg(SSLv2ServerFinished(sid=randstring(16)))
        raise self.SSLv2_ADDED_SERVERFINISHED()

    @ATMT.state()
    def SSLv2_ADDED_SERVERFINISHED(self):
        pass

    @ATMT.condition(SSLv2_ADDED_SERVERFINISHED)
    def sslv2_should_send_ServerFinished(self):
        self.flush_records()
        raise self.SSLv2_SENT_SERVERFINISHED()

    @ATMT.state()
    def SSLv2_SENT_SERVERFINISHED(self):
        self.vprint("SSLv2 handshake completed!")
        self.vprint_sessioninfo()
        if self.is_echo_server:
            self.vprint("Will now act as a simple echo server.")
        raise self.SSLv2_WAITING_CLIENTDATA()

    ######################## end of SSLv2 handshake ###########################

    @ATMT.state()
    def SSLv2_WAITING_CLIENTDATA(self):
        self.get_next_msg(self.max_client_idle_time, 1)
        raise self.SSLv2_RECEIVED_CLIENTDATA()

    @ATMT.state()
    def SSLv2_RECEIVED_CLIENTDATA(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_CLIENTDATA)
    def sslv2_should_handle_ClientData(self):
        if not self.buffer_in:
            self.vprint("Client idle time maxed out.")
            raise self.SSLv2_CLOSE_NOTIFY()
        p = self.buffer_in[0]
        self.buffer_in = self.buffer_in[1:]
        if hasattr(p, "load"):
            cli_data = p.load
            print("> Received: %r" % cli_data)
            if cli_data.startswith(b"goodbye"):
                self.vprint()
                self.vprint("Seems like the client left...")
                raise self.WAITING_CLIENT()
        else:
            cli_data = str(p)
            print("> Received: %r" % p)

        lines = cli_data.split(b"\n")
        for l in lines:
            if l.startswith(b"stop_server"):
                raise self.SSLv2_CLOSE_NOTIFY_FINAL()

        answer = b""
        if cli_data.startswith(b"GET / HTTP/1.1"):
            p = Raw(self.http_sessioninfo())

        if self.is_echo_server or recv_data.startswith(b"GET / HTTP/1.1"):
            self.add_record(is_sslv2=True)
            self.add_msg(p)
            raise self.SSLv2_ADDED_SERVERDATA()

        raise self.SSLv2_HANDLED_CLIENTDATA()

    @ATMT.state()
    def SSLv2_HANDLED_CLIENTDATA(self):
        raise self.SSLv2_WAITING_CLIENTDATA()

    @ATMT.state()
    def SSLv2_ADDED_SERVERDATA(self):
        pass

    @ATMT.condition(SSLv2_ADDED_SERVERDATA)
    def sslv2_should_send_ServerData(self):
        self.flush_records()
        raise self.SSLv2_SENT_SERVERDATA()

    @ATMT.state()
    def SSLv2_SENT_SERVERDATA(self):
        raise self.SSLv2_WAITING_CLIENTDATA()

    @ATMT.state()
    def SSLv2_CLOSE_NOTIFY(self):
        """
        There is no proper way to end an SSLv2 session.
        We try and send a 'goodbye' message as a substitute.
        """
        self.vprint()
        self.vprint("Trying to send 'goodbye' to the client...")

    @ATMT.condition(SSLv2_CLOSE_NOTIFY)
    def sslv2_close_session(self):
        self.add_record()
        self.add_msg(Raw('goodbye'))
        try:
            self.flush_records()
        except:
            self.vprint("Could not send our goodbye. The client probably left.")
            self.buffer_out = []
        self.socket.close()
        raise self.WAITING_CLIENT()

    @ATMT.state()
    def SSLv2_CLOSE_NOTIFY_FINAL(self):
        """
        There is no proper way to end an SSLv2 session.
        We try and send a 'goodbye' message as a substitute.
        """
        self.vprint()
        self.vprint("Trying to send 'goodbye' to the client...")

    @ATMT.condition(SSLv2_CLOSE_NOTIFY_FINAL)
    def sslv2_close_session_final(self):
        self.add_record()
        self.add_msg(Raw('goodbye'))
        try:
            self.flush_records()
        except:
            self.vprint("Could not send our goodbye. The client probably left.")
        self.socket.close()
        raise self.FINAL()

    @ATMT.state(final=True)
    def FINAL(self):
        self.vprint("Closing server socket...")
        self.serversocket.close()
        self.vprint("Ending TLS server automaton.")

