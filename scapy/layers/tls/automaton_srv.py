# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
#               2019 Romain Perez

"""
TLS server automaton. This makes for a primitive TLS stack.
Obviously you need rights for network access.

We support versions SSLv2 to TLS 1.3, along with many features.

In order to run a server listening on tcp/4433:
> from scapy.all import *
> t = TLSServerAutomaton(mycert='<cert.pem>', mykey='<key.pem>')
> t.run()
"""

import socket
import binascii
import struct
import time
import secrets
from scapy.error import log_runtime, warning

from scapy.config import conf
from scapy.packet import Raw
from scapy.pton_ntop import inet_pton
from scapy.utils import get_temp_file, randstring, repr_hex
from scapy.automaton import ATMT
from scapy.error import warning
from scapy.layers.tls.automaton import _TLSAutomaton
from scapy.layers.tls.cert import PrivKeyRSA, PrivKeyECDSA
from scapy.layers.tls.basefields import _tls_version, _tls_version_options
from scapy.layers.tls.session import tlsSession
from scapy.layers.tls.crypto.groups import _tls_named_groups
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_SH, \
    TLS_Ext_SupportedGroups, TLS_Ext_Cookie, \
    TLS_Ext_SignatureAlgorithms, TLS_Ext_PSKKeyExchangeModes, \
    TLS_Ext_EarlyDataIndicationTicket, \
    TLS_Ext_SupportedVersion_CH, TLS_Ext_RenegotiationInfo 
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_SH, TLS_Ext_KeyShare_SHCC, \
    KeyShareEntry, TLS_Ext_KeyShare_HRR, TLS_Ext_PreSharedKey_CH, \
    TLS_Ext_PreSharedKey_SH
from scapy.layers.tls.handshake import TLSCertificate, TLSCertificateRequest, \
    TLSCertificateVerify, TLSClientHello, TLSClientKeyExchange, TLSFinished, \
    TLSServerHello, TLSHelloRequest, TLSServerHelloDone, TLSServerKeyExchange, \
    _ASN1CertAndExt, TLS13ServerHello, TLS13ServerHelloCC, TLS13Certificate, TLS13ClientHello, \
    TLSEncryptedExtensions, TLSEncryptedExtensionsNDcPP, TLS13HelloRetryRequest, TLS13CertificateRequest, \
    TLS13KeyUpdate, TLS13KeyUpdateCC, TLS13NewSessionTicket
from scapy.layers.tls.handshake_sslv2 import SSLv2ClientCertificate, \
    SSLv2ClientFinished, SSLv2ClientHello, SSLv2ClientMasterKey, \
    SSLv2RequestCertificate, SSLv2ServerFinished, SSLv2ServerHello, \
    SSLv2ServerHelloCC, SSLv2ServerVerify
from scapy.layers.tls.record import TLSAlert, TLSChangeCipherSpec, \
    TLSApplicationData
from scapy.layers.tls.record_tls13 import TLS13
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.crypto.suites import _tls_cipher_suites_cls, \
    get_usable_ciphersuites

from scapy.packet import Raw
from scapy.layers.tls.crypto.groups import _nist_curves 
if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

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

    #def parse_args(self, server="127.0.0.1", sport=4433,
    def parse_args(self, server="10.83.84.67", sport=4433,
                   mycert=None, mykey=None,
                   preferred_ciphersuite=None,
                   client_auth=False,
                   hello_reset=False,
                   plain_ee=False,
                   missing_finished_message=False,
                   altered_signature=False,
                   altered_finish=False,
                   altered_y_coordinate=False,
                   undefined_TLS_version=None,
                   version_confusion=False,
                   invalid_supported_versions=False,
                   version=None,
                   specify_cipher=None,
                   specify_sig_alg=None,
                   explicit_ecdh_curve=False,
                   empty_certificate=False,
                   downgrade_protection=None,
                   non_zero_renegotiation_info=False,
                   altered_renegotiation_info=False,
                   verify_data=None,
                   valid_renegotiation_info=False,
                   altered_legacy_session_id=False,
                   is_echo_server=True,
                   max_client_idle_time=60,
                   handle_session_ticket=None,
                   session_ticket_file=None,
                   curve=None,
                   cookie=False,
                   psk=None,
                   psk_mode=None,
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
        except Exception:
            tmp = socket.getaddrinfo(socket.getfqdn(server), sport)

        self.serversocket = None
        self.ip_family = tmp[0][0]
        self.local_ip = tmp[0][4][0]
        self.local_port = sport
        self.remote_ip = None
        self.remote_port = None
        self.local_port = sport
        self.altered_finish = altered_finish 
        self.plain_ee = plain_ee
        self.missing_finished_message = missing_finished_message
        self.specify_cipher = specify_cipher
        self.altered_signature = altered_signature
        self.altered_y_coordinate = altered_y_coordinate
        self.version_confusion = version_confusion
        self.invalid_supported_versions = invalid_supported_versions
        self.undefined_TLS_version = undefined_TLS_version
        self.specify_sig_alg = specify_sig_alg
        self.explicit_ecdh_curve = explicit_ecdh_curve
        self.empty_certificate = empty_certificate
        self.downgrade_protection = downgrade_protection
        self.verify_data=verify_data
        self.altered_legacy_session_id = altered_legacy_session_id
        self.renegotiated_connection = None
        self.specify_tls_version = version
        self.preferred_ciphersuite = preferred_ciphersuite
        self.client_auth = client_auth
        self.hello_reset = hello_reset
        self.non_zero_renegotiation_info = non_zero_renegotiation_info
        self.valid_renegotiation_info = valid_renegotiation_info
        self.renegotiated_connection = None
        self.altered_renegotiation_info = altered_renegotiation_info
        self.is_echo_server = is_echo_server
        self.max_client_idle_time = max_client_idle_time
        self.curve = None
        #self.curve = curve
        self.cookie = cookie
        self.psk_secret = psk
        self.psk_mode = psk_mode
        if handle_session_ticket is None:
            handle_session_ticket = session_ticket_file is not None
        if handle_session_ticket:
            session_ticket_file = session_ticket_file or get_temp_file()
        self.handle_session_ticket = handle_session_ticket
        self.session_ticket_file = session_ticket_file
        for (group_id, ng) in _tls_named_groups.items():
            if ng == curve:
                self.curve = group_id

    def vprint_sessioninfo(self):
        if self.verbose:
            s = self.cur_session
            v = _tls_version[s.tls_version]
            self.vprint("Version       : %s" % v)
            cs = s.wcs.ciphersuite.name
            self.vprint("Cipher suite  : %s" % cs)
            if s.tls_version < 0x0304:
                ms = s.master_secret
            else:
                ms = s.tls13_master_secret
            self.vprint("Master secret : %s" % repr_hex(ms))
            if s.client_certs:
                self.vprint("Client certificate chain: %r" % s.client_certs)

            if s.tls_version <= 0x0303:
                self.vprint()
                self.vprint()
                print("CLIENT_RANDOM %s" % repr_hex(s.client_random), repr_hex(ms))
                #self.vprint("MASTER SECRET: %s" % repr_hex(ms))
                self.vprint()
                #fval = self.getfieldval("vdata")
                #print("This end verify data %s" % repr_hex(s.vdata))
            if s.tls_version >= 0x0304:
                res_secret = s.tls13_derived_secrets["resumption_secret"]
                self.vprint("Resumption master secret : %s" %
                            repr_hex(res_secret))
                self.vprint()
                self.vprint()
                print("CLIENT_HANDSHAKE_TRAFFIC_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["client_handshake_traffic_secret"]))
                print("SERVER_HANDSHAKE_TRAFFIC_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["server_handshake_traffic_secret"]))
                print("CLIENT_TRAFFIC_SECRET_0 %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["client_traffic_secrets"][0]))
                print("SERVER_TRAFFIC_SECRET_0 %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["server_traffic_secrets"][0]))
                print("EXPORTER_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["exporter_secret"]))
            self.vprint()

    def print_tls13secrets(self):
        s = self.cur_session
        self.vprint()
        self.vprint()
        print("CLIENT_HANDSHAKE_TRAFFIC_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["client_handshake_traffic_secret"]))
        print("SERVER_HANDSHAKE_TRAFFIC_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["server_handshake_traffic_secret"]))
        print("CLIENT_TRAFFIC_SECRET_0 %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["client_traffic_secrets"][0]))
        print("SERVER_TRAFFIC_SECRET_0 %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["server_traffic_secrets"][0]))
        print("EXPORTER_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["exporter_secret"]))

    def http_sessioninfo(self):
        header = "HTTP/1.1 200 OK\r\n"
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
        if self.cur_session.tls_version < 0x0304:
            ms = self.cur_session.master_secret
        else:
            ms = self.cur_session.tls13_master_secret

        s += "Master secret : %s\n" % repr_hex(ms)
        body = "<html><body><pre>%s</pre></body></html>\r\n\r\n" % s
        answer = (header + body) % len(body)
        return answer

    @ATMT.state(initial=True)
    def INITIAL(self):
        self.vprint("Starting TLS server automaton.")
        self.vprint("Receiving 'stop_server' will cause a graceful exit.")
        self.vprint("Interrupting with Ctrl-Z might leave a loose socket hanging.")  # noqa: E501
        raise self.BIND()

    @ATMT.state()
    def BIND(self):
        s = socket.socket(self.ip_family, socket.SOCK_STREAM)
        self.serversocket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.local_ip, self.local_port))
            s.listen(1)
        except Exception as e:
            m = "Unable to bind on %s:%d! (%s)" % (
                self.local_ip,
                self.local_port,
                e
            )
            self.vprint()
            self.vprint(m)
            self.vprint("Maybe some server is already listening there?")
            self.vprint()
            raise self.FINAL()
        raise self.WAITING_CLIENT()

    @ATMT.state()
    def SOCKET_CLOSED(self):
        raise self.WAITING_CLIENT()

    @ATMT.state()
    def WAITING_CLIENT(self):
        self.buffer_out = []
        self.buffer_in = []
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
        s = self.cur_session
        s.altered_finish = self.altered_finish
        s.version_confusion = self.version_confusion
        s.invalid_supported_versions = self.invalid_supported_versions
        s.plain_ee = self.plain_ee
        s.verify_data = self.verify_data
        s.missing_finished_message = self.missing_finished_message
        s.undefined_TLS_version =  self.undefined_TLS_version
        s.altered_signature = self.altered_signature
        s.specify_sig_alg = self.specify_sig_alg
        s.explicit_ecdh_curve = self.explicit_ecdh_curve
        s.empty_certificate = self.empty_certificate
        s.downgrade_protection = self.downgrade_protection
        s.non_zero_renegotiation_info = self.non_zero_renegotiation_info
        s.valid_renegotiation_info = self.valid_renegotiation_info
        s.hello_reset = self.hello_reset
        s.altered_legacy_session_id = self.altered_legacy_session_id
        s.renegotiated_connection = self.renegotiated_connection
        s.altered_renegotiation_info =  self.altered_renegotiation_info
        if isinstance(self.mykey, PrivKeyRSA):
            self.cur_session.server_rsa_key = self.mykey
        # elif isinstance(self.mykey, PrivKeyECDSA):
        #    self.cur_session.server_ecdsa_key = self.mykey
        raise self.WAITING_CLIENTFLIGHT1()

    @ATMT.state()
    def WAITING_CLIENTFLIGHT1(self):
        self.get_next_msg()
        raise self.RECEIVED_CLIENTFLIGHT1()

    @ATMT.state()
    def RECEIVED_CLIENTFLIGHT1(self):
        pass

    #                           TLS handshake                                 #

    @ATMT.condition(RECEIVED_CLIENTFLIGHT1, prio=1)
    def tls13_should_handle_ClientHello(self):
        if self.specify_tls_version <= 0x0303:
            self.raise_on_packet(TLSClientHello,
                             self.HANDLED_CLIENTHELLO)
        else:
            self.raise_on_packet(TLS13ClientHello,
                             self.tls13_HANDLED_CLIENTHELLO)

    @ATMT.condition(RECEIVED_CLIENTFLIGHT1, prio=2)
    def should_handle_ClientHello(self):
        self.raise_on_packet(TLSClientHello,
                             self.HANDLED_CLIENTHELLO)

    @ATMT.state()
    def HANDLED_CLIENTHELLO(self):
        """
        We extract cipher suites candidates from the client's proposition.
        """
        if self.specify_tls_version == 0x0200 or self.specify_tls_version == 0x0002:
            raise self.SSLv2_HANDLED_CLIENTHELLO()
        p=self.cur_pkt
        self.supported_tls13_tls12 = False
        if self.cur_session.advertised_tls_version >= 0x0304 and self.specify_tls_version <= 0x0303:
            versionlist = []
            tls13_12_list = [772, 771]
            for item in p['TLS Extension - Supported Versions (for ClientHello)'].versions[:]:
                if hex(item) == '0x303' or hex(item) == '0x304':
                    versionlist.append(item)
            if all(item in versionlist for item in tls13_12_list):
                self.supported_tls13_tls12 = True
        if self.specify_tls_version:
            self.cur_session.advertised_tls_version = self.specify_tls_version
        self.vprint("Contents of Client Hello Received")
        p.show()
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        if get_usable_ciphersuites(self.cur_pkt.ciphers, kx):
            raise self.PREPARE_SERVERFLIGHT1()
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
        if self.specify_cipher != None:
            #Allow for use case where ciphersuite is specifed and client only supports TLS 1.2
            c = self.specify_cipher
        if self.specify_tls_version <= 0x0303:
            v = self.specify_tls_version
            # Need to remove TLS 1.3 ciphersuites when specifying the test server use TLS 1.2:
            if self.supported_tls13_tls12 == True:
                for item in usable_suites[:]:
                    if hex(item) == '0x1301' or hex(item) == '0x1302' or hex(item) == '0x1303'or hex(item) == '0x1304' or hex(item) == '0x1305':
                        usable_suites.remove(item)
                c = usable_suites[0]
                if self.specify_cipher != None:
                    #Allow for use case where ciphersuite is specifed and client supports TLS 1.3 and 1.2
                    c = self.specify_cipher
            if self.specify_tls_version <= 0x0301 and self.supported_tls13_tls12 == False:
                # When the version is TLS 1.1, 1.0, or SSL v3 need to use the default ciphersuite of TLS_RSA_WITH_AES_128_CBC_SHA
                c = 0x002F
            if self.non_zero_renegotiation_info == True:
                ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x1)]
                self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
            if self.valid_renegotiation_info == True or self.altered_renegotiation_info == True:
                ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x0)]
                self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
            else:
                self.add_msg(TLSServerHello(cipher=c,version=v))
        elif self.specify_tls_version == 0x0303 and self.version_confusion == True:
            v = self.specify_tls_version
            self.add_msg(TLSServerHello(cipher=c,version=v))
        #elif self.specify_tls_version == 0x0303 and self.non_zero_renegotiation_info == True:
        #    ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x0)]
        #    self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
        else:
            self.add_msg(TLSServerHello(cipher=c))
        raise self.ADDED_SERVERHELLO()

    @ATMT.state()
    def ADDED_SERVERHELLO(self):
        pass

    @ATMT.condition(ADDED_SERVERHELLO)
    def should_add_Certificate(self):
        c = self.buffer_out[-1].msg[0].cipher
        if not _tls_cipher_suites_cls[c].kx_alg.anonymous:
            if self.empty_certificate == True:
                certs = []
                self.add_msg(TLSCertificate(certs=certs))
            else:
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
        #self.vprint(self.cur_pkt.mysummary())
        pass

    @ATMT.condition(HANDLED_CLIENTCERTIFICATE, prio=2)
    def should_handle_Alert_from_ClientCertificate(self):
        self.raise_on_packet(TLSAlert,
                             self.HANDLED_ALERT_FROM_CLIENTCERTIFICATE)

    @ATMT.state()
    def HANDLED_ALERT_FROM_CLIENTCERTIFICATE(self):
        self.vprint("Received Alert message instead of ClientKeyExchange!")
        self.vprint(self.cur_pkt.mysummary())
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
        self.vprint(self.cur_pkt.mysummary())
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
        if self.missing_finished_message is True:
            self.add_msg(TLSServerHelloDone())
        else:
            #self.cur_pkt.display()
            self.add_msg(TLSFinished())
            #self.cur_pkt.display()
            #myvdata=self.cur_pkt.vdata
            #s = self.cur_session
            #con_end = s.connection_end
            #handshake_msg = b"".join(s.handshake_messages)
            #ms = s.master_secret
            #verify_data = s.wcs.prf.compute_verify_data(con_end, "write", handshake_msg, ms)
            #rw1 = binascii.hexlify(myvdata)
            #print("This end verify data %s" % myvdata)
            #print("Other end verify data %s" % verify_data)
            #s = self.cur_session
            #con_end = s.connection_end
            #handshake_msg = b"".join(s.handshake_messages)
            #ms = s.master_secret
            #verify_data = s.rcs.prf.compute_verify_data(con_end, "read", handshake_msg, ms)
            #rw2 = binascii.hexlify(verify_data)
            #print("Other end verify data %s" % verify_data)
        raise self.ADDED_SERVERFINISHED()

    @ATMT.state()
    def ADDED_SERVERFINISHED(self):
        pass

    @ATMT.condition(ADDED_SERVERFINISHED)
    def should_send_ServerFlight2(self):
        self.flush_records()
        #print ("Test")
        s = self.cur_session
        client_verify_data = self.cur_pkt.vdata
        #print("Client verify data %s" % client_verify_data)
        #print("client verify_data type %s" %type (client_verify_data))
        #myvdata = str(self.cur_pkt.vdata)
        #my_str_as_bytes = str.encode(myvdata)
        #print(type(my_str_as_bytes)) # ensure it is byte representation
        #my_decoded_str = my_str_as_bytes.decode()
        #print(type(my_decoded_str)) # ensure it is string representation
        #single = my_decoded_str
        #single = str(self.cur_pkt.vdata)
        #print("".join([single, s.verify_data]))
        #rick = single + s.verify_data
        #print("".join([self.cur_pkt.vdata, s.verify_data]))
        #print("server verify_data type %s" % type(server_verify_data))
        #modified_list = str(s.verify_data).replace('b', '')
        #print("Other end verify data %s" % modified_list)
        #single = str(self.cur_pkt.vdata) 
        #both = str(self.cur_pkt.vdata) + modified_list
        #both = ("".join([single, modified_list]))
        #print("".join([single, modified_list]))
        #both =  both.encode()
        #modified_list = str(both).replace('b', '')
        #mystring = both.replace("''", "").replace("'", "").replace('b', '')
        #rick = str(mystring)
        #print("Both %s" % rick)
        server_verify_data = s.verify_data
        #print("server verify_data type %s" %type (server_verify_data))
        #print("Server verify data %s" % s.verify_data)
        self.renegotiated_connection = client_verify_data + server_verify_data
        #print("Both %s" % both)
        #self.renegotiated_connection = both
        #s = self.cur_session
        #con_end = s.connection_end
        #handshake_msg = b"".join(s.handshake_messages)
        #ms = s.master_secret
        #verify_data = s.rcs.prf.compute_verify_data(con_end, "read", handshake_msg, ms)
        #print("This end verify data %s" % verify_data)
        raise self.SENT_SERVERFLIGHT2()

    @ATMT.state()
    def SENT_SERVERFLIGHT2(self):
        if self.missing_finished_message is False:
            self.vprint("TLS handshake completed!")
            self.vprint_sessioninfo()
            if self.hello_reset:
                self.add_msg(TLSHelloRequest())
                self.flush_records()
            #if self.valid_renegotiation_info == True:
            #    raise self.WAITING_CLIENTFLIGHT1()
                #print ("waiting")
                #self.get_next_msg()
                #print ("received")
                #raise self.RECEIVED_CLIENTFLIGHTREG()
            if self.is_echo_server:
                self.vprint("Will now act as a simple echo server.")
            if self.altered_renegotiation_info == True:
            #if self.valid_renegotiation_info == True or self.altered_renegotiation_info == True:
                self.get_next_msg()
                #self.raise_on_packet(TLSClientHello, self.HANDLED_CLIENTHELLO)
                raise self.RECEIVED_CLIENTFLIGHTREG()
            raise self.WAITING_CLIENTDATA()
        else:
            raise self.WAITING_CLIENTDATA()

    @ATMT.state()
    def RECEIVED_CLIENTFLIGHTREG(self):
        pass

    @ATMT.condition(RECEIVED_CLIENTFLIGHTREG, prio=1)
    def should_handle_ClientHello2(self):
        self.raise_on_packet(TLSClientHello,
                             self.HANDLED_CLIENTHELLO2)

    @ATMT.state()
    def HANDLED_CLIENTHELLO2(self):
        """
        We extract cipher suites candidates from the client's proposition.
        """
        if self.specify_tls_version == 0x0200 or self.specify_tls_version == 0x0002:
            raise self.SSLv2_HANDLED_CLIENTHELLO()
        p=self.cur_pkt
        self.supported_tls13_tls12 = False
        if self.cur_session.advertised_tls_version >= 0x0304 and self.specify_tls_version <= 0x0303:
            versionlist = []
            tls13_12_list = [772, 771]
            for item in p['TLS Extension - Supported Versions (for ClientHello)'].versions[:]:
                if hex(item) == '0x303' or hex(item) == '0x304':
                    versionlist.append(item)
            if all(item in versionlist for item in tls13_12_list):
                self.supported_tls13_tls12 = True
        if self.specify_tls_version:
            self.cur_session.advertised_tls_version = self.specify_tls_version
        self.vprint("Contents of Client Hello Received")
        p.show()
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        if get_usable_ciphersuites(self.cur_pkt.ciphers, kx):
            raise self.PREPARE_SERVERFLIGHTREG()
        raise self.NO_USABLE_CIPHERSUITE()

    @ATMT.state()
    def NO_USABLE_CIPHERSUITE(self):
        self.vprint("No usable cipher suite!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(RECEIVED_CLIENTFLIGHTREG, prio=2)
    def missing_ClientHello(self):
        raise self.MISSING_CLIENTHELLO()

    @ATMT.state(final=True)
    def MISSING_CLIENTHELLO(self):
        self.vprint("Missing ClientHello message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def PREPARE_SERVERFLIGHTREG(self):
        self.add_record()

    @ATMT.condition(PREPARE_SERVERFLIGHTREG)
    def should_add_ServerHelloReg(self):
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
        if self.specify_cipher != None:
            #Allow for use case where ciphersuite is specifed and client only supports TLS 1.2
            c = self.specify_cipher
        if self.specify_tls_version <= 0x0303:
            v = self.specify_tls_version
        if self.altered_renegotiation_info == True:
                self.buffer_out = []
                #self.buffer_in = []
                self.add_record()
                #ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x0)]
                #Alter the fifth byte which is the client_verify_data
                self.altered_renegotiation_info = self.renegotiated_connection[:5] + randstring(1) + self.renegotiated_connection[6:]
                if self.altered_renegotiation_info == self.renegotiated_connection:
                    warning("renegotiation_info was not altered.  Run Test Again!")
                else:
                    ext = [TLS_Ext_RenegotiationInfo(renegotiated_connection=self.altered_renegotiation_info)]
                    self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
                    raise self.ADDED_SERVERHELLO()
                #self.buffer_out = []
                #self.add_record()
                #self.add_msg(TLSChangeCipherSpec())
                #self.add_msg(TLSFinished())
                #self.cur_pkt.display()
                #self.flush_records()
                #raise self.WAITING_CLIENTDATA()    
            # Need to remove TLS 1.3 ciphersuites when specifying the test server use TLS 1.2:
       #     if self.supported_tls13_tls12 == True:
       #         for item in usable_suites[:]:
       #             if hex(item) == '0x1301' or hex(item) == '0x1302' or hex(item) == '0x1303'or hex(item) == '0x1304' or hex(item) == '0x1305':
       #                 usable_suites.remove(item)
       #         c = usable_suites[0]
       #         if self.specify_cipher != None:
                    #Allow for use case where ciphersuite is specifed and client supports TLS 1.3 and 1.2
       #             c = self.specify_cipher
       #     if self.specify_tls_version <= 0x0301 and self.supported_tls13_tls12 == False:
                # When the version is TLS 1.1, 1.0, or SSL v3 need to use the default ciphersuite of TLS_RSA_WITH_AES_128_CBC_SHA
       #         c = 0x002F
       #     if self.non_zero_renegotiation_info == True:
       #         ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x1)]
       #         self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
       #     if self.valid_renegotiation_info == True:
       #         self.add_record()
       #         ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x0)]
       #         self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
       #         self.flush_records()
       #         raise self.WAITING_CLIENTDATA()
       #     else:
       #         self.add_msg(TLSServerHello(cipher=c,version=v))
       # elif self.specify_tls_version == 0x0303 and self.version_confusion == True:
       #     v = self.specify_tls_version
       #     self.add_msg(TLSServerHello(cipher=c,version=v))
        #elif self.specify_tls_version == 0x0303 and self.non_zero_renegotiation_info == True:
        #    ext = [TLS_Ext_RenegotiationInfo(reneg_conn_len=0x0)]
        #    self.add_msg(TLSServerHello(cipher=c,version=v, ext=ext))
        #else:
        #    self.add_msg(TLSServerHello(cipher=c))
        #self.flush_records()
        #raise self.WAITING_CLIENTDATA()
        #raise self.ADDED_SERVERHELLO()

    #                       end of TLS handshake                              #

    #                       TLS 1.3 handshake                                 #
    @ATMT.state()
    def tls13_HANDLED_CLIENTHELLO(self):
        """
          Check if we have to send an HelloRetryRequest
          XXX check also with non ECC groups
        """
        p=self.cur_pkt
        self.vprint("Contents of TLS 1.3 Client Hello Received:")
        p.show()
        s = self.cur_session
        m = s.handshake_messages_parsed[-1]
        #  Check if we have to send an HelloRetryRequest
        #  XXX check also with non ECC groups
        if self.curve:
            # We first look for a KeyShareEntry with same group as self.curve
            if not _tls_named_groups[self.curve] in s.tls13_client_pubshares:
                # We then check if self.curve was advertised in SupportedGroups
                # extension
                for e in m.ext:
                    if isinstance(e, TLS_Ext_SupportedGroups):
                        if self.curve in e.groups:
                            # Here, we need to send an HelloRetryRequest
                            raise self.tls13_PREPARE_HELLORETRYREQUEST()
        raise self.tls13_PREPARE_SERVERFLIGHT1()

    @ATMT.state()
    def tls13_PREPARE_HELLORETRYREQUEST(self):
        pass

    @ATMT.condition(tls13_PREPARE_HELLORETRYREQUEST)
    def tls13_should_add_HelloRetryRequest(self):
        self.add_record(is_tls13=False)
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        if self.specify_cipher:
            c = self.specify_cipher
        else:
            usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
            c = usable_suites[0]
        ext = [TLS_Ext_SupportedVersion_SH(version="TLS 1.3"),
               TLS_Ext_KeyShare_HRR(selected_group=_tls_named_groups[self.curve])]  # noqa: E501
        if self.cookie:
            ext += TLS_Ext_Cookie()
        p = TLS13HelloRetryRequest(cipher=c, ext=ext)
        self.add_msg(p)
        self.flush_records()
        raise self.tls13_HANDLED_HELLORETRYREQUEST()

    @ATMT.state()
    def tls13_HANDLED_HELLORETRYREQUEST(self):
        pass

    @ATMT.condition(tls13_HANDLED_HELLORETRYREQUEST)
    def tls13_should_add_ServerHello_from_HRR(self):
        raise self.WAITING_CLIENTFLIGHT1()
        #raise self.RECEIVED_CLIENTFLIGHT1()

    @ATMT.state()
    def tls13_PREPARE_SERVERFLIGHT1(self):
        if self.invalid_supported_versions == True:
            if isinstance(self.mykey, PrivKeyRSA):
                kx = "RSA"
            elif isinstance(self.mykey, PrivKeyECDSA):
                kx = "ECDSA"
            usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
            c = usable_suites[0]
            self.add_record(is_tls13=False)
            group = next(iter(self.cur_session.tls13_client_pubshares))
            ext = [TLS_Ext_SupportedVersion_SH(version="TLS 1.3")]
            ext += TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=group))
            p = TLS13ServerHello(cipher=c, sid=self.cur_session.sid, ext=ext)
            Raw(p)
            p['TLS Extension - Supported Versions (for ServerHello)'].version = 0x0303
            print ("Content of TLS 1.3 Server Hello specifying version TLS 1.2 in the Supported Versions TLS Extension")
            p.show()
            self.add_msg(p)
            self.flush_records()
            raise self.tls13_WAITING_CLIENTFLIGHT2()

        if self.version_confusion == True:
            self.add_record(is_tls13=False)
            if self.specify_cipher:
                c = self.specify_cipher
            group = next(iter(self.cur_session.tls13_client_pubshares))
            ext = [TLS_Ext_SupportedVersion_SH(version="TLS 1.3")]
            ext += TLS_Ext_KeyShare_SHCC(server_share=KeyShareEntry(group=group))
            p = TLS13ServerHelloCC(cipher=c, sid=self.cur_session.sid, ext=ext)
            print ("Content of TLS 1.3 Server Hello specifying a TLS 1.2 ciphersuite")
            p.show()
            self.add_msg(p)
            self.flush_records()
            raise self.tls13_WAITING_CLIENTFLIGHT2()
        self.add_record(is_tls13=False)

    def verify_psk_binder(self, psk_identity, obfuscated_age, binder):
        """
        This function verifies the binder received in the 'pre_shared_key'
        extension and return the resumption PSK associated with those
        values.

        The arguments psk_identity, obfuscated_age and binder are taken
        from 'pre_shared_key' in the ClientHello.
        """
        with open(self.session_ticket_file, "rb") as f:
            for line in f:
                s = line.strip().split(b';')
                if len(s) < 8:
                    continue
                ticket_label = binascii.unhexlify(s[0])
                ticket_nonce = binascii.unhexlify(s[1])
                tmp = binascii.unhexlify(s[2])
                ticket_lifetime = struct.unpack("!I", tmp)[0]
                tmp = binascii.unhexlify(s[3])
                ticket_age_add = struct.unpack("!I", tmp)[0]
                tmp = binascii.unhexlify(s[4])
                ticket_start_time = struct.unpack("!I", tmp)[0]
                resumption_secret = binascii.unhexlify(s[5])
                tmp = binascii.unhexlify(s[6])
                res_ciphersuite = struct.unpack("!H", tmp)[0]
                tmp = binascii.unhexlify(s[7])
                max_early_data_size = struct.unpack("!I", tmp)[0]

                # Here psk_identity is a Ticket type but ticket_label is bytes,
                # we need to convert psk_identiy to bytes in order to compare
                # both strings
                if psk_identity.__bytes__() == ticket_label:

                    # We compute the resumed PSK associated the resumption
                    # secret
                    self.vprint("Ticket found in database !")
                    if res_ciphersuite not in _tls_cipher_suites_cls:
                        warning("Unknown cipher suite %d", res_ciphersuite)
                        # we do not try to set a default nor stop the execution
                    else:
                        cs_cls = _tls_cipher_suites_cls[res_ciphersuite]

                    hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
                    hash_len = hkdf.hash.digest_size

                    tls13_psk_secret = hkdf.expand_label(resumption_secret,
                                                         b"resumption",
                                                         ticket_nonce,
                                                         hash_len)
                    # We verify that ticket age is not expired
                    agesec = int((time.time() - ticket_start_time))
                    # agems = agesec * 1000
                    ticket_age = (obfuscated_age - ticket_age_add) % 0xffffffff  # noqa: F841, E501

                    # We verify the PSK binder
                    s = self.cur_session
                    if s.tls13_retry:
                        handshake_context = struct.pack("B", 254)
                        handshake_context += struct.pack("B", 0)
                        handshake_context += struct.pack("B", 0)
                        handshake_context += struct.pack("B", hash_len)
                        digest = hashes.Hash(hkdf.hash, backend=default_backend())  # noqa: E501
                        digest.update(s.handshake_messages[0])
                        handshake_context += digest.finalize()
                        for m in s.handshake_messages[1:]:
                            if (isinstance(TLS13ClientHello) or
                                    isinstance(TLSClientHello)):
                                handshake_context += m[:-hash_len - 3]
                            else:
                                handshake_context += m
                    else:
                        handshake_context = s.handshake_messages[0][:-hash_len - 3]  # noqa: E501

                    # We compute the binder key
                    # XXX use the compute_tls13_early_secrets() function
                    tls13_early_secret = hkdf.extract(None, tls13_psk_secret)
                    binder_key = hkdf.derive_secret(tls13_early_secret,
                                                    b"res binder",
                                                    b"")
                    computed_binder = hkdf.compute_verify_data(binder_key,
                                                               handshake_context)  # noqa: E501
                    if (agesec < ticket_lifetime and
                            computed_binder == binder):
                        self.vprint("Ticket has been accepted ! ")
                        self.max_early_data_size = max_early_data_size
                        self.resumed_ciphersuite = res_ciphersuite
                        return tls13_psk_secret
        self.vprint("Ticket has not been accepted ! Fallback to a complete handshake")  # noqa: E501
        return None

    @ATMT.condition(tls13_PREPARE_SERVERFLIGHT1)
    def tls13_should_add_ServerHello(self):
        psk_identity = None
        psk_key_exchange_mode = None
        obfuscated_age = None
        # XXX check ClientHello extensions...
        for m in reversed(self.cur_session.handshake_messages_parsed):
            if isinstance(m, (TLS13ClientHello, TLSClientHello)):
                for e in m.ext:
                    if isinstance(e, TLS_Ext_PreSharedKey_CH):
                        psk_identity = e.identities[0].identity
                        obfuscated_age = e.identities[0].obfuscated_ticket_age
                        binder = e.binders[0].binder

                        # For out-of-bound PSK, obfuscated_ticket_age should be
                        # 0. We use this field to distinguish between out-of-
                        # bound PSK and resumed PSK
                        is_out_of_band_psk = (obfuscated_age == 0)

                    if isinstance(e, TLS_Ext_PSKKeyExchangeModes):
                        psk_key_exchange_mode = e.kxmodes[0]

        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        if self.specify_cipher:
            c = self.specify_cipher
        elif self.specify_cipher == 0:
            # Special use case for sending TLS_NULL_WITH_NULL_NULL 
            self.add_record(is_tls13=False)
            c = self.specify_cipher
            group = next(iter(self.cur_session.tls13_client_pubshares))
            ext = [TLS_Ext_SupportedVersion_SH(version="TLS 1.3")]
            ext += TLS_Ext_KeyShare_SHCC(server_share=KeyShareEntry(group=group))
            p = TLS13ServerHelloCC(cipher=c, sid=self.cur_session.sid, ext=ext)
            print ("Content of TLS 1.3 Server Hello specifying the NULL ciphersuite")
            p.show()
            self.add_msg(p)
            self.flush_records()
            raise self.tls13_WAITING_CLIENTFLIGHT2()
        else:
            usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
            c = usable_suites[0]
        group = next(iter(self.cur_session.tls13_client_pubshares))
        ext = [TLS_Ext_SupportedVersion_SH(version="TLS 1.3")]
        if (psk_identity and obfuscated_age and psk_key_exchange_mode):
            s = self.cur_session
            if is_out_of_band_psk:
                # Handshake with external PSK authentication
                # XXX test that self.psk_secret is set
                s.tls13_psk_secret = binascii.unhexlify(self.psk_secret)
                # 0: "psk_ke"
                # 1: "psk_dhe_ke"
                if psk_key_exchange_mode == 1:
                    server_kse = KeyShareEntry(group=group)
                    ext += TLS_Ext_KeyShare_SH(server_share=server_kse)
                ext += TLS_Ext_PreSharedKey_SH(selected_identity=0)
            else:
                resumption_psk = self.verify_psk_binder(psk_identity,
                                                        obfuscated_age,
                                                        binder)
                if resumption_psk is None:
                    # We did not find a ticket matching the one provided in the
                    # ClientHello. We fallback to a regular 1-RTT handshake
                    server_kse = KeyShareEntry(group=group)
                    ext += [TLS_Ext_KeyShare_SH(server_share=server_kse)]
                else:
                    # 0: "psk_ke"
                    # 1: "psk_dhe_ke"
                    if psk_key_exchange_mode == 1:
                        server_kse = KeyShareEntry(group=group)
                        ext += [TLS_Ext_KeyShare_SH(server_share=server_kse)]

                    ext += [TLS_Ext_PreSharedKey_SH(selected_identity=0)]
                    self.cur_session.tls13_psk_secret = resumption_psk
        #
        #else:
        elif self.curve and self.altered_y_coordinate == False:
            s = self.cur_session
            ext += TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=_tls_named_groups[self.curve]))

        elif self.altered_y_coordinate != True and not self.curve:
            # Standard Handshake
            ext += TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=group))

        if self.altered_y_coordinate == True and self.curve:
            s = self.cur_session
            #m = s.handshake_messages_parsed[-1]
            ext += TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=_tls_named_groups[self.curve]))

        if self.cur_session.sid is not None:
            if self.altered_legacy_session_id == True:
                t = self.cur_session.sid
                t = t[:14] + randstring(1) + t[15:]
                if t == self.cur_session.sid:
                    warning("session id was not altered.  Run Test Again!")
                else:
                    p = TLS13ServerHello(cipher=c, sid=t, ext=ext)
                    print("Contents of session id before altering: [%s]" % repr_hex(self.cur_session.sid))
                    print("Contents of session id after altering:  [%s]" % repr_hex(t))
            else:
                p = TLS13ServerHello(cipher=c, sid=self.cur_session.sid, ext=ext)
            Raw(p)
            print ("Contents of Server Hello")
            p.show2()
            r = TLSEncryptedExtensions(extlen=0)
        else:
            p = TLS13ServerHello(cipher=c, ext=ext) 
            Raw(p)
            print ("Contents of Server Hello")
            p.show2()
            r = TLSEncryptedExtensions(extlen=0)
        #p.show()
        Raw(p)
        if self.altered_y_coordinate == True and p['Key Share Entry'][0].group in _nist_curves:
            y_coordinate = p['Key Share Entry'][0].key_exchange
            print("Contents of x y coordinate before altering: [%s]" % repr_hex(y_coordinate))
            altered_y_coordinate = y_coordinate[:-3] + randstring(1) + y_coordinate[-2:]
            if altered_y_coordinate == y_coordinate:
                warning("y coordinate was not altered.  Run Test Again!")
            else:
                p['Key Share Entry'][0].key_exchange = altered_y_coordinate
                print("Contents of x y coordinate after altering:  [%s]" % repr_hex(p['Key Share Entry'][0].key_exchange))
                print(" ")
        if self.plain_ee is True:
            r = TLSEncryptedExtensionsNDcPP(extlen=0)
            print("Sending a TLS 1.3 Server Hello and a Plaintext Encrypted Extension Message")
            p.show2()
            r.show2()
            self.add_msg(p)
            self.add_msg(r)
            self.flush_records()
            p = self.buffer_in
            if isinstance(p, TLSAlert):
                raise self.CLOSE_NOTIFY()
        if self.undefined_TLS_version == 0x0304 or self.undefined_TLS_version == 0x7f13 or self.undefined_TLS_version == 0x7f12:
            p.version = self.undefined_TLS_version
            print("Sending a TLS 1.3 Server Hello Handshake with TLS 1.3 (or lower draft) version in the legacy field")
            p.show2()
            self.add_msg(p)
            self.flush_records()
            p = self.buffer_in
            if isinstance(p, TLSAlert):
                raise self.CLOSE_NOTIFY()
        self.add_msg(p)
        raise self.tls13_ADDED_SERVERHELLO()

    @ATMT.state()
    def tls13_ADDED_SERVERHELLO(self):
        # If the client proposed a non-empty session ID in his ClientHello
        # he requested the middlebox compatibility mode (RFC8446, appendix D.4)
        # In this case, the server should send a dummy ChangeCipherSpec in
        # between the ServerHello and the encrypted handshake messages
        if self.cur_session.sid is not None:
            self.add_record(is_tls12=True)
            self.add_msg(TLSChangeCipherSpec())

    @ATMT.condition(tls13_ADDED_SERVERHELLO)
    def tls13_should_add_EncryptedExtensions(self):
        self.add_record(is_tls13=True)
        self.add_msg(TLSEncryptedExtensions(extlen=0))
        raise self.tls13_ADDED_ENCRYPTEDEXTENSIONS()

    @ATMT.state()
    def tls13_ADDED_ENCRYPTEDEXTENSIONS(self):
        pass

    @ATMT.condition(tls13_ADDED_ENCRYPTEDEXTENSIONS)
    def tls13_should_add_CertificateRequest(self):
        if self.client_auth:
            ext = [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss"])]
            p = TLS13CertificateRequest(ext=ext)
            self.add_msg(p)
        raise self.tls13_ADDED_CERTIFICATEREQUEST()

    @ATMT.state()
    def tls13_ADDED_CERTIFICATEREQUEST(self):
        pass

    @ATMT.condition(tls13_ADDED_CERTIFICATEREQUEST)
    def tls13_should_add_Certificate(self):
        # If a PSK is set, an extension pre_shared_key
        # was send in the ServerHello. No certificate should
        # be send here
        if not self.cur_session.tls13_psk_secret:
            certs = []
            for c in self.cur_session.server_certs:
                certs += _ASN1CertAndExt(cert=c)
            if self.empty_certificate == True:
                certs = []
            self.add_msg(TLS13Certificate(certs=certs))
        raise self.tls13_ADDED_CERTIFICATE()

    @ATMT.state()
    def tls13_ADDED_CERTIFICATE(self):
        pass

    @ATMT.condition(tls13_ADDED_CERTIFICATE)
    def tls13_should_add_CertificateVerifiy(self):
        if not self.cur_session.tls13_psk_secret:
            self.add_msg(TLSCertificateVerify())
        raise self.tls13_ADDED_CERTIFICATEVERIFY()

    @ATMT.state()
    def tls13_ADDED_CERTIFICATEVERIFY(self):
        pass

    @ATMT.condition(tls13_ADDED_CERTIFICATEVERIFY)
    def tls13_should_add_Finished(self):
        if self.missing_finished_message is True:
            self.add_msg(TLS13KeyUpdateCC())
        else:
            self.add_msg(TLSFinished())
        raise self.tls13_ADDED_SERVERFINISHED()

    @ATMT.state()
    def tls13_ADDED_SERVERFINISHED(self):
        pass

    @ATMT.condition(tls13_ADDED_SERVERFINISHED)
    def tls13_should_send_ServerFlight1(self):
        self.flush_records()
        raise self.tls13_WAITING_CLIENTFLIGHT2()

    @ATMT.state()
    def tls13_WAITING_CLIENTFLIGHT2(self):
        self.get_next_msg()
        raise self.tls13_RECEIVED_CLIENTFLIGHT2()

    @ATMT.state()
    def tls13_RECEIVED_CLIENTFLIGHT2(self):
        pass

    @ATMT.condition(tls13_RECEIVED_CLIENTFLIGHT2, prio=1)
    def tls13_should_handle_ClientFlight2(self):
        self.raise_on_packet(TLS13Certificate,
                             self.TLS13_HANDLED_CLIENTCERTIFICATE)

    @ATMT.condition(tls13_RECEIVED_CLIENTFLIGHT2, prio=2)
    def tls13_should_handle_Alert_from_ClientCertificate(self):
        self.raise_on_packet(TLSAlert,
                             self.TLS13_HANDLED_ALERT_FROM_CLIENTCERTIFICATE)

    @ATMT.state()
    def TLS13_HANDLED_ALERT_FROM_CLIENTCERTIFICATE(self):
        #self.vprint("Received Alert message instead of ClientKeyExchange!")
        self.vprint("Received Alert message!")
        self.vprint(self.cur_pkt.mysummary())
        #self.cur_pkt.show()
        #self.vprint(self.cur_pkt)
        if self.altered_signature or self.altered_finish or self.altered_y_coordinate or self.specify_sig_alg or self.empty_certificate:
            self.print_tls13secrets()
        raise self.CLOSE_NOTIFY()

    # For Middlebox compatibility (see RFC8446, appendix D.4)
    # a dummy ChangeCipherSpec record can be send. In this case,
    # this function just read the ChangeCipherSpec message and
    # go back in a previous state continuing with the next TLS 1.3
    # record
    @ATMT.condition(tls13_RECEIVED_CLIENTFLIGHT2, prio=3)
    def tls13_should_handle_ClientCCS(self):
        self.raise_on_packet(TLSChangeCipherSpec,
                             self.tls13_RECEIVED_CLIENTFLIGHT2)

    @ATMT.condition(tls13_RECEIVED_CLIENTFLIGHT2, prio=4)
    def tls13_no_ClientCertificate(self):
        if self.client_auth:
            raise self.TLS13_MISSING_CLIENTCERTIFICATE()
        self.raise_on_packet(TLSFinished,
                             self.TLS13_HANDLED_CLIENTFINISHED)

    # RFC8446, section 4.4.2.4 :
    # "If the client does not send any certificates (i.e., it sends an empty
    # Certificate message), the server MAY at its discretion either
    # continue the handshake without client authentication or abort the
    # handshake with a "certificate_required" alert."
    # Here, we abort the handshake.
    @ATMT.state()
    def TLS13_HANDLED_CLIENTCERTIFICATE(self):
        if self.client_auth:
            self.vprint("Received client certificate chain...")
            if isinstance(self.cur_pkt, TLS13Certificate):
                if self.cur_pkt.certslen == 0:
                    self.vprint("but it's empty !")
                    raise self.TLS13_MISSING_CLIENTCERTIFICATE()

    @ATMT.condition(TLS13_HANDLED_CLIENTCERTIFICATE)
    def tls13_should_handle_ClientCertificateVerify(self):
        self.raise_on_packet(TLSCertificateVerify,
                             self.TLS13_HANDLED_CLIENT_CERTIFICATEVERIFY)

    @ATMT.condition(TLS13_HANDLED_CLIENTCERTIFICATE, prio=2)
    def tls13_no_Client_CertificateVerify(self):
        if self.client_auth:
            raise self.TLS13_MISSING_CLIENTCERTIFICATE()
        raise self.TLS13_HANDLED_CLIENT_CERTIFICATEVERIFY()

    @ATMT.state()
    def TLS13_HANDLED_CLIENT_CERTIFICATEVERIFY(self):
        pass

    @ATMT.condition(TLS13_HANDLED_CLIENT_CERTIFICATEVERIFY)
    def tls13_should_handle_ClientFinished(self):
        self.raise_on_packet(TLSFinished,
                             self.TLS13_HANDLED_CLIENTFINISHED)

    @ATMT.state()
    def TLS13_MISSING_CLIENTCERTIFICATE(self):
        self.vprint("Missing ClientCertificate!")
        self.add_record()
        self.add_msg(TLSAlert(level=2, descr=0x74))
        self.flush_records()
        self.vprint("Sending TLSAlert 116")
        self.socket.close()
        raise self.WAITING_CLIENT()

    @ATMT.state()
    def TLS13_HANDLED_CLIENTFINISHED(self):
        self.vprint("TLS handshake completed!")
        self.vprint_sessioninfo()
        if self.hello_reset:
            #self.add_record(is_tls12=False)
            self.add_msg(TLSHelloRequest())
            self.flush_records()
        if self.is_echo_server:
            self.vprint("Will now act as a simple echo server.")
        raise self.WAITING_CLIENTDATA()

    #                       end of TLS 1.3 handshake                          #

    @ATMT.state()
    def WAITING_CLIENTDATA(self):
        self.get_next_msg(self.max_client_idle_time, 1)
        #if self.valid_renegotiation_info == True:
        #    raise self.RECEIVED_CLIENTFLIGHT1()
        #else:
        raise self.RECEIVED_CLIENTDATA()

    @ATMT.state()
    def RECEIVED_CLIENTDATA(self):
        pass

    def save_ticket(self, ticket):
        """
        This function save a ticket and others parameters in the
        file given as argument to the automaton
        Warning : The file is not protected and contains sensitive
        information. It should be used only for testing purpose.
        """
        if (not isinstance(ticket, TLS13NewSessionTicket) or
                self.session_ticket_file is None):
            return

        s = self.cur_session
        with open(self.session_ticket_file, "ab") as f:
            # ticket;ticket_nonce;obfuscated_age;start_time;resumption_secret
            line = binascii.hexlify(ticket.ticket)
            line += b";"
            line += binascii.hexlify(ticket.ticket_nonce)
            line += b";"
            line += binascii.hexlify(struct.pack("!I", ticket.ticket_lifetime))
            line += b";"
            line += binascii.hexlify(struct.pack("!I", ticket.ticket_age_add))
            line += b";"
            line += binascii.hexlify(struct.pack("!I", int(time.time())))
            line += b";"
            line += binascii.hexlify(s.tls13_derived_secrets["resumption_secret"])  # noqa: E501
            line += b";"
            line += binascii.hexlify(struct.pack("!H", s.wcs.ciphersuite.val))
            line += b";"
            if (ticket.ext is None or ticket.extlen is None or
                    ticket.extlen == 0):
                line += binascii.hexlify(struct.pack("!I", 0))
            else:
                for e in ticket.ext:
                    if isinstance(e, TLS_Ext_EarlyDataIndicationTicket):
                        max_size = struct.pack("!I", e.max_early_data_size)
                        line += binascii.hexlify(max_size)
            line += b"\n"
            f.write(line)

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
            for line in lines:
                if line.startswith(b"stop_server"):
                    raise self.CLOSE_NOTIFY_FINAL()
        elif isinstance(p, TLSAlert):
            print("> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        elif isinstance(p, TLS13KeyUpdate):
            print("> Received: %r" % p)
            p = TLS13KeyUpdate(request_update=0)
            self.add_record()
            self.add_msg(p)
            raise self.ADDED_SERVERDATA()
        else:
            print("> Received: %r" % p)

        if recv_data.startswith(b"GET / HTTP/1.1"):
            p = TLSApplicationData(data=self.http_sessioninfo())

        if self.is_echo_server or recv_data.startswith(b"GET / HTTP/1.1"):
            self.add_record()
            self.add_msg(p)
            if self.handle_session_ticket:
                self.add_record()
                ticket = TLS13NewSessionTicket(ext=[])
                self.add_msg(ticket)
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
        if self.session_ticket_file:
            save_ticket = False
            for p in self.buffer_out:
                if isinstance(p, TLS13):
                    # Check if there's a NewSessionTicket to send
                    save_ticket = all(map(lambda x: isinstance(x, TLS13NewSessionTicket),  # noqa: E501
                                          p.inner.msg))
                    if save_ticket:
                        break
        self.flush_records()
        if self.session_ticket_file and save_ticket:
            # Loop backward in message send to retrieve the parsed
            # NewSessionTicket. This message is not completely build before the
            # flush_records() call. Other way to build this message before ?
            for p in reversed(self.cur_session.handshake_messages_parsed):
                if isinstance(p, TLS13NewSessionTicket):
                    self.save_ticket(p)
                    break
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
        except Exception:
            self.vprint("Could not send termination Alert, maybe the client left?")  # noqa: E501
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
        except Exception:
            self.vprint("Could not send termination Alert, maybe the client left?")  # noqa: E501
        # We might call shutdown, but unit tests with s_client fail with this
        # self.socket.shutdown(1)
        self.socket.close()
        raise self.FINAL()

    #                          SSLv2 handshake                                #

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
        if self.specify_tls_version:
            version = self.specify_tls_version
        cert = self.mycert
        ciphers = self.cur_pkt.ciphers
        connection_id = randstring(16)
        p = SSLv2ServerHello(cert=cert,
                             ciphers=ciphers,
                             version=version,
                             connection_id=connection_id)
        p.show()
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

    #                       SSLv2 client authentication                       #

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
        self.vprint("Received client certificate...")
        # We could care about the client CA, but we don't.
        raise self.SSLv2_HANDLED_CLIENTFINISHED()

    #                   end of SSLv2 client authentication                    #

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

    #                        end of SSLv2 handshake                           #

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
        for line in lines:
            if line.startswith(b"stop_server"):
                raise self.SSLv2_CLOSE_NOTIFY_FINAL()

        if cli_data.startswith(b"GET / HTTP/1.1"):
            p = Raw(self.http_sessioninfo())

        if self.is_echo_server or cli_data.startswith(b"GET / HTTP/1.1"):
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
        except Exception:
            self.vprint("Could not send our goodbye. The client probably left.")  # noqa: E501
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
        except Exception:
            self.vprint("Could not send our goodbye. The client probably left.")  # noqa: E501
        self.socket.close()
        raise self.FINAL()

    @ATMT.state(stop=True, final=True)
    def FINAL(self):
        self.vprint("Closing server socket...")
        self.serversocket.close()
        self.vprint("Ending TLS server automaton.")
