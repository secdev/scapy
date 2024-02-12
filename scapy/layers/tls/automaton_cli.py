# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
#               2019 Romain Perez

"""
TLS client automaton. This makes for a primitive TLS stack.
Obviously you need rights for network access.

We support versions SSLv2 to TLS 1.3, along with many features.

In order to run a client to tcp/50000 with one cipher suite of your choice::

    from scapy.layers.tls import *
    ch = TLSClientHello(ciphers=<int code of the cipher suite>)
    t = TLSClientAutomaton(dport=50000, client_hello=ch)
    t.run()

You can also use it as a SuperSocket using the ``tlslink`` io::

    from scapy.layers.tls import *
    a = TLSClientAutomaton.tlslink(Raw, server="scapy.net", dport=443)
    a.send(HTTP()/HTTPRequest())
    while True:
        a.recv()

You can also use the io with a TCPSession, e.g. to get an HTTPS answer::

    from scapy.all import *
    from scapy.layers.http import *
    from scapy.layers.tls import *
    a = TLSClientAutomaton.tlslink(HTTP, server="www.google.com", dport=443)
    pkt = a.sr1(HTTP()/HTTPRequest(), session=TCPSession(app=True),
                timeout=2)
"""

import socket
import binascii
import struct
import time
import secrets

from scapy.config import conf
from scapy.utils import randstring, repr_hex
from scapy.automaton import ATMT, select_objects
from scapy.error import warning
from scapy.layers.tls.automaton import _TLSAutomaton
from scapy.layers.tls.basefields import _tls_version, _tls_version_options
from scapy.layers.tls.session import tlsSession
from scapy.layers.tls.extensions import TLS_Ext_SupportedGroups, \
    TLS_Ext_SupportedVersion_CH, TLS_Ext_SignatureAlgorithms, TLS_Ext_RenegotiationInfo, \
    TLS_Ext_SupportedVersion_SH, TLS_Ext_PSKKeyExchangeModes, TLS_Ext_EarlyDataIndication, \
    TLS_Ext_ServerName, ServerName
from scapy.layers.tls.handshake import TLSCertificate, TLSCertificateRequest, \
    TLSCertificateVerify, TLSClientHello, TLSClientKeyExchange, \
    TLSEncryptedExtensions, TLSFinished, TLSServerHello, TLSServerHelloDone, TLSHelloRequest, \
    TLSServerKeyExchange, TLS13Certificate, TLS13ClientHello,  \
    TLS13ServerHello, TLS13HelloRetryRequest, TLS13CertificateRequest, \
    _ASN1CertAndExt, TLS13KeyUpdate, TLS13NewSessionTicket
from scapy.layers.tls.handshake_sslv2 import SSLv2ClientHello, \
    SSLv2ServerHello, SSLv2ClientMasterKey, SSLv2ServerVerify, \
    SSLv2ClientFinished, SSLv2ServerFinished, SSLv2ClientCertificate, \
    SSLv2RequestCertificate
from scapy.layers.tls.keyexchange import ClientDiffieHellmanPublic
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_CH, \
    KeyShareEntry, TLS_Ext_KeyShare_HRR, PSKIdentity, PSKBinderEntry, \
    TLS_Ext_PreSharedKey_CH
from scapy.layers.tls.record import TLSAlert, TLSChangeCipherSpec, \
    TLSApplicationData
from scapy.layers.tls.crypto.suites import _tls_cipher_suites, \
    _tls_cipher_suites_cls
from scapy.layers.tls.crypto.groups import _tls_named_groups
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.libs import six
from scapy.packet import Raw
from scapy.compat import bytes_encode
from scapy.layers.tls.crypto.groups import _nist_curves
from scapy.layers.tls.crypto.groups import _tls_named_ffdh_groups

class TLSClientAutomaton(_TLSAutomaton):
    """
    A simple TLS test client automaton. Try to overload some states or
    conditions and see what happens on the other side.

    Rather than with an interruption, the best way to stop this client is by
    typing 'quit'. This won't be a message sent to the server.

    :param server: the server IP or hostname. defaults to 127.0.0.1
    :param dport: the server port. defaults to 4433
    :param server_name: the SNI to use. It does not need to be set
    :param mycert:
    :param mykey: may be provided as filenames. They will be used in
        the handshake, should the server ask for client authentication.
    :param client_hello: may hold a TLSClientHello or SSLv2ClientHello to be
        sent to the server. This is particularly useful for extensions
        tweaking. If not set, a default is populated accordingly.
    :param version: is a quicker way to advertise a protocol version ("sslv2",
        "tls1", "tls12", etc.) It may be overridden by the previous
        'client_hello'.
    :param data: is a list of raw data to be sent to the server once the
        handshake has been completed. Both 'stop_server' and 'quit' will
        work this way.
    """

    def parse_args(self, server="127.0.0.1", dport=4433, server_name=None,
                   mycert=None, mykey=None,
                   client_hello=None, version=None,
                   altered_finish=False,
                   altered_y_coordinate=False,
                   use_legacy=False,
                   empty_cke=False,
                   empty_pubkey=False,
                   empty_certificate=False,
                   tls13_renegotiation=False,
                   force_fatal_alert=False,
                   provide_early_data=False,
                   missing_finished_message=False,
                   altered_pre_master_secret=False,
                   specify_sig_alg=False,
                   non_zero_renegotiation_info=False,
                   valid_renegotiation_info=False,
                   scsv_renegotiation_info=False,
                   scsv_ctr = False,
                   reject_tls12_renegotiation = False,
                   no_renegotiation_info_2nd_ch=False,
                   altered_renegotiation_info=False,
                   sg=None,
                   resumption_master_secret=None,
                   session_ticket_file_in=None,
                   session_ticket_file_out=None,
                   psk=None, psk_mode=None,
                   data=None,
                   ciphersuite=None,
                   curve=None,
                   **kargs):

        super(TLSClientAutomaton, self).parse_args(mycert=mycert,
                                                   mykey=mykey,
                                                   **kargs)
        tmp = socket.getaddrinfo(server, dport)
        self.remote_family = tmp[0][0]
        self.remote_ip = tmp[0][4][0]
        self.remote_port = dport
        self.server_name = server_name
        self.altered_finish = altered_finish
        self.missing_finished_message = missing_finished_message
        self.altered_y_coordinate = altered_y_coordinate
        self.use_legacy = use_legacy
        self.downgrade_protection = None
        self.empty_cke = empty_cke
        self.empty_pubkey = empty_pubkey
        self.empty_certificate = empty_certificate
        self.non_zero_renegotiation_info = non_zero_renegotiation_info
        self.valid_renegotiation_info = valid_renegotiation_info
        self.renegotiated_connection = None
        self.scsv_renegotiation_info = scsv_renegotiation_info
        self.scsv_ctr = scsv_ctr
        self.reject_tls12_renegotiation = reject_tls12_renegotiation
        self.no_renegotiation_info_2nd_ch = no_renegotiation_info_2nd_ch
        self.altered_renegotiation_info = altered_renegotiation_info
        self.tls13_renegotiation = tls13_renegotiation
        self.force_fatal_alert = force_fatal_alert
        self.provide_early_data = provide_early_data
        self.altered_pre_master_secret = altered_pre_master_secret
        self.specify_sig_alg = specify_sig_alg
        if sg != None:
            self.sg = sg
        else:
            self.sg = None
        self.local_ip = None
        self.local_port = None
        self.socket = None

        if isinstance(client_hello, (TLSClientHello, TLS13ClientHello)):
            self.client_hello = client_hello
        else:
            self.client_hello = None
        self.advertised_tls_version = None
        if version:
            v = _tls_version_options.get(version, None)
            if not v:
                self.vprint("Unrecognized TLS version option.")
            else:
                self.advertised_tls_version = v

        self.linebreak = False
        if isinstance(data, bytes):
            self.data_to_send = [data]
        elif isinstance(data, six.string_types):
            self.data_to_send = [bytes_encode(data)]
        elif isinstance(data, list):
            self.data_to_send = list(bytes_encode(d) for d in reversed(data))
        else:
            self.data_to_send = []
        self.curve = None

        if self.advertised_tls_version == 0x0304:
            self.ciphersuite = 0x1301
            if ciphersuite is not None:
                cs = int(ciphersuite, 16)
                if cs in _tls_cipher_suites.keys():
                    self.ciphersuite = cs
            if conf.crypto_valid_advanced:
                # Default to secp256r1 if supported
                self.curve = 23
            else:
                # Or x25519 otherwise
                self.curve = 29
            self.resumption_master_secret = resumption_master_secret
            self.session_ticket_file_in = session_ticket_file_in
            self.session_ticket_file_out = session_ticket_file_out
            self.tls13_psk_secret = psk
            self.tls13_psk_mode = psk_mode
            if curve is not None:
                for (group_id, ng) in _tls_named_groups.items():
                    if ng == curve:
                        if curve == "x25519":
                            if conf.crypto_valid_advanced:
                                self.curve = group_id
                        else:
                            self.curve = group_id

    def vprint_sessioninfo(self):
        if self.verbose:
            s = self.cur_session
            v = _tls_version[s.tls_version]
            self.vprint("Version       : %s" % v)
            cs = s.wcs.ciphersuite.name
            self.vprint("Cipher suite  : %s" % cs)
            if s.tls_version >= 0x0304:
                ms = s.tls13_master_secret
            else:
                ms = s.master_secret
            if s.tls_version <= 0x0303:
                self.vprint("CLIENT RANDOM: %s" % repr_hex(s.client_random))
                self.vprint("MASTER SECRET: %s" % repr_hex(ms))
                self.vprint()
            if s.tls_version <= 0x0303:
                self.vprint()
                self.vprint()
                print("CLIENT_RANDOM %s" % repr_hex(s.client_random), repr_hex(ms))
                #self.vprint("MASTER SECRET: %s" % repr_hex(ms))
                self.vprint()
            if s.tls_version >= 0x0304:
                self.vprint()
                print("CLIENT_HANDSHAKE_TRAFFIC_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["client_handshake_traffic_secret"]))
                print("SERVER_HANDSHAKE_TRAFFIC_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["server_handshake_traffic_secret"]))
                print("CLIENT_TRAFFIC_SECRET_0 %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["client_traffic_secrets"][0]))
                print("SERVER_TRAFFIC_SECRET_0 %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["server_traffic_secrets"][0]))
                print("EXPORTER_SECRET %s" % repr_hex(s.client_random), repr_hex(s.tls13_derived_secrets["exporter_secret"]))
                self.vprint()
            if s.server_certs:
                self.vprint("Server certificate chain: %r" % s.server_certs)
            if s.tls_version >= 0x0304 and s.missing_finished_message != True:
                res_secret = s.tls13_derived_secrets["resumption_secret"]
                self.vprint("Resumption master secret : %s" %
                            repr_hex(res_secret))
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

    @ATMT.state(initial=True)
    def INITIAL(self):
        self.vprint("Starting TLS client automaton.")
        raise self.INIT_TLS_SESSION()

    @ATMT.ioevent(INITIAL, name="tls", as_supersocket="tlslink")
    def _socket(self, fd):
        pass

    @ATMT.state()
    def INIT_TLS_SESSION(self):
        self.cur_session = tlsSession(connection_end="client")
        s = self.cur_session
        s.client_certs = self.mycert
        s.client_key = self.mykey
        s.altered_finish = self.altered_finish
        s.downgrade_protection = self.downgrade_protection
        s.altered_y_coordinate = self.altered_y_coordinate
        s.empty_pubkey = self.empty_pubkey
        s.empty_cke = self.empty_cke
        s.empty_certificate = self.empty_certificate
        #s.valid_renegotiation_info =self.valid_renegotiation_info
        s.scsv_renegotiation_info = self.scsv_renegotiation_info
        s.scsv_ctr = self.scsv_ctr
        s.tls13_renegotiation = self.tls13_renegotiation
        s.force_fatal_alert = self.force_fatal_alert
        s.provide_early_data = self.provide_early_data
        s.missing_finished_message = self.missing_finished_message
        s.altered_pre_master_secret = self.altered_pre_master_secret
        s.specify_sig_alg = self.specify_sig_alg
        v = self.advertised_tls_version
        if v:
            s.advertised_tls_version = v
        else:
            default_version = s.advertised_tls_version
            self.advertised_tls_version = default_version

        if s.advertised_tls_version >= 0x0304:
            # For out of band PSK, the PSK is given as an argument
            # to the automaton
            if self.tls13_psk_secret:
                s.tls13_psk_secret = binascii.unhexlify(self.tls13_psk_secret)

            # For resumed PSK, the PSK is computed from
            if self.session_ticket_file_in:
                with open(self.session_ticket_file_in, 'rb') as f:

                    resumed_ciphersuite_len = struct.unpack("B", f.read(1))[0]
                    s.tls13_ticket_ciphersuite = \
                        struct.unpack("!H", f.read(resumed_ciphersuite_len))[0]

                    ticket_nonce_len = struct.unpack("B", f.read(1))[0]
                    # XXX add client_session_nonce member in tlsSession
                    s.client_session_nonce = f.read(ticket_nonce_len)

                    client_ticket_age_len = struct.unpack("!H", f.read(2))[0]
                    tmp = f.read(client_ticket_age_len)
                    s.client_ticket_age = struct.unpack("!I", tmp)[0]

                    client_ticket_age_add_len = struct.unpack(
                        "!H", f.read(2))[0]
                    tmp = f.read(client_ticket_age_add_len)
                    s.client_session_ticket_age_add = struct.unpack(
                        "!I", tmp)[0]

                    ticket_len = struct.unpack("!H", f.read(2))[0]
                    s.client_session_ticket = f.read(ticket_len)

                if self.resumption_master_secret:

                    if s.tls13_ticket_ciphersuite not in _tls_cipher_suites_cls:  # noqa: E501
                        warning("Unknown cipher suite %d", s.tls13_ticket_ciphersuite)  # noqa: E501
                        # we do not try to set a default nor stop the execution
                    else:
                        cs_cls = _tls_cipher_suites_cls[s.tls13_ticket_ciphersuite]  # noqa: E501

                    hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
                    hash_len = hkdf.hash.digest_size

                    s.tls13_psk_secret = hkdf.expand_label(binascii.unhexlify(self.resumption_master_secret),  # noqa: E501
                                                           b"resumption",
                                                           s.client_session_nonce,  # noqa: E501
                                                           hash_len)
        raise self.CONNECT()

    @ATMT.state()
    def CONNECT(self):
        s = socket.socket(self.remote_family, socket.SOCK_STREAM)
        self.vprint()
        self.vprint("Trying to connect on %s:%d" % (self.remote_ip,
                                                    self.remote_port))
        s.connect((self.remote_ip, self.remote_port))
        self.socket = s
        self.local_ip, self.local_port = self.socket.getsockname()[:2]
        self.vprint()
        if self.cur_session.advertised_tls_version in [0x0200, 0x0002]:
            raise self.SSLv2_PREPARE_CLIENTHELLO()
        elif self.cur_session.advertised_tls_version >= 0x0304:
            raise self.TLS13_START()
        else:
            raise self.PREPARE_CLIENTFLIGHT1()

    #                           TLS handshake                                 #

    @ATMT.state()
    def PREPARE_CLIENTFLIGHT1(self):
        self.add_record()

    @ATMT.condition(PREPARE_CLIENTFLIGHT1)
    def should_add_ClientHello(self):
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
        ext = []
        #Using these sigs below as default
        sigs = ["sha1+rsa", "sha256+rsa", "sha384+rsa", "sha1+ecdsa", "sha256+ecdsa", "sha384+ecdsa", "sha384+rsaepss", "sha384+rsapss"]
        if self.sg != None:
            supported_groups = self.sg
        #supported_groups = ["secp256r1", "secp384r1", "x448"]
        # Add TLS_Ext_SignatureAlgorithms for TLS 1.2 ClientHello
        if self.cur_session.advertised_tls_version == 0x0303:
            if self.empty_pubkey == True:
                ext += TLS_Ext_SupportedGroups(groups=supported_groups)
            if self.specify_sig_alg:
                ext += [TLS_Ext_SignatureAlgorithms(sig_algs=self.specify_sig_alg)]
                r = hex(self.specify_sig_alg)
                print(" ")
                print("Signature Algorithm used in Client Hello Message: [%s]" % r)
                print(" ")
            else:
                #ext += [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"])]
                ext += [TLS_Ext_SignatureAlgorithms(sig_algs=sigs)]
        if self.non_zero_renegotiation_info == True:
            ext += TLS_Ext_RenegotiationInfo(renegotiated_connection=0x1, reneg_conn_len=0x1)
        elif self.valid_renegotiation_info == True or self.no_renegotiation_info_2nd_ch == True or self.altered_renegotiation_info == True:
            ext += TLS_Ext_RenegotiationInfo(reneg_conn_len=0x0)
        # Add TLS_Ext_ServerName
        if self.server_name:
            ext += TLS_Ext_ServerName(
                servernames=[ServerName(servername=self.server_name)]
            )
        p.ext = ext
        self.client_hello = p
        self.add_msg(p)
        p.display()
        if self.specify_sig_alg:
            p.display()
        raise self.ADDED_CLIENTHELLO()

    @ATMT.state()
    def ADDED_CLIENTHELLO(self):
        pass

    @ATMT.condition(ADDED_CLIENTHELLO)
    def should_send_ClientFlight1(self):
        self.flush_records()
        if self.non_zero_renegotiation_info == True:
                        self.raise_on_packet(TLSAlert,
                    self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1)
        else:
            raise self.SENT_CLIENTFLIGHT1()

    @ATMT.state()
    def SENT_CLIENTFLIGHT1(self):
        raise self.WAITING_SERVERFLIGHT1()

    @ATMT.state()
    def WAITING_SERVERFLIGHT1(self):
        self.get_next_msg()
        raise self.RECEIVED_SERVERFLIGHT1()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT1(self):
        pass

    @ATMT.condition(RECEIVED_SERVERFLIGHT1, prio=1)
    def should_handle_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        self.raise_on_packet(TLSServerHello,
                             self.HANDLED_SERVERHELLO)

    @ATMT.state()
    def HANDLED_SERVERHELLO(self):
        pass

    @ATMT.condition(RECEIVED_SERVERFLIGHT1, prio=2)
    def missing_ServerHello(self):
        raise self.MISSING_SERVERHELLO()

    @ATMT.state()
    def MISSING_SERVERHELLO(self):
        self.vprint("Missing TLS ServerHello message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_SERVERHELLO, prio=1)
    def should_handle_ServerCertificate(self):
        if not self.cur_session.prcs.key_exchange.anonymous:
            self.raise_on_packet(TLSCertificate,
                                 self.HANDLED_SERVERCERTIFICATE)
        raise self.HANDLED_SERVERCERTIFICATE()

    @ATMT.state()
    def HANDLED_SERVERCERTIFICATE(self):
        pass

    @ATMT.condition(HANDLED_SERVERHELLO, prio=2)
    def missing_ServerCertificate(self):
        raise self.MISSING_SERVERCERTIFICATE()

    @ATMT.state()
    def MISSING_SERVERCERTIFICATE(self):
        self.vprint("Missing TLS Certificate message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def HANDLED_CERTIFICATEREQUEST(self):
        self.vprint("Server asked for a certificate...")
        if not self.mykey or not self.mycert:
            self.vprint("No client certificate to send!")
            self.vprint("Will try and send an empty Certificate message...")

    @ATMT.condition(HANDLED_SERVERCERTIFICATE, prio=1)
    def should_handle_ServerKeyExchange_from_ServerCertificate(self):
        """
        XXX We should check the ServerKeyExchange attributes for discrepancies
        with our own ClientHello, along with the ServerHello and Certificate.
        """
        self.raise_on_packet(TLSServerKeyExchange,
                             self.HANDLED_SERVERKEYEXCHANGE)

    @ATMT.state(final=True)
    def MISSING_SERVERKEYEXCHANGE(self):
        pass

    @ATMT.condition(HANDLED_SERVERCERTIFICATE, prio=2)
    def missing_ServerKeyExchange(self):
        if not self.cur_session.prcs.key_exchange.no_ske:
            raise self.MISSING_SERVERKEYEXCHANGE()

    @ATMT.state()
    def HANDLED_SERVERKEYEXCHANGE(self):
        pass

    def should_handle_CertificateRequest(self):
        """
        XXX We should check the CertificateRequest attributes for discrepancies
        with the cipher suite, etc.
        """
        self.raise_on_packet(TLSCertificateRequest,
                             self.HANDLED_CERTIFICATEREQUEST)

    @ATMT.condition(HANDLED_SERVERKEYEXCHANGE, prio=2)
    def should_handle_CertificateRequest_from_ServerKeyExchange(self):
        self.should_handle_CertificateRequest()

    @ATMT.condition(HANDLED_SERVERCERTIFICATE, prio=3)
    def should_handle_CertificateRequest_from_ServerCertificate(self):
        self.should_handle_CertificateRequest()

    def should_handle_ServerHelloDone(self):
        self.raise_on_packet(TLSServerHelloDone,
                             self.HANDLED_SERVERHELLODONE)

    @ATMT.condition(HANDLED_SERVERKEYEXCHANGE, prio=1)
    def should_handle_ServerHelloDone_from_ServerKeyExchange(self):
        return self.should_handle_ServerHelloDone()

    @ATMT.condition(HANDLED_CERTIFICATEREQUEST, prio=4)
    def should_handle_ServerHelloDone_from_CertificateRequest(self):
        return self.should_handle_ServerHelloDone()

    @ATMT.condition(HANDLED_SERVERCERTIFICATE, prio=4)
    def should_handle_ServerHelloDone_from_ServerCertificate(self):
        return self.should_handle_ServerHelloDone()

    @ATMT.state()
    def HANDLED_SERVERHELLODONE(self):
        raise self.PREPARE_CLIENTFLIGHT2()

    @ATMT.state()
    def PREPARE_CLIENTFLIGHT2(self):
        self.add_record()

    @ATMT.condition(PREPARE_CLIENTFLIGHT2, prio=1)
    def should_add_ClientCertificate(self):
        """
        If the server sent a CertificateRequest, we send a Certificate message.
        If no certificate is available, an empty Certificate message is sent:
        - this is a SHOULD in RFC 4346 (Section 7.4.6)
        - this is a MUST in RFC 5246 (Section 7.4.6)

        XXX We may want to add a complete chain.
        """
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if TLSCertificateRequest not in hs_msg:
            return
        certs = []
        if self.mycert:
            certs = [self.mycert]
        if self.empty_certificate == True:
            certs = []
        self.add_msg(TLSCertificate(certs=certs))
        raise self.ADDED_CLIENTCERTIFICATE()

    @ATMT.state()
    def ADDED_CLIENTCERTIFICATE(self):
        pass

    def should_add_ClientKeyExchange(self):
        if self.empty_cke == True:
            p=(TLSClientKeyExchange(exchkeys=None)) 
            #p=(TLSClientKeyExchange(exchkeys=None) / ClientDiffieHellmanPublic(dh_Yc=0x00, dh_Yclen=0x00))
            Raw(p)
            p.show2()
            self.add_msg(p)
            self.flush_records()
            self.get_next_msg(0.3, 1)
            raise self.RECEIVED_SERVERDATA()
        #if self.empty_pubkey == True:
        #    p = (TLSClientKeyExchange())
        #    Raw(p)
        #    self.add_msg(p)
        #    self.dh_Yc = 0 
        #    self.dh_Yclen = 0
        #    self.flush_records()
        #    self.get_next_msg(0.3, 1)
        #    raise self.RECEIVED_SERVERDATA()
        #if self.altered_y_coordinate == True:
        #    p = (TLSClientKeyExchange())
        #    self.add_msg(p)
        #    self.flush_records()
        #    self.get_next_msg(0.3, 1)
        #    raise self.RECEIVED_SERVERDATA()
        else:
            self.add_msg(TLSClientKeyExchange())
        #self.add_msg(TLSClientKeyExchange())
        raise self.ADDED_CLIENTKEYEXCHANGE()

    @ATMT.condition(PREPARE_CLIENTFLIGHT2, prio=2)
    def should_add_ClientKeyExchange_from_ClientFlight2(self):
        return self.should_add_ClientKeyExchange()

    @ATMT.condition(ADDED_CLIENTCERTIFICATE)
    def should_add_ClientKeyExchange_from_ClientCertificate(self):
        return self.should_add_ClientKeyExchange()

    @ATMT.state()
    def ADDED_CLIENTKEYEXCHANGE(self):
        pass

    @ATMT.condition(ADDED_CLIENTKEYEXCHANGE, prio=1)
    def should_add_ClientVerify(self):
        """
        XXX Section 7.4.7.1 of RFC 5246 states that the CertificateVerify
        message is only sent following a client certificate that has signing
        capability (i.e. not those containing fixed DH params).
        We should verify that before adding the message. We should also handle
        the case when the Certificate message was empty.
        """
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if (TLSCertificateRequest not in hs_msg or
            self.mycert is None or
                self.mykey is None):
            return
        self.add_msg(TLSCertificateVerify())
        raise self.ADDED_CERTIFICATEVERIFY()

    @ATMT.state()
    def ADDED_CERTIFICATEVERIFY(self):
        pass

    @ATMT.condition(ADDED_CERTIFICATEVERIFY)
    def should_add_ChangeCipherSpec_from_CertificateVerify(self):
        self.add_record()
        self.add_msg(TLSChangeCipherSpec())
        raise self.ADDED_CHANGECIPHERSPEC()

    @ATMT.condition(ADDED_CLIENTKEYEXCHANGE, prio=2)
    def should_add_ChangeCipherSpec_from_ClientKeyExchange(self):
        self.add_record()
        self.add_msg(TLSChangeCipherSpec())
        raise self.ADDED_CHANGECIPHERSPEC()

    @ATMT.state()
    def ADDED_CHANGECIPHERSPEC(self):
        pass

    @ATMT.condition(ADDED_CHANGECIPHERSPEC)
    def should_add_ClientFinished(self):
        self.add_record()
        if self.missing_finished_message == True:
            p=(TLSApplicationData(data=b'\xEF\xBB\xBF'))
            print ("Sending some random Application Data")
            p.show2()
            self.add_msg(p)
        else:
            self.add_msg(TLSFinished())
        raise self.ADDED_CLIENTFINISHED()

    @ATMT.state()
    def ADDED_CLIENTFINISHED(self):
        pass

    @ATMT.condition(ADDED_CLIENTFINISHED)
    def should_send_ClientFlight2(self):
        s = self.cur_session
        #client_verify_data = self.cur_pkt.vdata
        self.flush_records()
        client_verify_data = s.verify_data
        self.renegotiated_connection = client_verify_data
        if self.empty_pubkey == True or self.altered_finish == True or self.missing_finished_message or self.altered_pre_master_secret == True or self.altered_y_coordinate == True or self.empty_certificate == True:
            self.raise_on_packet(TLSAlert,
                    self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1)
        else:
            raise self.SENT_CLIENTFLIGHT2()

    @ATMT.state()
    def SENT_CLIENTFLIGHT2(self):
        raise self.WAITING_SERVERFLIGHT2()

    @ATMT.state()
    def WAITING_SERVERFLIGHT2(self):
        self.get_next_msg()
        raise self.RECEIVED_SERVERFLIGHT2()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT2(self):
        pass

    @ATMT.condition(RECEIVED_SERVERFLIGHT2)
    def should_handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec,
                             self.HANDLED_CHANGECIPHERSPEC)

    @ATMT.state()
    def HANDLED_CHANGECIPHERSPEC(self):
        pass

    @ATMT.condition(HANDLED_CHANGECIPHERSPEC)
    def should_handle_Finished(self):
        self.raise_on_packet(TLSFinished,
                             self.HANDLED_SERVERFINISHED)

    @ATMT.state()
    def HANDLED_SERVERFINISHED(self):
        self.vprint("TLS handshake completed!")
        self.vprint_sessioninfo()
        self.vprint("You may send data or use 'quit'.")
        #if self.valid_renegotiation_info == True or self.non_zero_renegotiation_info == True or self.no_renegotiation_info_2nd_ch == True or self.altered_renegotiation_info == True:
            #raise self.WAITING_SERVERDATA()
            #self.scsv_ctr = True
            #raise self.WAITING_SERVERFLIGHT0_REG()
            #raise self.RECEIVED_SERVERFLIGHT0_REG()


    #                       end of TLS handshake                              #

    @ATMT.condition(HANDLED_SERVERFINISHED)
    def should_wait_ClientData(self):
        raise self.WAIT_CLIENTDATA()

    @ATMT.state()
    def WAIT_CLIENTDATA(self):
        pass

    @ATMT.condition(WAIT_CLIENTDATA, prio=1)
    def add_ClientData(self):
        r"""
        The user may type in:
        GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n
        Special characters are handled so that it becomes a valid HTTP request.
        """
        print ("Waiting Client Data...")
        if not self.data_to_send:
            if self.is_atmt_socket:
                # Socket mode
                fd = select_objects([self.ioin["tls"]], 0)
                if fd:
                    self.add_record()
                    self.add_msg(TLSApplicationData(data=fd[0].recv()))
                    raise self.ADDED_CLIENTDATA()
                raise self.WAITING_SERVERDATA()
            else:
                data = six.moves.input().replace('\\r', '\r').replace('\\n', '\n').encode()  # noqa: E501
        else:
            data = self.data_to_send.pop()
        if data == b"quit":
            return
        # Command to skip sending
        elif data == b"wait":
            raise self.WAITING_SERVERDATA()
        # Command to perform a key_update (for a TLS 1.3 session)
        elif data == b"key_update":
            if self.cur_session.tls_version >= 0x0304:
                self.add_record()
                self.add_msg(TLS13KeyUpdate(request_update="update_requested"))
                raise self.ADDED_CLIENTDATA()

        if self.linebreak:
            data += b"\n"
        self.add_record()
        self.add_msg(TLSApplicationData(data=data))
        raise self.ADDED_CLIENTDATA()

    @ATMT.condition(WAIT_CLIENTDATA, prio=2)
    def no_more_ClientData(self):
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def ADDED_CLIENTDATA(self):
        pass

    @ATMT.condition(ADDED_CLIENTDATA)
    def should_send_ClientData(self):
        self.flush_records()
        # Determine if there's a response from the server to the HTTP GET Client Data
        if self.valid_renegotiation_info == True or self.non_zero_renegotiation_info == True or self.no_renegotiation_info_2nd_ch == True or self.altered_renegotiation_info == True:
            self.get_next_msg(0.3, 1)
            # If there's a response switch to WAITING_SERVERDATA
            if self.buffer_in:
                raise self.WAITING_SERVERDATA()
            # If there is no repsonse wait for a Hello Request/Initiate our own 
            if not self.buffer_in:
                raise self.WAITING_SERVERFLIGHT0_REG()
        else:
            raise self.SENT_CLIENTDATA()

    @ATMT.state()
    def SENT_CLIENTDATA(self):
        raise self.WAITING_SERVERDATA()

    @ATMT.state()
    def WAITING_SERVERDATA(self):
        self.get_next_msg(0.3, 1)
        raise self.RECEIVED_SERVERDATA()

    @ATMT.state()
    def RECEIVED_SERVERDATA(self):
        pass

    @ATMT.condition(RECEIVED_SERVERDATA, prio=1)
    def should_handle_ServerData(self):
        if not self.buffer_in:
            raise self.WAIT_CLIENTDATA()
        p = self.buffer_in[0]
        if isinstance(p, TLSApplicationData):
            if self.is_atmt_socket:
                # Socket mode
                self.oi.tls.send(p.data)
            else:
                print("> Received: %r" % p.data)
        elif isinstance(p, TLSAlert):
            print("> Received: %r" % p)
            raise self.CLOSE_NOTIFY()
        elif isinstance(p, TLS13NewSessionTicket):
            print("> Received: %r " % p)
            # If arg session_ticket_file_out is set, we save
            # the ticket for resumption...
            if self.session_ticket_file_out:
                # Struct of ticket file :
                #  * ciphersuite_len (1 byte)
                #  * ciphersuite (ciphersuite_len bytes) :
                #       we need to the store the ciphersuite for resumption
                #  * ticket_nonce_len (1 byte)
                #  * ticket_nonce (ticket_nonce_len bytes) :
                #       we need to store the nonce to compute the PSK
                #       for resumption
                #  * ticket_age_len (2 bytes)
                #  * ticket_age (ticket_age_len bytes) :
                #       we need to store the time we received the ticket for
                #       computing the obfuscated_ticket_age when resuming
                #  * ticket_age_add_len (2 bytes)
                    f.write(struct.pack("B", 2))
                    # we choose wcs arbitrarily...
                    f.write(struct.pack("!H",
                                        self.cur_session.wcs.ciphersuite.val))
                    f.write(struct.pack("B", p.noncelen))
                    f.write(p.ticket_nonce)
                    f.write(struct.pack("!H", 4))
                    f.write(struct.pack("!I", int(time.time())))
                    f.write(struct.pack("!H", 4))
                    f.write(struct.pack("!I", p.ticket_age_add))
                    f.write(struct.pack("!H", p.ticketlen))
                    f.write(self.cur_session.client_session_ticket)

        else:
            print("> Received: %r" % p)
        self.buffer_in = self.buffer_in[1:]
        if self.force_fatal_alert == True:
            self.add_record()
            #p = TLS13ClientHello(ciphers=0x1301)
            p=(TLSApplicationData(data=b'\xEF\xBB\xBF'))
            self.add_msg(p)
            #self.flush_records()
            self.flush_recordsCC()
            self.vprint("Sent altered application data to the Server to force a fatal alert")
            raise self.HANDLED_SERVERDATA()
        #if self.reject_tls12_renegotiation == True or self.valid_renegotiation_info == True:
            # Have the client try renegotiation
            #raise self.PREPARE_CLIENTFLIGHT1_REG()
        # Have the client initiate renegotiation 
        if self.valid_renegotiation_info == True or self.non_zero_renegotiation_info == True or self.no_renegotiation_info_2nd_ch == True or self.altered_renegotiation_info == True or self.reject_tls12_renegotiation == True:
            #raise self.WAITING_SERVERFLIGHT0_REG()
            raise self.PREPARE_CLIENTFLIGHT1_REG()

        else:
            raise self.HANDLED_SERVERDATA()

    @ATMT.state()
    def WAITING_SERVERFLIGHT0_REG(self):
        pass

    @ATMT.condition(WAITING_SERVERFLIGHT0_REG, prio=1)
    def should_handle_Hello_Request(self):
        if not self.buffer_in:
            self.get_next_msg(30, 1)
            #p = self.buffer_in[0]
            #if isinstance(p, TLSHelloRequest):
            self.raise_on_packet(TLSHelloRequest,
                    self.PREPARE_CLIENTFLIGHT1_REG)
            #self.get_next_msg(30, 1)
        else:
            self.get_next_msg(30, 1)
        #raise self.PREPARE_CLIENTFLIGHT1_REG()
        self.raise_on_packet(TLSHelloRequest,
                             self.PREPARE_CLIENTFLIGHT1_REG)
        raise self.PREPARE_CLIENTFLIGHT1_REG()

    @ATMT.state()
    def PREPARE_CLIENTFLIGHT1_REG(self):
        #self.cur_pkt.display()
        self.add_record()

    @ATMT.condition(PREPARE_CLIENTFLIGHT1_REG)
    def should_add_ClientHello_Reg(self):
        #
        s = self.cur_session
        s.scsv_ctr = True
        p = TLSClientHello()
        ext = []
        if self.specify_sig_alg:
            ext += [TLS_Ext_SignatureAlgorithms(sig_algs=self.specify_sig_alg)]
            p.ext = ext
        else:
            sigs = ["sha1+rsa", "sha256+rsa", "sha384+rsa", "sha1+ecdsa", "sha256+ecdsa", "sha384+ecdsa", "sha384+rsaepss", "sha384+rsapss"]
            ext += [TLS_Ext_SignatureAlgorithms(sig_algs=sigs)]
            p.ext = ext
        #ext += [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"])]
        if self.no_renegotiation_info_2nd_ch == True:
            p.ext = ext
        elif self.altered_renegotiation_info == True:
            altered_renegotiated_connection = self.renegotiated_connection[:-3] + randstring(1) + self.renegotiated_connection[-2:]
            if altered_renegotiated_connection == self.renegotiated_connection:
                warning("renegotiated_connectio was not altered.  Run Test Again!")
            ext += [TLS_Ext_RenegotiationInfo(renegotiated_connection=altered_renegotiated_connection, reneg_conn_len=0xC)]
            p.ext = ext
        else:
            ext += [TLS_Ext_RenegotiationInfo(renegotiated_connection=self.renegotiated_connection, reneg_conn_len=0xC)]
            p.ext = ext
        #p.display()
        self.client_hello = p
        self.add_msg(p)
        raise self.ADDED_CLIENTHELLO_REG()

    @ATMT.state()
    def ADDED_CLIENTHELLO_REG(self):
        pass

    @ATMT.condition(ADDED_CLIENTHELLO_REG)
    def should_send_ClientFlight1_Reg(self):
        self.flush_records()
        if self.non_zero_renegotiation_info == True or self.scsv_renegotiation_info == True or self.no_renegotiation_info_2nd_ch == True or self.altered_renegotiation_info == True or self.reject_tls12_renegotiation == True:
            self.raise_on_packet(TLSAlert,
                    self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1)
        #if self.valid_renegotiation_info == True and self.reject_tls12_renegotiation == True:
        #    print ("Made it BOTH")
        #    #raise self.WAITING_SERVERDATA()
        #    raise self.WAIT_CLIENTDATA()

        #else:
        #    raise self.SENT_CLIENTFLIGHT1_REG()
        raise self.SENT_CLIENTFLIGHT1_REG()

    @ATMT.state()
    def SENT_CLIENTFLIGHT1_REG(self):
        raise self.WAITING_SERVERFLIGHT1_REG()

    @ATMT.state()
    def WAITING_SERVERFLIGHT1_REG(self):
        self.get_next_msg()
        raise self.RECEIVED_SERVERFLIGHT1_REG()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT1_REG(self):
        pass

    @ATMT.condition(RECEIVED_SERVERFLIGHT1_REG, prio=1)
    def should_handle_ServerHello_Reg(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        #raise self.HANDLED_SERVERHELLO_REG()
        self.raise_on_packet(TLSServerHello,
                             self.HANDLED_SERVERHELLO_REG)

    @ATMT.state()
    def HANDLED_SERVERHELLO_REG(self):
        pass

    @ATMT.condition(RECEIVED_SERVERFLIGHT1_REG, prio=2)
    def missing_ServerHello_Reg(self):
        raise self.MISSING_SERVERHELLO_REG()

    @ATMT.state()
    def MISSING_SERVERHELLO_REG(self):
        self.vprint("Missing TLS ServerHello message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(HANDLED_SERVERHELLO_REG, prio=1)
    def should_handle_ServerCertificate_Reg(self):
        #if not self.cur_session.prcs.key_exchange.anonymous:
        self.raise_on_packet(TLSCertificate,
                self.HANDLED_SERVERCERTIFICATE_REG)
        raise self.HANDLED_SERVERCERTIFICATE_REG()

    @ATMT.state()
    def HANDLED_SERVERCERTIFICATE_REG(self):
        pass

    @ATMT.condition(HANDLED_SERVERHELLO_REG, prio=2)
    def missing_ServerCertificate(self):
        raise self.MISSING_SERVERCERTIFICATE_REG()

    @ATMT.state()
    def MISSING_SERVERCERTIFICATE_REG(self):
        self.vprint("Missing TLS Certificate message!")
        raise self.CLOSE_NOTIFY()
    
    @ATMT.state()
    def HANDLED_CERTIFICATEREQUEST_REG(self):
        self.vprint("Server asked for a certificate...")
        if not self.mykey or not self.mycert:
            self.vprint("No client certificate to send!")
            self.vprint("Will try and send an empty Certificate message...")

    @ATMT.condition(HANDLED_SERVERCERTIFICATE_REG, prio=1)
    def should_handle_ServerKeyExchange_from_ServerCertificate_Reg(self):
        """
        XXX We should check the ServerKeyExchange attributes for discrepancies
        with our own ClientHello, along with the ServerHello and Certificate.
        """
        self.raise_on_packet(TLSServerKeyExchange,
                         self.HANDLED_SERVERKEYEXCHANGE_REG)

    @ATMT.state(final=True)
    def MISSING_SERVERKEYEXCHANGE_REG(self):
        pass

    @ATMT.condition(HANDLED_SERVERCERTIFICATE_REG, prio=2)
    def missing_ServerKeyExchange(self):
        if not self.cur_session.prcs.key_exchange.no_ske:
            raise self.MISSING_SERVERKEYEXCHANGE_REG()

    @ATMT.state()
    def HANDLED_SERVERKEYEXCHANGE_REG(self):
        pass

    def should_handle_CertificateRequest_Reg(self):
        raise self.HANDLED_CERTIFICATEREQUEST_REG()
        #"""
        #XXX We should check the CertificateRequest attributes for discrepancies
        #with the cipher suite, etc.
        #"""
        #self.raise_on_packet(TLSCertificateRequest,
        #                 self.HANDLED_CERTIFICATEREQUEST_REG)

    @ATMT.condition(HANDLED_SERVERKEYEXCHANGE_REG, prio=2)
    def should_handle_CertificateRequest_from_ServerKeyExchange_Reg(self):
        self.should_handle_CertificateRequest_Reg()

    @ATMT.condition(HANDLED_SERVERCERTIFICATE_REG, prio=3)
    def should_handle_CertificateRequest_from_ServerCertificate_Reg(self):
        self.should_handle_CertificateRequest_Reg()

    def should_handle_ServerHelloDone_Reg(self):
        self.raise_on_packet(TLSServerHelloDone,
                         self.HANDLED_SERVERHELLODONE_REG)

    @ATMT.condition(HANDLED_SERVERKEYEXCHANGE_REG, prio=1)
    def should_handle_ServerHelloDone_from_ServerKeyExchange_Reg(self):
        return self.should_handle_ServerHelloDone_Reg()

    @ATMT.condition(HANDLED_CERTIFICATEREQUEST_REG, prio=4)
    def should_handle_ServerHelloDone_from_CertificateRequest_Reg(self):
        return self.should_handle_ServerHelloDone_Reg()

    @ATMT.condition(HANDLED_SERVERCERTIFICATE_REG, prio=4)
    def should_handle_ServerHelloDone_from_ServerCertificate_Reg(self):
        return self.should_handle_ServerHelloDone_Reg()

    @ATMT.state()
    def HANDLED_SERVERHELLODONE_REG(self):
        raise self.PREPARE_CLIENTFLIGHT2_REG()

    @ATMT.state()
    def PREPARE_CLIENTFLIGHT2_REG(self):
        self.add_record()
        #
        raise self.ADDED_CLIENTCERTIFICATE_REG()

    @ATMT.condition(PREPARE_CLIENTFLIGHT2_REG, prio=1)
    def should_add_ClientCertificate_Reg(self):
        """
        If the server sent a CertificateRequest, we send a Certificate message.
        If no certificate is available, an empty Certificate message is sent:
        - this is a SHOULD in RFC 4346 (Section 7.4.6)
        - this is a MUST in RFC 5246 (Section 7.4.6)

        XXX We may want to add a complete chain.
        """
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if TLSCertificateRequest not in hs_msg:
            return
        certs = []
        if self.mycert:
            certs = [self.mycert]
        self.add_msg(TLSCertificate(certs=certs))
        raise self.ADDED_CLIENTCERTIFICATE_REG()

    @ATMT.state()
    def ADDED_CLIENTCERTIFICATE_REG(self):
        pass

    def should_add_ClientKeyExchange_Reg(self):
        self.add_msg(TLSClientKeyExchange())
        raise self.ADDED_CLIENTKEYEXCHANGE_REG()

    @ATMT.condition(PREPARE_CLIENTFLIGHT2_REG, prio=2)
    def should_add_ClientKeyExchange_from_ClientFlight2_Reg(self):
        return self.should_add_ClientKeyExchange_Reg()

    @ATMT.condition(ADDED_CLIENTCERTIFICATE_REG)
    def should_add_ClientKeyExchange_from_ClientCertificate_Reg(self):
        return self.should_add_ClientKeyExchange_Reg()

    @ATMT.state()
    def ADDED_CLIENTKEYEXCHANGE_REG(self):
        pass

    @ATMT.condition(ADDED_CLIENTKEYEXCHANGE_REG, prio=1)
    def should_add_ClientVerify_Reg(self):
        #"""
        #XXX Section 7.4.7.1 of RFC 5246 states that the CertificateVerify
        #message is only sent following a client certificate that has signing
        #capability (i.e. not those containing fixed DH params).
        #We should verify that before adding the message. We should also handle
        #the case when the Certificate message was empty.
        #"""
        #hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        #if (TLSCertificateRequest not in hs_msg or
        #    self.mycert is None or
        #        self.mykey is None):
        #    return
        #self.add_msg(TLSCertificateVerify())
        raise self.ADDED_CERTIFICATEVERIFY_REG()

    @ATMT.state()
    def ADDED_CERTIFICATEVERIFY_REG(self):
        pass

    @ATMT.condition(ADDED_CERTIFICATEVERIFY_REG)
    def should_add_ChangeCipherSpec_from_CertificateVerify_Reg(self):
        self.add_record()
        self.add_msg(TLSChangeCipherSpec())
        raise self.ADDED_CHANGECIPHERSPEC_REG()

    @ATMT.condition(ADDED_CLIENTKEYEXCHANGE_REG, prio=2)
    def should_add_ChangeCipherSpec_from_ClientKeyExchange_Reg(self):
        self.add_record()
        self.add_msg(TLSChangeCipherSpec())
        raise self.ADDED_CHANGECIPHERSPEC_REG()

    @ATMT.state()
    def ADDED_CHANGECIPHERSPEC_REG(self):
        pass

    @ATMT.condition(ADDED_CHANGECIPHERSPEC_REG)
    def should_add_ClientFinished_Reg(self):
        self.add_record()
        self.add_msg(TLSFinished())
        raise self.ADDED_CLIENTFINISHED_REG()

    @ATMT.state()
    def ADDED_CLIENTFINISHED_REG(self):
        pass

    @ATMT.condition(ADDED_CLIENTFINISHED_REG)
    def should_send_ClientFlight2_Reg(self):
        self.flush_records()
        if self.empty_pubkey == True or self.altered_finish == True or self.missing_finished_message or self.altered_pre_master_secret == True or self.altered_y_coordinate == True:
            self.raise_on_packet(TLSAlert,
                    self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1)
        else:
            raise self.SENT_CLIENTFLIGHT2_REG()

    @ATMT.state()
    def SENT_CLIENTFLIGHT2_REG(self):
        raise self.WAITING_SERVERFLIGHT2_REG()

    @ATMT.state()
    def WAITING_SERVERFLIGHT2_REG(self):
        self.get_next_msg()
        raise self.RECEIVED_SERVERFLIGHT2_REG()

    @ATMT.state()
    def RECEIVED_SERVERFLIGHT2_REG(self):
        pass

    @ATMT.condition(RECEIVED_SERVERFLIGHT2_REG)
    def should_handle_ChangeCipherSpec_Reg(self):
        self.raise_on_packet(TLSChangeCipherSpec,
                             self.HANDLED_CHANGECIPHERSPEC_REG)

    @ATMT.state()
    def HANDLED_CHANGECIPHERSPEC_REG(self):
        pass

    @ATMT.condition(HANDLED_CHANGECIPHERSPEC_REG)
    def should_handle_Finished_Reg(self):
        self.raise_on_packet(TLSFinished,
                             self.HANDLED_SERVERFINISHED_REG)

    @ATMT.state()
    def HANDLED_SERVERFINISHED_REG(self):
        self.vprint("TLS handshake re completed!")
        self.vprint_sessioninfo()
        self.vprint("You may send data or use 'quit'.")


    #                       end of TLS Resumption handshake                              #

    @ATMT.state()
    def HANDLED_SERVERDATA(self):
        raise self.WAIT_CLIENTDATA()

    @ATMT.state()
    def CLOSE_NOTIFY(self):
        self.vprint()
        self.vprint("Trying to send a TLSAlert to the server...")

    @ATMT.condition(CLOSE_NOTIFY)
    def close_session(self):
        self.add_record()
        self.add_msg(TLSAlert(level=1, descr=0))
        try:
            self.flush_records()
        except Exception:
            self.vprint("Could not send termination Alert, maybe the server stopped?")  # noqa: E501
        raise self.FINAL()

    #                          SSLv2 handshake                                #

    @ATMT.state()
    def SSLv2_PREPARE_CLIENTHELLO(self):
        pass

    @ATMT.condition(SSLv2_PREPARE_CLIENTHELLO)
    def sslv2_should_add_ClientHello(self):
        self.add_record(is_sslv2=True)
        p = self.client_hello or SSLv2ClientHello(challenge=randstring(16))
        self.add_msg(p)
        raise self.SSLv2_ADDED_CLIENTHELLO()

    @ATMT.state()
    def SSLv2_ADDED_CLIENTHELLO(self):
        pass

    @ATMT.condition(SSLv2_ADDED_CLIENTHELLO)
    def sslv2_should_send_ClientHello(self):
        self.flush_records()
        raise self.SSLv2_SENT_CLIENTHELLO()

    @ATMT.state()
    def SSLv2_SENT_CLIENTHELLO(self):
        raise self.SSLv2_WAITING_SERVERHELLO()

    @ATMT.state()
    def SSLv2_WAITING_SERVERHELLO(self):
        self.get_next_msg()
        raise self.SSLv2_RECEIVED_SERVERHELLO()

    @ATMT.state()
    def SSLv2_RECEIVED_SERVERHELLO(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_SERVERHELLO, prio=1)
    def sslv2_should_handle_ServerHello(self):
        self.raise_on_packet(SSLv2ServerHello,
                             self.SSLv2_HANDLED_SERVERHELLO)

    @ATMT.state()
    def SSLv2_HANDLED_SERVERHELLO(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_SERVERHELLO, prio=2)
    def sslv2_missing_ServerHello(self):
        raise self.SSLv2_MISSING_SERVERHELLO()

    @ATMT.state()
    def SSLv2_MISSING_SERVERHELLO(self):
        self.vprint("Missing SSLv2 ServerHello message!")
        raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.condition(SSLv2_HANDLED_SERVERHELLO)
    def sslv2_should_add_ClientMasterKey(self):
        self.add_record(is_sslv2=True)
        self.add_msg(SSLv2ClientMasterKey())
        raise self.SSLv2_ADDED_CLIENTMASTERKEY()

    @ATMT.state()
    def SSLv2_ADDED_CLIENTMASTERKEY(self):
        pass

    @ATMT.condition(SSLv2_ADDED_CLIENTMASTERKEY)
    def sslv2_should_send_ClientMasterKey(self):
        self.flush_records()
        raise self.SSLv2_SENT_CLIENTMASTERKEY()

    @ATMT.state()
    def SSLv2_SENT_CLIENTMASTERKEY(self):
        raise self.SSLv2_WAITING_SERVERVERIFY()

    @ATMT.state()
    def SSLv2_WAITING_SERVERVERIFY(self):
        # We give the server 0.5 second to send his ServerVerify.
        # Else we assume that he's waiting for our ClientFinished.
        self.get_next_msg(0.5, 0)
        raise self.SSLv2_RECEIVED_SERVERVERIFY()

    @ATMT.state()
    def SSLv2_RECEIVED_SERVERVERIFY(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_SERVERVERIFY, prio=1)
    def sslv2_should_handle_ServerVerify(self):
        self.raise_on_packet(SSLv2ServerVerify,
                             self.SSLv2_HANDLED_SERVERVERIFY,
                             get_next_msg=False)

    @ATMT.state()
    def SSLv2_HANDLED_SERVERVERIFY(self):
        pass

    def sslv2_should_add_ClientFinished(self):
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if SSLv2ClientFinished in hs_msg:
            return
        self.add_record(is_sslv2=True)
        self.add_msg(SSLv2ClientFinished())
        raise self.SSLv2_ADDED_CLIENTFINISHED()

    @ATMT.condition(SSLv2_HANDLED_SERVERVERIFY, prio=1)
    def sslv2_should_add_ClientFinished_from_ServerVerify(self):
        return self.sslv2_should_add_ClientFinished()

    @ATMT.condition(SSLv2_HANDLED_SERVERVERIFY, prio=2)
    def sslv2_should_wait_ServerFinished_from_ServerVerify(self):
        raise self.SSLv2_WAITING_SERVERFINISHED()

    @ATMT.condition(SSLv2_RECEIVED_SERVERVERIFY, prio=2)
    def sslv2_should_add_ClientFinished_from_NoServerVerify(self):
        return self.sslv2_should_add_ClientFinished()

    @ATMT.condition(SSLv2_RECEIVED_SERVERVERIFY, prio=3)
    def sslv2_missing_ServerVerify(self):
        raise self.SSLv2_MISSING_SERVERVERIFY()

    @ATMT.state(final=True)
    def SSLv2_MISSING_SERVERVERIFY(self):
        self.vprint("Missing SSLv2 ServerVerify message!")
        raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.state()
    def SSLv2_ADDED_CLIENTFINISHED(self):
        pass

    @ATMT.condition(SSLv2_ADDED_CLIENTFINISHED)
    def sslv2_should_send_ClientFinished(self):
        self.flush_records()
        raise self.SSLv2_SENT_CLIENTFINISHED()

    @ATMT.state()
    def SSLv2_SENT_CLIENTFINISHED(self):
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if SSLv2ServerVerify in hs_msg:
            raise self.SSLv2_WAITING_SERVERFINISHED()
        else:
            self.get_next_msg()
            raise self.SSLv2_RECEIVED_SERVERVERIFY()

    @ATMT.state()
    def SSLv2_WAITING_SERVERFINISHED(self):
        self.get_next_msg()
        raise self.SSLv2_RECEIVED_SERVERFINISHED()

    @ATMT.state()
    def SSLv2_RECEIVED_SERVERFINISHED(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_SERVERFINISHED, prio=1)
    def sslv2_should_handle_ServerFinished(self):
        self.raise_on_packet(SSLv2ServerFinished,
                             self.SSLv2_HANDLED_SERVERFINISHED)

    #                       SSLv2 client authentication                       #

    @ATMT.condition(SSLv2_RECEIVED_SERVERFINISHED, prio=2)
    def sslv2_should_handle_RequestCertificate(self):
        self.raise_on_packet(SSLv2RequestCertificate,
                             self.SSLv2_HANDLED_REQUESTCERTIFICATE)

    @ATMT.state()
    def SSLv2_HANDLED_REQUESTCERTIFICATE(self):
        self.vprint("Server asked for a certificate...")
        if not self.mykey or not self.mycert:
            self.vprint("No client certificate to send!")
            raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.condition(SSLv2_HANDLED_REQUESTCERTIFICATE)
    def sslv2_should_add_ClientCertificate(self):
        self.add_record(is_sslv2=True)
        self.add_msg(SSLv2ClientCertificate(certdata=self.mycert))
        raise self.SSLv2_ADDED_CLIENTCERTIFICATE()

    @ATMT.state()
    def SSLv2_ADDED_CLIENTCERTIFICATE(self):
        pass

    @ATMT.condition(SSLv2_ADDED_CLIENTCERTIFICATE)
    def sslv2_should_send_ClientCertificate(self):
        self.flush_records()
        raise self.SSLv2_SENT_CLIENTCERTIFICATE()

    @ATMT.state()
    def SSLv2_SENT_CLIENTCERTIFICATE(self):
        raise self.SSLv2_WAITING_SERVERFINISHED()

    #                   end of SSLv2 client authentication                    #

    @ATMT.state()
    def SSLv2_HANDLED_SERVERFINISHED(self):
        self.vprint("SSLv2 handshake completed!")
        self.vprint_sessioninfo()
        self.vprint("You may send data or use 'quit'.")

    @ATMT.condition(SSLv2_RECEIVED_SERVERFINISHED, prio=3)
    def sslv2_missing_ServerFinished(self):
        raise self.SSLv2_MISSING_SERVERFINISHED()

    @ATMT.state()
    def SSLv2_MISSING_SERVERFINISHED(self):
        self.vprint("Missing SSLv2 ServerFinished message!")
        raise self.SSLv2_CLOSE_NOTIFY()

    #                        end of SSLv2 handshake                           #

    @ATMT.condition(SSLv2_HANDLED_SERVERFINISHED)
    def sslv2_should_wait_ClientData(self):
        raise self.SSLv2_WAITING_CLIENTDATA()

    @ATMT.state()
    def SSLv2_WAITING_CLIENTDATA(self):
        pass

    @ATMT.condition(SSLv2_WAITING_CLIENTDATA, prio=1)
    def sslv2_add_ClientData(self):
        if not self.data_to_send:
            data = six.moves.input().replace('\\r', '\r').replace('\\n', '\n').encode()  # noqa: E501
        else:
            data = self.data_to_send.pop()
            self.vprint("> Read from list: %s" % data)
        if data == "quit":
            return
        if self.linebreak:
            data += "\n"
        self.add_record(is_sslv2=True)
        self.add_msg(Raw(data))
        raise self.SSLv2_ADDED_CLIENTDATA()

    @ATMT.condition(SSLv2_WAITING_CLIENTDATA, prio=2)
    def sslv2_no_more_ClientData(self):
        raise self.SSLv2_CLOSE_NOTIFY()

    @ATMT.state()
    def SSLv2_ADDED_CLIENTDATA(self):
        pass

    @ATMT.condition(SSLv2_ADDED_CLIENTDATA)
    def sslv2_should_send_ClientData(self):
        self.flush_records()
        raise self.SSLv2_SENT_CLIENTDATA()

    @ATMT.state()
    def SSLv2_SENT_CLIENTDATA(self):
        raise self.SSLv2_WAITING_SERVERDATA()

    @ATMT.state()
    def SSLv2_WAITING_SERVERDATA(self):
        self.get_next_msg(0.3, 1)
        raise self.SSLv2_RECEIVED_SERVERDATA()

    @ATMT.state()
    def SSLv2_RECEIVED_SERVERDATA(self):
        pass

    @ATMT.condition(SSLv2_RECEIVED_SERVERDATA)
    def sslv2_should_handle_ServerData(self):
        if not self.buffer_in:
            raise self.SSLv2_WAITING_CLIENTDATA()
        p = self.buffer_in[0]
        print("> Received: %r" % p.load)
        if p.load.startswith(b"goodbye"):
            raise self.SSLv2_CLOSE_NOTIFY()
        self.buffer_in = self.buffer_in[1:]
        raise self.SSLv2_HANDLED_SERVERDATA()

    @ATMT.state()
    def SSLv2_HANDLED_SERVERDATA(self):
        raise self.SSLv2_WAITING_CLIENTDATA()

    @ATMT.state()
    def SSLv2_CLOSE_NOTIFY(self):
        """
        There is no proper way to end an SSLv2 session.
        We try and send a 'goodbye' message as a substitute.
        """
        self.vprint()
        self.vprint("Trying to send a 'goodbye' to the server...")

    @ATMT.condition(SSLv2_CLOSE_NOTIFY)
    def sslv2_close_session(self):
        self.add_record()
        self.add_msg(Raw('goodbye'))
        try:
            self.flush_records()
        except Exception:
            self.vprint("Could not send our goodbye. The server probably stopped.")  # noqa: E501
        self.socket.close()
        raise self.FINAL()

    #                         TLS 1.3 handshake                               #

    @ATMT.state()
    def TLS13_START(self):
        pass

    @ATMT.condition(TLS13_START)
    def tls13_should_add_ClientHello(self):
        # we have to use the legacy, plaintext TLS record here
        #supported_groups = ["secp256r1", "secp384r1", "x448"]
        if self.sg != None:
            supported_groups = self.sg
        else:
            supported_groups = ["secp256r1", "secp384r1", "x448"]
            if conf.crypto_valid_advanced:
                supported_groups.append("x25519")
        self.add_record(is_tls13=False)
        if self.client_hello:
            p = self.client_hello
        else:
            if self.ciphersuite is None:
                c = 0x1301
            else:
                c = self.ciphersuite
            if self.use_legacy == True:
                p = TLS13ClientHello(ciphers=c,version=0x0304)
                self.vprint("Contents of Client Hello")
                p.show2()
            else:
                p = TLS13ClientHello(ciphers=c)

        ext = []
        ext += TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3"])

        s = self.cur_session

        if s.tls13_psk_secret:
            # Check if DHE is need (both for out of band and resumption PSK)
            if self.tls13_psk_mode == "psk_dhe_ke":
                ext += TLS_Ext_PSKKeyExchangeModes(kxmodes="psk_dhe_ke")
                ext += TLS_Ext_SupportedGroups(groups=supported_groups)
                ext += TLS_Ext_KeyShare_CH(
                    client_shares=[KeyShareEntry(group=self.curve)]
                )
            else:
                ext += TLS_Ext_PSKKeyExchangeModes(kxmodes="psk_ke")

            # RFC844, section 4.2.11.
            # "The "pre_shared_key" extension MUST be the last extension
            # in the ClientHello "
            # Compute the pre_shared_key extension for resumption PSK
            if s.client_session_ticket:
                cs_cls = _tls_cipher_suites_cls[s.tls13_ticket_ciphersuite]  # noqa: E501
                hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
                hash_len = hkdf.hash.digest_size
                # We compute the client's view of the age of the ticket (ie
                # the time since the receipt of the ticket) in ms
                agems = int((time.time() - s.client_ticket_age) * 1000)
                # Then we compute the obfuscated version of the ticket age
                # by adding the "ticket_age_add" value included in the
                # ticket (modulo 2^32)
                obfuscated_age = ((agems + s.client_session_ticket_age_add) &
                                  0xffffffff)

                psk_id = PSKIdentity(identity=s.client_session_ticket,
                                     obfuscated_ticket_age=obfuscated_age)

                psk_binder_entry = PSKBinderEntry(binder_len=hash_len,
                                                  binder=b"\x00" * hash_len)

                if self.provide_early_data == True:
                    ext += TLS_Ext_EarlyDataIndication()
                # Preshared Key Must be Last Extension
                ext += TLS_Ext_PreSharedKey_CH(identities=[psk_id],
                                               binders=[psk_binder_entry])
            else:
                # Compute the pre_shared_key extension for out of band PSK
                # (SHA256 is used as default hash function for HKDF for out
                # of band PSK)
                hkdf = TLS13_HKDF("sha256")
                hash_len = hkdf.hash.digest_size
                psk_id = PSKIdentity(identity='Client_identity')
                # XXX see how to not pass binder as argument
                psk_binder_entry = PSKBinderEntry(binder_len=hash_len,
                                                  binder=b"\x00" * hash_len)

                ext += TLS_Ext_PreSharedKey_CH(identities=[psk_id],
                                               binders=[psk_binder_entry])
        else:
            ext += TLS_Ext_SupportedGroups(groups=supported_groups)
            ext += TLS_Ext_KeyShare_CH(
                client_shares=[KeyShareEntry(group=self.curve)]
            )
            ext += TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss",
                                                         "sha256+rsa"])
        # Add TLS_Ext_ServerName
        if self.server_name:
            ext += TLS_Ext_ServerName(
                servernames=[ServerName(servername=self.server_name)]
            )
        p.ext = ext
        #
        if self.altered_y_coordinate == True and p['Key Share Entry'].group in _nist_curves:
            #print ("Contents of Client Hello before altering y coordinate")
            #p.show2()
            Raw(p)
            y_coordinate = p['Key Share Entry'][0].key_exchange
            print("Contents of x y coordinate before altering: [%s]" % repr_hex(y_coordinate))
            altered_y_coordinate = y_coordinate[:-3] + randstring(1) + y_coordinate[-2:]
            if altered_y_coordinate == y_coordinate:
                warning("y coordinate was not altered.  Run Test Again!")
            else:
                p['Key Share Entry'][0].key_exchange = altered_y_coordinate
                print("Contents of x y coordinate after altering:  [%s]" % repr_hex(p['Key Share Entry'][0].key_exchange))
                print(" ")
        self.add_msg(p)
        raise self.TLS13_ADDED_CLIENTHELLO()

    @ATMT.state()
    def TLS13_ADDED_CLIENTHELLO(self):
        raise self.TLS13_SENDING_CLIENTFLIGHT1()

    @ATMT.state()
    def TLS13_SENDING_CLIENTFLIGHT1(self):
        pass

    @ATMT.condition(TLS13_SENDING_CLIENTFLIGHT1)
    def tls13_should_send_ClientFlight1(self):
        self.flush_records()
        if self.provide_early_data == True:
            data = b'GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n'
            self.add_record()
            self.add_msg(TLSApplicationData(data=data))
            self.flush_records()
            raise self.TLS13_SENT_CLIENTFLIGHT1()
        else:
            raise self.TLS13_SENT_CLIENTFLIGHT1()

    @ATMT.state()
    def TLS13_SENT_CLIENTFLIGHT1(self):
        raise self.TLS13_WAITING_SERVERFLIGHT1()

    @ATMT.state()
    def TLS13_WAITING_SERVERFLIGHT1(self):
        self.get_next_msg()
        raise self.TLS13_RECEIVED_SERVERFLIGHT1()

    @ATMT.state()
    def TLS13_RECEIVED_SERVERFLIGHT1(self):
        pass

    @ATMT.condition(TLS13_RECEIVED_SERVERFLIGHT1, prio=1)
    def tls13_should_handle_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        self.raise_on_packet(TLS13ServerHello,
                             self.TLS13_HANDLED_SERVERHELLO)

    @ATMT.condition(TLS13_RECEIVED_SERVERFLIGHT1, prio=2)
    def tls13_should_handle_HelloRetryRequest(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        self.raise_on_packet(TLS13HelloRetryRequest,
                             self.TLS13_HELLO_RETRY_REQUESTED)

    @ATMT.condition(TLS13_RECEIVED_SERVERFLIGHT1, prio=3)
    def tls13_should_handle_AlertMessage_(self):
        self.raise_on_packet(TLSAlert,
                             self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1)

    @ATMT.state()
    def TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1(self):
        self.vprint("Received Alert message !")
        self.vprint(self.cur_pkt.mysummary())
        if self.missing_finished_message or self.altered_finish:
            if self.advertised_tls_version == 0x0304:
                self.print_tls13secrets()
        raise self.CLOSE_NOTIFY()

    @ATMT.condition(TLS13_RECEIVED_SERVERFLIGHT1, prio=4)
    def tls13_missing_ServerHello(self):
        raise self.MISSING_SERVERHELLO()

    @ATMT.state()
    def TLS13_HELLO_RETRY_REQUESTED(self):
        pass

    @ATMT.condition(TLS13_HELLO_RETRY_REQUESTED)
    def tls13_should_add_ClientHello_Retry(self):
        s = self.cur_session
        s.tls13_retry = True
        # we have to use the legacy, plaintext TLS record here
        self.add_record(is_tls13=False)
        # We retrieve the group to be used and the selected version from the
        # previous message
        hrr = s.handshake_messages_parsed[-1]
        if isinstance(hrr, TLS13HelloRetryRequest):
            pass
        ciphersuite = hrr.cipher
        if hrr.ext:
            for e in hrr.ext:
                if isinstance(e, TLS_Ext_KeyShare_HRR):
                    selected_group = e.selected_group
                if isinstance(e, TLS_Ext_SupportedVersion_SH):
                    selected_version = e.version
        if not selected_group or not selected_version:
            raise self.CLOSE_NOTIFY()

        ext = []
        ext += TLS_Ext_SupportedVersion_CH(versions=[_tls_version[selected_version]])  # noqa: E501

        if s.tls13_psk_secret:
            if self.tls13_psk_mode == "psk_dhe_ke":
                ext += TLS_Ext_PSKKeyExchangeModes(kxmodes="psk_dhe_ke"),
                ext += TLS_Ext_SupportedGroups(groups=[_tls_named_groups[selected_group]])  # noqa: E501
                ext += TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group=selected_group)])  # noqa: E501
            else:
                ext += TLS_Ext_PSKKeyExchangeModes(kxmodes="psk_ke")

            if s.client_session_ticket:

                # XXX Retrieve parameters from first ClientHello...
                cs_cls = _tls_cipher_suites_cls[s.tls13_ticket_ciphersuite]
                hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
                hash_len = hkdf.hash.digest_size

                # We compute the client's view of the age of the ticket (ie
                # the time since the receipt of the ticket) in ms
                agems = int((time.time() - s.client_ticket_age) * 1000)

                # Then we compute the obfuscated version of the ticket age by
                # adding the "ticket_age_add" value included in the ticket
                # (modulo 2^32)
                obfuscated_age = ((agems + s.client_session_ticket_age_add) &
                                  0xffffffff)

                psk_id = PSKIdentity(identity=s.client_session_ticket,
                                     obfuscated_ticket_age=obfuscated_age)

                psk_binder_entry = PSKBinderEntry(binder_len=hash_len,
                                                  binder=b"\x00" * hash_len)

                ext += TLS_Ext_PreSharedKey_CH(identities=[psk_id],
                                               binders=[psk_binder_entry])
            else:
                hkdf = TLS13_HKDF("sha256")
                hash_len = hkdf.hash.digest_size
                psk_id = PSKIdentity(identity='Client_identity')
                psk_binder_entry = PSKBinderEntry(binder_len=hash_len,
                                                  binder=b"\x00" * hash_len)

                ext += TLS_Ext_PreSharedKey_CH(identities=[psk_id],
                                               binders=[psk_binder_entry])

        else:
            ext += TLS_Ext_SupportedGroups(groups=[_tls_named_groups[selected_group]])  # noqa: E501
            ext += TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group=selected_group)])  # noqa: E501
            ext += TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss"])

        p = TLS13ClientHello(ciphers=ciphersuite, ext=ext)
        self.add_msg(p)
        raise self.TLS13_ADDED_CLIENTHELLO()

    @ATMT.state()
    def TLS13_HANDLED_SERVERHELLO(self):
        pass

    @ATMT.condition(TLS13_HANDLED_SERVERHELLO, prio=1)
    def tls13_should_handle_encrytpedExtensions(self):
        self.raise_on_packet(TLSEncryptedExtensions,
                             self.TLS13_HANDLED_ENCRYPTEDEXTENSIONS)

    @ATMT.condition(TLS13_HANDLED_SERVERHELLO, prio=2)
    def tls13_should_handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec,
                             self.TLS13_HANDLED_CHANGE_CIPHER_SPEC)

    @ATMT.state()
    def TLS13_HANDLED_CHANGE_CIPHER_SPEC(self):
        self.cur_session.middlebox_compatibility = True
        raise self.TLS13_HANDLED_SERVERHELLO()

    @ATMT.condition(TLS13_HANDLED_SERVERHELLO, prio=3)
    def tls13_missing_encryptedExtension(self):
        self.vprint("Missing TLS 1.3 EncryptedExtensions message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def TLS13_HANDLED_ENCRYPTEDEXTENSIONS(self):
        pass

    @ATMT.condition(TLS13_HANDLED_ENCRYPTEDEXTENSIONS, prio=1)
    def tls13_should_handle_certificateRequest_from_encryptedExtensions(self):
        """
        XXX We should check the CertificateRequest attributes for discrepancies
        with the cipher suite, etc.
        """
        self.raise_on_packet(TLS13CertificateRequest,
                             self.TLS13_HANDLED_CERTIFICATEREQUEST)

    @ATMT.condition(TLS13_HANDLED_ENCRYPTEDEXTENSIONS, prio=2)
    def tls13_should_handle_certificate_from_encryptedExtensions(self):
        self.tls13_should_handle_Certificate()

    @ATMT.condition(TLS13_HANDLED_ENCRYPTEDEXTENSIONS, prio=3)
    def tls13_should_handle_finished_from_encryptedExtensions(self):
        if self.cur_session.tls13_psk_secret:
            self.raise_on_packet(TLSFinished,
                                 self.TLS13_HANDLED_FINISHED)

    @ATMT.state()
    def TLS13_HANDLED_CERTIFICATEREQUEST(self):
        pass

    @ATMT.condition(TLS13_HANDLED_CERTIFICATEREQUEST, prio=1)
    def tls13_should_handle_Certificate_from_CertificateRequest(self):
        return self.tls13_should_handle_Certificate()

    def tls13_should_handle_Certificate(self):
        self.raise_on_packet(TLS13Certificate,
                             self.TLS13_HANDLED_CERTIFICATE)

    @ATMT.state()
    def TLS13_HANDLED_CERTIFICATE(self):
        pass

    @ATMT.condition(TLS13_HANDLED_CERTIFICATE, prio=1)
    def tls13_should_handle_CertificateVerify(self):
        self.raise_on_packet(TLSCertificateVerify,
                             self.TLS13_HANDLED_CERTIFICATE_VERIFY)

    @ATMT.condition(TLS13_HANDLED_CERTIFICATE, prio=2)
    def tls13_missing_CertificateVerify(self):
        self.vprint("Missing TLS 1.3 CertificateVerify message!")
        raise self.CLOSE_NOTIFY()

    @ATMT.state()
    def TLS13_HANDLED_CERTIFICATE_VERIFY(self):
        pass

    @ATMT.condition(TLS13_HANDLED_CERTIFICATE_VERIFY, prio=1)
    def tls13_should_handle_finished(self):
        self.raise_on_packet(TLSFinished,
                             self.TLS13_HANDLED_FINISHED)

    @ATMT.state()
    def TLS13_HANDLED_FINISHED(self):
        raise self.TLS13_PREPARE_CLIENTFLIGHT2()

    @ATMT.state()
    def TLS13_PREPARE_CLIENTFLIGHT2(self):
        if self.cur_session.middlebox_compatibility:
            self.add_record(is_tls12=True)
            self.add_msg(TLSChangeCipherSpec())
        self.add_record(is_tls13=True)

    @ATMT.condition(TLS13_PREPARE_CLIENTFLIGHT2, prio=1)
    def tls13_should_add_ClientCertificate(self):
        """
        If the server sent a CertificateRequest, we send a Certificate message.
        If no certificate is available, an empty Certificate message is sent:
        - this is a SHOULD in RFC 4346 (Section 7.4.6)
        - this is a MUST in RFC 5246 (Section 7.4.6)

        XXX We may want to add a complete chain.
        """
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if TLS13CertificateRequest not in hs_msg:
            raise self.TLS13_ADDED_CLIENTCERTIFICATE()
            # return
        certs = []
        if self.mycert:
            certs += _ASN1CertAndExt(cert=self.mycert)

        if self.empty_certificate == True:
            certs = []
        self.add_msg(TLS13Certificate(certs=certs))
        raise self.TLS13_ADDED_CLIENTCERTIFICATE()

    @ATMT.state()
    def TLS13_ADDED_CLIENTCERTIFICATE(self):
        pass

    @ATMT.condition(TLS13_ADDED_CLIENTCERTIFICATE, prio=1)
    def tls13_should_add_ClientCertificateVerify(self):
        """
        XXX Section 7.4.7.1 of RFC 5246 states that the CertificateVerify
        message is only sent following a client certificate that has signing
        capability (i.e. not those containing fixed DH params).
        We should verify that before adding the message. We should also handle
        the case when the Certificate message was empty.
        """
        hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        if (TLS13CertificateRequest not in hs_msg or
                self.mycert is None or
                self.mykey is None):
            return self.tls13_should_add_ClientFinished()
        self.add_msg(TLSCertificateVerify())
        raise self.TLS13_ADDED_CERTIFICATEVERIFY()

    @ATMT.state()
    def TLS13_ADDED_CERTIFICATEVERIFY(self):
        return self.tls13_should_add_ClientFinished()

    @ATMT.condition(TLS13_PREPARE_CLIENTFLIGHT2, prio=2)
    def tls13_should_add_ClientFinished(self):
        if self.missing_finished_message == True:
            p=(TLSApplicationData(data=b'\xEF\xBB\xBF'))
            print ("Sending some random Application Data")
            p.show2()
            self.add_msg(p)
        else:
            self.add_msg(TLSFinished())
        raise self.TLS13_ADDED_CLIENTFINISHED()

    @ATMT.state()
    def TLS13_ADDED_CLIENTFINISHED(self):
        pass

    @ATMT.condition(TLS13_ADDED_CLIENTFINISHED)
    def tls13_should_send_ClientFlight2(self):
        self.flush_records()
        if self.altered_finish == True or self.missing_finished_message == True:
                self.raise_on_packet(TLSAlert,
                    self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1)
            #raise self.WAIT_CLIENTDATA()
        else:
            raise self.TLS13_SENT_CLIENTFLIGHT2()

    @ATMT.state()
    def TLS13_SENT_CLIENTFLIGHT2(self):
        self.vprint("TLS 1.3 handshake completed!")
        self.vprint_sessioninfo()
        self.vprint("You may send data or use 'quit'.")
        #
        if self.tls13_renegotiation == True:
            p = TLS13ClientHello(ciphers=0x1301)
            self.add_msg(p)
            self.flush_records()
            self.get_next_msg()
            raise self.TLS13_HANDLED_ALERT_FROM_SERVERFLIGHT1()
        else:
            raise self.WAIT_CLIENTDATA()

    @ATMT.state()
    def SOCKET_CLOSED(self):
        raise self.FINAL()

    @ATMT.state(stop=True)
    def STOP(self):
        # Called on atmt.stop()
        if self.cur_session.advertised_tls_version in [0x0200, 0x0002]:
            raise self.SSLv2_CLOSE_NOTIFY()
        else:
            raise self.CLOSE_NOTIFY()

    @ATMT.state(final=True)
    def FINAL(self):
        # We might call shutdown, but it may happen that the server
        # did not wait for us to shutdown after answering our data query.
        # self.socket.shutdown(1)
        self.vprint("Closing client socket...")
        self.socket.close()
        self.vprint("Ending TLS client automaton.")
