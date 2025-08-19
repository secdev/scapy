# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Forwarding machine.
"""

import enum
import functools
import os
import select
import socket
import ssl
import threading
import traceback

from scapy.asn1.asn1 import ASN1_OID
from scapy.config import conf
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import StreamSocket, StreamSocketPeekless
from scapy.themes import DefaultTheme
from scapy.utils import get_temp_file
from scapy.volatile import RandInt

from scapy.layers.tls.all import (
    Cert,
    PrivKeyECDSA,
)
from scapy.layers.x509 import (
    X509_AlgorithmIdentifier,
)

from cryptography.hazmat.primitives import serialization

# Typing imports
from typing import (
    Type,
    Optional,
)


class ForwardMachine:
    """
    Forward Machine

    This binds a port and relay any connections from 'clients' to
    their original destination a 'server'. Forwarding machine can be used in
    two modes:

    - SERVER: the server binds a port on its local IP and forwards packets to a
        ``remote_address``.
    - TPROXY: the server binds can intercept packets to any IP destination, provided
        that they are routed through the local server, and some tweaking of the OS
        routes;

    The TPROXY mode is expected to be used on a router with FORWARDING and only a
    specific set of nat rules set to -j TPROXY. A script called 'vethrelay.sh'
    is provided in the documentation for setting this up.

    ForwardMachine supports transparently proxifying TLS. By default, it will generate
    lookalike self-signed certificates, but it's also possible to specify a certificate
    by using crtfile and keyfile.

    Parameters:

    :param port: the port to listen on
    :param cls: the scapy class to parse on that port
    :param af: the address family to use (default AF_INET)
    :param proto: the proto to use (default SOCK_STREAM)
    :param remote_address: the IP to use in SERVER mode, or by default in TPROXY when
        the destination is the local IP.
    :param remote_af: (optional) if provided, use a different address family to connect
        to the remote host.
    :param bind_address: the IP to bind locally. "0.0.0.0" by default in SERVER mode,
        but "2.2.2.2" by default in TPROXY (if you are using the provided
        'vethrelay.sh' script).
    :param tls: enable TLS (in both the server and client)
    :param crtfile: (optional) if provided, uses a certificate instead of self signed
        ones.
    :param keyfile: (optional) path to the key file
    :param timeout: the timeout before connecting to the real server (default 2)

    Methods to override:

    :func xfrmcs: a function to call when forwarding a packet from the 'client' to
        the server. If it raises a FORWARD exception, the packet is forwarded as it. If
        it raises a DROP Exception, the packet is discarded. If it raises a
        FORWARD_REPLACE(pkt) exception, then pkt is forwarded instead of the original
        packet.
    :func xfrmsc: same as xfrmcs for packets forwarded from the 'server' to the
        'client'.
    """

    class MODE(enum.Enum):
        SERVER = 0
        TPROXY = 1

    def __init__(
        self,
        mode: MODE,
        port: int,
        cls: Type[Packet],
        af: socket.AddressFamily = socket.AF_INET,
        proto: socket.SocketKind = socket.SOCK_STREAM,
        remote_address: str = None,
        remote_af: Optional[socket.AddressFamily] = None,
        bind_address: str = None,
        tls: bool = False,
        crtfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        timeout: int = 2,
        MTU: int = MTU,
        **kwargs,
    ):
        self.mode = mode
        self.port = port
        self.cls = cls
        self.af = af
        self.remote_af = remote_af if remote_af is not None else af
        self.proto = proto
        self.tls = tls
        self.crtfile = crtfile
        self.keyfile = keyfile
        self.timeout = timeout
        self.MTU = MTU
        self.remote_address = remote_address
        if self.tls or self.af == 40:  # TLS or VSOCK
            self.sockcls = StreamSocketPeekless
        else:
            self.sockcls = StreamSocket
        # Chose 'bind_address' depending on the mode
        self.bind_address = bind_address
        if self.bind_address is None:
            if self.mode == ForwardMachine.MODE.SERVER:
                self.bind_address = "0.0.0.0"
            elif self.mode == ForwardMachine.MODE.TPROXY:
                self.bind_address = "2.2.2.2"
            else:
                raise ValueError("Unknown mode :/")
        red = lambda z: functools.reduce(lambda x, y: x + y, z)
        # Utils
        self.ct = DefaultTheme()
        self.local_ips = red(red(list(x.ips.values())) for x in conf.ifaces.values())
        self.cache = {}
        super(ForwardMachine, self).__init__(**kwargs)

    def run(self):
        """
        Function to start the relay server
        """
        self.ssock = socket.socket(self.af, self.proto, 0)
        self.ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.mode == ForwardMachine.MODE.TPROXY:
            self.ssock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)  # TPROXY !
        self.ssock.bind((self.bind_address, self.port))
        self.ssock.listen(5)
        print(self.ct.green("Relay server waiting on port %s" % self.port))
        while True:
            conn, addr = self.ssock.accept()
            # Calc dest
            dest = conn.getsockname()
            if self.mode == ForwardMachine.MODE.SERVER or (
                dest[0] in self.local_ips and self.remote_address
            ):
                dest = (self.remote_address,) + dest[1:]
            print(self.ct.green("%s -> %s connected !" % (repr(addr), repr(dest))))
            try:
                threading.Thread(
                    target=self.handler,
                    args=(conn, addr, dest),
                ).start()
            except Exception:
                print(self.ct.red("%s errored !" % repr(addr)))
                conn.close()
                pass

    def xfrmcs(self, pkt, ctx):
        """
        DEV: overwrite me to handle client->server
        """
        raise self.FORWARD()

    def xfrmsc(self, pkt, ctx):
        """
        DEV: overwrite me to handle server->client
        """
        raise self.FORWARD()

    # Command Exceptions

    class DROP(Exception):
        # Drop this packet.
        pass

    class FORWARD(Exception):
        # Forward this packet.
        pass

    class FORWARD_REPLACE(Exception):
        # Replace the content and forward.
        def __init__(self, data):
            self.data = data

    class ANSWER(Exception):
        # Answer directly
        def __init__(self, data):
            self.data = data

    class REDIRECT_TO(Exception):
        # Redirect this socket to another destination
        def __init__(self, host, port, then=None, server_hostname=None):
            self.dest = (host, port)
            self.server_hostname = server_hostname
            self.then = then or ForwardMachine.FORWARD()

    class CONTEXT:
        """
        CONTEXT object kept during a session
        """

        def __init__(self, addr, dest):
            self.addr = addr
            self.dest = dest
            self.tls_sni_name = None  # Retrieved when receiving a connection

    def print_reply(self, evt, cs, req, rep):
        if evt == self.FORWARD:
            if cs:
                print("C ==> S: %s" % req.summary())
            else:
                print("S ==> C: %s" % req.summary())
        elif evt == self.FORWARD_REPLACE:
            if cs:
                print("C /=> S: %s -> %s" % (req.summary(), rep.summary()))
            else:
                print("S /=> C: %s -> %s" % (req.summary(), rep.summary()))
        elif evt == self.DROP:
            if cs:
                print("C => 0: %s" % req.summary())
            else:
                print("S => 0: %s" % req.summary())
        elif evt == self.ANSWER:
            if cs:
                print("C <=| : %s -> %s" % (req.summary(), rep.summary()))
            else:
                print("S <=| : %s -> %s" % (req.summary(), rep.summary()))

    def destalias(self, dest):
        """
        Alias a destination to another destination.
        A destination is the tuple (host, port)
        """
        return dest

    def _getpeersock(self, dest, server_hostname=None):
        """
        Get peer socket
        """
        s = socket.socket(self.remote_af, self.proto)
        s.settimeout(self.timeout)
        ndest = self.destalias(dest)
        if ndest != dest:
            print("C: %s redirected to %s" % (repr(dest), repr(ndest)))
        dest = ndest
        s.connect(dest)
        return s

    def gen_alike_chain(self, certs, privkey):
        """
        Modify a real certificate chain to be served by our own privatekey
        """
        c, certs = certs[0], certs[1:]
        if certs:
            # Recursive: if there are certificates above this one in the chain, do them
            # first.
            certs = self.gen_alike_chain(certs, privkey)
        else:
            # Last certificate of the chain. Make it self-signed
            c.tbsCertificate.issuer = c.tbsCertificate.subject
        # Set SubjectPublicKeyInfo to the one from our private key
        c.setSubjectPublicKeyFromPrivateKey(privkey)
        # Filter out extensions that would cause trouble
        c.tbsCertificate.serialNumber.val = int(
            RandInt()
        )  # otherwise SEC_ERROR_REUSED_ISSUER_AND_SERIAL
        c.tbsCertificate.extensions = [
            x
            for x in c.tbsCertificate.extensions
            if x.extnID
            not in [
                "2.5.29.32",  # CPS
                "2.5.29.31",  # cRLDistributionPoints
                "1.3.6.1.5.5.7.1.1",  # authorityInfoAccess
                "1.3.6.1.4.1.11129.2.4.2",  # SCT
                "2.5.29.14",  # subjectKeyIdentifier
                "2.5.29.35",  # authorityKeyIdentifier
            ]
        ]
        # For now, we only provide a RSA private key, so we can only sign with that :/
        c.tbsCertificate.signature = X509_AlgorithmIdentifier(
            algorithm=ASN1_OID("ecdsa-with-SHA384"),
        )
        # Resign.
        c = Cert(privkey.resignCert(c))
        # Return
        return [c] + certs

    def get_key_and_alike_chain(self, cas, dest, server_name):
        """
        Generate a PrivateKey and a clone of the 'cas' certificate chain signed with it,
        if not already cached.

        The cache uses server_name or dest as key.
        """
        ident = server_name or dest
        if ident in self.cache:
            return self.cache[ident]
        # Parse CAs
        certs = [Cert(c.public_bytes()) for c in cas]
        # certs = certs[:1]
        # Generate Private Key
        privkey = PrivKeyECDSA()
        # Iterate
        certs = self.gen_alike_chain(certs, privkey)
        # Build a chain object. This checks that everything is properly signed, and
        # re-order the certs.
        # chain = Chain(certs, cert0=certs[-1])
        self.cache[ident] = privkey, certs
        return privkey, certs

    def handler(self, sock, addr, dest):
        """
        Handler of a client socket
        """
        ctx = self.CONTEXT(addr, dest)  # we have a context object
        # Initialize peer socket
        ss = self._getpeersock(dest)
        # Wrap both server and peer sockets in SSL
        if self.tls:
            # Build client SSL context
            clisslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            clisslcontext.load_default_certs()
            clisslcontext.check_hostname = False
            clisslcontext.verify_mode = ssl.CERT_NONE

            # This acts as follows:
            # - start the server-side TLS handshake
            # - use the SNI callback to pop a client-side socket (using the real
            #   provided SNI)
            # - serve the certificate

            _clisock = [ss]

            def cb_sni(sock, server_name, _):
                """
                This callback occurs after the TLSClientHello is received by the server
                """
                ss = _clisock[0]
                ctx.tls_sni_name = server_name  # the requested SNI
                # Use that SNI to wrap the client socket
                ss = clisslcontext.wrap_socket(ss, server_hostname=server_name)
                # Get certificate chain
                cas = ss._sslobj.get_unverified_chain()
                if self.crtfile is None:
                    # SELF-SIGNED mode
                    # Generate private key based on the type of certificate
                    privkey, certs = self.get_key_and_alike_chain(
                        cas, dest, server_name
                    )
                    # Load result certificate our SSL server
                    # (this is dumb but we need to store them on disk)
                    certfile = get_temp_file()
                    with open(certfile, "w") as fd:
                        for c in certs:
                            fd.write(c.pem)
                    keyfile = get_temp_file()
                    with open(keyfile, "wb") as fd:
                        password = os.urandom(32)
                        fd.write(
                            privkey.key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.BestAvailableEncryption(  # noqa: E501
                                    password
                                ),
                            )
                        )
                else:
                    # Certificate is provided
                    certfile = self.crtfile
                    keyfile = self.keyfile
                sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                sslcontext.check_hostname = False
                sslcontext.verify_mode = ssl.CERT_NONE  # note: server side
                sslcontext.load_cert_chain(certfile, keyfile, password=password)
                sock.context = sslcontext
                # Return success
                _clisock[0] = ss
                return None  # Continue

            # Server SSL context
            sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            sslcontext.sni_callback = cb_sni
            try:
                sock = sslcontext.wrap_socket(sock, server_side=True)
            except Exception as ex:
                print(self.ct.red("%s errored in SSL: %s" % (repr(addr), str(ex))))
                sock.close()
                return
            ss = _clisock[0]
        # Wrap the sockets
        sock = self.sockcls(sock, self.cls)
        ss = self.sockcls(ss, self.cls)
        try:
            while True:
                # Listen on both ends of the connection
                for thissock in select.select([ss, sock], [], [], 0)[0]:
                    if thissock is ss:
                        cs = 0
                        func = self.xfrmsc
                        othersock = sock
                    else:
                        cs = 1
                        func = self.xfrmcs
                        othersock = ss
                    # get data
                    try:
                        data = thissock.recv(self.MTU)
                    except EOFError:
                        raise RuntimeError
                    if not data:
                        # Session needs more data
                        continue
                    try:
                        # And pipe everything into the processdata
                        try:
                            func(data, ctx)
                            # If this doesn't raise, it's a user error.
                            print(
                                self.ct.red(
                                    "%s ERROR: you must always raise in %s !" % func
                                )
                            )
                            return
                        except self.REDIRECT_TO as ex:
                            # Replace the peer socket with a new socket
                            oldss = ss
                            ss = self._getpeersock(
                                ex.dest, server_hostname=ex.server_hostname
                            )
                            ss = self.sockcls(ss, self.cls)
                            print(
                                "C: %s redirected to %s"
                                % (repr(ctx.dest), repr(ex.dest))
                            )
                            ctx.dest = ex.dest  # update context
                            # Shut the old one.
                            oldss.ins.shutdown(socket.SHUT_RDWR)
                            oldss.close()
                            # Replace othersock/thissock
                            if oldss is thissock:
                                thissock = ss
                            else:
                                othersock = ss
                            # Raise what's next.
                            raise ex.then
                    except self.FORWARD:
                        # Forward the data to the other host
                        othersock.send(data)
                        self.print_reply(self.FORWARD, cs, data, None)
                    except self.FORWARD_REPLACE as ex:
                        # Forward custom data to the other host
                        othersock.send(ex.data)
                        self.print_reply(self.FORWARD_REPLACE, cs, data, ex.data)
                    except self.DROP:
                        # Drop
                        self.print_reply(self.DROP, cs, data, None)
                    except self.ANSWER as ex:
                        # Respond with custom data
                        thissock.send(ex.data)
                        self.print_reply(self.ANSWER, cs, data, ex.data)
                    except Exception as ex:
                        # Processing failed. forward to not break anything
                        print(
                            self.ct.orange(
                                "Exception happened in handling client %s ! (forward)"
                                % repr(addr)
                            )
                        )
                        traceback.print_exception(ex)
                        othersock.send(data)
                        self.print_reply(self.FORWARD, cs, data, None)
        except RuntimeError:
            print(self.ct.red("%s DISCONNECTED !" % repr(addr)))
            sock.close()
            ss.close()
