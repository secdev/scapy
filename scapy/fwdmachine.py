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
import sys
import threading
import traceback

from scapy.asn1.asn1 import ASN1_OID, ASN1_INTEGER
from scapy.config import conf
from scapy.consts import LINUX
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import StreamSocket, StreamSocketPeekless
from scapy.themes import DefaultTheme
from scapy.utils import get_temp_file

from scapy.layers.tls.all import (
    Cert,
    PrivKey,
    PrivKeyECDSA,
)
from scapy.layers.x509 import (
    X509_ExtBasicConstraints,
    X509_Extension,
)

# Crypto imports
if conf.crypto_valid:
    from cryptography.hazmat.primitives import serialization

# Typing imports
from typing import (
    Optional,
    Type,
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
    :param remote_port: the port to use in SERVER mode. (else use 'port')
    :param remote_af: (optional) if provided, use a different address family to connect
        to the remote host.
    :param bind_address: the IP to bind locally. "0.0.0.0" by default
    :param iface: the interface to bind (defaults to ANY in SERVER,
        but "vethrelay" by default in TPROXY (if you are using the provided
        'vethrelay.sh' script).
    :param tls: enable TLS (in both the server and client)
    :param no_check_certificate: with TLS, do not check the certificate of the
        upstream server.
    :param crtfile: (optional) if provided, uses a certificate instead of self signed
        ones.
    :param keyfile: (optional) path to the key file
    :param keyfilepwd: (optional) password of the keyfile
    :param rootcrtfile: optional CA certificate used to sign lookalike chains.
        Clients must trust this CA. Otherwise the highest clone is self-signed.
    :param rootkeyfile: unencrypted signing private key for rootcrtfile
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
        remote_port: int = None,
        remote_af: Optional[socket.AddressFamily] = None,
        bind_address: str = None,
        iface: str = None,
        tls: bool = False,
        no_check_certificate: bool = False,
        crtfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        keyfilepwd: Optional[str] = None,
        timeout: int = 2,
        MTU: int = MTU,
        rootcrtfile: Optional[str] = None,
        rootkeyfile: Optional[str] = None,
        **kwargs,
    ):
        self.mode = mode
        self.port = port
        self.cls = cls
        self.af = af
        self.remote_af = remote_af if remote_af is not None else af
        self.proto = proto
        self.tls = tls
        if tls and sys.version_info <= (3, 10):
            raise OSError("Sorry ! ForwardMachine's tls option requires Python 3.10+")
        self.no_check_certificate = no_check_certificate
        self.crtfile = crtfile
        self.keyfile = keyfile
        self.keyfilepwd = keyfilepwd
        if bool(rootcrtfile) != bool(rootkeyfile):
            raise ValueError("rootcrtfile and rootkeyfile must be provided together")
        if rootcrtfile and crtfile:
            raise ValueError("crtfile and rootcrtfile are mutually exclusive")
        self.rootcert = Cert(rootcrtfile) if rootcrtfile else None
        self.rootkey = PrivKey(rootkeyfile) if rootkeyfile else None
        if self.rootkey is not None:
            if self.rootkey.pubkey.der != self.rootcert.pubkey.der:
                raise ValueError("The root certificate and private key do not match")
            if not self.rootcert.cA:
                raise ValueError("The root certificate must be a CA")
        self.timeout = timeout
        self.MTU = MTU
        self.remote_address = remote_address
        self.remote_port = remote_port
        if self.tls or self.af == 40:  # TLS or VSOCK
            self.sockcls = StreamSocketPeekless
        else:
            self.sockcls = StreamSocket
        self.bind_address = bind_address or "0.0.0.0"
        # Chose 'iface' depending on the mode
        if iface is None and self.mode == ForwardMachine.MODE.TPROXY:
            iface = "vethrelay"
        self.iface = iface
        # Utils
        self.ct = DefaultTheme()
        red = lambda z: functools.reduce(lambda x, y: x + y, z)
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
        if self.iface is not None and False:
            self.ssock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self.iface.encode(),
            )
        self.ssock.bind((self.bind_address, self.port))
        self.ssock.listen(5)
        print(self.ct.green("Relay server waiting on port %s" % self.port))
        while True:
            conn, addr = self.ssock.accept()
            # Calc dest
            dest = conn.getsockname()
            if self.mode == ForwardMachine.MODE.SERVER:
                dest = (self.remote_address, self.remote_port or self.port)
            elif dest[0] in self.local_ips and self.remote_address:
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

    class ERROR(Exception):
        # Show an error
        pass

    class CONTEXT:
        """
        CONTEXT object kept during a session
        """

        def __init__(self, fwdm, addr, dest, remote_af, proto, tls, cls):
            self.addr = addr
            self.dest = dest
            self.remote_af = remote_af
            self.proto = proto
            self.tls = tls
            self.tls_sni_name = None  # Retrieved when receiving a connection
            self.cls = cls

        @property
        def sockcls(self):
            if self.tls or self.remote_af == 40:  # TLS or VSOCK
                return StreamSocketPeekless
            else:
                return StreamSocket

    def vprint(self, evt, ctx, cs, req, rep):
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
        elif evt == self.REDIRECT_TO:
            print(
                "C: %s was redirected from %s to %s"
                % (repr(ctx.addr), repr(req), repr(rep))
            )
        elif evt == self.ERROR:
            print(self.ct.red("ERROR: %s %s" % (repr(ctx.addr), req)))

    def destalias(self, dest):
        """
        Alias a destination to another destination.
        A destination is the tuple (host, port)
        """
        return dest

    def newconn(self, ctx):
        """
        Callback when a new connection is established.
        """
        pass

    def delconn(self, ctx):
        """
        Callback when a connection is deleted.
        """
        pass

    def _getpeersock(self, dest, ctx, server_hostname=None):
        """
        Get peer socket
        """
        s = socket.socket(ctx.remote_af, ctx.proto)
        if (
            LINUX
            and self.mode == ForwardMachine.MODE.TPROXY
            and ctx.remote_af in (socket.AF_INET, socket.AF_INET6)
        ):
            # Here's a trick: we set SO_PRIORITY to 1 so that we can exclude those
            # packets from the nftables rules that setup the TPROXY when an OUTPUT
            # rule is configured.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 1)
        s.settimeout(self.timeout)
        ndest = self.destalias(dest)
        if ndest != dest:
            self.vprint(self.REDIRECT_TO, ctx, 1, dest, ndest)
        dest = ndest
        s.connect(dest)
        return s

    def get_key_and_alike_chain(self, cas, dest, server_name):
        """
        Generate a PrivateKey and a clone of the 'cas' certificate chain signed with it,
        if not already cached.

        The cache includes the destination, SNI and upstream chain.
        """
        # The peer supplies the leaf first; the root is usually omitted.
        certs = [Cert(c.public_bytes()) for c in cas]
        if not certs:
            raise ValueError("The upstream server did not provide a certificate")

        # Reuse clones only for the same destination, SNI and upstream chain.
        ident = (dest, server_name, tuple(c.der for c in certs))
        if ident in self.cache:
            return self.cache[ident]

        # Generate the private key for the cloned leaf certificate.
        privkey = PrivKeyECDSA()

        # If the peer supplied only a leaf, create a separate CA template.
        if self.rootcert is None and not certs[-1].cA:
            root = Cert(certs[-1].der)
            root.tbsCertificate.extensions = [
                X509_Extension(
                    extnID=ASN1_OID("basicConstraints"),
                    critical=True,
                    extnValue=X509_ExtBasicConstraints(cA=True),
                ),
            ]
            certs = certs + [root]
        elif self.rootcert is not None and certs[-1].isSelfSigned() and len(certs) > 1:
            # Replace the original trust anchor with the supplied one.
            certs = certs[:-1]

        # Prepare the trust anchor and its key as the first issuer.
        result = []
        parent = self.rootcert
        if parent is not None and not parent.skid:
            parent = Cert(parent.der)
            parent.updateSubjectKeyIdentifier()
        signer = self.rootkey

        # Clone from the root towards the leaf so each issuer is ready first.
        for index in range(len(certs) - 1, -1, -1):
            # Give each clone its own key, using the returned key for the leaf.
            c = Cert(certs[index].der)
            key = privkey if index == 0 else PrivKeyECDSA()
            c.setSubjectPublicKeyFromPrivateKey(key)

            # Use X.509 v3 and regenerate the key identifier and serial number.
            c.tbsCertificate.version = ASN1_INTEGER(2)
            c.updateSubjectKeyIdentifier()
            c.tbsCertificate.serialNumber = ASN1_INTEGER(
                int.from_bytes(os.urandom(20), "big") >> 1 or 1
            )

            # Self-sign the root, or link the clone to its cloned issuer.
            if parent is None:
                parent, signer = c, key
            c.tbsCertificate.issuer = parent.tbsCertificate.subject.copy()
            c.updateAuthorityKeyIdentifier(parent)
            for extension in c.tbsCertificate.extensions:
                if extension.extnID == "2.5.29.35":
                    # These optional fields refer to the original issuer.
                    extension.extnValue.authorityCertIssuer = None
                    extension.extnValue.authorityCertSerialNumber = None

            # Remove policies, revocation URLs and CT data from the original chain.
            c.tbsCertificate.extensions = [
                x for x in c.tbsCertificate.extensions
                if x.extnID not in [
                    "2.5.29.32",  # certificatePolicies
                    "2.5.29.31",  # cRLDistributionPoints
                    "1.3.6.1.5.5.7.1.1",  # authorityInfoAccess
                    "1.3.6.1.4.1.11129.2.4.2",  # SCT
                    "1.3.6.1.4.1.11129.2.4.3",  # CT poison
                ]
            ]

            # Sign the clone, keep leaf-first order and advance to the next child.
            c.resignWith(signer)
            result.insert(0, c)
            parent, signer = c, key

        # Include the supplied trust anchor and cache the completed chain.
        if self.rootcert is not None:
            result.append(self.rootcert)
        self.cache[ident] = privkey, result
        return privkey, result

    def handler(self, sock, addr, dest):
        """
        Handler of a client socket
        """
        # we have a context object
        ctx = self.CONTEXT(
            self,
            addr=addr,
            dest=dest,
            remote_af=self.remote_af,
            proto=self.proto,
            tls=self.tls,
            cls=self.cls,
        )
        self.newconn(ctx)

        # Initialize peer socket
        ss = self._getpeersock(dest, ctx)

        # Wrap both server and peer sockets in SSL
        if ctx.tls:
            # Build client SSL context
            if self.no_check_certificate:
                clisslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                clisslcontext.check_hostname = False
                clisslcontext.verify_mode = ssl.CERT_NONE
            else:
                clisslcontext = ssl.create_default_context()

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
                ss = clisslcontext.wrap_socket(
                    ss, server_hostname=server_name or dest[0]
                )
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
                    password = self.keyfilepwd
                    certfile = self.crtfile
                    keyfile = self.keyfile
                sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                sslcontext.check_hostname = False
                sslcontext.verify_mode = ssl.CERT_NONE  # note: server side
                sslcontext.load_cert_chain(certfile, keyfile, password=password)
                sock.context = sslcontext
                # Return success
                _clisock[0] = ss
                return None  # Continue

            # Server SSL context
            sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sslcontext.sni_callback = cb_sni
            try:
                sock = sslcontext.wrap_socket(sock, server_side=True)
            except Exception as ex:
                self.vprint(self.ERROR, ctx, 1, "TLS failure: %s" % ex, None)
                sock.close()
                return
            ss = _clisock[0]
        # Wrap the sockets
        sock = ctx.sockcls(sock, ctx.cls)
        ss = ctx.sockcls(ss, ctx.cls)
        sock.streamsession = ss.streamsession
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
                    except EOFError as ex:
                        othersock.ins.shutdown(socket.SHUT_RDWR)
                        raise RuntimeError(str(ex))
                    if not data:
                        # Session needs more data
                        continue
                    try:
                        # And pipe everything into the processdata
                        try:
                            func(data, ctx)
                            # If this doesn't raise, it's a user error.
                            self.vprint(
                                self.ERROR,
                                ctx,
                                1,
                                "you must always raise in: %s" % func,
                                None,
                            )
                            return
                        except self.REDIRECT_TO as ex:
                            # Replace the peer socket with a new socket
                            oldss = ss
                            ss = self._getpeersock(
                                ex.dest,
                                ctx,
                                server_hostname=ex.server_hostname,
                            )
                            ss = ctx.sockcls(ss, ctx.cls)
                            self.vprint(self.REDIRECT_TO, ctx, 1, ctx.dest, ex.dest)
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
                        self.vprint(self.FORWARD, ctx, cs, data, None)
                    except self.FORWARD_REPLACE as ex:
                        # Forward custom data to the other host
                        othersock.send(ex.data)
                        self.vprint(self.FORWARD_REPLACE, ctx, cs, data, ex.data)
                    except self.DROP:
                        # Drop
                        self.vprint(self.DROP, ctx, cs, data, None)
                    except self.ANSWER as ex:
                        # Respond with custom data
                        thissock.send(ex.data)
                        self.vprint(self.ANSWER, ctx, cs, data, ex.data)
                    except Exception as ex:
                        # Processing failed. forward to not break anything
                        self.vprint(
                            self.ERROR,
                            ctx,
                            1,
                            "Exception happened in handler (forward)",
                            None,
                        )
                        traceback.print_exception(ex)
                        othersock.send(data)
                        self.vprint(self.FORWARD, ctx, cs, data, None)
        except RuntimeError as ex:
            print(self.ct.red("%s DISCONNECTED !: %s" % (repr(addr), str(ex))))
            self.delconn(ctx)
            sock.close()
            ss.close()
