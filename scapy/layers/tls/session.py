## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS session handler.
"""

import random
import socket
import struct

from scapy.config import conf
from scapy.error import warning
from scapy.packet import Packet
from scapy.utils import repr_hex
from scapy.layers.tls.crypto.compression import Comp_NULL
from scapy.layers.tls.crypto.prf import PRF

# Note the following import may happen inside connState.__init__()
# in order to avoid to avoid cyclical dependancies.
# from scapy.layers.tls.crypto.suites import TLS_NULL_WITH_NULL_NULL


###############################################################################
### Connection states                                                       ###
###############################################################################

class connState(object):
    """
    From RFC 5246, section 6.1:
    A TLS connection state is the operating environment of the TLS Record
    Protocol.  It specifies a compression algorithm, an encryption
    algorithm, and a MAC algorithm.  In addition, the parameters for
    these algorithms are known: the MAC key and the bulk encryption keys
    for the connection in both the read and the write directions.
    Logically, there are always four connection states outstanding: the
    current read and write states, and the pending read and write states.
    All records are processed under the current read and write states.
    The security parameters for the pending states can be set by the TLS
    Handshake Protocol, and the ChangeCipherSpec can selectively make
    either of the pending states current, in which case the appropriate
    current state is disposed of and replaced with the pending state; the
    pending state is then reinitialized to an empty state.  It is illegal
    to make a state that has not been initialized with security
    parameters a current state.  The initial current state always
    specifies that no encryption, compression, or MAC will be used.

    These attributes and behaviours are mostly mapped in this class.
    Also, note that scapy may make a current state out of a pending state
    which has been initialized with dummy security parameters. We need
    this in order to know when the content of a TLS message is encrypted,
    whether we possess the right keys to decipher/verify it or not.
    For instance, when scapy parses a CKE without knowledge of any secret,
    and then a CCS, it needs to know that the following Finished
    is encrypted and signed according to a new cipher suite, even though
    it cannot decipher the message nor verify its integrity.
    """

    def __init__(self,
                 connection_end="client",
                 read_or_write="read",
                 compression_alg=Comp_NULL,
                 ciphersuite=None,
                 tls_version=0x0303):

        # It is the user's responsibility to keep the record seq_num
        # under 2**64-1. If this value gets maxed out, the TLS class in
        # record.py will crash when trying to encode it with struct.pack().
        self.seq_num = 0

        self.connection_end = connection_end
        self.row = read_or_write

        if ciphersuite is None:
            from scapy.layers.tls.crypto.suites import TLS_NULL_WITH_NULL_NULL
            ciphersuite = TLS_NULL_WITH_NULL_NULL

        self.ciphersuite = ciphersuite(tls_version=tls_version)

        self.compression = compression_alg()
        self.key_exchange = ciphersuite.kx_alg()
        self.prf = PRF(ciphersuite.hash_alg.name, tls_version)

        # The attributes below usually get updated by .derive_keys()
        # As discussed, we need to initialize cipher and mac with dummy values.

        self.master_secret = None       # 48-byte shared secret
        self.cipher_secret = None       # key for the symmetric cipher
        self.mac_secret = None          # key for the MAC (stays None for AEAD)

        self.cipher = ciphersuite.cipher_alg()

        if ciphersuite.hmac_alg is None:        # AEAD
            self.hmac = None
            self.mac_len = self.cipher.tag_len
        else:
            self.hmac = ciphersuite.hmac_alg()
            self.mac_len = self.hmac.hmac_len

    def debug_repr(self, name, secret):
        if conf.debug_tls and secret:
            print "%s %s %s: %s" % (self.connection_end,
                                    self.row,
                                    name,
                                    repr_hex(secret))

    def derive_keys(self,
                    client_random="",
                    server_random="",
                    master_secret=""):

        cs = self.ciphersuite
        self.master_secret = master_secret

        # Derive the keys according to the cipher type and protocol version
        key_block = self.prf.derive_key_block(master_secret,
                                              server_random,
                                              client_random,
                                              cs.key_block_len)

        # When slicing the key_block, keep the right half of the material
        skip_first = False
        if ((self.connection_end == "client" and self.row == "read") or
            (self.connection_end == "server" and self.row == "write")):
            skip_first = True

        pos = 0
        cipher_alg = cs.cipher_alg

        ### MAC secret (for block and stream ciphers)
        if (cipher_alg.type == "stream") or (cipher_alg.type == "block"):
            start = pos
            if skip_first:
                start += cs.hmac_alg.key_len
            end = start + cs.hmac_alg.key_len
            self.mac_secret = key_block[start:end]
            self.debug_repr("mac_secret", self.mac_secret)
            pos += 2*cs.hmac_alg.key_len
        else:
            self.mac_secret = None

        ### Cipher secret
        start = pos
        if skip_first:
            start += cipher_alg.key_len
        end = start + cipher_alg.key_len
        key = key_block[start:end]
        if cs.kx_alg.export:
            reqLen = cipher_alg.expanded_key_len
            key = self.prf.postprocess_key_for_export(key,
                                                      client_random,
                                                      server_random,
                                                      self.connection_end,
                                                      self.row,
                                                      reqLen)
        self.cipher_secret = key
        self.debug_repr("cipher_secret", self.cipher_secret)
        pos += 2*cipher_alg.key_len

        ### Implicit IV (for block and AEAD ciphers)
        start = pos
        if cipher_alg.type == "block":
            if skip_first:
                start += cipher_alg.block_size
            end = start + cipher_alg.block_size
        elif cipher_alg.type == "aead":
            if skip_first:
                start += cipher_alg.salt_len
            end = start + cipher_alg.salt_len

        ### Now we have the secrets, we can instantiate the algorithms
        if cs.hmac_alg is None:         # AEAD
            self.hmac = None
            self.mac_len = cipher_alg.tag_len
        else:
            self.hmac = cs.hmac_alg(self.mac_secret)
            self.mac_len = self.hmac.hmac_len

        if cipher_alg.type == "stream":
            cipher = cipher_alg(self.cipher_secret)
        elif cipher_alg.type == "block":
            # We set an IV every time, even though it does not matter for
            # TLS 1.1+ as it requires an explicit IV. Indeed the cipher.iv
            # would get updated in TLS.post_build() or TLS.pre_dissect().
            iv = key_block[start:end]
            if cs.kx_alg.export:
                reqLen = cipher_alg.block_size
                iv = self.prf.generate_iv_for_export(client_random,
                                                     server_random,
                                                     self.connection_end,
                                                     self.row,
                                                     reqLen)
            cipher = cipher_alg(self.cipher_secret, iv)
            self.debug_repr("block iv", iv)
        elif cipher_alg.type == "aead":
            salt = key_block[start:end]
            nonce_explicit_init = 0
            # If you ever wanted to set a random nonce_explicit, use this:
            #exp_bit_len = cipher_alg.nonce_explicit_len * 8
            #nonce_explicit_init = random.randint(0, 2**exp_bit_len - 1)
            cipher = cipher_alg(self.cipher_secret, salt, nonce_explicit_init)
            self.debug_repr("aead salt", salt)
        self.cipher = cipher

    def __repr__(self):
        def indent(s):
            if s and s[-1] == '\n':
                s = s[:-1]
            s = '\n'.join(map(lambda x: '\t'+x, s.split('\n')) + [''])
            return s

        res =  "Connection end : %s\n" % self.connection_end.upper()
        res += "Cipher suite   : %s (0x%04x)\n" % (self.ciphersuite.name,
                                                   self.ciphersuite.val)
        res += "Compression Alg: %s (0x%02x)\n" % (self.compression.name,
                                                   self.compression.val)
        tabsize = 4
        return res.expandtabs(tabsize)

class readConnState(connState):
    def __init__(self, **kargs):
        connState.__init__(self, read_or_write="read", **kargs)

class writeConnState(connState):
    def __init__(self, **kargs):
        connState.__init__(self, read_or_write="write", **kargs)


###############################################################################
### TLS session                                                             ###
###############################################################################

class tlsSession(object):
    """
    This is our TLS context, which gathers information from both sides of the
    TLS connection. These sides are represented by a readConnState instance and
    a writeConnState instance. Along with overarching network attributes, a
    tlsSession object also holds negotiated, shared information, such as the
    key exchange parameters and the master secret (when available).
    """
    def __init__(self,
                 ipsrc=None, ipdst=None,
                 sport=None, dport=None, sid=None,
                 connection_end="client",
                 wcs=None, rcs=None):

        ### Network settings

        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.sport = sport
        self.dport = dport
        self.sid = sid

        # Our TCP socket. None until we send (or receive) a packet.
        self.sock = None


        ### Connection states

        self.connection_end = connection_end

        if wcs is None:
            self.wcs = writeConnState(connection_end=connection_end)
            self.wcs.derive_keys(client_random="",
                                 server_random="",
                                 master_secret="")
        if rcs is None:
            self.rcs = readConnState(connection_end=connection_end)
            self.rcs.derive_keys(client_random="",
                                 server_random="",
                                 master_secret="")

        # The pending write/read states are updated by the building/parsing
        # of various TLS packets. They get committed to self.wcs/self.rcs
        # once scapy builds/parses a ChangeCipherSpec message.
        self.pwcs = None
        self.triggered_pwcs_commit = False
        self.prcs = None
        self.triggered_prcs_commit = False


        ### Certificates and private keys

        # The server certificate chain, as a list of Cert instances.
        # Either we act as server and it has to be provided, or it is expected
        # to be sent by the server through a Certificate message.
        # The server certificate should be self.server_certs[0].
        self.server_certs = []

        # The server private key, as a PrivKey instance, when acting as server.
        # XXX It would be nice to be able to provide both an RSA and an ECDSA
        # key in order for the same scapy server to support both families of
        # cipher suites. See INIT_TLS_SESSION() in automaton.py.
        # (For now server_key holds either one of both types for DHE
        # authentication, while server_rsa_key is used only for RSAkx.)
        self.server_key = None
        self.server_rsa_key = None
        #self.server_ecdsa_key = None

        # Back in the dreadful EXPORT days, US servers were forbidden to use
        # RSA keys longer than 512 bits for RSAkx. When their usual RSA key
        # was longer than this, they had to create a new key and send it via
        # a ServerRSAParams message. When receiving such a message,
        # scapy stores this key in server_tmp_rsa_key as a PubKey instance.
        self.server_tmp_rsa_key = None

        # When client authentication is performed, we need at least a
        # client certificate chain. If we act as client, we also have
        # to provide the key associated with the first certificate.
        self.client_certs = []
        self.client_key = None


        ### Ephemeral key exchange parameters

        ## XXX Explain why we need pubkey (which should be contained in privkey)
        # also, params is used to hold params between the SKE and the CKE
        self.server_kx_privkey = None
        self.server_kx_pubkey = None
        self.client_kx_privkey = None
        self.client_kx_pubkey = None

        self.client_kx_ffdh_params = None
        self.client_kx_ecdh_params = None

        ## Either an instance of FFDHParams or ECDHParams.
        ## Depending on which side of the connection we operate,
        ## one of these params will not hold 'priv' and 'secret' attributes.
        ## We did not use these intermediaries for RSAkx, as the 'priv' would
        ## equate the PrivKey, and the 'secret' the pre_master_secret.
        ## (It could have been useful for RSAkx export, though...)
        #self.server_kx_params = None
        #self.client_kx_params = None


        ### Negotiated session parameters

        # The advertised TLS version found in the ClientHello (and
        # EncryptedPreMasterSecret if used). If acting as server, it is set to
        # the value advertised by the client in its ClientHello.
        #XXX See what needs to be changed in automaton.py in order to keep
        # this to None. For now it is necessary for running the client.
        self.advertised_tls_version = 0x303

        # The agreed-upon TLS version found in the ServerHello.
        self.tls_version = None

        # These attributes should eventually be known to both sides.
        self.client_random = None
        self.server_random = None
        self.pre_master_secret = None
        self.master_secret = None

        # Handshake messages needed for Finished computation/validation.
        # No record layer headers, no HelloRequests, no ChangeCipherSpecs.
        self.handshake_messages = []
        self.handshake_messages_parsed = []

        # All exchanged TLS packets.
        self.exchanged_pkts = []


    ### Master secret management

    def compute_master_secret(self):
        if self.pre_master_secret is None:
            warning("Missing pre_master_secret while computing master_secret")
        if self.client_random is None:
            warning("Missing client_random while computing master_secret")
        if self.server_random is None:
            warning("Missing server_random while computing master_secret")

        ms = self.pwcs.prf.compute_master_secret(self.pre_master_secret,
                                                 self.client_random,
                                                 self.server_random)
        self.master_secret = ms
        if conf.debug_tls:
            print "master secret: %s" % repr_hex(ms)

    def compute_ms_and_derive_keys(self):
        self.compute_master_secret()
        self.prcs.derive_keys(client_random=self.client_random,
                              server_random=self.server_random,
                              master_secret=self.master_secret)
        self.pwcs.derive_keys(client_random=self.client_random,
                              server_random=self.server_random,
                              master_secret=self.master_secret)


    ### Tests for record building/parsing

    def consider_read_padding(self):
        # Return True if padding is needed. Used by TLSPadField.
        return self.rcs.cipher.type == "block"

    def consider_write_padding(self):
        # Return True if padding is needed. Used by TLSPadField.
        return self.wcs.cipher.type == "block"

    def use_explicit_iv(self, version, cipher_type):
        # Return True if an explicit IV is needed. Required for TLS 1.1+
        # when either a block or an AEAD cipher is used.
        if cipher_type == "stream":
            return False
        return version >= 0x0302


    ### Python object management

    def hash(self):
        s1 = struct.pack("!H", self.sport)
        s2 = struct.pack("!H", self.dport)
        family = socket.AF_INET
        if ':' in self.ipsrc:
            family = socket.AF_INET6
        s1 += socket.inet_pton(family, self.ipsrc)
        s2 += socket.inet_pton(family, self.ipdst)
        return strxor(s1, s2)

    def eq(self, other):
        ok = False
        if (self.sport == other.sport and self.dport == other.dport and
            self.ipsrc == other.ipsrc and self.ipdst == other.ipdst):
            ok = True

        if (not ok and
            self.dport == other.sport and self.sport == other.dport and
            self.ipdst == other.ipsrc and self.ipsrc == other.ipdst):
            ok = True

        if ok:
            if self.sid and other.sid:
                return self.sid == other.sid
            return True

        return False

    def __repr__(self):
        sid = repr(self.sid)
        if len(sid) > 12:
            sid = sid[:11] + "..."
        return "%s:%s > %s:%s" % (self.ipsrc, str(self.sport),
                                  self.ipdst, str(self.dport))


###############################################################################
### Session singleton                                                       ###
###############################################################################

class _GenericTLSSessionInheritance(Packet):
    """
    Many classes inside the TLS module need to get access to session-related
    information. For instance, an encrypted TLS record cannot be parsed without
    some knowledge of the cipher suite being used and the secrets which have
    been negotiated. Passing information is also essential to the handshake.
    To this end, various TLS objects inherit from the present class.
    """
    __slots__ = ["tls_session"]
    name = "Dummy Generic TLS Packet"
    fields_desc = []

    def __init__(self, _pkt="", post_transform=None, _internal=0,
                 _underlayer=None, tls_session=None, **fields):
        try:
            setme = self.tls_session is None
        except:
            setme = True

        if setme:
            if tls_session is None:
                self.tls_session = tlsSession()
            else:
                self.tls_session = tls_session

        Packet.__init__(self, _pkt=_pkt, post_transform=post_transform,
                        _internal=_internal, _underlayer=_underlayer,
                        **fields)

    def tls_session_update(self, msg_str):
        """
        post_{build, dissection}_tls_session_update() are used to update the
        tlsSession context. The default definitions below, along with
        tls_session_update(), may prevent code duplication in some cases.
        """
        pass

    def post_build_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)

    def copy(self):
        pkt = Packet.copy(self)
        pkt.tls_session = self.tls_session
        return pkt

    def clone_with(self, payload=None, **kargs):
        pkt = Packet.clone_with(self, payload=payload, **kargs)
        pkt.tls_session = self.tls_session
        return pkt

    def show2(self):
        """
        Rebuild the TLS packet with the same context, and then .show() it.
        We need self.__class__ to call the subclass in a dynamic way.
        """
        self.__class__(str(self), tls_session=self.tls_session).show()

    # Uncomment this when the automata update IPs and ports properly
    #def mysummary(self):
    #    return "TLS %s" % repr(self.tls_session)


###############################################################################
### Multiple TLS sessions                                                   ###
###############################################################################

class _tls_sessions(object):
    def __init__(self):
        self.sessions = {}

    def add(self, session):
        s = self.find(session)
        if s:
            print "TLS session already exists. Not adding..."
            return

        h = session.hash()
        if self.sessions.has_key(h):
            self.sessions[h].append(session)
        else:
            self.sessions[h] = [session]

    def rem(self, session):
        s = self.find(session)
        if s:
            print "TLS session does not exist. Not removing..."
            return

        h = session.hash()
        self.sessions[h].remove(session)

    def find(self, session):
        h = session.hash()
        if self.sessions.has_key(h):
            for k in self.sessions[h]:
                if k.eq(session):
                    if conf.tls_verbose:
                        print "Found Matching session %s" % k
                    return k
        if conf.tls_verbose:
            print "Did not find matching session %s" % session
        return None

    def __repr__(self):
        res = [("First endpoint", "Second endpoint", "Session ID")]
        for l in self.sessions.values():
            for s in l:
                src = "%s[%d]" % (s.ipsrc, s.sport)
                dst = "%s[%d]" % (s.ipdst, s.dport)
                sid = repr(s.sid)
                if len(sid) > 12:
                    sid = sid[:11] + "..."
                res.append((src, dst, sid))
        colwidth = map(lambda x: max(map(lambda y: len(y), x)),
                       apply(zip, res))
        fmt = "  ".join(map(lambda x: "%%-%ds"%x, colwidth))
        return "\n".join(map(lambda x: fmt % x, res))


conf.tls_sessions = _tls_sessions()
conf.tls_verbose = False

