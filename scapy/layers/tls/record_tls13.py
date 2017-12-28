## This file is part of Scapy
## Copyright (C) 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
Common TLS 1.3 fields & bindings.

This module covers the record layer, along with the ChangeCipherSpec, Alert and
ApplicationData submessages. For the Handshake type, see tls_handshake.py.

See the TLS class documentation for more information.
"""

import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import *
from scapy.packet import *
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.basefields import (_TLSVersionField, _tls_version,
                                         _TLSMACField, _TLSLengthField, _tls_type)
from scapy.layers.tls.record import _TLSMsgListField
from scapy.layers.tls.crypto.cipher_aead import AEADTagError
from scapy.layers.tls.crypto.cipher_stream import Cipher_NULL
from scapy.layers.tls.crypto.ciphers import CipherError


###############################################################################
### TLS Record Protocol                                                     ###
###############################################################################

class TLSInnerPlaintext(_GenericTLSSessionInheritance):
    name = "TLS Inner Plaintext"
    fields_desc = [ _TLSMsgListField("msg", []),
                    ByteEnumField("type", None, _tls_type),
                    XStrField("pad", "") ]

    def pre_dissect(self, s):
        """
        We need to parse the padding and type as soon as possible,
        else we won't be able to parse the message list...
        """
        if len(s) < 1:
            raise Exception("Invalid InnerPlaintext (too short).")

        l = len(s) - 1
        if s[-1] != b"\x00":
            msg_len = l
        else:
            n = 1
            while s[-n] != b"\x00" and n < l:
                n += 1
            msg_len = l - n
        self.fields_desc[0].length_from = lambda pkt: msg_len

        self.type = struct.unpack("B", s[msg_len:msg_len+1])[0]

        return s

class _TLSInnerPlaintextField(PacketField):
    def __init__(self, name, default, *args, **kargs):
        super(_TLSInnerPlaintextField, self).__init__(name,
                                                      default,
                                                      TLSInnerPlaintext)

    def m2i(self, pkt, m):
        return self.cls(m, tls_session=pkt.tls_session)

    def getfield(self, pkt, s):
        tag_len = pkt.tls_session.rcs.mac_len
        frag_len = pkt.len - tag_len
        if frag_len < 1:
            warning("InnerPlaintext should at least contain a byte type!")
            return s, None
        remain, i = super(_TLSInnerPlaintextField, self).getfield(pkt, s[:frag_len])
        # remain should be empty here
        return remain + s[frag_len:], i

    def i2m(self, pkt, p):
        if isinstance(p, _GenericTLSSessionInheritance):
            p.tls_session = pkt.tls_session
            if not pkt.tls_session.frozen:
                return p.raw_stateful()
        return raw(p)


class TLS13(_GenericTLSSessionInheritance):
    __slots__ = ["deciphered_len"]
    name = "TLS 1.3"
    fields_desc = [ ByteEnumField("type", 0x17, _tls_type),
                    _TLSVersionField("version", 0x0301, _tls_version),
                    _TLSLengthField("len", None),
                    _TLSInnerPlaintextField("inner", TLSInnerPlaintext()),
                    _TLSMACField("auth_tag", None) ]

    def __init__(self, *args, **kargs):
        self.deciphered_len = kargs.get("deciphered_len", None)
        super(TLS13, self).__init__(*args, **kargs)


    ### Parsing methods

    def _tls_auth_decrypt(self, s):
        """
        Provided with the record header and AEAD-ciphered data, return the
        sliced and clear tuple (TLSInnerPlaintext, tag). Note that
        we still return the slicing of the original input in case of decryption
        failure. Also, if the integrity check fails, a warning will be issued,
        but we still return the sliced (unauthenticated) plaintext.
        """
        rcs = self.tls_session.rcs
        read_seq_num = struct.pack("!Q", rcs.seq_num)
        rcs.seq_num += 1
        try:
            return rcs.cipher.auth_decrypt(b"", s, read_seq_num)
        except CipherError as e:
            return e.args
        except AEADTagError as e:
            pkt_info = self.firstlayer().summary()
            log_runtime.info("TLS: record integrity check failed [%s]", pkt_info)
            return e.args

    def pre_dissect(self, s):
        """
        Decrypt, verify and decompress the message.
        """
        if len(s) < 5:
            raise Exception("Invalid record: header is too short.")

        if isinstance(self.tls_session.rcs.cipher, Cipher_NULL):
            self.deciphered_len = None
            return s
        else:
            msglen = struct.unpack('!H', s[3:5])[0]
            hdr, efrag, r = s[:5], s[5:5+msglen], s[msglen+5:]
            frag, auth_tag = self._tls_auth_decrypt(efrag)
            self.deciphered_len = len(frag)
            return hdr + frag + auth_tag + r

    def post_dissect(self, s):
        """
        Commit the pending read state if it has been triggered. We update
        nothing if the prcs was not set, as this probably means that we're
        working out-of-context (and we need to keep the default rcs).
        """
        if self.tls_session.triggered_prcs_commit:
            if self.tls_session.prcs is not None:
                self.tls_session.rcs = self.tls_session.prcs
                self.tls_session.prcs = None
            self.tls_session.triggered_prcs_commit = False
        return s

    def do_dissect_payload(self, s):
        """
        Try to dissect the following data as a TLS message.
        Note that overloading .guess_payload_class() would not be enough,
        as the TLS session to be used would get lost.
        """
        if s:
            try:
                p = TLS(s, _internal=1, _underlayer=self,
                        tls_session = self.tls_session)
            except KeyboardInterrupt:
                raise
            except:
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)


    ### Building methods

    def _tls_auth_encrypt(self, s):
        """
        Return the TLSCiphertext.encrypted_record for AEAD ciphers.
        """
        wcs = self.tls_session.wcs
        write_seq_num = struct.pack("!Q", wcs.seq_num)
        wcs.seq_num += 1
        return wcs.cipher.auth_encrypt(s, b"", write_seq_num)

    def post_build(self, pkt, pay):
        """
        Apply the previous methods according to the writing cipher type.
        """
        # Compute the length of TLSPlaintext fragment
        hdr, frag = pkt[:5], pkt[5:]
        if not isinstance(self.tls_session.rcs.cipher, Cipher_NULL):
            frag = self._tls_auth_encrypt(frag)

        if self.len is not None:
            # The user gave us a 'len', let's respect this ultimately
            hdr = hdr[:3] + struct.pack("!H", self.len)
        else:
            # Update header with the length of TLSCiphertext.inner
            hdr = hdr[:3] + struct.pack("!H", len(frag))

        # Now we commit the pending write state if it has been triggered. We
        # update nothing if the pwcs was not set. This probably means that
        # we're working out-of-context (and we need to keep the default wcs).
        if self.tls_session.triggered_pwcs_commit:
            if self.tls_session.pwcs is not None:
                self.tls_session.wcs = self.tls_session.pwcs
                self.tls_session.pwcs = None
            self.tls_session.triggered_pwcs_commit = False

        return hdr + frag + pay

