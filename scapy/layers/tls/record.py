## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Common TLS fields & bindings.

This module covers the record layer, along with the ChangeCipherSpec, Alert and
ApplicationData submessages. For the Handshake type, see tls_handshake.py.

See the TLS class documentation for more information.
"""

import struct

from scapy.config import conf
from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import TCP
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.handshake import _tls_handshake_cls, _TLSHandshake
from scapy.layers.tls.basefields import (_TLSVersionField, _tls_version,
                                         _TLSIVField, _TLSMACField,
                                         _TLSPadField, _TLSPadLenField,
                                         _TLSLengthField, _tls_type)
from scapy.layers.tls.crypto.pkcs1 import randstring, pkcs_i2osp
from scapy.layers.tls.crypto.compression import Comp_NULL
from scapy.layers.tls.crypto.cipher_aead import AEADTagError
from scapy.layers.tls.crypto.cipher_stream import Cipher_NULL
from scapy.layers.tls.crypto.ciphers import CipherError
from scapy.layers.tls.crypto.h_mac import HMACError


###############################################################################
### TLS Record Protocol                                                     ###
###############################################################################

class _TLSEncryptedContent(Raw):
    """
    When the content of a TLS record (more precisely, a TLSCiphertext) could
    not be deciphered, we use this class to represent the encrypted data.
    The MAC will still be parsed from the whole message, even though it could
    not been verified. When present (depending on cipher type and protocol
    version), the nonce_explicit, IV and/or padding will also be parsed.
    """
    name = "Encrypted Content"


class _TLSMsgListField(PacketListField):
    """
    This is the actual content of the TLS record. As a TLS record may pack
    multiple sublayer messages (notably, several handshake messages),
    we inherit from PacketListField.
    """
    def __init__(self, name, default, length_from=None):
        PacketListField.__init__(self, name, default, cls=None,
                                 length_from=length_from)

    def m2i(self, pkt, m):
        """
        Try to parse one of the TLS subprotocols (ccs, alert, handshake or
        application_data). This is used inside a loop managed by .getfield().
        """
        cls = Raw
        if pkt.type == 22:
            if len(m) >= 1:
                msgtype = ord(m[0])
                cls = _tls_handshake_cls.get(msgtype, Raw)
        elif pkt.type == 20:
            cls = TLSChangeCipherSpec
        elif pkt.type == 21:
            cls = TLSAlert
        elif pkt.type == 23:
            cls = TLSApplicationData

        if cls is Raw:
            return Raw(m)
        else:
            return cls(m, tls_session=pkt.tls_session)

    def getfield(self, pkt, s):
        """
        If the decryption of the content did not fail with a CipherError,
        we begin a loop on the clear content in order to get as much messages
        as possible, of the type advertised in the record header. This is
        notably important for several TLS handshake implementations, which
        may for instance pack a server_hello, a certificate, a
        server_key_exchange and a server_hello_done, all in one record.
        Each parsed message may update the TLS context throught their method
        .post_dissection_tls_session_update().

        If the decryption failed with a CipherError, presumably because we
        missed the session keys, we signal it by returning a
        _TLSEncryptedContent packet which simply contains the ciphered data.
        """
        l = self.length_from(pkt)
        lst = []
        ret = ""
        remain = s
        if l is not None:
            remain, ret = s[:l], s[l:]

        if pkt.decipherable:
            if remain == "":
                return ret, [TLSApplicationData(data="")]
            while remain:
                raw_msg = remain
                p = self.m2i(pkt, remain)
                if Padding in p:
                    pad = p[Padding]
                    remain = pad.load
                    del(pad.underlayer.payload)
                    if len(remain) != 0:
                        raw_msg = raw_msg[:-len(remain)]
                else:
                    remain = ""

                if not isinstance(p, Raw):
                    p.post_dissection_tls_session_update(raw_msg)

                lst.append(p)
            return remain + ret, lst
        else:
            return ret, _TLSEncryptedContent(remain)

    def i2m(self, pkt, p):
       """
       Update the context with information from the built packet.
       If no type was given at the record layer, we try to infer it.
       """
       cur = ""
       if isinstance(p, _GenericTLSSessionInheritance):
           if pkt.type is None:
               if isinstance(p, TLSChangeCipherSpec):
                   pkt.type = 20
               elif isinstance(p, TLSAlert):
                   pkt.type = 21
               elif isinstance(p, _TLSHandshake):
                   pkt.type = 22
               elif isinstance(p, TLSApplicationData):
                   pkt.type = 23
           p.tls_session = pkt.tls_session
           cur = str(p)
           p.post_build_tls_session_update(cur)
       else:
           cur = str(p)
       return cur

    def addfield(self, pkt, s, val):
        """
        Reconstruct the header because the TLS type may have been updated.
        Then, append the content.
        """
        res = ""
        for p in val:
            res += self.i2m(pkt, p)
        if not pkt.type:
            pkt.type = 0
        hdr = struct.pack("!B", pkt.type) + s[1:5]
        return hdr + res


class TLS(_GenericTLSSessionInheritance):
    """
    The generic TLS Record message, based on section 6.2 of RFC 5246.

    When reading a TLS message, we try to parse as much as we can.
    In .pre_dissect(), according to the type of the current cipher algorithm
    (self.tls_session.rcs.cipher.type), we extract the 'iv', 'mac', 'pad' and
    'padlen'. Some of these fields may remain blank: for instance, when using
    a stream cipher, there is no IV nor any padding.

    Once we have isolated the ciphered message aggregate (which should be one
    or several TLS messages of the same type), we try to decipher it. Either we
    succeed and store the clear data in 'msg', or we graciously fail with a
    CipherError and store the ciphered data in 'msg'.

    Unless the user manually provides the session secrets through the passing
    of a 'tls_session', obviously the ciphered messages will not be deciphered.
    Indeed, the need for a proper context may also present itself when trying
    to parse clear handshake messages.

    For instance, suppose you sniffed the beginning of a DHE-RSA negotiation:
        t1 = TLS(<client_hello>)
        t2 = TLS(<server_hello | certificate | server_key_exchange>)
        t3 = TLS(<server_hello | certificate | server_key_exchange>,
                 tls_session=t1.tls_session)
    As no context was passed to t2, neither was any client_random. Hence scapy
    will not be able to verify the signature of the server_key_exchange inside
    t2. However, it should be able to do so for t3, thanks to the tls_session.
    The consequence of not having a complete TLS context is even more obvious
    when trying to parse ciphered content, as we decribed before.

    Thus, in order to parse TLS-protected communications with scapy:
    _either scapy reads every message from one side of the TLS connection and
    builds every message from the other side (as such, it should know the
    secrets needed for the generation of the pre_master_secret), while passing
    the same tls_session context (this is how our automaton.py mostly works);
    _or, if scapy did not build any TLS message, it has to create a TLS context
    and feed it with secrets retrieved by whatever technique. Note that the
    knowing the private key of the server certificate will not be sufficient
    if a PFS ciphersuite was used. However, if you got a master_secret somehow,
    use it with tls_session.(w|r)cs.derive_keys() and leave the rest to scapy.

    When building a TLS message, we expect the tls_session to have the right
    parameters for ciphering. Else, .post_build() might fail.
    """
    __slots__ = ["decipherable"]
    name = "TLS"
    fields_desc = [ ByteEnumField("type", None, _tls_type),
                    _TLSVersionField("version", None, _tls_version),
                    _TLSLengthField("len", None),
                    _TLSIVField("iv", None),
                    _TLSMsgListField("msg", None,
                                     length_from=lambda pkt: pkt.len),
                    _TLSMACField("mac", None),
                    _TLSPadField("pad", None),
                    _TLSPadLenField("padlen", None) ]

    def __init__(self, *args, **kargs):
        """
        As long as 'decipherable' is True, _TLSMsgListField will try to
        decipher the content of the TLS message. Else, it will simply
        store/deliver the ciphered version.
        """
        self.decipherable = True
        _GenericTLSSessionInheritance.__init__(self, *args, **kargs)


    ### Parsing methods

    def _tls_auth_decrypt(self, hdr, s):
        """
        Provided with the record header and AEAD-ciphered data, return the
        sliced and clear tuple (nonce, TLSCompressed.fragment, mac). Note that
        we still return the slicing of the original input in case of decryption
        failure. Also, if the integrity check fails, a warning will be issued,
        but we still return the sliced (unauthenticated) plaintext.
        """
        try:
            read_seq_num = struct.pack("!Q", self.tls_session.rcs.seq_num)
            self.tls_session.rcs.seq_num += 1
            # self.type and self.version have not been parsed yet,
            # this is why we need to look into the provided hdr.
            add_data = read_seq_num + hdr[0] + hdr[1:3]
            # Last two bytes of add_data are appended by the return function
            return self.tls_session.rcs.cipher.auth_decrypt(add_data, s)
        except CipherError as e:
            self.decipherable = False
            return e.args
        except AEADTagError as e:
            print "INTEGRITY CHECK FAILED"
            return e.args

    def _tls_decrypt(self, s):
        """
        Provided with stream- or block-ciphered data, return the clear version.
        The cipher should have been updated with the right IV early on,
        which should not be at the beginning of the input.
        Note that we still return the slicing of the original input
        in case of decryption failure.
        """
        try:
            return self.tls_session.rcs.cipher.decrypt(s)
        except CipherError as e:
            self.decipherable = False
            return e.args

    def _tls_hmac_verify(self, hdr, msg, mac):
        """
        Provided with the record header, the TLSCompressed.fragment and the
        HMAC, return True if the HMAC is correct. If we could not compute the
        HMAC because the key was missing, there is no sense in verifying
        anything, thus we also return True.

        Meant to be used with a block cipher or a stream cipher.
        It would fail with an AEAD cipher, because rcs.hmac would be None.
        See RFC 5246, section 6.2.3.
        """
        mac_len = self.tls_session.rcs.mac_len
        if mac_len == 0:            # should be TLS_NULL_WITH_NULL_NULL
            return True
        if len(mac) != mac_len:
            return False

        read_seq_num = struct.pack("!Q", self.tls_session.rcs.seq_num)
        self.tls_session.rcs.seq_num += 1
        alg = self.tls_session.rcs.hmac

        version = struct.unpack("!H", hdr[1:3])[0]
        try:
            if version > 0x300:
                h = alg.digest(read_seq_num + hdr + msg)
            elif version == 0x300:
                h = alg.digest_sslv3(read_seq_num + hdr[0] + hdr[3:5] + msg)
            else:
                raise Exception("Unrecognized version.")
        except HMACError:
            h = mac
        return h == mac

    def _tls_decompress(self, s):
        """
        Provided with the TLSCompressed.fragment,
        return the TLSPlaintext.fragment.
        """
        alg = self.tls_session.rcs.compression
        return alg.decompress(s)

    def pre_dissect(self, s):
        """
        Decrypt, verify and decompress the message,
        i.e. apply the previous methods according to the reading cipher type.
        If the decryption was successful, 'len' will be the length of the
        TLSPlaintext.fragment. Else, it should be the length of the
        _TLSEncryptedContent.
        """
        if len(s) < 5:
            raise Exception("Invalid record: header is too short.")

        msglen = struct.unpack('!H', s[3:5])[0]
        hdr, efrag, r = s[:5], s[5:5+msglen], s[msglen+5:]

        iv = mac = pad = ""

        cipher_type = self.tls_session.rcs.cipher.type

        if cipher_type == 'block':
            version = struct.unpack("!H", s[1:3])[0]

            # Decrypt
            if version >= 0x0302:
                # Explicit IV for TLS 1.1 and 1.2
                block_size = self.tls_session.rcs.cipher.block_size
                iv, efrag = efrag[:block_size], efrag[block_size:]
                self.tls_session.rcs.cipher.iv = iv
                pfrag = self._tls_decrypt(efrag)
                hdr = hdr[:3] + struct.pack("!H", len(pfrag))
            else:
                # Implicit IV for SSLv3 and TLS 1.0
                pfrag = self._tls_decrypt(efrag)

            # Excerpt below better corresponds to TLS 1.1 IV definition,
            # but the result is the same as with TLS 1.2 anyway.
            # This leading *IV* has been decrypted by _tls_decrypt with a
            # random IV, hence it does not correspond to anything.
            # What actually matters is that we got the first encrypted block
            # in order to decrypt the second block (first data block).
            #if version >= 0x0302:
            #    block_size = self.tls_session.rcs.cipher.block_size
            #    iv, pfrag = pfrag[:block_size], pfrag[block_size:]
            #    l = struct.unpack('!H', hdr[3:5])[0]
            #    hdr = hdr[:3] + struct.pack('!H', l-block_size)

            # Extract padding ('pad' actually includes the trailing padlen)
            padlen = ord(pfrag[-1]) + 1
            mfrag, pad = pfrag[:-padlen], pfrag[-padlen:]

            # Extract MAC
            l = self.tls_session.rcs.mac_len
            if l != 0:
                cfrag, mac = mfrag[:-l], mfrag[-l:]
            else:
                cfrag, mac = mfrag, ""

            # Verify integrity
            hdr = hdr[:3] + struct.pack('!H', len(cfrag))
            is_mac_ok = self._tls_hmac_verify(hdr, cfrag, mac)
            if not is_mac_ok:
                print "INTEGRITY CHECK FAILED"

        elif cipher_type == 'stream':
            # Decrypt
            pfrag = self._tls_decrypt(efrag)
            mfrag = pfrag

            # Extract MAC
            l = self.tls_session.rcs.mac_len
            if l != 0:
                cfrag, mac = mfrag[:-l], mfrag[-l:]
            else:
                cfrag, mac = mfrag, ""

            # Verify integrity
            hdr = hdr[:3] + struct.pack('!H', len(cfrag))
            is_mac_ok = self._tls_hmac_verify(hdr, cfrag, mac)
            if not is_mac_ok:
                print "INTEGRITY CHECK FAILED"

        elif cipher_type == 'aead':
            # Authenticated encryption
            # crypto/cipher_aead.py prints a warning for integrity failure
            iv, cfrag, mac = self._tls_auth_decrypt(hdr, efrag)

        if self.decipherable:
            frag = self._tls_decompress(cfrag)
        else:
            frag = cfrag

        reconstructed_body = iv + frag + mac + pad

        l = len(frag)
        # note that we do not include the MAC, only the content
        hdr = hdr[:3] + struct.pack("!H", l)

        return hdr + reconstructed_body + r

    def post_dissect(self, s):
        """
        Commit the pending read state if it has been triggered.
        We update nothing if the prcs was not set, as this probably means that
        we're working out-of-context (and we need to keep the default rcs).
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

    def _tls_compress(self, s):
        """
        Provided with the TLSPlaintext.fragment,
        return the TLSCompressed.fragment.
        """
        alg = self.tls_session.wcs.compression
        return alg.compress(s)

    def _tls_auth_encrypt(self, s):
        """
        Return the TLSCiphertext.fragment for AEAD ciphers, i.e. the whole
        GenericAEADCipher. Also, the additional data is computed right here.
        """
        write_seq_num = struct.pack("!Q", self.tls_session.wcs.seq_num)
        self.tls_session.wcs.seq_num += 1
        add_data = (write_seq_num +
                    pkcs_i2osp(self.type, 1) +
                    pkcs_i2osp(self.version, 2) +
                    pkcs_i2osp(len(s), 2))
        return self.tls_session.wcs.cipher.auth_encrypt(s, add_data)

    def _tls_hmac_add(self, hdr, msg):
        """
        Provided with the record header (concatenation of the TLSCompressed
        type, version and length fields) and the TLSCompressed.fragment,
        return the concatenation of the TLSCompressed.fragment and the HMAC.

        Meant to be used with a block cipher or a stream cipher.
        It would fail with an AEAD cipher, because wcs.hmac would be None.
        See RFC 5246, section 6.2.3.
        """
        write_seq_num = struct.pack("!Q", self.tls_session.wcs.seq_num)
        self.tls_session.wcs.seq_num += 1
        alg = self.tls_session.wcs.hmac

        version = struct.unpack("!H", hdr[1:3])[0]
        if version > 0x300:
            h = alg.digest(write_seq_num + hdr + msg)
        elif version == 0x300:
            h = alg.digest_sslv3(write_seq_num + hdr[0] + hdr[3:5] + msg)
        else:
            raise Exception("Unrecognized version.")
        return msg + h

    def _tls_pad(self, s):
        """
        Provided with the concatenation of the TLSCompressed.fragment and the
        HMAC, append the right padding and return it as a whole.
        This is the TLS-style padding: while SSL allowed for random padding,
        TLS (misguidedly) specifies the repetition of the same byte all over,
        and this byte must be equal to len(<entire padding>) - 1.

        Meant to be used with a block cipher only.
        """
        padding = ""
        block_size = self.tls_session.wcs.cipher.block_size
        padlen = block_size - ((len(s) + 1) % block_size)
        if padlen == block_size:
            padlen = 0
        pad_pattern = chr(padlen)
        padding = pad_pattern * (padlen + 1)
        return s + padding

    def _tls_encrypt(self, s):
        """
        Return the stream- or block-ciphered version of the concatenated input.
        In case of GenericBlockCipher, no IV has been specifically prepended to
        the output, so this might not be the whole TLSCiphertext.fragment yet.
        """
        return self.tls_session.wcs.cipher.encrypt(s)

    def post_build(self, pkt, pay):
        """
        Apply the previous methods according to the writing cipher type.
        """
        # Compute the length of TLSPlaintext fragment
        hdr, frag = pkt[:5], pkt[5:]
        l = len(frag)
        hdr = hdr[:3] + struct.pack("!H", l)

        # Compression
        cfrag = self._tls_compress(frag)
        l = len(cfrag)      # Update the length as a result of compression
        hdr = hdr[:3] + struct.pack("!H", l)

        cipher_type = self.tls_session.wcs.cipher.type

        if cipher_type == 'block':
            # Integrity
            mfrag = self._tls_hmac_add(hdr, cfrag)

            # Excerpt below better corresponds to TLS 1.1 IV definition,
            # but the result is the same as with TLS 1.2 anyway.
            #if self.version >= 0x0302:
            #    l = self.tls_session.wcs.cipher.block_size
            #    iv = randstring(l)
            #    mfrag = iv + mfrag

            # Add padding
            pfrag = self._tls_pad(mfrag)

            # Encryption
            if self.version >= 0x0302:
                # Explicit IV for TLS 1.1 and 1.2
                l = self.tls_session.wcs.cipher.block_size
                iv = randstring(l)
                self.tls_session.wcs.cipher.iv = iv
                efrag = self._tls_encrypt(pfrag)
                efrag = iv + efrag
            else:
                # Implicit IV for SSLv3 and TLS 1.0
                efrag = self._tls_encrypt(pfrag)

        elif cipher_type == "stream":
            # Integrity
            mfrag = self._tls_hmac_add(hdr, cfrag)
            # Encryption
            efrag = self._tls_encrypt(mfrag)

        elif cipher_type == "aead":
            # Authenticated encryption (with nonce_explicit as header)
            efrag = self._tls_auth_encrypt(cfrag)

        # Now, we can commit pending write state if needed
        # We update nothing if the pwcs was not set. This probably means that
        # we're working out-of-context (and we need to keep the default wcs).
        if self.tls_session.triggered_pwcs_commit:
            if self.tls_session.pwcs is not None:
                self.tls_session.wcs = self.tls_session.pwcs
                self.tls_session.pwcs = None
            self.tls_session.triggered_pwcs_commit = False

        if self.len is not None:
            # The user gave us a 'len', let's respect this ultimately
            hdr = hdr[:3] + struct.pack("!H", self.len)
        else:
            # Update header with the length of TLSCiphertext.fragment
            hdr = hdr[:3] + struct.pack("!H", len(efrag))

        return hdr + efrag + pay


###############################################################################
### TLS ChangeCipherSpec                                                    ###
###############################################################################

_tls_changecipherspec_type = { 1: "change_cipher_spec" }

class TLSChangeCipherSpec(_GenericTLSSessionInheritance):
    """
    Note that, as they are not handshake messages, the ccs messages do not get
    appended to the list of messages whose integrity gets verified through the
    Finished messages.
    """
    name = "TLS ChangeCipherSpec"
    fields_desc = [ ByteEnumField("msgtype", 1, _tls_changecipherspec_type) ]

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session.triggered_prcs_commit = True

    def post_build_tls_session_update(self, msg_str):
        # Unlike for dissection case, we cannot commit pending write
        # state as current write state. We need to delay this after
        # the ChangeCipherSpec message has indeed been sent
        self.tls_session.triggered_pwcs_commit = True


###############################################################################
### TLS Alert                                                               ###
###############################################################################

_tls_alert_level = { 1: "warning", 2: "fatal"}

_tls_alert_description = {
    0: "close_notify",                 10: "unexpected_message",
    20: "bad_record_mac",              21: "decryption_failed",
    22: "record_overflow",             30: "decompression_failure",
    40: "handshake_failure",           41: "no_certificate_RESERVED",
    42: "bad_certificate",             43: "unsupported_certificate",
    44: "certificate_revoked",         45: "certificate_expired",
    46: "certificate_unknown",         47: "illegal_parameter",
    48: "unknown_ca",                  49: "access_denied",
    50: "decode_error",                51: "decrypt_error",
    60: "export_restriction_RESERVED", 70: "protocol_version",
    71: "insufficient_security",       80: "internal_error",
    90: "user_canceled",              100: "no_renegotiation",
   110: "unsupported_extension",      111: "certificate_unobtainable",
   112: "unrecognized_name",          113: "bad_certificate_status_response",
   114: "bad_certificate_hash_value", 115: "unknown_psk_identity" }

class TLSAlert(_GenericTLSSessionInheritance):
    name = "TLS Alert"
    fields_desc = [ ByteEnumField("level", None, _tls_alert_level),
                    ByteEnumField("descr", None, _tls_alert_description) ]

    def post_dissection_tls_session_update(self, msg_str):
        pass

    def post_build_tls_session_update(self, msg_str):
        pass


###############################################################################
### TLS Application Data                                                    ###
###############################################################################

class TLSApplicationData(_GenericTLSSessionInheritance):
    name = "TLS Application Data"
    fields_desc = [ StrField("data", "") ]

    def post_dissection_tls_session_update(self, msg_str):
        pass

    def post_build_tls_session_update(self, msg_str):
        pass


###############################################################################
### Bindings                                                                ###
###############################################################################

bind_bottom_up(TCP, TLS, {"dport": 443})
bind_bottom_up(TCP, TLS, {"sport": 443})

