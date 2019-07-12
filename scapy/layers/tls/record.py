# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
# 2015, 2016, 2017 Maxence Tury
# This program is published under a GPLv2 license

"""
Common TLS fields & bindings.

This module covers the record layer, along with the ChangeCipherSpec, Alert and
ApplicationData submessages. For the Handshake type, see tls_handshake.py.

See the TLS class documentation for more information.
"""

import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import ByteEnumField, PacketListField, StrField
from scapy.compat import raw, chb, orb
from scapy.utils import randstring
from scapy.packet import Raw, Padding, bind_layers
from scapy.layers.inet import TCP
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.handshake import (_tls_handshake_cls, _TLSHandshake,
                                        _tls13_handshake_cls, TLS13ServerHello)
from scapy.layers.tls.basefields import (_TLSVersionField, _tls_version,
                                         _TLSIVField, _TLSMACField,
                                         _TLSPadField, _TLSPadLenField,
                                         _TLSLengthField, _tls_type)
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp
from scapy.layers.tls.crypto.cipher_aead import AEADTagError
from scapy.layers.tls.crypto.cipher_stream import Cipher_NULL
from scapy.layers.tls.crypto.common import CipherError
from scapy.layers.tls.crypto.h_mac import HMACError
import scapy.modules.six as six
if conf.crypto_valid_advanced:
    from scapy.layers.tls.crypto.cipher_aead import Cipher_CHACHA20_POLY1305

# Util


def _tls_version_check(version, min):
    """Returns if version >= min, or False if version == None"""
    if version is None:
        return False
    return version >= min

###############################################################################
#   TLS Record Protocol                                                       #
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
        if not length_from:
            length_from = self._get_length
        super(_TLSMsgListField, self).__init__(name, default, cls=None,
                                               length_from=length_from)

    def _get_length(self, pkt):
        if pkt.deciphered_len is None:
            return pkt.len
        return pkt.deciphered_len

    def m2i(self, pkt, m):
        """
        Try to parse one of the TLS subprotocols (ccs, alert, handshake or
        application_data). This is used inside a loop managed by .getfield().
        """
        cls = Raw
        if pkt.type == 22:
            if len(m) >= 1:
                msgtype = orb(m[0])
                if ((pkt.tls_session.advertised_tls_version == 0x0304) or
                        (pkt.tls_session.tls_version and
                         pkt.tls_session.tls_version == 0x0304)):
                    cls = _tls13_handshake_cls.get(msgtype, Raw)
                else:
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
            try:
                return cls(m, tls_session=pkt.tls_session)
            except Exception:
                if conf.debug_dissector:
                    raise
                return Raw(m)

    def getfield(self, pkt, s):
        """
        If the decryption of the content did not fail with a CipherError,
        we begin a loop on the clear content in order to get as much messages
        as possible, of the type advertised in the record header. This is
        notably important for several TLS handshake implementations, which
        may for instance pack a server_hello, a certificate, a
        server_key_exchange and a server_hello_done, all in one record.
        Each parsed message may update the TLS context through their method
        .post_dissection_tls_session_update().

        If the decryption failed with a CipherError, presumably because we
        missed the session keys, we signal it by returning a
        _TLSEncryptedContent packet which simply contains the ciphered data.
        """
        tmp_len = self.length_from(pkt)
        lst = []
        ret = b""
        remain = s
        if tmp_len is not None:
            remain, ret = s[:tmp_len], s[tmp_len:]

        if remain == b"":
            if (((pkt.tls_session.tls_version or 0x0303) > 0x0200) and
                    hasattr(pkt, "type") and pkt.type == 23):
                return ret, [TLSApplicationData(data=b"")]
            else:
                return ret, [Raw(load=b"")]

        if False in six.itervalues(pkt.tls_session.rcs.cipher.ready):
            return ret, _TLSEncryptedContent(remain)
        else:
            while remain:
                raw_msg = remain
                p = self.m2i(pkt, remain)
                if Padding in p:
                    pad = p[Padding]
                    remain = pad.load
                    del pad.underlayer.payload
                    if len(remain) != 0:
                        raw_msg = raw_msg[:-len(remain)]
                else:
                    remain = b""

                if isinstance(p, _GenericTLSSessionInheritance):
                    if not p.tls_session.frozen:
                        p.post_dissection_tls_session_update(raw_msg)

                lst.append(p)
            return remain + ret, lst

    def i2m(self, pkt, p):
        """
        Update the context with information from the built packet.
        If no type was given at the record layer, we try to infer it.
        """
        cur = b""
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
            if not pkt.tls_session.frozen:
                cur = p.raw_stateful()
                p.post_build_tls_session_update(cur)
            else:
                cur = raw(p)
        else:
            pkt.type = 23
            cur = raw(p)
        return cur

    def addfield(self, pkt, s, val):
        """
        Reconstruct the header because the TLS type may have been updated.
        Then, append the content.
        """
        res = b""
        for p in val:
            res += self.i2m(pkt, p)
        if (isinstance(pkt, _GenericTLSSessionInheritance) and
            _tls_version_check(pkt.tls_session.tls_version, 0x0304) and
                not isinstance(pkt, TLS13ServerHello)):
            return s + res
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
    a stream cipher, there is no IV nor any padding. The 'len' should always
    hold the length of the ciphered message; for the plaintext version, you
    should rely on the additional 'deciphered_len' attribute.

    XXX Fix 'deciphered_len' which should not be defined when failing with
    AEAD decryption. This is related to the 'decryption_success' below.
    Also, follow this behaviour in record_sslv2.py and record_tls13.py

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
    (Note that to do things properly, here 't1.tls_session' should actually be
    't1.tls_session.mirror()'. See session.py for explanations.)

    As no context was passed to t2, neither was any client_random. Hence Scapy
    will not be able to verify the signature of the server_key_exchange inside
    t2. However, it should be able to do so for t3, thanks to the tls_session.
    The consequence of not having a complete TLS context is even more obvious
    when trying to parse ciphered content, as we described before.

    Thus, in order to parse TLS-protected communications with Scapy:
    _either Scapy reads every message from one side of the TLS connection and
    builds every message from the other side (as such, it should know the
    secrets needed for the generation of the pre_master_secret), while passing
    the same tls_session context (this is how our automaton.py mostly works);
    _or, if Scapy did not build any TLS message, it has to create a TLS context
    and feed it with secrets retrieved by whatever technique. Note that the
    knowing the private key of the server certificate will not be sufficient
    if a PFS ciphersuite was used. However, if you got a master_secret somehow,
    use it with tls_session.(w|r)cs.derive_keys() and leave the rest to Scapy.

    When building a TLS message with raw_stateful, we expect the tls_session to
    have the right parameters for ciphering. Else, .post_build() might fail.
    """
    __slots__ = ["deciphered_len"]
    name = "TLS"
    fields_desc = [ByteEnumField("type", None, _tls_type),
                   _TLSVersionField("version", None, _tls_version),
                   _TLSLengthField("len", None),
                   _TLSIVField("iv", None),
                   _TLSMsgListField("msg", []),
                   _TLSMACField("mac", None),
                   _TLSPadField("pad", None),
                   _TLSPadLenField("padlen", None)]

    def __init__(self, *args, **kargs):
        self.deciphered_len = kargs.get("deciphered_len", None)
        super(TLS, self).__init__(*args, **kargs)

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        If the TLS class was called on raw SSLv2 data, we want to return an
        SSLv2 record instance. We acknowledge the risk of SSLv2 packets with a
        msglen of 0x1403, 0x1503, 0x1603 or 0x1703 which will never be casted
        as SSLv2 records but TLS ones instead, but hey, we can't be held
        responsible for low-minded extensibility choices.
        """
        if _pkt and len(_pkt) >= 2:
            byte0 = orb(_pkt[0])
            byte1 = orb(_pkt[1])
            if (byte0 not in _tls_type) or (byte1 != 3):
                from scapy.layers.tls.record_sslv2 import SSLv2
                return SSLv2
            else:
                s = kargs.get("tls_session", None)
                if s and _tls_version_check(s.tls_version, 0x0304):
                    if s.rcs and not isinstance(s.rcs.cipher, Cipher_NULL):
                        from scapy.layers.tls.record_tls13 import TLS13
                        return TLS13
        if _pkt and len(_pkt) < 5:
            # Layer detected as TLS but too small to be a real packet (len<5).
            # Those packets are usually customly implemented
            # Scapy should not try to decode them
            return conf.raw_layer
        return TLS

    # Parsing methods

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
            add_data = read_seq_num + hdr[:3]
            # Last two bytes of add_data are appended by the return function
            return self.tls_session.rcs.cipher.auth_decrypt(add_data, s,
                                                            read_seq_num)
        except CipherError as e:
            return e.args
        except AEADTagError as e:
            pkt_info = self.firstlayer().summary()
            log_runtime.info("TLS: record integrity check failed [%s]", pkt_info)  # noqa: E501
            return e.args

    def _tls_decrypt(self, s):
        """
        Provided with stream- or block-ciphered data, return the clear version.
        The cipher should have been updated with the right IV early on,
        which should not be at the beginning of the input.
        In case of decryption failure, a CipherError will be raised with
        the slicing of the original input as first argument.
        """
        return self.tls_session.rcs.cipher.decrypt(s)

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
        read_seq_num = struct.pack("!Q", self.tls_session.rcs.seq_num)
        self.tls_session.rcs.seq_num += 1

        mac_len = self.tls_session.rcs.mac_len
        if mac_len == 0:            # should be TLS_NULL_WITH_NULL_NULL
            return True
        if len(mac) != mac_len:
            return False

        alg = self.tls_session.rcs.hmac
        version = struct.unpack("!H", hdr[1:3])[0]
        try:
            if version > 0x300:
                h = alg.digest(read_seq_num + hdr + msg)
            elif version == 0x300:
                h = alg.digest_sslv3(read_seq_num + hdr[:1] + hdr[3:5] + msg)
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
        hdr, efrag, r = s[:5], s[5:5 + msglen], s[msglen + 5:]

        iv = mac = pad = b""
        self.padlen = None
        decryption_success = False

        cipher_type = self.tls_session.rcs.cipher.type

        if cipher_type == 'block':
            version = struct.unpack("!H", s[1:3])[0]

            # Decrypt
            try:
                if version >= 0x0302:
                    # Explicit IV for TLS 1.1 and 1.2
                    block_size = self.tls_session.rcs.cipher.block_size
                    iv, efrag = efrag[:block_size], efrag[block_size:]
                    self.tls_session.rcs.cipher.iv = iv
                    pfrag = self._tls_decrypt(efrag)
                else:
                    # Implicit IV for SSLv3 and TLS 1.0
                    pfrag = self._tls_decrypt(efrag)
            except CipherError as e:
                # This will end up dissected as _TLSEncryptedContent.
                cfrag = e.args[0]
            else:
                decryption_success = True
                # Excerpt below better corresponds to TLS 1.1 IV definition,
                # but the result is the same as with TLS 1.2 anyway.
                # This leading *IV* has been decrypted by _tls_decrypt with a
                # random IV, hence it does not correspond to anything.
                # What actually matters is that we got the first encrypted block  # noqa: E501
                # in order to decrypt the second block (first data block).
                # if version >= 0x0302:
                #    block_size = self.tls_session.rcs.cipher.block_size
                #    iv, pfrag = pfrag[:block_size], pfrag[block_size:]
                #    l = struct.unpack('!H', hdr[3:5])[0]
                #    hdr = hdr[:3] + struct.pack('!H', l-block_size)

                # Extract padding ('pad' actually includes the trailing padlen)
                padlen = orb(pfrag[-1]) + 1
                mfrag, pad = pfrag[:-padlen], pfrag[-padlen:]
                self.padlen = padlen

                # Extract MAC
                tmp_len = self.tls_session.rcs.mac_len
                if tmp_len != 0:
                    cfrag, mac = mfrag[:-tmp_len], mfrag[-tmp_len:]
                else:
                    cfrag, mac = mfrag, b""

                # Verify integrity
                chdr = hdr[:3] + struct.pack('!H', len(cfrag))
                is_mac_ok = self._tls_hmac_verify(chdr, cfrag, mac)
                if not is_mac_ok:
                    pkt_info = self.firstlayer().summary()
                    log_runtime.info("TLS: record integrity check failed [%s]", pkt_info)  # noqa: E501

        elif cipher_type == 'stream':
            # Decrypt
            try:
                pfrag = self._tls_decrypt(efrag)
            except CipherError as e:
                # This will end up dissected as _TLSEncryptedContent.
                cfrag = e.args[0]
            else:
                decryption_success = True
                mfrag = pfrag

                # Extract MAC
                tmp_len = self.tls_session.rcs.mac_len
                if tmp_len != 0:
                    cfrag, mac = mfrag[:-tmp_len], mfrag[-tmp_len:]
                else:
                    cfrag, mac = mfrag, b""

                # Verify integrity
                chdr = hdr[:3] + struct.pack('!H', len(cfrag))
                is_mac_ok = self._tls_hmac_verify(chdr, cfrag, mac)
                if not is_mac_ok:
                    pkt_info = self.firstlayer().summary()
                    log_runtime.info("TLS: record integrity check failed [%s]", pkt_info)  # noqa: E501

        elif cipher_type == 'aead':
            # Authenticated encryption
            # crypto/cipher_aead.py prints a warning for integrity failure
            if (conf.crypto_valid_advanced and
                    isinstance(self.tls_session.rcs.cipher, Cipher_CHACHA20_POLY1305)):  # noqa: E501
                iv = b""
                cfrag, mac = self._tls_auth_decrypt(hdr, efrag)
            else:
                iv, cfrag, mac = self._tls_auth_decrypt(hdr, efrag)
            decryption_success = True       # see XXX above

        frag = self._tls_decompress(cfrag)

        if decryption_success:
            self.deciphered_len = len(frag)
        else:
            self.deciphered_len = None

        reconstructed_body = iv + frag + mac + pad

        return hdr + reconstructed_body + r

    def post_dissect(self, s):
        """
        Commit the pending r/w state if it has been triggered (e.g. by an
        underlying TLSChangeCipherSpec or a SSLv2ClientMasterKey). We update
        nothing if the prcs was not set, as this probably means that we're
        working out-of-context (and we need to keep the default rcs).
        """
        if (self.tls_session.tls_version and
                self.tls_session.tls_version <= 0x0303):
            if self.tls_session.triggered_prcs_commit:
                if self.tls_session.prcs is not None:
                    self.tls_session.rcs = self.tls_session.prcs
                    self.tls_session.prcs = None
                self.tls_session.triggered_prcs_commit = False
            if self.tls_session.triggered_pwcs_commit:
                if self.tls_session.pwcs is not None:
                    self.tls_session.wcs = self.tls_session.pwcs
                    self.tls_session.pwcs = None
                self.tls_session.triggered_pwcs_commit = False
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
                        tls_session=self.tls_session)
            except KeyboardInterrupt:
                raise
            except Exception:
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    # Building methods

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
        return self.tls_session.wcs.cipher.auth_encrypt(s, add_data,
                                                        write_seq_num)

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
            h = alg.digest_sslv3(write_seq_num + hdr[:1] + hdr[3:5] + msg)
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
        padding = b""
        block_size = self.tls_session.wcs.cipher.block_size
        padlen = block_size - ((len(s) + 1) % block_size)
        if padlen == block_size:
            padlen = 0
        pad_pattern = chb(padlen)
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
        tmp_len = len(frag)
        hdr = hdr[:3] + struct.pack("!H", tmp_len)

        # Compression
        cfrag = self._tls_compress(frag)
        tmp_len = len(cfrag)  # Update the length as a result of compression
        hdr = hdr[:3] + struct.pack("!H", tmp_len)

        cipher_type = self.tls_session.wcs.cipher.type

        if cipher_type == 'block':
            # Integrity
            mfrag = self._tls_hmac_add(hdr, cfrag)

            # Excerpt below better corresponds to TLS 1.1 IV definition,
            # but the result is the same as with TLS 1.2 anyway.
            # if self.version >= 0x0302:
            #    l = self.tls_session.wcs.cipher.block_size
            #    iv = randstring(l)
            #    mfrag = iv + mfrag

            # Add padding
            pfrag = self._tls_pad(mfrag)

            # Encryption
            if self.version >= 0x0302:
                # Explicit IV for TLS 1.1 and 1.2
                tmp_len = self.tls_session.wcs.cipher.block_size
                iv = randstring(tmp_len)
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

        if self.len is not None:
            # The user gave us a 'len', let's respect this ultimately
            hdr = hdr[:3] + struct.pack("!H", self.len)
        else:
            # Update header with the length of TLSCiphertext.fragment
            hdr = hdr[:3] + struct.pack("!H", len(efrag))

        # Now we commit the pending write state if it has been triggered (e.g.
        # by an underlying TLSChangeCipherSpec or a SSLv2ClientMasterKey). We
        # update nothing if the pwcs was not set. This probably means that
        # we're working out-of-context (and we need to keep the default wcs).
        if self.tls_session.triggered_pwcs_commit:
            if self.tls_session.pwcs is not None:
                self.tls_session.wcs = self.tls_session.pwcs
                self.tls_session.pwcs = None
            self.tls_session.triggered_pwcs_commit = False

        return hdr + efrag + pay


###############################################################################
#   TLS ChangeCipherSpec                                                      #
###############################################################################

_tls_changecipherspec_type = {1: "change_cipher_spec"}


class TLSChangeCipherSpec(_GenericTLSSessionInheritance):
    """
    Note that, as they are not handshake messages, the ccs messages do not get
    appended to the list of messages whose integrity gets verified through the
    Finished messages.
    """
    name = "TLS ChangeCipherSpec"
    fields_desc = [ByteEnumField("msgtype", 1, _tls_changecipherspec_type)]

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session.triggered_prcs_commit = True

    def post_build_tls_session_update(self, msg_str):
        # Unlike for dissection case, we cannot commit pending write
        # state as current write state. We need to delay this after
        # the ChangeCipherSpec message has indeed been sent
        self.tls_session.triggered_pwcs_commit = True


###############################################################################
#   TLS Alert                                                                 #
###############################################################################

_tls_alert_level = {1: "warning", 2: "fatal"}

_tls_alert_description = {
    0: "close_notify", 10: "unexpected_message",
    20: "bad_record_mac", 21: "decryption_failed",
    22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate_RESERVED",
    42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error",
    60: "export_restriction_RESERVED", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error",
    90: "user_canceled", 100: "no_renegotiation",
    110: "unsupported_extension", 111: "certificate_unobtainable",
    112: "unrecognized_name", 113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value", 115: "unknown_psk_identity"}


class TLSAlert(_GenericTLSSessionInheritance):
    name = "TLS Alert"
    fields_desc = [ByteEnumField("level", None, _tls_alert_level),
                   ByteEnumField("descr", None, _tls_alert_description)]

    def post_dissection_tls_session_update(self, msg_str):
        pass

    def post_build_tls_session_update(self, msg_str):
        pass


###############################################################################
#   TLS Application Data                                                      #
###############################################################################

class TLSApplicationData(_GenericTLSSessionInheritance):
    name = "TLS Application Data"
    fields_desc = [StrField("data", "")]

    def post_dissection_tls_session_update(self, msg_str):
        pass

    def post_build_tls_session_update(self, msg_str):
        pass


###############################################################################
#   Bindings                                                                  #
###############################################################################

bind_layers(TCP, TLS, sport=443)
bind_layers(TCP, TLS, dport=443)
