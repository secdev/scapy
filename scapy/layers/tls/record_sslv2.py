## This file is part of Scapy
## Copyright (C) 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
SSLv2 Record.
"""

import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.compat import *
from scapy.fields import *
from scapy.packet import *
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.record import _TLSMsgListField, TLS
from scapy.layers.tls.handshake_sslv2 import _sslv2_handshake_cls
from scapy.layers.tls.basefields import (_SSLv2LengthField, _SSLv2PadField,
                                         _SSLv2PadLenField, _TLSMACField)


###############################################################################
### SSLv2 Record Protocol                                                   ###
###############################################################################

class _SSLv2MsgListField(_TLSMsgListField):
    def __init__(self, name, default, length_from=None):
        if not length_from:
            length_from=lambda pkt: ((pkt.len & 0x7fff) -
                                     (pkt.padlen or 0) -
                                     len(pkt.mac))
        super(_SSLv2MsgListField, self).__init__(name, default, length_from)

    def m2i(self, pkt, m):
        cls = Raw
        if len(m) >= 1:
            msgtype = orb(m[0])
            cls = _sslv2_handshake_cls.get(msgtype, Raw)

        if cls is Raw:
            return Raw(m)
        else:
            return cls(m, tls_session=pkt.tls_session)

    def i2m(self, pkt, p):
       cur = b""
       if isinstance(p, _GenericTLSSessionInheritance):
           p.tls_session = pkt.tls_session
           if not pkt.tls_session.frozen:
               cur = p.raw_stateful()
               p.post_build_tls_session_update(cur)
           else:
               cur = raw(p)
       else:
           cur = raw(p)
       return cur

    def addfield(self, pkt, s, val):
        res = b""
        for p in val:
            res += self.i2m(pkt, p)
        return s + res


class SSLv2(TLS):
    """
    The encrypted_data is the encrypted version of mac+msg+pad.
    """
    __slots__ = ["with_padding", "protected_record"]
    name = "SSLv2"
    fields_desc = [ _SSLv2LengthField("len", None),
                    _SSLv2PadLenField("padlen", None),
                    _TLSMACField("mac", b""),
                    _SSLv2MsgListField("msg", []),
                    _SSLv2PadField("pad", "") ]

    def __init__(self, *args, **kargs):
        self.with_padding = kargs.get("with_padding", False)
        self.protected_record = kargs.get("protected_record", None)
        super(SSLv2, self).__init__(*args, **kargs)

    ### Parsing methods

    def _sslv2_mac_verify(self, msg, mac):
        secret = self.tls_session.rcs.cipher.key
        if secret is None:
            return True

        mac_len = self.tls_session.rcs.mac_len
        if mac_len == 0:            # should be TLS_NULL_WITH_NULL_NULL
            return True
        if len(mac) != mac_len:
            return False

        read_seq_num = struct.pack("!I", self.tls_session.rcs.seq_num)
        alg = self.tls_session.rcs.hash
        h = alg.digest(secret + msg + read_seq_num)
        return h == mac

    def pre_dissect(self, s):
        if len(s) < 2:
            raise Exception("Invalid record: header is too short.")

        msglen = struct.unpack("!H", s[:2])[0]
        if msglen & 0x8000:
            hdrlen = 2
            msglen_clean = msglen & 0x7fff
        else:
            hdrlen = 3
            msglen_clean = msglen & 0x3fff

        hdr = s[:hdrlen]
        efrag = s[hdrlen:hdrlen+msglen_clean]
        self.protected_record = s[:hdrlen+msglen_clean]
        r = s[hdrlen+msglen_clean:]

        mac = pad = b""

        cipher_type = self.tls_session.rcs.cipher.type

        # Decrypt (with implicit IV if block cipher)
        mfrag = self._tls_decrypt(efrag)

        # Extract MAC
        maclen = self.tls_session.rcs.mac_len
        if maclen == 0:
            mac, pfrag = b"", mfrag
        else:
            mac, pfrag = mfrag[:maclen], mfrag[maclen:]

        # Extract padding
        padlen = 0
        if hdrlen == 3:
            padlen = orb(s[2])
        if padlen == 0:
            cfrag, pad = pfrag, b""
        else:
            cfrag, pad = pfrag[:-padlen], pfrag[-padlen:]

        # Verify integrity
        is_mac_ok = self._sslv2_mac_verify(cfrag + pad, mac)
        if not is_mac_ok:
            pkt_info = self.firstlayer().summary()
            log_runtime.info("TLS: record integrity check failed [%s]", pkt_info)

        reconstructed_body = mac + cfrag + pad
        return hdr + reconstructed_body + r

    def post_dissect(self, s):
        """
        SSLv2 may force us to commit the write connState here.
        """
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

        if self.tls_session.prcs is not None:
            self.tls_session.prcs.seq_num += 1
        self.tls_session.rcs.seq_num += 1
        return s

    def do_dissect_payload(self, s):
        if s:
            try:
                p = SSLv2(s, _internal=1, _underlayer=self,
                          tls_session = self.tls_session)
            except KeyboardInterrupt:
                raise
            except:
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)


    ### Building methods

    def _sslv2_mac_add(self, msg):
        secret = self.tls_session.wcs.cipher.key
        if secret is None:
            return msg

        write_seq_num = struct.pack("!I", self.tls_session.wcs.seq_num)
        alg = self.tls_session.wcs.hash
        h = alg.digest(secret + msg + write_seq_num)
        return h + msg

    def _sslv2_pad(self, s):
        padding = b""
        block_size = self.tls_session.wcs.cipher.block_size
        padlen = block_size - (len(s) % block_size)
        if padlen == block_size:
            padlen = 0
        padding = b"\x00" * padlen
        return s + padding

    def post_build(self, pkt, pay):
        if self.protected_record is not None:
            # we do not update the tls_session
            return self.protected_record + pay

        if self.padlen is None:
            cfrag = pkt[2:]
        else:
            cfrag = pkt[3:]

        if self.pad == b"" and self.tls_session.wcs.cipher.type == 'block':
            pfrag = self._sslv2_pad(cfrag)
        else:
            pad = self.pad or b""
            pfrag = cfrag + pad

        padlen = self.padlen
        if padlen is None:
            padlen = len(pfrag) - len(cfrag)
        hdr = pkt[:2]
        if padlen > 0:
            hdr += struct.pack("B", padlen)

        # Integrity
        if self.mac == b"":
            mfrag = self._sslv2_mac_add(pfrag)
        else:
            mfrag = self.mac + pfrag

        # Encryption
        efrag = self._tls_encrypt(mfrag)

        if self.len is not None:
            l = self.len
            if not self.with_padding:
                l |= 0x8000
            hdr = struct.pack("!H", l) + hdr[2:]
        else:
            # Update header with the length of TLSCiphertext.fragment
            msglen_new = len(efrag)
            if padlen:
                if msglen_new > 0x3fff:
                    raise Exception("Invalid record: encrypted data too long.")
            else:
                if msglen_new > 0x7fff:
                    raise Exception("Invalid record: encrypted data too long.")
                msglen_new |= 0x8000
            hdr = struct.pack("!H", msglen_new) + hdr[2:]

        # Now we commit the pending write state if it has been triggered (e.g.
        # by an underlying TLSChangeCipherSpec or a SSLv2ClientMasterKey). We
        # update nothing if the pwcs was not set. This probably means that
        # we're working out-of-context (and we need to keep the default wcs).
        # SSLv2 may force us to commit the reading connState here.
        if self.tls_session.triggered_pwcs_commit:
            if self.tls_session.pwcs is not None:
                self.tls_session.wcs = self.tls_session.pwcs
                self.tls_session.pwcs = None
            self.tls_session.triggered_pwcs_commit = False
        if self.tls_session.triggered_prcs_commit:
            if self.tls_session.prcs is not None:
                self.tls_session.rcs = self.tls_session.prcs
                self.tls_session.prcs = None
            self.tls_session.triggered_prcs_commit = False

        if self.tls_session.pwcs is not None:
            self.tls_session.pwcs.seq_num += 1
        self.tls_session.wcs.seq_num += 1

        return hdr + efrag + pay

