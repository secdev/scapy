## This file is part of Scapy
## Copyright (C) 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
Stateless HKDF for TLS 1.3.
"""

import struct

from scapy.config import conf
from scapy.layers.tls.crypto.pkcs1 import _get_hash

if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from cryptography.hazmat.primitives.hashes import Hash
    from cryptography.hazmat.primitives.hmac import HMAC


class TLS13_HKDF(object):
    def __init__(self, hash_name="sha256"):
        self.hash = _get_hash(hash_name)

    def extract(self, salt, ikm):
        h = self.hash
        hkdf = HKDF(h, h.digest_size, salt, None, default_backend())
        if ikm is None:
            ikm = b"\x00" * h.digest_size
        return hkdf._extract(ikm)

    def expand(self, prk, info, L):
        h = self.hash
        hkdf = HKDFExpand(h, L, info, default_backend())
        return hkdf.derive(prk)

    def expand_label(self, secret, label, hash_value, length):
        hkdf_label  = struct.pack("!H", length)
        hkdf_label += struct.pack("B", 9 + len(label))
        hkdf_label += b"TLS 1.3, "
        hkdf_label += label
        hkdf_label += struct.pack("B", len(hash_value))
        hkdf_label += hash_value
        return self.expand(secret, hkdf_label, length)

    def derive_secret(self, secret, label, messages):
        h = Hash(self.hash, backend=default_backend())
        h.update(messages)
        hash_messages = h.finalize()
        hash_len = self.hash.digest_size
        return self.expand_label(secret, label, hash_messages, hash_len)

    def compute_verify_data(self, basekey, handshake_context):
        hash_len = self.hash.digest_size
        finished_key = self.expand_label(basekey, b"finished", b"", hash_len)

        h = Hash(self.hash, backend=default_backend())
        h.update(handshake_context)
        hash_value = h.finalize()

        hm = HMAC(finished_key, self.hash, default_backend())
        hm.update(hash_value)
        return hm.finalize()

