# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2025 Jackson Sippe


from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend

class QUICCrypto:
    # Initial salt for QUIC version 1 (RFC9001 Section 5.2)
    INITIAL_SALTS = {
        1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    }
    
    def __init__(self, dcid: bytes, version: int):
        """
        Initialize the QUIC crypto state. Derives initial keys from DCID and version.
        
        :param dcid: Destination Connection ID (bytes)
        :param version: QUIC Version (int)
        """
        if version not in self.INITIAL_SALTS:
            raise ValueError(f"No initial salt defined for QUIC version {version}")
        
        self.version = version
        self.dcid = dcid
        self.salt = self.INITIAL_SALTS[version]
        
        # The AEAD for initial keys is AES-128-GCM, and QUIC uses 16-byte keys, 12-byte IVs
        # The header protection uses AES-ECB with a 16-byte key
        self.aead_key_length = 16
        self.iv_length = 12
        self.hp_key_length = 16
        self.hash_cls = hashes.SHA256
        
        # Derive secrets
        initial_secret = self._hkdf_extract(self.salt, dcid)
        client_initial_secret = self._hkdf_expand_label(initial_secret, b"client in", b"", self.hash_cls().digest_size)
        server_initial_secret = self._hkdf_expand_label(initial_secret, b"server in", b"", self.hash_cls().digest_size)
        
        # Derive client keys
        self.client_key = self._hkdf_expand_label(client_initial_secret, b"quic key", b"", self.aead_key_length)
        self.client_iv = self._hkdf_expand_label(client_initial_secret, b"quic iv", b"", self.iv_length)
        self.client_hp_key = self._hkdf_expand_label(client_initial_secret, b"quic hp", b"", self.hp_key_length)
        
        # Derive server keys
        self.server_key = self._hkdf_expand_label(server_initial_secret, b"quic key", b"", self.aead_key_length)
        self.server_iv = self._hkdf_expand_label(server_initial_secret, b"quic iv", b"", self.iv_length)
        self.server_hp_key = self._hkdf_expand_label(server_initial_secret, b"quic hp", b"", self.hp_key_length)
        
    def _hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract using SHA-256."""
        # HKDF-Extract is essentially HMAC with salt
        hk = hmac.HMAC(salt, self.hash_cls(), backend=default_backend())
        hk.update(ikm)
        return hk.finalize()

    def _hkdf_expand_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        """
        HKDF-Expand-Label as defined by TLS 1.3 and QUIC.
        
        HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)
            
        Where HkdfLabel = length(Label) + Label + length(Context) + Context
        """
        full_label = b"tls13 " + label
        
        # The "HkdfLabel" structure in TLS 1.3 for QUIC:
        # struct {
        #   uint16 length = Length;
        #   opaque label<0..255> = "quic " + Label;
        #   opaque context<0..255> = Context;
        # } HkdfLabel;
        #
        # length is a 2-byte integer
        # Then a single-byte length for label and context each, followed by label and context bytes
        hkdf_label = (length.to_bytes(2, "big") +
                      bytes([len(full_label)]) + full_label +
                      bytes([len(context)]) + context)
        
        hkdf = HKDFExpand(
            algorithm=self.hash_cls(),
            length=length,
            info=hkdf_label,
            backend=default_backend()
        )
        return hkdf.derive(secret)
    
    def _aead_encrypt(self, key: bytes, iv: bytes, pn: int, aad: bytes, plaintext: bytes) -> bytes:
        """
        AEAD Encrypt using AES-128-GCM.
        
        :param key: The AEAD key
        :param iv: The AEAD IV
        :param pn: Packet number (for nonce construction)
        :param aad: Additional authenticated data
        :param plaintext: The data to encrypt
        :return: ciphertext including authentication tag
        """
        nonce = self._build_nonce(iv, pn)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext + encryptor.tag
    
    def _aead_decrypt(self, key: bytes, iv: bytes, pn: int, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        AEAD Decrypt using AES-128-GCM.
        
        :param key: The AEAD key
        :param iv: The AEAD IV
        :param pn: Packet number (for nonce construction)
        :param aad: Additional authenticated data
        :param ciphertext: The data to decrypt (including authentication tag)
        :return: decrypted plaintext
        """
        nonce = self._build_nonce(iv, pn)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(aad)
        
        # The last 16 bytes of ciphertext are the authentication tag
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext
    
    def _build_nonce(self, iv: bytes, pn: int) -> bytes:
        """
        QUIC constructs the nonce by XORing the packet number with the IV.
        The IV length is 12 bytes, and the PN is encoded in a variable-length manner.
        """
        pn_bytes = pn.to_bytes(4, "big")
        # IV length is 12, PN length might be shorter. Right-align PN in the IV.
        padded_pn = (b"\x00" * (len(iv) - len(pn_bytes))) + pn_bytes
        return bytes(a ^ b for a, b in zip(iv, padded_pn))
    
    def header_protect(self, sample: bytes, first_byte: bytes, pn_bytes: bytes, is_client: bool) -> (bytes, bytes):
        """
        Apply header protection as defined by QUIC.
        
        The header protection key is used to create a mask by encrypting a sample of ciphertext.
        The first protected byte (one byte from the flags) and the PN bytes are XORed with parts of this mask.
        
        :param hp_key: the header protection key
        :param sample: 16-byte sample from the ciphertext after the header
        :param first_byte: the first header byte to protect/unprotect
        :param pn_bytes: the packet number bytes to protect/unprotect
        :return: (modified_first_byte, modified_pn_bytes)
        """
        # QUIC header protection uses AES-ECB for generating a mask.
        hp_key = self.client_hp_key if is_client else self.server_hp_key
        cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend()).encryptor()
        mask = cipher.update(sample) + cipher.finalize()
        
        # Mask the first byte (only the lower 5 bits are protected)
        first_byte_masked = bytes([(first_byte ^ (mask[0] & 0x0f))])
        
        # Mask the PN bytes
        masked_pn = bytes(p ^ m for p, m in zip(pn_bytes, mask[1:1+len(pn_bytes)]))
        
        return first_byte_masked, masked_pn
    
    def encrypt_packet(self, is_client: bool, pn: int, recdata: bytes, payload: bytes):
        """
        :param is_client: True if sender is client, else server
        :param pn: packet number
        :param recdata: The QUIC header bytes (unprotected)
        :param payload: The plaintext payload
        :return: encrypted packet (header + ciphertext)
        """
        key = self.client_key if is_client else self.server_key
        iv = self.client_iv if is_client else self.server_iv
        
        ciphertext_with_tag = self._aead_encrypt(key, iv, pn, recdata, payload)
        
        return ciphertext_with_tag
    
    def decrypt_packet(self, is_client: bool, pn: int, recdata: bytes, ciphertext: bytes):
        """
        :param is_client: True if sender is client, else server
        :param pn: packet number
        :param recdata: The QUIC header bytes (unprotected)
        :param ciphertext: The encrypted payload including tag
        :return: decrypted payload
        """
        key = self.client_key if is_client else self.server_key
        iv = self.client_iv if is_client else self.server_iv
        tag = ciphertext[-16:]  # Last 16 bytes are the tag
        ciphertext = ciphertext[:-16]
        # Decrypt the payload
        plaintext = self._aead_decrypt(key, iv, pn, recdata, ciphertext, tag)
        return plaintext