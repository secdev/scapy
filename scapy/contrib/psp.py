# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2025

r"""
PSP layer
=========

Example of use:

>>> payload = IP() / UDP() / Raw("A" * 9)
>>> iv = b'\x01\x02\x03\x04\x05\x06\x07\x08'
>>> spi = 0x11223344
>>> key = b'\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00'
>>> psp_packet = PSP(nexthdr=4, cryptoffset=5, spi=spi, iv=iv, data=payload)
>>> hexdump(psp_packet)
0000  04 01 05 01 11 22 33 44 01 02 03 04 05 06 07 08  ....."3D........
0010  45 00 00 25 00 01 00 00 40 11 7C C5 7F 00 00 01  E..%....@.|.....
0020  7F 00 00 01 00 35 00 35 00 11 BB 5A 41 41 41 41  .....5.5...ZAAAA
0030  41 41 41 41 41                                   AAAAA
>>>
>>> psp_packet.encrypt(key)
>>> hexdump(psp_packet)
0000  04 01 05 01 11 22 33 44 01 02 03 04 05 06 07 08  ....."3D........
0010  45 00 00 25 00 01 00 00 40 11 7C C5 7F 00 00 01  E..%....@.|.....
0020  7F 00 00 01 8A D9 3D 08 45 C7 70 67 5C DA C3 9B  ......=.E.pg\...
0030  86 17 62 A0 CF BD 8C 46 06 15 31 91 8A C5 C2 A8  ..b....F..1.....
0040  9E A3 1B A8 F0                                   .....
>>>
>>> psp_packet.decrypt(key)
>>> hexdump(psp_packet)
0000  04 01 05 01 11 22 33 44 01 02 03 04 05 06 07 08  ....."3D........
0010  45 00 00 25 00 01 00 00 40 11 7C C5 7F 00 00 01  E..%....@.|.....
0020  7F 00 00 01 00 35 00 35 00 11 BB 5A 41 41 41 41  .....5.5...ZAAAA
0030  41 41 41 41 41                                   AAAAA
>>>

"""

from scapy.config import conf
from scapy.error import log_loading
from scapy.fields import (
    BitField,
    ByteField,
    ConditionalField,
    XIntField,
    XStrField,
    StrFixedLenField,
)
from scapy.packet import (
    Packet,
    bind_bottom_up,
    bind_top_down,
)
from scapy.layers.inet import UDP

###############################################################################
if conf.crypto_valid:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import (
        aead,
    )
else:
    log_loading.info("Can't import python-cryptography v1.7+. "
                     "Disabled PSP encryption/authentication.")

###############################################################################
import struct


class PSP(Packet):
    """
    PSP Security Protocol

    See https://github.com/google/psp/blob/main/doc/PSP_Arch_Spec.pdf
    """
    name = 'PSP'

    fields_desc = [
        ByteField('nexthdr', 0),
        ByteField('hdrextlen', 1),
        BitField("reserved", 0, 2),
        BitField("cryptoffset", 0, 6),
        BitField("sample", 0, 1),
        BitField("drop", 0, 1),
        BitField("version", 0, 4),
        BitField("is_virt", 0, 1),
        BitField("one_bit", 1, 1),
        XIntField('spi', 0x00),
        StrFixedLenField('iv', '\x00' * 8, 8),
        ConditionalField(XIntField("virtkey", 0x00), lambda pkt: pkt.is_virt == 1),
        ConditionalField(XIntField("sectoken", 0x00), lambda pkt: pkt.is_virt == 1),
        XStrField('data', None),
    ]

    def sanitize_cipher(self):
        """
        Ensure we support the ciper to encrypt/decrypt this packet

        :returns: the supported cipher suite
        :raise scapy.layers.psp.PSPCipherError: if the requested cipeher
            is unsupported
        """
        if self.version not in (0, 1):
            raise PSPCipherError('Can not encrypt/decrypt using unsupported version %s'
                                 % (self.version))
        return aead.AESGCM

    def encrypt(self, key):
        """
        Encrypt a PSP packet

        :param key:    the secret key used for encryption
        :raise scapy.layers.psp.PSPCipherError: if the requested cipeher
            is unsupported
        """
        cipher = self.sanitize_cipher()
        encrypt_start_offset = 16 + self.cryptoffset * 4
        iv = struct.pack("!L", self.spi) + self.iv
        plain = b''
        to_encrypt = bytes(self.data)
        self.data = b''
        psp_header = bytes(self)
        header_length = len(psp_header)
        # Header should always be fully plaintext
        if header_length < encrypt_start_offset:
            plain = to_encrypt[:encrypt_start_offset - header_length]
            to_encrypt = to_encrypt[encrypt_start_offset - header_length:]
        cipher = cipher(key)
        payload = cipher.encrypt(iv, to_encrypt, psp_header + plain)
        self.data = plain + payload

    def decrypt(self, key):
        """
        Decrypt a PSP packet

        :param key: the secret key used for encryption
        :raise scapy.layers.psp.PSPIntegrityError: if the integrity check
            fails with an AEAD algorithm
        :raise scapy.layers.psp.PSPCipherError: if the requested cipeher
            is unsupported
        """
        cipher = self.sanitize_cipher()
        self.icv_size = 16
        iv = struct.pack("!L", self.spi) + self.iv
        data = self.data[:len(self.data) - self.icv_size]
        icv = self.data[len(self.data) - self.icv_size:]

        decrypt_start_offset = 16 + self.cryptoffset * 4
        plain = b''
        to_decrypt = bytes(data)
        self.data = b''
        psp_header = bytes(self)
        header_length = len(psp_header)
        # Header should always be fully plaintext
        if header_length < decrypt_start_offset:
            plain = to_decrypt[:decrypt_start_offset - header_length]
            to_decrypt = to_decrypt[decrypt_start_offset - header_length:]
        cipher = cipher(key)
        try:
            data = cipher.decrypt(iv, to_decrypt + icv, psp_header + plain)
            self.data = plain + data
        except InvalidTag as err:
            raise PSPIntegrityError(err)


bind_bottom_up(UDP, PSP, dport=1000)
bind_bottom_up(UDP, PSP, sport=1000)
bind_top_down(UDP, PSP, dport=1000, sport=1000)

###############################################################################


class PSPCipherError(Exception):
    """
    Error risen when the cipher is unsupported.
    """
    pass


class PSPIntegrityError(Exception):
    """
    Error risen when the integrity check fails.
    """
    pass
