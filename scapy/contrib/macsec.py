# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Sabrina Dubroca <sd@queasysnail.net>

# scapy.contrib.description = 802.1AE - IEEE MAC Security standard (MACsec)
# scapy.contrib.status = loads

"""
Classes and functions for MACsec.
"""

from __future__ import absolute_import
from __future__ import print_function
import struct
import copy

from scapy.config import conf
from scapy.fields import BitField, ConditionalField, IntField, PacketField, \
    XShortEnumField
from scapy.packet import Packet, Raw, bind_layers
from scapy.layers.l2 import Ether, Dot1AD, Dot1Q
from scapy.layers.eap import MACsecSCI
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.compat import raw
from scapy.data import ETH_P_MACSEC, ETHER_TYPES, ETH_P_IP, ETH_P_IPV6
from scapy.error import log_loading
import scapy.libs.six as six

if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
    )
else:
    log_loading.info("Can't import python-cryptography v1.7+. "
                     "Disabled MACsec encryption/authentication.")


NOSCI_LEN = 14 + 6
SCI_LEN = 8
DEFAULT_ICV_LEN = 16


class MACsecSA(object):
    """Representation of a MACsec Secure Association

    Provides encapsulation, decapsulation, encryption, and decryption
    of MACsec frames
    """
    def __init__(self, sci, an, pn, key, icvlen, encrypt, send_sci, xpn_en=False, ssci=None, salt=None):  # noqa: E501
        if isinstance(sci, six.integer_types):
            self.sci = struct.pack('!Q', sci)
        elif isinstance(sci, bytes):
            self.sci = sci
        else:
            raise TypeError("SCI must be either bytes or int")
        self.an = an
        self.pn = pn
        self.key = key
        self.icvlen = icvlen
        self.do_encrypt = encrypt
        self.send_sci = send_sci
        self.xpn_en = xpn_en
        if self.xpn_en:
            # Get SSCI (32 bits)
            if isinstance(ssci, six.integer_types):
                self.ssci = struct.pack('!L', ssci)
            elif isinstance(ssci, bytes):
                self.ssci = ssci
            else:
                raise TypeError("SSCI must be either bytes or int")
            # Get Salt (96 bits, only bytes allowed)
            if isinstance(salt, bytes):
                self.salt = salt
            else:
                raise TypeError("Salt must be bytes")

    def make_iv(self, pkt):
        """generate an IV for the packet"""
        if self.xpn_en:
            tmp_pn = (self.pn & 0xFFFFFFFF00000000) | (pkt[MACsec].pn & 0xFFFFFFFF)  # noqa: E501
            tmp_iv = self.ssci + struct.pack('!Q', tmp_pn)
            return bytes(bytearray([a ^ b for a, b in zip(bytearray(tmp_iv), bytearray(self.salt))]))  # noqa: E501
        else:
            return self.sci + struct.pack('!I', pkt[MACsec].pn)

    @staticmethod
    def split_pkt(pkt, assoclen, icvlen=0):
        """
        split the packet into associated data, plaintext or ciphertext, and
        optional ICV
        """
        data = raw(pkt)
        assoc = data[:assoclen]
        if icvlen:
            icv = data[-icvlen:]
            enc = data[assoclen:-icvlen]
        else:
            icv = b''
            enc = data[assoclen:]
        return assoc, enc, icv

    def e_bit(self):
        """returns the value of the E bit for packets sent through this SA"""
        return self.do_encrypt

    def c_bit(self):
        """returns the value of the C bit for packets sent through this SA"""
        return self.do_encrypt or self.icvlen != DEFAULT_ICV_LEN

    @staticmethod
    def shortlen(pkt):
        """determine shortlen for a raw packet (not encapsulated yet)"""
        datalen = len(pkt) - 2 * 6
        if datalen < 48:
            return datalen
        return 0

    def encap(self, pkt):
        """encapsulate a frame using this Secure Association"""
        if pkt.name != Ether().name:
            raise TypeError('cannot encapsulate packet in MACsec, must be Ethernet')  # noqa: E501
        hdr = copy.deepcopy(pkt)
        payload = hdr.payload
        del hdr.payload
        tag = MACsec(sci=self.sci, an=self.an,
                     SC=self.send_sci,
                     E=self.e_bit(), C=self.c_bit(),
                     shortlen=MACsecSA.shortlen(pkt),
                     pn=(self.pn & 0xFFFFFFFF), type=pkt.type)
        hdr.type = ETH_P_MACSEC
        return hdr / tag / payload

    # this doesn't really need to be a method, but for symmetry with
    # encap(), it is
    def decap(self, orig_pkt):
        """decapsulate a MACsec frame"""
        if not isinstance(orig_pkt, Ether) or \
                not isinstance(orig_pkt.payload, MACsec):
            raise TypeError(
                'cannot decapsulate MACsec packet, must be Ethernet/MACsec'
            )
        packet = copy.deepcopy(orig_pkt)
        prev_layer = packet[MACsec].underlayer
        prev_layer.type = packet[MACsec].type
        next_layer = packet[MACsec].payload
        del prev_layer.payload
        if prev_layer.name == Ether().name:
            return Ether(raw(prev_layer / next_layer))
        return prev_layer / next_layer

    def encrypt(self, orig_pkt, assoclen=None):
        """encrypt a MACsec frame for this Secure Association"""
        hdr = copy.deepcopy(orig_pkt)
        del hdr[MACsec].payload
        del hdr[MACsec].type
        pktlen = len(orig_pkt)
        if self.send_sci:
            hdrlen = NOSCI_LEN + SCI_LEN
        else:
            hdrlen = NOSCI_LEN
        if assoclen is None or not self.do_encrypt:
            if self.do_encrypt:
                assoclen = hdrlen
            else:
                assoclen = pktlen
        iv = self.make_iv(orig_pkt)
        assoc, pt, _ = MACsecSA.split_pkt(orig_pkt, assoclen)
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(assoc)
        ct = encryptor.update(pt) + encryptor.finalize()
        hdr[MACsec].payload = Raw(assoc[hdrlen:assoclen] + ct + encryptor.tag)
        return hdr

    def decrypt(self, orig_pkt, assoclen=None):
        """decrypt a MACsec frame for this Secure Association"""
        hdr = copy.deepcopy(orig_pkt)
        del hdr[MACsec].payload
        pktlen = len(orig_pkt)
        if self.send_sci:
            hdrlen = NOSCI_LEN + SCI_LEN
        else:
            hdrlen = NOSCI_LEN
        if assoclen is None or not self.do_encrypt:
            if self.do_encrypt:
                assoclen = hdrlen
            else:
                assoclen = pktlen - self.icvlen
        iv = self.make_iv(hdr)
        assoc, ct, icv = MACsecSA.split_pkt(orig_pkt, assoclen, self.icvlen)
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, icv),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(assoc)
        pt = assoc[hdrlen:assoclen]
        pt += decryptor.update(ct)
        pt += decryptor.finalize()
        hdr[MACsec].type = struct.unpack('!H', pt[0:2])[0]
        hdr[MACsec].payload = Raw(pt[2:])
        return hdr


class MACsec(Packet):
    """representation of one MACsec frame"""
    name = '802.1AE'
    deprecated_fields = {
        'an': ("AN", "2.4.4"),
        'pn': ("PN", "2.4.4"),
        'sci': ("SCI", "2.4.4"),
        'shortlen': ("SL", "2.4.4"),
    }
    # 802.1AE-2018 - Section 9
    fields_desc = [
        # 802.1AE-2018 - Section 9.5
        BitField('Ver', 0, 1),
        BitField('ES', 0, 1),  # End Station
        BitField('SC', 0, 1),  # Secure Channel
        BitField('SCB', 0, 1),  # Single Copy Broadcast
        BitField('E', 0, 1),  # Encryption
        BitField('C', 0, 1),  # Changed Text
        BitField('AN', 0, 2),  # Association Number
        # 802.1AE-2018 - Section 9.7
        BitField('reserved', 0, 2),
        BitField('SL', 0, 6),  # Short Length
        # 802.1AE-2018 - Section 9.8
        IntField("PN", 1),  # Packet Number
        # 802.1AE-2018 - Section 9.9
        ConditionalField(
            PacketField("SCI", None, MACsecSCI),
            lambda pkt: pkt.SC
        ),
        # Off-spec. Used for conveniency (only present if passed manually)
        ConditionalField(XShortEnumField("type", None, ETHER_TYPES),
                         lambda pkt: "type" in pkt.fields)]

    def mysummary(self):
        summary = self.sprintf("an=%MACsec.an%, pn=%MACsec.pn%")
        if self.SC:
            summary += self.sprintf(", sci=%MACsec.sci%")
        if self.type is not None:
            summary += self.sprintf(", %MACsec.type%")
        return summary


bind_layers(MACsec, IP, type=ETH_P_IP)
bind_layers(MACsec, IPv6, type=ETH_P_IPV6)

bind_layers(Dot1AD, MACsec, type=ETH_P_MACSEC)
bind_layers(Dot1Q, MACsec, type=ETH_P_MACSEC)
bind_layers(Ether, MACsec, type=ETH_P_MACSEC)
