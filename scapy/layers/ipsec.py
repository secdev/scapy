#############################################################################
## ipsec.py --- IPSec support for Scapy                                    ##
##                                                                         ##
## Copyright (C) 2014  6WIND                                               ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation.                              ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
#############################################################################
"""
IPSec layer
===========

Example of use:

>>> sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC',
...                          crypt_key='sixteenbytes key')
>>> p = IP(src='1.1.1.1', dst='2.2.2.2')
>>> p /= TCP(sport=45012, dport=80)
>>> p /= Raw('testdata')
>>> p = IP(str(p))
>>> p
<IP  version=4L ihl=5L tos=0x0 len=48 id=1 flags= frag=0L ttl=64 proto=tcp chksum=0x74c2 src=1.1.1.1 dst=2.2.2.2 options=[] |<TCP  sport=45012 dport=http seq=0 ack=0 dataofs=5L reserved=0L flags=S window=8192 chksum=0x1914 urgptr=0 options=[] |<Raw  load='testdata' |>>>
>>>
>>> e = sa.encrypt(p)
>>> e
<IP  version=4L ihl=5L tos=0x0 len=76 id=1 flags= frag=0L ttl=64 proto=esp chksum=0x747a src=1.1.1.1 dst=2.2.2.2 |<ESP  spi=0xdeadbeef seq=1 data='\xf8\xdb\x1e\x83[T\xab\\\xd2\x1b\xed\xd1\xe5\xc8Y\xc2\xa5d\x92\xc1\x05\x17\xa6\x92\x831\xe6\xc1]\x9a\xd6K}W\x8bFfd\xa5B*+\xde\xc8\x89\xbf{\xa9' |>>
>>>
>>> d = sa.decrypt(e)
>>> d
<IP  version=4L ihl=5L tos=0x0 len=48 id=1 flags= frag=0L ttl=64 proto=tcp chksum=0x74c2 src=1.1.1.1 dst=2.2.2.2 |<TCP  sport=45012 dport=http seq=0 ack=0 dataofs=5L reserved=0L flags=S window=8192 chksum=0x1914 urgptr=0 options=[] |<Raw  load='testdata' |>>>
>>>
>>> d == p
True
"""

import socket
import struct
try:
    from Crypto.Util.number import GCD as gcd
except ImportError:
    try:
        from fractions import gcd
    except ImportError:
        def gcd(a, b):
            """Fallback implementation when Crypto is missing, and fractions does
            not exist (Python 2.5)

            """
            if b > a:
                a, b = b, a
            c = a % b
            return b if c == 0 else gcd(c, b)


from scapy.data import IP_PROTOS

from scapy.fields import ByteEnumField, ByteField, StrField, XIntField, IntField, \
    ShortField, PacketField

from scapy.packet import Packet, bind_layers, Raw

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, \
    IPv6ExtHdrRouting


#------------------------------------------------------------------------------
class AH(Packet):
    """
    Authentication Header

    See https://tools.ietf.org/rfc/rfc4302.txt
    """

    name = 'AH'

    fields_desc = [
        ByteEnumField('nh', None, IP_PROTOS),
        ByteField('payloadlen', None),
        ShortField('reserved', None),
        XIntField('spi', 0x0),
        IntField('seq', 0),
        StrField('icv', None),
        StrField('padding', None),
    ]

    overload_fields = {
        IP: {'proto': socket.IPPROTO_AH},
        IPv6: {'nh': socket.IPPROTO_AH},
        IPv6ExtHdrHopByHop: {'nh': socket.IPPROTO_AH},
        IPv6ExtHdrDestOpt: {'nh': socket.IPPROTO_AH},
        IPv6ExtHdrRouting: {'nh': socket.IPPROTO_AH},
    }

bind_layers(IP, AH, proto=socket.IPPROTO_AH)
bind_layers(IPv6, AH, nh=socket.IPPROTO_AH)

#------------------------------------------------------------------------------
class ESP(Packet):
    """
    Encapsulated Security Payload

    See https://tools.ietf.org/rfc/rfc4303.txt
    """
    name = 'ESP'

    fields_desc = [
        XIntField('spi', 0x0),
        IntField('seq', 0),
        StrField('data', None),
    ]

    overload_fields = {
        IP: {'proto': socket.IPPROTO_ESP},
        IPv6: {'nh': socket.IPPROTO_ESP},
        IPv6ExtHdrHopByHop: {'nh': socket.IPPROTO_ESP},
        IPv6ExtHdrDestOpt: {'nh': socket.IPPROTO_ESP},
        IPv6ExtHdrRouting: {'nh': socket.IPPROTO_ESP},
    }

bind_layers(IP, ESP, proto=socket.IPPROTO_ESP)
bind_layers(IPv6, ESP, nh=socket.IPPROTO_ESP)
bind_layers(UDP, ESP, dport=4500)  # NAT-Traversal encapsulation
bind_layers(UDP, ESP, sport=4500)  # NAT-Traversal encapsulation

#------------------------------------------------------------------------------
class _ESPPlain(Packet):
    """
    Internal class to represent unencrypted ESP packets.
    """
    name = 'ESP'

    fields_desc = [
        XIntField('spi', 0x0),
        IntField('seq', 0),

        StrField('iv', ''),
        PacketField('data', '', Raw),
        StrField('padding', ''),

        ByteField('padlen', 0),
        ByteEnumField('nh', 0, IP_PROTOS),
        StrField('icv', ''),
    ]

    def data_for_encryption(self):
        return str(self.data) + self.padding + chr(self.padlen) + chr(self.nh)

#------------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES
    from Crypto.Cipher import DES
    from Crypto.Cipher import DES3
    from Crypto.Cipher import CAST
    from Crypto.Cipher import Blowfish
    from Crypto.Util import Counter
    from Crypto import Random
except ImportError:
    # no error if pycrypto is not available but encryption won't be supported
    AES = None
    DES = None
    DES3 = None
    CAST = None
    Blowfish = None
    Random = None

#------------------------------------------------------------------------------
def _lcm(a, b):
    """
    Least Common Multiple between 2 integers.
    """
    if a == 0 or b == 0:
        return 0
    else:
        return abs(a * b) / gcd(a, b)

class CryptAlgo(object):
    """
    IPSec encryption algorithm
    """

    def __init__(self, name, cipher, mode, block_size=None, iv_size=None, key_size=None, icv_size=None):
        """
        @param name: the name of this encryption algorithm
        @param cipher: a Cipher module
        @param mode: the mode used with the cipher module
        @param block_size: the length a block for this algo. Defaults to the
                           `block_size` of the cipher.
        @param iv_size: the length of the initialization vector of this algo.
                        Defaults to the `block_size` of the cipher.
        @param key_size: an integer or list/tuple of integers. If specified,
                         force the secret keys length to one of the values.
                         Defaults to the `key_size` of the cipher.
        """
        self.name = name
        self.cipher = cipher
        self.mode = mode
        self.icv_size = icv_size
        self.is_aead = (hasattr(self.cipher, 'MODE_GCM') and
                        self.mode == self.cipher.MODE_GCM) or \
                        (hasattr(self.cipher, 'MODE_CCM') and
                        self.mode == self.cipher.MODE_CCM)

        if block_size is not None:
            self.block_size = block_size
        elif cipher is not None:
            self.block_size = cipher.block_size
        else:
            self.block_size = 1

        if iv_size is None:
            self.iv_size = self.block_size
        else:
            self.iv_size = iv_size

        if key_size is not None:
            self.key_size = key_size
        elif cipher is not None:
            self.key_size = cipher.key_size
        else:
            self.key_size = None

    def check_key(self, key):
        """
        Check that the key length is valid.

        @param key:    a byte string
        """
        if self.key_size and not (len(key) == self.key_size or len(key) in self.key_size):
            raise TypeError('invalid key size %s, must be %s' %
                            (len(key), self.key_size))

    def generate_iv(self):
        """
        Generate a random initialization vector. If pycrypto is not available,
        return a buffer of the correct length filled with only '\x00'.
        """
        if Random:
            return Random.get_random_bytes(self.iv_size)
        else:
            return chr(0) * self.iv_size

    def new_cipher(self, key, iv):
        """
        @param key:    the secret key, a byte string
        @param iv:     the initialization vector, a byte string
        @return:    an initialized cipher object for this algo
        """
        if (hasattr(self.cipher, 'MODE_CTR') and self.mode == self.cipher.MODE_CTR
            or self.is_aead):
            # in counter mode, the "iv" must be incremented for each block
            # it is calculated like this:
            # +---------+------------------+---------+
            # |  nonce  |        IV        | counter |
            # +---------+------------------+---------+
            #   m bytes       n bytes        4 bytes
            # <-------------------------------------->
            #               block_size
            nonce_size = self.cipher.block_size - self.iv_size - 4

            # instead of asking for an extra parameter, we extract the last
            # nonce_size bytes of the key and use them as the nonce.
            # +----------------------------+---------+
            # |        cipher key          |  nonce  |
            # +----------------------------+---------+
            #                              <--------->
            #                               nonce_size
            cipher_key, nonce = key[:-nonce_size], key[-nonce_size:]
            if self.is_aead:
                return self.cipher.new(cipher_key, self.mode, nonce + iv,
                                       counter=Counter.new(4 * 8, prefix=nonce + iv))

            return self.cipher.new(cipher_key, self.mode,
                                   counter=Counter.new(4 * 8, prefix=nonce + iv))
        else:
            return self.cipher.new(key, self.mode, iv)

    def pad(self, esp):
        """
        Add the correct amount of padding so that the data to encrypt is
        exactly a multiple of the algorithm's block size.

        Also, make sure that the total ESP packet length is a multiple of 4 or
        8 bytes with IP or IPv6 respectively.

        @param esp:    an unencrypted _ESPPlain packet
        """
        # 2 extra bytes for padlen and nh
        data_len = len(esp.data) + 2

        # according to the RFC4303, section 2.4. Padding (for Encryption)
        # the size of the ESP payload must be a multiple of 32 bits
        align = _lcm(self.block_size, 4)

        # pad for block size
        esp.padlen = -data_len % align

        # padding must be an array of bytes starting from 1 to padlen
        esp.padding = ''.join(chr(b) for b in xrange(1, esp.padlen + 1))

        # If the following test fails, it means that this algo does not comply
        # with the RFC
        payload_len = len(esp.iv) + len(esp.data) + len(esp.padding) + 2
        if payload_len % 4 != 0:
            raise ValueError('The size of the ESP data is not aligned to 32 bits after padding.')

        return esp

    def encrypt(self, esp, key):
        """
        Encrypt an ESP packet

        @param esp:  an unencrypted _ESPPlain packet with valid padding
        @param key:  the secret key used for encryption

        @return:    a valid ESP packet encrypted with this algorithm
        """
        data = esp.data_for_encryption()

        if self.cipher:
            self.check_key(key)
            cipher = self.new_cipher(key, esp.iv)

            if self.is_aead:
                cipher.update(struct.pack('!LL', esp.spi, esp.seq))
                data = cipher.encrypt(data)
                data += cipher.digest()[:self.icv_size]
            else:
                data = cipher.encrypt(data)

        return ESP(spi=esp.spi, seq=esp.seq, data=esp.iv + data)

    def decrypt(self, esp, key, icv_size=0):
        """
        Decrypt an ESP packet

        @param esp:        an encrypted ESP packet
        @param key:        the secret key used for encryption
        @param icv_size:   the length of the icv used for integrity check

        @return:    a valid ESP packet encrypted with this algorithm
        """
        self.check_key(key)

        if self.cipher and self.is_aead:
            icv_size = self.icv_size

        iv = esp.data[:self.iv_size]
        data = esp.data[self.iv_size:len(esp.data) - icv_size]
        icv = esp.data[len(esp.data) - icv_size:]

        if self.cipher:
            cipher = self.new_cipher(key, iv)

            if self.is_aead:
                cipher.update(struct.pack('!LL', esp.spi, esp.seq))

            data = cipher.decrypt(data)

        # extract padlen and nh
        padlen = ord(data[-2])
        nh = ord(data[-1])

        # then use padlen to determine data and padding
        data = data[:len(data) - padlen - 2]
        padding = data[len(data) - padlen - 2: len(data) - 2]

        return _ESPPlain(spi=esp.spi,
                        seq=esp.seq,
                        iv=iv,
                        data=data,
                        padding=padding,
                        padlen=padlen,
                        nh=nh,
                        icv=icv)

#------------------------------------------------------------------------------
# The names of the encryption algorithms are the same than in scapy.contrib.ikev2
# see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

CRYPT_ALGOS = {
    'NULL': CryptAlgo('NULL', cipher=None, mode=None, iv_size=0),
}

if AES:
    CRYPT_ALGOS['AES-CBC'] = CryptAlgo('AES-CBC',
                                       cipher=AES,
                                       mode=AES.MODE_CBC)
    # specific case for counter mode:
    # the last 4 bytes of the key are used to carry the nonce of the counter
    CRYPT_ALGOS['AES-CTR'] = CryptAlgo('AES-CTR',
                                       cipher=AES,
                                       mode=AES.MODE_CTR,
                                       block_size=1,
                                       iv_size=8,
                                       key_size=(16 + 4, 24 + 4, 32 + 4))
    if hasattr(AES, "MODE_GCM"):
        CRYPT_ALGOS['AES-GCM'] = CryptAlgo('AES-GCM',
                                           cipher=AES,
                                           mode=AES.MODE_GCM,
                                           iv_size=8,
                                           icv_size=8,
                                           key_size=(16 + 4, 24 + 4, 32 + 4))
    if hasattr(AES, "MODE_CCM"):
        CRYPT_ALGOS['AES-CCM'] = CryptAlgo('AES-CCM',
                                           cipher=AES,
                                           mode=AES.MODE_CCM,
                                           iv_size=8,
                                           icv_size=8,
                                           key_size=(16 + 4, 24 + 4, 32 + 4))
if DES:
    CRYPT_ALGOS['DES'] = CryptAlgo('DES',
                                   cipher=DES,
                                   mode=DES.MODE_CBC)
if Blowfish:
    CRYPT_ALGOS['Blowfish'] = CryptAlgo('Blowfish',
                                        cipher=Blowfish,
                                        mode=Blowfish.MODE_CBC)
if DES3:
    CRYPT_ALGOS['3DES'] = CryptAlgo('3DES',
                                    cipher=DES3,
                                    mode=DES3.MODE_CBC)
if CAST:
    CRYPT_ALGOS['CAST'] = CryptAlgo('CAST',
                                    cipher=CAST,
                                    mode=CAST.MODE_CBC)

#------------------------------------------------------------------------------
try:
    from Crypto.Hash import HMAC
    from Crypto.Hash import SHA
    from Crypto.Hash import MD5
    from Crypto.Hash import SHA256
    from Crypto.Hash import SHA384
    from Crypto.Hash import SHA512
except ImportError:
    # no error if pycrypto is not available but authentication won't be supported
    HMAC = None
    SHA = None
    MD5 = None
    SHA256 = None
    SHA384 = None
try:
    from Crypto.Hash import XCBCMAC
except ImportError:
    XCBCMAC = None

#------------------------------------------------------------------------------
class IPSecIntegrityError(Exception):
    """
    Error risen when the integrity check fails.
    """
    pass

class AuthAlgo(object):
    """
    IPSec integrity algorithm
    """

    def __init__(self, name, mac, digestmod, icv_size, key_size=None):
        """
        @param name: the name of this integrity algorithm
        @param mac: a Message Authentication Code module
        @param digestmod: a Hash or Cipher module
        @param icv_size: the length of the integrity check value of this algo
        @param key_size: an integer or list/tuple of integers. If specified,
                         force the secret keys length to one of the values.
                         Defaults to the `key_size` of the cipher.
        """
        self.name = name
        self.mac = mac
        self.digestmod = digestmod
        self.icv_size = icv_size
        self.key_size = key_size

    def check_key(self, key):
        """
        Check that the key length is valid.

        @param key:    a byte string
        """
        if self.key_size and len(key) not in self.key_size:
            raise TypeError('invalid key size %s, must be one of %s' %
                            (len(key), self.key_size))

    def new_mac(self, key):
        """
        @param key:    a byte string
        @return:       an initialized mac object for this algo
        """
        if self.mac is XCBCMAC:
            # specific case here, ciphermod instead of digestmod
            return self.mac.new(key, ciphermod=self.digestmod)
        else:
            return self.mac.new(key, digestmod=self.digestmod)

    def sign(self, pkt, key):
        """
        Sign an IPSec (ESP or AH) packet with this algo.

        @param pkt:    a packet that contains a valid encrypted ESP or AH layer
        @param key:    the authentication key, a byte string

        @return: the signed packet
        """
        if not self.mac:
            return pkt

        self.check_key(key)

        mac = self.new_mac(key)

        if pkt.haslayer(ESP):
            mac.update(str(pkt[ESP]))
            pkt[ESP].data += mac.digest()[:self.icv_size]

        elif pkt.haslayer(AH):
            clone = zero_mutable_fields(pkt.copy(), sending=True)
            mac.update(str(clone))
            pkt[AH].icv = mac.digest()[:self.icv_size]

        return pkt

    def verify(self, pkt, key):
        """
        Check that the integrity check value (icv) of a packet is valid.

        @param pkt:    a packet that contains a valid encrypted ESP or AH layer
        @param key:    the authentication key, a byte string

        @raise IPSecIntegrityError: if the integrity check fails
        """
        if not self.mac or self.icv_size == 0:
            return

        self.check_key(key)

        mac = self.new_mac(key)

        pkt_icv = 'not found'
        computed_icv = 'not computed'

        if isinstance(pkt, ESP):
            pkt_icv = pkt.data[len(pkt.data) - self.icv_size:]

            pkt = pkt.copy()
            pkt.data = pkt.data[:len(pkt.data) - self.icv_size]
            mac.update(str(pkt))
            computed_icv = mac.digest()[:self.icv_size]

        elif pkt.haslayer(AH):
            pkt_icv = pkt[AH].icv[:self.icv_size]

            clone = zero_mutable_fields(pkt.copy(), sending=False)
            mac.update(str(clone))
            computed_icv = mac.digest()[:self.icv_size]

        if pkt_icv != computed_icv:
            raise IPSecIntegrityError('pkt_icv=%r, computed_icv=%r' %
                                      (pkt_icv, computed_icv))

#------------------------------------------------------------------------------
# The names of the integrity algorithms are the same than in scapy.contrib.ikev2
# see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

AUTH_ALGOS = {
    'NULL': AuthAlgo('NULL', mac=None, digestmod=None, icv_size=0),
}

if HMAC:
    if SHA:
        AUTH_ALGOS['HMAC-SHA1-96'] = AuthAlgo('HMAC-SHA1-96',
                                              mac=HMAC,
                                              digestmod=SHA,
                                              icv_size=12)
    if SHA256:
        AUTH_ALGOS['SHA2-256-128'] = AuthAlgo('SHA2-256-128',
                                              mac=HMAC,
                                              digestmod=SHA256,
                                              icv_size=16)
    if SHA384:
        AUTH_ALGOS['SHA2-384-192'] = AuthAlgo('SHA2-384-192',
                                              mac=HMAC,
                                              digestmod=SHA384,
                                              icv_size=24)
    if SHA512:
        AUTH_ALGOS['SHA2-512-256'] = AuthAlgo('SHA2-512-256',
                                              mac=HMAC,
                                              digestmod=SHA512,
                                              icv_size=32)
    if MD5:
        AUTH_ALGOS['HMAC-MD5-96'] = AuthAlgo('HMAC-MD5-96',
                                             mac=HMAC,
                                             digestmod=MD5,
                                             icv_size=12)
if AES and XCBCMAC:
    AUTH_ALGOS['AES-XCBC-96'] = AuthAlgo('AES-XCBC-96',
                                         mac=XCBCMAC,
                                         digestmod=AES,
                                         icv_size=12,
                                         key_size=(16,))

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
def split_for_transport(orig_pkt, transport_proto):
    """
    Split an IP(v6) packet in the correct location to insert an ESP or AH
    header.

    @param orig_pkt: the packet to split. Must be an IP or IPv6 packet
    @param transport_proto: the IPSec protocol number that will be inserted
                            at the split position.
    @return: a tuple (header, nh, payload) where nh is the protocol number of
             payload.
    """
    header = orig_pkt.copy()
    next_hdr = header.payload
    nh = None

    if header.version == 4:
        nh = header.proto
        header.proto = transport_proto
        header.remove_payload()
        del header.chksum
        del header.len

        return header, nh, next_hdr
    else:
        found_rt_hdr = False
        prev = header

        # Since the RFC 4302 is vague about where the ESP/AH headers should be
        # inserted in IPv6, I chose to follow the linux implementation.
        while isinstance(next_hdr, (IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt)):
            if isinstance(next_hdr, IPv6ExtHdrHopByHop):
                pass
            if isinstance(next_hdr, IPv6ExtHdrRouting):
                found_rt_hdr = True
            elif isinstance(next_hdr, IPv6ExtHdrDestOpt) and found_rt_hdr:
                break

            prev = next_hdr
            next_hdr = next_hdr.payload

        nh = prev.nh
        prev.nh = transport_proto
        prev.remove_payload()
        del header.plen

        return header, nh, next_hdr

#------------------------------------------------------------------------------
# see RFC 4302 - Appendix A. Mutability of IP Options/Extension Headers
IMMUTABLE_IPV4_OPTIONS = (
    0, # End Of List
    1, # No OPeration
    2, # Security
    5, # Extended Security
    6, # Commercial Security
    20, # Router Alert
    21, # Sender Directed Multi-Destination Delivery
)
def zero_mutable_fields(pkt, sending=False):
    """
    When using AH, all "mutable" fields must be "zeroed" before calculating
    the ICV. See RFC 4302, Section 3.3.3.1. Handling Mutable Fields.

    @param pkt: an IP(v6) packet containing an AH layer.
                NOTE: The packet will be modified
    @param sending: if true, ipv6 routing headers will not be reordered
    """

    if pkt.haslayer(AH):
        pkt[AH].icv = chr(0) * len(pkt[AH].icv)
    else:
        raise TypeError('no AH layer found')

    if pkt.version == 4:
        # the tos field has been replaced by DSCP and ECN
        # Routers may rewrite the DS field as needed to provide a
        # desired local or end-to-end service
        pkt.tos = 0
        # an intermediate router might set the DF bit, even if the source
        # did not select it.
        pkt.flags = 0
        # changed en route as a normal course of processing by routers
        pkt.ttl = 0
        # will change if any of these other fields change
        pkt.chksum = 0

        immutable_opts = []
        for opt in pkt.options:
            if opt.option in IMMUTABLE_IPV4_OPTIONS:
                immutable_opts.append(opt)
            else:
                immutable_opts.append(Raw(chr(0) * len(opt)))
        pkt.options = immutable_opts

    else:
        # holds DSCP and ECN
        pkt.tc = 0
        # The flow label described in AHv1 was mutable, and in RFC 2460 [DH98]
        # was potentially mutable. To retain compatibility with existing AH
        # implementations, the flow label is not included in the ICV in AHv2.
        pkt.fl = 0
        # same as ttl
        pkt.hlim = 0

        next_hdr = pkt.payload

        while isinstance(next_hdr, (IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt)):
            if isinstance(next_hdr, (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt)):
                for opt in next_hdr.options:
                    if opt.otype & 0x20:
                        # option data can change en-route and must be zeroed
                        opt.optdata = chr(0) * opt.optlen
            elif isinstance(next_hdr, IPv6ExtHdrRouting) and sending:
                # The sender must order the field so that it appears as it
                # will at the receiver, prior to performing the ICV computation.
                next_hdr.segleft = 0
                if next_hdr.addresses:
                    final = next_hdr.addresses.pop()
                    next_hdr.addresses.insert(0, pkt.dst)
                    pkt.dst = final
            else:
                break

            next_hdr = next_hdr.payload

    return pkt

#------------------------------------------------------------------------------
class SecurityAssociation(object):
    """
    This class is responsible of "encryption" and "decryption" of IPSec packets.
    """

    SUPPORTED_PROTOS = (IP, IPv6)

    def __init__(self, proto, spi, seq_num=1, crypt_algo=None, crypt_key=None,
                 auth_algo=None, auth_key=None, tunnel_header=None, nat_t_header=None):
        """
        @param proto: the IPSec proto to use (ESP or AH)
        @param spi: the Security Parameters Index of this SA
        @param seq_num: the initial value for the sequence number on encrypted
                        packets
        @param crypt_algo: the encryption algorithm name (only used with ESP)
        @param crypt_key: the encryption key (only used with ESP)
        @param auth_algo: the integrity algorithm name
        @param auth_key: the integrity key
        @param tunnel_header: an instance of a IP(v6) header that will be used
                              to encapsulate the encrypted packets.
        @param nat_t_header: an instance of a UDP header that will be used
                             for NAT-Traversal.
        """

        if proto not in (ESP, AH, ESP.name, AH.name):
            raise ValueError("proto must be either ESP or AH")
        if isinstance(proto, basestring):
            self.proto = eval(proto)
        else:
            self.proto = proto

        self.spi = spi
        self.seq_num = seq_num

        if crypt_algo:
            if crypt_algo not in CRYPT_ALGOS:
                raise TypeError('unsupported encryption algo %r, try %r' %
                                (crypt_algo, CRYPT_ALGOS.keys()))
            self.crypt_algo = CRYPT_ALGOS[crypt_algo]
            self.crypt_algo.check_key(crypt_key)
            self.crypt_key = crypt_key
        else:
            self.crypt_algo = CRYPT_ALGOS['NULL']
            self.crypt_key = None

        if auth_algo:
            if auth_algo not in AUTH_ALGOS:
                raise TypeError('unsupported integrity algo %r, try %r' %
                                (auth_algo, AUTH_ALGOS.keys()))
            self.auth_algo = AUTH_ALGOS[auth_algo]
            self.auth_algo.check_key(auth_key)
            self.auth_key = auth_key
        else:
            self.auth_algo = AUTH_ALGOS['NULL']
            self.auth_key = None

        if tunnel_header and not isinstance(tunnel_header, (IP, IPv6)):
            raise TypeError('tunnel_header must be %s or %s' % (IP.name, IPv6.name))
        self.tunnel_header = tunnel_header

        if nat_t_header:
            if proto is not ESP:
                raise TypeError('nat_t_header is only allowed with ESP')
            if not isinstance(nat_t_header, UDP):
                raise TypeError('nat_t_header must be %s' % UDP.name)
        self.nat_t_header = nat_t_header

    def check_spi(self, pkt):
        if pkt.spi != self.spi:
            raise TypeError('packet spi=0x%x does not match the SA spi=0x%x' %
                            (pkt.spi, self.spi))

    def _encrypt_esp(self, pkt, seq_num=None, iv=None):

        if iv is None:
            iv = self.crypt_algo.generate_iv()
        else:
            if len(iv) != self.crypt_algo.iv_size:
                raise TypeError('iv length must be %s' % self.crypt_algo.iv_size)

        esp = _ESPPlain(spi=self.spi, seq=seq_num or self.seq_num, iv=iv)

        if self.tunnel_header:
            tunnel = self.tunnel_header.copy()

            if tunnel.version == 4:
                del tunnel.proto
                del tunnel.len
                del tunnel.chksum
            else:
                del tunnel.nh
                del tunnel.plen

            pkt = tunnel.__class__(str(tunnel / pkt))

        ip_header, nh, payload = split_for_transport(pkt, socket.IPPROTO_ESP)
        esp.data = payload
        esp.nh = nh

        esp = self.crypt_algo.pad(esp)
        esp = self.crypt_algo.encrypt(esp, self.crypt_key)

        self.auth_algo.sign(esp, self.auth_key)

        if self.nat_t_header:
            nat_t_header = self.nat_t_header.copy()
            nat_t_header.chksum = 0
            del nat_t_header.len
            if ip_header.version == 4:
                del ip_header.proto
            else:
                del ip_header.nh
            ip_header /= nat_t_header

        if ip_header.version == 4:
            ip_header.len = len(ip_header) + len(esp)
            del ip_header.chksum
            ip_header = ip_header.__class__(str(ip_header))
        else:
            ip_header.plen = len(ip_header.payload) + len(esp)

        # sequence number must always change, unless specified by the user
        if seq_num is None:
            self.seq_num += 1

        return ip_header / esp

    def _encrypt_ah(self, pkt, seq_num=None):

        ah = AH(spi=self.spi, seq=seq_num or self.seq_num,
                icv=chr(0) * self.auth_algo.icv_size)

        if self.tunnel_header:
            tunnel = self.tunnel_header.copy()

            if tunnel.version == 4:
                del tunnel.proto
                del tunnel.len
                del tunnel.chksum
            else:
                del tunnel.nh
                del tunnel.plen

            pkt = tunnel.__class__(str(tunnel / pkt))

        ip_header, nh, payload = split_for_transport(pkt, socket.IPPROTO_AH)
        ah.nh = nh

        if ip_header.version == 6 and len(ah) % 8 != 0:
            # For IPv6, the total length of the header must be a multiple of
            # 8-octet units.
            ah.padding = chr(0) * (-len(ah) % 8)
        elif len(ah) % 4 != 0:
            # For IPv4, the total length of the header must be a multiple of
            # 4-octet units.
            ah.padding = chr(0) * (-len(ah) % 4)

        # RFC 4302 - Section 2.2. Payload Length
        # This 8-bit field specifies the length of AH in 32-bit words (4-byte
        # units), minus "2".
        ah.payloadlen = len(ah) / 4 - 2

        if ip_header.version == 4:
            ip_header.len = len(ip_header) + len(ah) + len(payload)
            del ip_header.chksum
            ip_header = ip_header.__class__(str(ip_header))
        else:
            ip_header.plen = len(ip_header.payload) + len(ah) + len(payload)

        signed_pkt = self.auth_algo.sign(ip_header / ah / payload, self.auth_key)

        # sequence number must always change, unless specified by the user
        if seq_num is None:
            self.seq_num += 1

        return signed_pkt

    def encrypt(self, pkt, seq_num=None, iv=None):
        """
        Encrypt (and encapsulate) an IP(v6) packet with ESP or AH according
        to this SecurityAssociation.

        @param pkt:     the packet to encrypt
        @param seq_num: if specified, use this sequence number instead of the
                        generated one
        @param iv:      if specified, use this initialization vector for
                        encryption instead of a random one.

        @return: the encrypted/encapsulated packet
        """
        if not isinstance(pkt, self.SUPPORTED_PROTOS):
            raise TypeError('cannot encrypt %s, supported protos are %s'
                            % (pkt.__class__, self.SUPPORTED_PROTOS))
        if self.proto is ESP:
            return self._encrypt_esp(pkt, seq_num=seq_num, iv=iv)
        else:
            return self._encrypt_ah(pkt, seq_num=seq_num)

    def _decrypt_esp(self, pkt, verify=True):

        encrypted = pkt[ESP]

        if verify:
            self.check_spi(pkt)
            self.auth_algo.verify(encrypted, self.auth_key)

        esp = self.crypt_algo.decrypt(encrypted, self.crypt_key,
                                      self.auth_algo.icv_size)

        if self.tunnel_header:
            # drop the tunnel header and return the payload untouched

            pkt.remove_payload()
            if pkt.version == 4:
                pkt.proto = esp.nh
            else:
                pkt.nh = esp.nh
            cls = pkt.guess_payload_class(esp.data)

            return cls(esp.data)
        else:
            ip_header = pkt

            if ip_header.version == 4:
                ip_header.proto = esp.nh
                del ip_header.chksum
                ip_header.remove_payload()
                ip_header.len = len(ip_header) + len(esp.data)
                # recompute checksum
                ip_header = ip_header.__class__(str(ip_header))
            else:
                encrypted.underlayer.nh = esp.nh
                encrypted.underlayer.remove_payload()
                ip_header.plen = len(ip_header.payload) + len(esp.data)

            cls = ip_header.guess_payload_class(esp.data)

            # reassemble the ip_header with the ESP payload
            return ip_header / cls(esp.data)

    def _decrypt_ah(self, pkt, verify=True):

        if verify:
            self.check_spi(pkt)
            self.auth_algo.verify(pkt, self.auth_key)

        ah = pkt[AH]
        payload = ah.payload
        payload.remove_underlayer(None)  # useless argument...

        if self.tunnel_header:
            return payload
        else:
            ip_header = pkt

            if ip_header.version == 4:
                ip_header.proto = ah.nh
                del ip_header.chksum
                ip_header.remove_payload()
                ip_header.len = len(ip_header) + len(payload)
                # recompute checksum
                ip_header = ip_header.__class__(str(ip_header))
            else:
                ah.underlayer.nh = ah.nh
                ah.underlayer.remove_payload()
                ip_header.plen = len(ip_header.payload) + len(payload)

            # reassemble the ip_header with the AH payload
            return ip_header / payload

    def decrypt(self, pkt, verify=True):
        """
        Decrypt (and decapsulate) an IP(v6) packet containing ESP or AH.

        @param pkt:     the packet to decrypt
        @param verify:  if False, do not perform the integrity check

        @return: the decrypted/decapsulated packet
        @raise IPSecIntegrityError: if the integrity check fails
        """
        if not isinstance(pkt, self.SUPPORTED_PROTOS):
            raise TypeError('cannot decrypt %s, supported protos are %s'
                            % (pkt.__class__, self.SUPPORTED_PROTOS))

        if self.proto is ESP and pkt.haslayer(ESP):
            return self._decrypt_esp(pkt, verify=verify)
        elif self.proto is AH and pkt.haslayer(AH):
            return self._decrypt_ah(pkt, verify=verify)
        else:
            raise TypeError('%s has no %s layer' % (pkt, self.proto.name))
