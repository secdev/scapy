## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS helpers, provided as out-of-context methods.
"""

from scapy.error import warning
from scapy.fields import (ByteEnumField, ShortEnumField,
                          FieldLenField, StrLenField)
from scapy.packet import Packet

from scapy.layers.tls.basefields import _tls_type, _tls_version


class TLSPlaintext(Packet):
    name = "TLS Plaintext"
    fields_desc = [ ByteEnumField("type", None, _tls_type),
                    ShortEnumField("version", None, _tls_version),
                    FieldLenField("len", None, length_of="fragment",
                                  fmt="!H"),
                    StrLenField("fragment", "",
                                length_from = lambda pkt: pkt.length) ]

class TLSCompressed(TLSPlaintext):
    name = "TLS Compressed"

class TLSCiphertext(TLSPlaintext):
    name = "TLS Ciphertext"


def _tls_compress(alg, p):
    """
    Compress p (a TLSPlaintext instance) using compression algorithm instance
    alg and return a TLSCompressed instance.
    """
    c = TLSCompressed()
    c.type = p.type
    c.version = p.version
    c.fragment = alg.compress(p.fragment)
    c.len = len(c.fragment)
    return c

def _tls_decompress(alg, c):
    """
    Decompress c (a TLSCompressed instance) using compression algorithm
    instance alg and return a TLSPlaintext instance.
    """
    p = TLSPlaintext()
    p.type = c.type
    p.version = c.version
    p.fragment = alg.decompress(c.fragment)
    p.len = len(p.fragment)
    return p

def _tls_mac_add(alg, c, write_seq_num):
    """
    Compute the MAC using provided MAC alg instance over TLSCiphertext c using
    current write sequence number write_seq_num. Computed MAC is then appended
    to c.fragment and c.length is updated to reflect that change. It is the
    caller responsability to increment the sequence number after the operation.
    The function has no return value.
    """
    write_seq_num = struct.pack("!Q", write_seq_num)
    h = alg.digest(write_seq_num + str(c))
    c.fragment += h
    c.len += alg.hash_len

def _tls_mac_verify(alg, p, read_seq_num):
    """
    Verify if the MAC in provided message (message resulting from decryption
    and padding removal) is valid. Current read sequence number is used in
    the verification process.

    If the MAC is valid:
     - The function returns True
     - The packet p is updated in the following way: trailing MAC value is
       removed from p.fragment and length is updated accordingly.

    In case of error, False is returned, and p may have been modified.

    Also note that it is the caller's responsibility to update the read
    sequence number after the operation.
    """
    h_size = alg.hash_len
    if p.len < h_size:
        return False
    received_h = p.fragment[-h_size:]
    p.len -= h_size
    p.fragment = p.fragment[:-h_size]

    read_seq_num = struct.pack("!Q", read_seq_num)
    h = alg.digest(read_seq_num + str(p))
    return h == received_h

def _tls_add_pad(p, block_size):
    """
    Provided with cipher block size parameter and current TLSCompressed packet
    p (after MAC addition), the function adds required, deterministic padding
    to p.fragment before encryption step, as it is defined for TLS (i.e. not
    SSL and its allowed random padding). The function has no return value.
    """
    padlen = block_size - ((p.len + 1) % block_size)
    if padlen == block_size:
        padlen =  0
    padding = chr(padlen) * (padlen + 1)
    p.len += len(padding)
    p.fragment += padding

def _tls_del_pad(p):
    """
    Provided with a just decrypted TLSCiphertext (now a TLSPlaintext instance)
    p, the function removes the trailing padding found in p.fragment. It also
    performs some sanity checks on the padding (length, content, ...). False
    is returned if one of the check fails. Otherwise, True is returned,
    indicating that p.fragment and p.len have been updated.
    """

    if p.len < 1:
        warning("Message format is invalid (padding)")
        return False

    padlen = ord(p.fragment[-1]) + 1
    if (p.len < padlen):
        warning("Invalid padding length")
        return False

    if (p.fragment[-padlen:] != p.fragment[-1] * padlen):
        warning("Padding content is invalid %s" % repr(p.fragment[-padlen:]))
        return False

    p.fragment = p.fragment[:-padlen]
    p.len -= padlen

    return True

def _tls_encrypt(alg, p):
    """
    Provided with an already MACed TLSCompressed packet, and a stream or block
    cipher alg, the function converts it into a TLSCiphertext (i.e. encrypts it
    and updates length). The function returns a newly created TLSCiphertext
    instance.
    """
    c = TLSCiphertext()
    c.type = p.type
    c.version = p.version
    c.fragment = alg.encrypt(p.fragment)
    c.len = len(c.fragment)
    return c

def _tls_decrypt(alg, c):
    """
    Provided with a TLSCiphertext instance c, and a stream or block cipher alg,
    the function decrypts c.fragment and returns a newly created TLSPlaintext.
    """
    p = TLSPlaintext()
    p.type = c.type
    p.version = c.version
    p.fragment = alg.decrypt(c.fragment)
    p.len = len(p.fragment)
    return p

def _tls_aead_auth_encrypt(alg, p, write_seq_num):
    """
    Provided with a TLSCompressed instance p, the function applies AEAD
    cipher alg to p.fragment and builds a new TLSCiphertext instance. Unlike
    for block and stream ciphers, for which the authentication step is done
    separately, AEAD alg does it simultaneously: this is the reason why
    write_seq_num is passed to the function, to be incorporated in
    authenticated data. Note that it is the caller's responibility to increment
    write_seq_num afterwards.
    """
    P = str(p)
    write_seq_num = struct.pack("!Q", write_seq_num)
    A = write_seq_num + P[:5]

    c = TLCCiphertext()
    c.type = p.type
    c.version = p.version
    c.fragment = alg.auth_encrypt(P, A)
    c.len = len(c.fragment)
    return c

def _tls_aead_auth_decrypt(alg, c, read_seq_num):
    """
    Provided with a TLSCiphertext instance c, the function applies AEAD
    cipher alg auth_decrypt function to c.fragment (and additional data)
    in order to authenticate the data and decrypt c.fragment. When those
    steps succeed, the result is a newly created TLSCompressed instance.
    On error, None is returned. Note that it is the caller's responsibility to
    increment read_seq_num afterwards.
    """
    # 'Deduce' TLSCompressed length from TLSCiphertext length
    # There is actually no guaranty of this equality, but this is defined as
    # such in TLS 1.2 specifications, and it works for GCM and CCM at least.
    l = p.len - alg.nonce_explicit_len - alg.tag_len
    read_seq_num = struct.pack("!Q", read_seq_num)
    A = read_seq_num + struct.pack('!BHH', p.type, p.version, l)

    p = TLSCompressed()
    p.type = c.type
    p.version = c.version
    p.len = l
    p.fragment = alg.auth_decrypt(A, c.fragment)

    if p.fragment is None: # Verification failed.
        return None
    return p

