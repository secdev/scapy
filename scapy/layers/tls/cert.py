# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2008 Arnaud Ebalard <arnaud.ebalard@eads.net>
#                                   <arno@natisbad.org>
#   2015, 2016, 2017 Maxence Tury   <maxence.tury@ssi.gouv.fr>
#   2022-2025        Gabriel Potter

r"""
High-level methods for PKI objects (X.509 certificates, CRLs, CSR, Keys, CMS).
Supported keys include RSA, ECDSA and EdDSA.

The classes below are wrappers for the ASN.1 objects defined in x509.py.

Example 1: Certificate & Private key
____________________________________

For instance, here is what you could do in order to modify the subject public
key info of a 'cert' and then resign it with whatever 'key'::

    >>> from scapy.layers.tls.cert import *
    >>> cert = Cert("cert.der")
    >>> k = PrivKeyRSA()  # generate a private key
    >>> cert.setSubjectPublicKeyFromPrivateKey(k)
    >>> cert.resignWith(k)
    >>> cert.export("newcert.pem")
    >>> k.export("mykey.pem")

One could also edit arguments like the serial number, as such::

    >>> from scapy.layers.tls.cert import *
    >>> c = Cert("mycert.pem")
    >>> c.tbsCertificate.serialNumber = 0x4B1D
    >>> k = PrivKey("mykey.pem")  # import an existing private key
    >>> c.resignWith(k)
    >>> c.export("newcert.pem")

To export the public key of a private key::

    >>> k = PrivKey("mykey.pem")
    >>> k.pubkey.export("mypubkey.pem")

Example 2: CertList and CertTree
________________________________

Load a .pem file that contains multiple certificates::

    >>> l = CertList("ca_chain.pem")
    >>> l.show()
    0000 [X.509 Cert Subject:/C=FR/OU=Scapy Test PKI/CN=Scapy Test CA...]
    0001 [X.509 Cert Subject:/C=FR/OU=Scapy Test PKI/CN=Scapy Test Client...]

Use 'CertTree' to organize the certificates in a tree::

    >>> tree = CertTree("ca_chain.pem")  # or tree = CertTree(l)
    >>> tree.show()
    /C=Ulaanbaatar/OU=Scapy Test PKI/CN=Scapy Test CA [Self Signed]
        /C=FR/OU=Scapy Test PKI/CN=Scapy Test Client [Not Self Signed]

Example 3: Certificate Signing Request (CSR)
____________________________________________

Scapy's :py:class:`~scapy.layers.tls.cert.CSR` class supports both PKCS#10 and CMC
formats.

Load and display a CSR::

    >>> csr = CSR("cert.req")
    >>> csr
    [CSR Format: CMC, Subject:/O=TestOrg/CN=TestCN, Verified: True]
    >>> csr.certReq.show()
    ###[ PKCS10_CertificationRequest ]###
       \certificationRequestInfo\
        |###[ PKCS10_CertificationRequestInfo ]###
        |  version   = 0x0 <ASN1_INTEGER[0]
        |  \subject   \
        |   |###[ X509_RDN ]###
        |   |  \rdn       \
        |   |   |###[ X509_AttributeTypeAndValue ]###
        |   |   |  type      = <ASN1_OID['organizationName']>
        |   |   |  value     = <ASN1_UTF8_STRING[b'TestOrg']>
        [...]

Get its public key and verify its signature::

    >>> csr.pubkey
    <scapy.layers.tls.cert.PubKeyRSA at 0x7f3481149310>
    >>> csr.verifySelf()
    True

No need for obnoxious openssl tweaking anymore. :)
"""

import base64
import enum
import os
import time
import warnings

from scapy.config import conf, crypto_validator
from scapy.compat import Self
from scapy.error import warning
from scapy.utils import binrepr
from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_NULL,
    ASN1_OID,
    ASN1_STRING,
)
from scapy.asn1.mib import hash_by_oid
from scapy.packet import Packet
from scapy.layers.x509 import (
    CMS_CertificateChoices,
    CMS_ContentInfo,
    CMS_EncapsulatedContentInfo,
    CMS_IssuerAndSerialNumber,
    CMS_RevocationInfoChoice,
    CMS_SignedAttrsForSignature,
    CMS_SignedData,
    CMS_SignerInfo,
    CMS_SubjectKeyIdentifier,
    ECDSAPrivateKey_OpenSSL,
    ECDSAPrivateKey,
    ECDSAPublicKey,
    EdDSAPrivateKey,
    EdDSAPublicKey,
    PKCS10_CertificationRequest,
    RSAPrivateKey_OpenSSL,
    RSAPrivateKey,
    RSAPublicKey,
    X509_AlgorithmIdentifier,
    X509_Attribute,
    X509_AttributeValue,
    X509_Cert,
    X509_CRL,
    X509_SubjectPublicKeyInfo,
)
from scapy.layers.tls.crypto.pkcs1 import (
    _DecryptAndSignRSA,
    _EncryptAndVerifyRSA,
    _get_hash,
    pkcs_os2ip,
)
from scapy.compat import bytes_encode

# Typing imports
from typing import (
    List,
    Optional,
    Union,
)

if conf.crypto_valid:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519

    # cryptography raised the minimum RSA key length to 1024 in 43.0+
    # https://github.com/pyca/cryptography/pull/10278
    # but we need still 512 for EXPORT40 ciphers (yes EXPORT is terrible)
    # https://datatracker.ietf.org/doc/html/rfc2246#autoid-66
    # The following detects the change and hacks around it using the backend

    try:
        rsa.generate_private_key(public_exponent=65537, key_size=512)
        _RSA_512_SUPPORTED = True
    except ValueError:
        # cryptography > 43.0
        _RSA_512_SUPPORTED = False
        from cryptography.hazmat.primitives.asymmetric.rsa import rust_openssl


# Maximum allowed size in bytes for a certificate file, to avoid
# loading huge file when importing a cert
_MAX_KEY_SIZE = 50 * 1024
_MAX_CERT_SIZE = 50 * 1024
_MAX_CRL_SIZE = 10 * 1024 * 1024  # some are that big
_MAX_CSR_SIZE = 50 * 1024


#####################################################################
# Some helpers
#####################################################################


@conf.commands.register
def der2pem(der_string, obj="UNKNOWN"):
    """Convert DER octet string to PEM format (with optional header)"""
    # Encode a byte string in PEM format. Header advertises <obj> type.
    pem_string = "-----BEGIN %s-----\n" % obj
    base64_string = base64.b64encode(der_string).decode()
    chunks = [base64_string[i : i + 64] for i in range(0, len(base64_string), 64)]
    pem_string += "\n".join(chunks)
    pem_string += "\n-----END %s-----\n" % obj
    return pem_string


@conf.commands.register
def pem2der(pem_string):
    """Convert PEM string to DER format"""
    # Encode all lines between the first '-----\n' and the 2nd-to-last '-----'.
    pem_string = pem_string.replace(b"\r", b"")
    first_idx = pem_string.find(b"-----\n") + 6
    if pem_string.find(b"-----BEGIN", first_idx) != -1:
        raise Exception("pem2der() expects only one PEM-encoded object")
    last_idx = pem_string.rfind(b"-----", 0, pem_string.rfind(b"-----"))
    base64_string = pem_string[first_idx:last_idx]
    base64_string.replace(b"\n", b"")
    der_string = base64.b64decode(base64_string)
    return der_string


def split_pem(s):
    """
    Split PEM objects. Useful to process concatenated certificates.
    """
    pem_strings = []
    while s != b"":
        start_idx = s.find(b"-----BEGIN")
        if start_idx == -1:
            break
        end_idx = s.find(b"-----END")
        if end_idx == -1:
            raise Exception("Invalid PEM object (missing END tag)")
        end_idx = s.find(b"\n", end_idx) + 1
        if end_idx == 0:
            # There is no final \n
            end_idx = len(s)
        pem_strings.append(s[start_idx:end_idx])
        s = s[end_idx:]
    return pem_strings


class _PKIObj(object):
    def __init__(self, frmt, der):
        self.frmt = frmt
        self._der = der


class _PKIObjMaker(type):
    def __call__(cls, obj_path, obj_max_size, pem_marker=None):
        # This enables transparent DER and PEM-encoded data imports.
        # Note that when importing a PEM file with multiple objects (like ECDSA
        # private keys output by openssl), it will concatenate every object in
        # order to create a 'der' attribute. When converting a 'multi' DER file
        # into a PEM file, though, the PEM attribute will not be valid,
        # because we do not try to identify the class of each object.
        error_msg = "Unable to import data"

        if obj_path is None:
            raise Exception(error_msg)
        obj_path = bytes_encode(obj_path)

        if (b"\x00" not in obj_path) and os.path.isfile(obj_path):
            _size = os.path.getsize(obj_path)
            if _size > obj_max_size:
                raise Exception(error_msg)
            try:
                with open(obj_path, "rb") as f:
                    _raw = f.read()
            except Exception:
                raise Exception(error_msg)
        else:
            _raw = obj_path

        try:
            if b"-----BEGIN" in _raw:
                frmt = "PEM"
                pem = _raw
                der_list = split_pem(pem)
                der = b"".join(map(pem2der, der_list))
            else:
                frmt = "DER"
                der = _raw
        except Exception:
            raise Exception(error_msg)

        p = _PKIObj(frmt, der)
        return p


#####################################################################
# PKI objects wrappers
#####################################################################

###############
# Public Keys #
###############


class _PubKeyFactory(_PKIObjMaker):
    """
    Metaclass for PubKey creation.
    It casts the appropriate class on the fly, then fills in
    the appropriate attributes with import_from_asn1pkt() submethod.
    """

    def __call__(cls, key_path=None, cryptography_obj=None):
        # This allows to import cryptography objects directly
        if cryptography_obj is not None:
            obj = type.__call__(cls)
            obj.__class__ = cls
            obj.frmt = "original"
            obj.marker = "PUBLIC KEY"
            obj.pubkey = cryptography_obj
            return obj

        if key_path is None:
            obj = type.__call__(cls)
            if cls is PubKey:
                cls = PubKeyRSA
            obj.__class__ = cls
            obj.frmt = "original"
            obj.fill_and_store()
            return obj

        # This deals with the rare RSA 'kx export' call.
        if isinstance(key_path, tuple):
            obj = type.__call__(cls)
            obj.__class__ = PubKeyRSA
            obj.frmt = "tuple"
            obj.import_from_tuple(key_path)
            return obj

        # Now for the usual calls, key_path may be the path to either:
        # _an X509_SubjectPublicKeyInfo, as processed by openssl;
        # _an RSAPublicKey;
        # _an ECDSAPublicKey;
        # _an EdDSAPublicKey.
        obj = _PKIObjMaker.__call__(cls, key_path, _MAX_KEY_SIZE)
        try:
            spki = X509_SubjectPublicKeyInfo(obj._der)
            pubkey = spki.subjectPublicKey
            if isinstance(pubkey, RSAPublicKey):
                obj.__class__ = PubKeyRSA
                obj.import_from_asn1pkt(pubkey)
            elif isinstance(pubkey, ECDSAPublicKey):
                obj.__class__ = PubKeyECDSA
                obj.import_from_der(obj._der)
            elif isinstance(pubkey, EdDSAPublicKey):
                obj.__class__ = PubKeyEdDSA
                obj.import_from_der(obj._der)
            else:
                raise
            obj.marker = "PUBLIC KEY"
        except Exception:
            try:
                pubkey = RSAPublicKey(obj._der)
                obj.__class__ = PubKeyRSA
                obj.import_from_asn1pkt(pubkey)
                obj.marker = "RSA PUBLIC KEY"
            except Exception:
                # We cannot import an ECDSA public key without curve knowledge
                if conf.debug_dissector:
                    raise
                raise Exception("Unable to import public key")
        return obj


class PubKey(metaclass=_PubKeyFactory):
    """
    Parent class for PubKeyRSA, PubKeyECDSA and PubKeyEdDSA.
    Provides common verifyCert() and export() methods.
    """

    def verifyCert(self, cert):
        """Verifies either a Cert or an X509_Cert."""
        h = _get_cert_sig_hashname(cert)
        tbsCert = cert.tbsCertificate
        sigVal = bytes(cert.signatureValue)
        return self.verify(bytes(tbsCert), sigVal, h=h, t="pkcs")

    def verifyCsr(self, csr):
        """Verifies a CSR."""
        h = _get_csr_sig_hashname(csr)
        certReqInfo = csr.certReq.certificationRequestInfo
        sigVal = bytes(csr.certReq.signature)
        return self.verify(bytes(certReqInfo), sigVal, h=h, t="pkcs")

    @property
    def pem(self):
        return der2pem(self.der, self.marker)

    @property
    def der(self):
        return self.pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_numbers(self, *args, **kwargs):
        return self.pubkey.public_numbers(*args, **kwargs)

    @property
    def key_size(self):
        return self.pubkey.key_size

    def export(self, filename, fmt=None):
        """
        Export public key in 'fmt' format (DER or PEM) to file 'filename'
        """
        if fmt is None:
            if filename.endswith(".pem"):
                fmt = "PEM"
            else:
                fmt = "DER"
        with open(filename, "wb") as f:
            if fmt == "DER":
                return f.write(self.der)
            elif fmt == "PEM":
                return f.write(self.pem.encode())

    @crypto_validator
    def verify(self, msg, sig, h="sha256", **kwargs):
        """
        Verify signed data.
        """
        raise NotImplementedError


class PubKeyRSA(PubKey, _EncryptAndVerifyRSA):
    """
    Wrapper for RSA keys based on _EncryptAndVerifyRSA from crypto/pkcs1.py
    Use the 'key' attribute to access original object.
    """

    @crypto_validator
    def fill_and_store(self, modulus=None, modulusLen=None, pubExp=None):
        pubExp = pubExp or 65537
        if not modulus:
            real_modulusLen = modulusLen or 2048
            if real_modulusLen < 1024 and not _RSA_512_SUPPORTED:
                # cryptography > 43.0 compatibility
                private_key = rust_openssl.rsa.generate_private_key(
                    public_exponent=pubExp,
                    key_size=real_modulusLen,
                )
            else:
                private_key = rsa.generate_private_key(
                    public_exponent=pubExp,
                    key_size=real_modulusLen,
                    backend=default_backend(),
                )
            self.pubkey = private_key.public_key()
        else:
            real_modulusLen = len(binrepr(modulus))
            if modulusLen and real_modulusLen != modulusLen:
                warning("modulus and modulusLen do not match!")
            pubNum = rsa.RSAPublicNumbers(n=modulus, e=pubExp)
            self.pubkey = pubNum.public_key(default_backend())

        self.marker = "PUBLIC KEY"

        # Lines below are only useful for the legacy part of pkcs1.py
        pubNum = self.pubkey.public_numbers()
        self._modulusLen = real_modulusLen
        self._modulus = pubNum.n
        self._pubExp = pubNum.e

    @crypto_validator
    def import_from_tuple(self, tup):
        # this is rarely used
        e, m, mLen = tup
        if isinstance(m, bytes):
            m = pkcs_os2ip(m)
        if isinstance(e, bytes):
            e = pkcs_os2ip(e)
        self.fill_and_store(modulus=m, pubExp=e)

    def import_from_asn1pkt(self, pubkey):
        modulus = pubkey.modulus.val
        pubExp = pubkey.publicExponent.val
        self.fill_and_store(modulus=modulus, pubExp=pubExp)

    def encrypt(self, msg, t="pkcs", h="sha256", mgf=None, L=None):
        # no ECDSA encryption support, hence no ECDSA specific keywords here
        return _EncryptAndVerifyRSA.encrypt(self, msg, t=t, h=h, mgf=mgf, L=L)

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        return _EncryptAndVerifyRSA.verify(self, msg, sig, t=t, h=h, mgf=mgf, L=L)


class PubKeyECDSA(PubKey):
    """
    Wrapper for ECDSA keys based on the cryptography library.
    Use the 'key' attribute to access original object.
    """

    @crypto_validator
    def fill_and_store(self, curve=None):
        curve = curve or ec.SECP256R1
        private_key = ec.generate_private_key(curve(), default_backend())
        self.pubkey = private_key.public_key()

    @crypto_validator
    def import_from_der(self, pubkey):
        # No lib support for explicit curves nor compressed points.
        self.pubkey = serialization.load_der_public_key(
            pubkey,
            backend=default_backend(),
        )

    def encrypt(self, msg, h="sha256", **kwargs):
        raise Exception("No ECDSA encryption support")

    @crypto_validator
    def verify(self, msg, sig, h="sha256", **kwargs):
        # 'sig' should be a DER-encoded signature, as per RFC 3279
        try:
            self.pubkey.verify(sig, msg, ec.ECDSA(_get_hash(h)))
            return True
        except InvalidSignature:
            return False


class PubKeyEdDSA(PubKey):
    """
    Wrapper for EdDSA keys based on the cryptography library.
    Use the 'key' attribute to access original object.
    """

    @crypto_validator
    def fill_and_store(self, curve=None):
        curve = curve or x25519.X25519PrivateKey
        private_key = curve.generate()
        self.pubkey = private_key.public_key()

    @crypto_validator
    def import_from_der(self, pubkey):
        self.pubkey = serialization.load_der_public_key(
            pubkey,
            backend=default_backend(),
        )

    def encrypt(self, msg, **kwargs):
        raise Exception("No EdDSA encryption support")

    @crypto_validator
    def verify(self, msg, sig, **kwargs):
        # 'sig' should be a DER-encoded signature, as per RFC 3279
        try:
            self.pubkey.verify(sig, msg)
            return True
        except InvalidSignature:
            return False


################
# Private Keys #
################


class _PrivKeyFactory(_PKIObjMaker):
    """
    Metaclass for PrivKey creation.
    It casts the appropriate class on the fly, then fills in
    the appropriate attributes with import_from_asn1pkt() submethod.
    """

    def __call__(cls, key_path=None, cryptography_obj=None):
        """
        key_path may be the path to either:
            _an RSAPrivateKey_OpenSSL (as generated by openssl);
            _an ECDSAPrivateKey_OpenSSL (as generated by openssl);
            _an RSAPrivateKey;
            _an ECDSAPrivateKey.
        """
        if key_path is None:
            obj = type.__call__(cls)
            if cls is PrivKey:
                cls = PrivKeyECDSA
            obj.__class__ = cls
            obj.frmt = "original"
            obj.fill_and_store()
            return obj

        # This allows to import cryptography objects directly
        if cryptography_obj is not None:
            # We (stupidly) need to go through the whole import process because RSA
            # does more than just importing the cryptography objects...
            obj = _PKIObj(
                "DER",
                cryptography_obj.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )
        else:
            # Load from file
            obj = _PKIObjMaker.__call__(cls, key_path, _MAX_KEY_SIZE)

        try:
            privkey = RSAPrivateKey_OpenSSL(obj._der)
            privkey = privkey.privateKey
            obj.__class__ = PrivKeyRSA
            obj.marker = "PRIVATE KEY"
        except Exception:
            try:
                privkey = ECDSAPrivateKey_OpenSSL(obj._der)
                privkey = privkey.privateKey
                obj.__class__ = PrivKeyECDSA
                obj.marker = "EC PRIVATE KEY"
            except Exception:
                try:
                    privkey = RSAPrivateKey(obj._der)
                    obj.__class__ = PrivKeyRSA
                    obj.marker = "RSA PRIVATE KEY"
                except Exception:
                    try:
                        privkey = ECDSAPrivateKey(obj._der)
                        obj.__class__ = PrivKeyECDSA
                        obj.marker = "EC PRIVATE KEY"
                    except Exception:
                        try:
                            privkey = EdDSAPrivateKey(obj._der)
                            obj.__class__ = PrivKeyEdDSA
                            obj.marker = "PRIVATE KEY"
                        except Exception:
                            raise Exception("Unable to import private key")
        try:
            obj.import_from_asn1pkt(privkey)
        except ImportError:
            pass
        return obj


class _Raw_ASN1_BIT_STRING(ASN1_BIT_STRING):
    """A ASN1_BIT_STRING that ignores BER encoding"""

    def __bytes__(self):
        return self.val_readable

    __str__ = __bytes__


class PrivKey(metaclass=_PrivKeyFactory):
    """
    Parent class for PrivKeyRSA, PrivKeyECDSA and PrivKeyEdDSA.
    Provides common signTBSCert(), resignCert(), verifyCert()
    and export() methods.
    """

    def signTBSCert(self, tbsCert, h="sha256"):
        """
        Note that this will always copy the signature field from the
        tbsCertificate into the signatureAlgorithm field of the result,
        regardless of the coherence between its contents (which might
        indicate ecdsa-with-SHA512) and the result (e.g. RSA signing MD2).

        There is a small inheritance trick for the computation of sigVal
        below: in order to use a sign() method which would apply
        to both PrivKeyRSA and PrivKeyECDSA, the sign() methods of the
        subclasses accept any argument, be it from the RSA or ECDSA world,
        and then they keep the ones they're interested in.
        Here, t will be passed eventually to pkcs1._DecryptAndSignRSA.sign().
        """
        sigAlg = tbsCert.signature
        h = h or hash_by_oid[sigAlg.algorithm.val]
        sigVal = self.sign(bytes(tbsCert), h=h, t="pkcs")
        c = X509_Cert()
        c.tbsCertificate = tbsCert
        c.signatureAlgorithm = sigAlg
        c.signatureValue = _Raw_ASN1_BIT_STRING(sigVal, readable=True)
        return c

    def resignCert(self, cert):
        """Rewrite the signature of either a Cert or an X509_Cert."""
        return self.signTBSCert(cert.tbsCertificate, h=None)

    def verifyCert(self, cert):
        """Verifies either a Cert or an X509_Cert."""
        return self.pubkey.verifyCert(cert)

    def verifyCsr(self, cert):
        """Verifies either a CSR."""
        return self.pubkey.verifyCsr(cert)

    @property
    def pem(self):
        return der2pem(self.der, self.marker)

    @property
    def der(self):
        return self.key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def export(self, filename, fmt=None):
        """
        Export private key in 'fmt' format (DER or PEM) to file 'filename'
        """
        if fmt is None:
            if filename.endswith(".pem"):
                fmt = "PEM"
            else:
                fmt = "DER"
        with open(filename, "wb") as f:
            if fmt == "DER":
                return f.write(self.der)
            elif fmt == "PEM":
                return f.write(self.pem.encode())

    @crypto_validator
    def sign(self, data, h="sha256", **kwargs):
        """
        Sign data.
        """
        raise NotImplementedError

    @crypto_validator
    def verify(self, msg, sig, h="sha256", **kwargs):
        """
        Verify signed data.
        """
        raise NotImplementedError


class PrivKeyRSA(PrivKey, _DecryptAndSignRSA):
    """
    Wrapper for RSA keys based on _DecryptAndSignRSA from crypto/pkcs1.py
    Use the 'key' attribute to access original object.
    """

    @crypto_validator
    def fill_and_store(
        self,
        modulus=None,
        modulusLen=None,
        pubExp=None,
        prime1=None,
        prime2=None,
        coefficient=None,
        exponent1=None,
        exponent2=None,
        privExp=None,
    ):
        pubExp = pubExp or 65537
        if None in [
            modulus,
            prime1,
            prime2,
            coefficient,
            privExp,
            exponent1,
            exponent2,
        ]:
            # note that the library requires every parameter
            # in order to call RSAPrivateNumbers(...)
            # if one of these is missing, we generate a whole new key
            real_modulusLen = modulusLen or 2048
            if real_modulusLen < 1024 and not _RSA_512_SUPPORTED:
                # cryptography > 43.0 compatibility
                self.key = rust_openssl.rsa.generate_private_key(
                    public_exponent=pubExp,
                    key_size=real_modulusLen,
                )
            else:
                self.key = rsa.generate_private_key(
                    public_exponent=pubExp,
                    key_size=real_modulusLen,
                    backend=default_backend(),
                )
            pubkey = self.key.public_key()
        else:
            real_modulusLen = len(binrepr(modulus))
            if modulusLen and real_modulusLen != modulusLen:
                warning("modulus and modulusLen do not match!")
            pubNum = rsa.RSAPublicNumbers(n=modulus, e=pubExp)
            privNum = rsa.RSAPrivateNumbers(
                p=prime1,
                q=prime2,
                dmp1=exponent1,
                dmq1=exponent2,
                iqmp=coefficient,
                d=privExp,
                public_numbers=pubNum,
            )
            self.key = privNum.private_key(default_backend())
            pubkey = self.key.public_key()

        self.marker = "PRIVATE KEY"

        # Lines below are only useful for the legacy part of pkcs1.py
        pubNum = pubkey.public_numbers()
        self._modulusLen = real_modulusLen
        self._modulus = pubNum.n
        self._pubExp = pubNum.e

        self.pubkey = PubKeyRSA((pubNum.e, pubNum.n, real_modulusLen))

    def import_from_asn1pkt(self, privkey):
        modulus = privkey.modulus.val
        pubExp = privkey.publicExponent.val
        privExp = privkey.privateExponent.val
        prime1 = privkey.prime1.val
        prime2 = privkey.prime2.val
        exponent1 = privkey.exponent1.val
        exponent2 = privkey.exponent2.val
        coefficient = privkey.coefficient.val
        self.fill_and_store(
            modulus=modulus,
            pubExp=pubExp,
            privExp=privExp,
            prime1=prime1,
            prime2=prime2,
            exponent1=exponent1,
            exponent2=exponent2,
            coefficient=coefficient,
        )

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        return self.pubkey.verify(
            msg=msg,
            sig=sig,
            t=t,
            h=h,
            mgf=mgf,
            L=L,
        )

    def sign(self, data, t="pkcs", h="sha256", mgf=None, L=None):
        return _DecryptAndSignRSA.sign(self, data, t=t, h=h, mgf=mgf, L=L)


class PrivKeyECDSA(PrivKey):
    """
    Wrapper for ECDSA keys based on SigningKey from ecdsa library.
    Use the 'key' attribute to access original object.
    """

    @crypto_validator
    def fill_and_store(self, curve=None):
        curve = curve or ec.SECP256R1
        self.key = ec.generate_private_key(curve(), default_backend())
        self.pubkey = PubKeyECDSA(cryptography_obj=self.key.public_key())
        self.marker = "EC PRIVATE KEY"

    @crypto_validator
    def import_from_asn1pkt(self, privkey):
        self.key = serialization.load_der_private_key(
            bytes(privkey), None, backend=default_backend()
        )
        self.pubkey = PubKeyECDSA(cryptography_obj=self.key.public_key())
        self.marker = "EC PRIVATE KEY"

    @crypto_validator
    def verify(self, msg, sig, h="sha256", **kwargs):
        return self.pubkey.verify(msg=msg, sig=sig, h=h, **kwargs)

    @crypto_validator
    def sign(self, data, h="sha256", **kwargs):
        return self.key.sign(data, ec.ECDSA(_get_hash(h)))


class PrivKeyEdDSA(PrivKey):
    """
    Wrapper for EdDSA keys
    Use the 'key' attribute to access original object.
    """

    @crypto_validator
    def fill_and_store(self, curve=None):
        curve = curve or x25519.X25519PrivateKey
        self.key = curve.generate()
        self.pubkey = PubKeyECDSA(cryptography_obj=self.key.public_key())
        self.marker = "PRIVATE KEY"

    @crypto_validator
    def import_from_asn1pkt(self, privkey):
        self.key = serialization.load_der_private_key(
            bytes(privkey), None, backend=default_backend()
        )
        self.pubkey = PubKeyECDSA(cryptography_obj=self.key.public_key())
        self.marker = "PRIVATE KEY"

    @crypto_validator
    def verify(self, msg, sig, **kwargs):
        return self.pubkey.verify(msg=msg, sig=sig, **kwargs)

    @crypto_validator
    def sign(self, data, **kwargs):
        return self.key.sign(data)


################
# Certificates #
################


class _CertMaker(_PKIObjMaker):
    """
    Metaclass for Cert creation. It is not necessary as it was for the keys,
    but we reuse the model instead of creating redundant constructors.
    """

    def __call__(cls, cert_path=None, cryptography_obj=None):
        # This allows to import cryptography objects directly
        if cryptography_obj is not None:
            obj = _PKIObj(
                "DER",
                cryptography_obj.public_bytes(
                    encoding=serialization.Encoding.DER,
                ),
            )
        else:
            # Load from file
            obj = _PKIObjMaker.__call__(cls, cert_path, _MAX_CERT_SIZE, "CERTIFICATE")
        obj.__class__ = Cert
        obj.marker = "CERTIFICATE"
        try:
            cert = X509_Cert(obj._der)
        except Exception:
            if conf.debug_dissector:
                raise
            raise Exception("Unable to import certificate")
        obj.import_from_asn1pkt(cert)
        return obj


def _get_cert_sig_hashname(cert):
    """
    Return the hash associated with the signature algorithm of a certificate.
    """
    tbsCert = cert.tbsCertificate
    sigAlg = tbsCert.signature
    return hash_by_oid[sigAlg.algorithm.val]


def _get_csr_sig_hashname(csr):
    """
    Return the hash associated with the signature algorithm of a CSR.
    """
    certReq = csr.certReq
    sigAlg = certReq.signatureAlgorithm
    return hash_by_oid[sigAlg.algorithm.val]


class Cert(metaclass=_CertMaker):
    """
    Wrapper for the X509_Cert from layers/x509.py.
    Use the 'x509Cert' attribute to access original object.
    """

    def import_from_asn1pkt(self, cert):
        error_msg = "Unable to import certificate"

        self.x509Cert = cert

        tbsCert = cert.tbsCertificate

        if tbsCert.version:
            self.version = tbsCert.version.val + 1
        else:
            self.version = 1
        self.serial = tbsCert.serialNumber.val
        self.sigAlg = tbsCert.signature.algorithm.oidname
        self.issuer = tbsCert.get_issuer()
        self.issuer_str = tbsCert.get_issuer_str()
        self.issuer_hash = hash(self.issuer_str)
        self.subject = tbsCert.get_subject()
        self.subject_str = tbsCert.get_subject_str()
        self.subject_hash = hash(self.subject_str)
        self.authorityKeyID = None

        self.notBefore_str = tbsCert.validity.not_before.pretty_time
        try:
            self.notBefore = tbsCert.validity.not_before.datetime.timetuple()
        except ValueError:
            raise Exception(error_msg)
        self.notBefore_str_simple = time.strftime("%x", self.notBefore)

        self.notAfter_str = tbsCert.validity.not_after.pretty_time
        try:
            self.notAfter = tbsCert.validity.not_after.datetime.timetuple()
        except ValueError:
            raise Exception(error_msg)
        self.notAfter_str_simple = time.strftime("%x", self.notAfter)

        self.pubkey = PubKey(bytes(tbsCert.subjectPublicKeyInfo))

        if tbsCert.extensions:
            for extn in tbsCert.extensions:
                if extn.extnID.oidname == "basicConstraints":
                    self.cA = False
                    if extn.extnValue.cA:
                        self.cA = not (extn.extnValue.cA.val == 0)
                elif extn.extnID.oidname == "keyUsage":
                    self.keyUsage = extn.extnValue.get_keyUsage()
                elif extn.extnID.oidname == "extKeyUsage":
                    self.extKeyUsage = extn.extnValue.get_extendedKeyUsage()
                elif extn.extnID.oidname == "authorityKeyIdentifier":
                    self.authorityKeyID = extn.extnValue.keyIdentifier.val

        self.signatureValue = bytes(cert.signatureValue)
        self.signatureLen = len(self.signatureValue)

    def isIssuer(self, other):
        """
        True if 'other' issued 'self', i.e.:
          - self.issuer == other.subject
          - self is signed by other
        """
        if self.issuer_hash != other.subject_hash:
            return False
        return other.pubkey.verifyCert(self)

    def isIssuerCert(self, other):
        return self.isIssuer(other)

    def isSelfSigned(self):
        """
        Return True if the certificate is self-signed:
          - issuer and subject are the same
          - the signature of the certificate is valid.
        """
        if self.issuer_hash == self.subject_hash:
            return self.isIssuer(self)
        return False

    def encrypt(self, msg, t="pkcs", h="sha256", mgf=None, L=None):
        # no ECDSA *encryption* support, hence only RSA specific keywords here
        return self.pubkey.encrypt(msg, t=t, h=h, mgf=mgf, L=L)

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        return self.pubkey.verify(msg, sig, t=t, h=h, mgf=mgf, L=L)

    def getSignatureHash(self):
        """
        Return the hash cryptography object used by the 'signatureAlgorithm'
        """
        return _get_hash(_get_cert_sig_hashname(self))

    def setSubjectPublicKeyFromPrivateKey(self, key):
        """
        Replace the subjectPublicKeyInfo of this certificate with the one from
        the provided key.
        """
        if isinstance(key, (PubKey, PrivKey)):
            if isinstance(key, PrivKey):
                pubkey = key.pubkey
            else:
                pubkey = key
            self.tbsCertificate.subjectPublicKeyInfo = X509_SubjectPublicKeyInfo(
                pubkey.der
            )
        else:
            raise ValueError("Unknown type 'key', should be PubKey or PrivKey")

    def resignWith(self, key):
        """
        Resign a certificate with a specific key
        """
        self.import_from_asn1pkt(key.resignCert(self))

    def remainingDays(self, now=None):
        """
        Based on the value of notAfter field, returns the number of
        days the certificate will still be valid. The date used for the
        comparison is the current and local date, as returned by
        time.localtime(), except if 'now' argument is provided another
        one. 'now' argument can be given as either a time tuple or a string
        representing the date. Accepted format for the string version
        are:

         - '%b %d %H:%M:%S %Y %Z' e.g. 'Jan 30 07:38:59 2008 GMT'
         - '%m/%d/%y' e.g. '01/30/08' (less precise)

        If the certificate is no more valid at the date considered, then
        a negative value is returned representing the number of days
        since it has expired.

        The number of days is returned as a float to deal with the unlikely
        case of certificates that are still just valid.
        """
        if now is None:
            now = time.localtime()
        elif isinstance(now, str):
            try:
                if "/" in now:
                    now = time.strptime(now, "%m/%d/%y")
                else:
                    now = time.strptime(now, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                warning("Bad time string provided, will use localtime() instead.")
                now = time.localtime()

        now = time.mktime(now)
        nft = time.mktime(self.notAfter)
        diff = (nft - now) / (24.0 * 3600)
        return diff

    def isRevoked(self, crl_list):
        """
        Given a list of trusted CRL (their signature has already been
        verified with trusted anchors), this function returns True if
        the certificate is marked as revoked by one of those CRL.

        Note that if the Certificate was on hold in a previous CRL and
        is now valid again in a new CRL and bot are in the list, it
        will be considered revoked: this is because _all_ CRLs are
        checked (not only the freshest) and revocation status is not
        handled.

        Also note that the check on the issuer is performed on the
        Authority Key Identifier if available in _both_ the CRL and the
        Cert. Otherwise, the issuers are simply compared.
        """
        for c in crl_list:
            if (
                self.authorityKeyID is not None
                and c.authorityKeyID is not None
                and self.authorityKeyID == c.authorityKeyID
            ):
                return self.serial in (x[0] for x in c.revoked_cert_serials)
            elif self.issuer == c.issuer:
                return self.serial in (x[0] for x in c.revoked_cert_serials)
        return False

    @property
    def tbsCertificate(self):
        return self.x509Cert.tbsCertificate

    @property
    def pem(self):
        return der2pem(self.der, self.marker)

    @property
    def der(self):
        return bytes(self.x509Cert)

    @property
    def pubKey(self):
        warnings.warn(
            "Cert.pubKey is deprecated and will be removed in a future version. "
            "Use Cert.pubkey",
            DeprecationWarning,
        )
        return self.pubkey

    def __eq__(self, other):
        return self.der == other.der

    def __hash__(self):
        return hash(self.der)

    def export(self, filename, fmt=None):
        """
        Export certificate in 'fmt' format (DER or PEM) to file 'filename'
        """
        if fmt is None:
            if filename.endswith(".pem"):
                fmt = "PEM"
            else:
                fmt = "DER"
        with open(filename, "wb") as f:
            if fmt == "DER":
                return f.write(self.der)
            elif fmt == "PEM":
                return f.write(self.pem.encode())

    def show(self):
        print("Serial: %s" % self.serial)
        print("Issuer: " + self.issuer_str)
        print("Subject: " + self.subject_str)
        print("Validity: %s to %s" % (self.notBefore_str, self.notAfter_str))

    def __repr__(self):
        return "[X.509 Cert. Subject:%s, Issuer:%s]" % (
            self.subject_str,
            self.issuer_str,
        )


################################
# Certificate Revocation Lists #
################################


class _CRLMaker(_PKIObjMaker):
    """
    Metaclass for CRL creation. It is not necessary as it was for the keys,
    but we reuse the model instead of creating redundant constructors.
    """

    def __call__(cls, cert_path):
        obj = _PKIObjMaker.__call__(cls, cert_path, _MAX_CRL_SIZE, "X509 CRL")
        obj.__class__ = CRL
        try:
            crl = X509_CRL(obj._der)
        except Exception:
            raise Exception("Unable to import CRL")
        obj.import_from_asn1pkt(crl)
        return obj


class CRL(metaclass=_CRLMaker):
    """
    Wrapper for the X509_CRL from layers/x509.py.
    Use the 'x509CRL' attribute to access original object.
    """

    def import_from_asn1pkt(self, crl):
        error_msg = "Unable to import CRL"

        self.x509CRL = crl

        tbsCertList = crl.tbsCertList
        self.tbsCertList = bytes(tbsCertList)

        if tbsCertList.version:
            self.version = tbsCertList.version.val + 1
        else:
            self.version = 1
        self.sigAlg = tbsCertList.signature.algorithm.oidname
        self.issuer = tbsCertList.get_issuer()
        self.issuer_str = tbsCertList.get_issuer_str()
        self.issuer_hash = hash(self.issuer_str)

        self.lastUpdate_str = tbsCertList.this_update.pretty_time
        lastUpdate = tbsCertList.this_update.val
        if lastUpdate[-1] == "Z":
            lastUpdate = lastUpdate[:-1]
        try:
            self.lastUpdate = time.strptime(lastUpdate, "%y%m%d%H%M%S")
        except Exception:
            raise Exception(error_msg)
        self.lastUpdate_str_simple = time.strftime("%x", self.lastUpdate)

        self.nextUpdate = None
        self.nextUpdate_str_simple = None
        if tbsCertList.next_update:
            self.nextUpdate_str = tbsCertList.next_update.pretty_time
            nextUpdate = tbsCertList.next_update.val
            if nextUpdate[-1] == "Z":
                nextUpdate = nextUpdate[:-1]
            try:
                self.nextUpdate = time.strptime(nextUpdate, "%y%m%d%H%M%S")
            except Exception:
                raise Exception(error_msg)
            self.nextUpdate_str_simple = time.strftime("%x", self.nextUpdate)

        if tbsCertList.crlExtensions:
            for extension in tbsCertList.crlExtensions:
                if extension.extnID.oidname == "cRLNumber":
                    self.number = extension.extnValue.cRLNumber.val

        revoked = []
        if tbsCertList.revokedCertificates:
            for cert in tbsCertList.revokedCertificates:
                serial = cert.serialNumber.val
                date = cert.revocationDate.val
                if date[-1] == "Z":
                    date = date[:-1]
                try:
                    time.strptime(date, "%y%m%d%H%M%S")
                except Exception:
                    raise Exception(error_msg)
                revoked.append((serial, date))
        self.revoked_cert_serials = revoked

        self.signatureValue = bytes(crl.signatureValue)
        self.signatureLen = len(self.signatureValue)

    def isIssuer(self, other):
        # This is exactly the same thing as in Cert method.
        if self.issuer_hash != other.subject_hash:
            return False
        return other.pubkey.verifyCert(self)

    def verify(self, anchors):
        # Return True iff the CRL is signed by one of the provided anchors.
        return any(self.isIssuer(a) for a in anchors)

    def show(self):
        print("Version: %d" % self.version)
        print("sigAlg: " + self.sigAlg)
        print("Issuer: " + self.issuer_str)
        print("lastUpdate: %s" % self.lastUpdate_str)
        print("nextUpdate: %s" % self.nextUpdate_str)


###############################
# Certificate Signing Request #
###############################


class _CSRMaker(_PKIObjMaker):
    """
    Metaclass for CSR creation. It is not necessary as it was for the keys,
    but we reuse the model instead of creating redundant constructors.
    """

    def __call__(cls, cert_path):
        obj = _PKIObjMaker.__call__(cls, cert_path, _MAX_CSR_SIZE)
        obj.__class__ = CSR
        try:
            # PKCS#10 format
            csr = PKCS10_CertificationRequest(obj._der)
            obj.marker = "NEW CERTIFICATE REQUEST"
            obj.fmt = CSR.FORMAT.PKCS10
        except Exception:
            try:
                # CMC format
                csr = CMS_ContentInfo(obj._der)
                obj.marker = "NEW CERTIFICATE REQUEST"
                obj.fmt = CSR.FORMAT.CMC
            except Exception:
                raise Exception("Unable to import CSR")

        obj.import_from_asn1pkt(csr)
        return obj


class CSR(metaclass=_CSRMaker):
    """
    Wrapper for the CSR formats.
    This can handle both PKCS#10 and CMC formats.
    """

    class FORMAT(enum.Enum):
        """
        The format used by the CSR.
        """

        PKCS10 = "PKCS#10"
        CMC = "CMC"

    def import_from_asn1pkt(self, csr):
        self.csr = csr
        certReqInfo = self.certReq.certificationRequestInfo

        # Subject
        self.subject = certReqInfo.get_subject()
        self.subject_str = certReqInfo.get_subject_str()
        self.subject_hash = hash(self.subject_str)

        # pubkey
        self.pubkey = PubKey(bytes(certReqInfo.subjectPublicKeyInfo))

        # Get the "subjectKeyIdentifier" from the "extensionRequest" attribute
        try:
            extReq = next(
                x.values[0].value
                for x in certReqInfo.attributes
                if x.type.val == "1.2.840.113549.1.9.14"  # extKeyUsage
            )
            self.sid = next(
                x.extnValue.keyIdentifier
                for x in extReq.extensions
                if x.extnID.val == "2.5.29.14"  # subjectKeyIdentifier
            )
        except StopIteration:
            self.sid = None

    @property
    def certReq(self):
        csr = self.csr

        if self.fmt == CSR.FORMAT.PKCS10:
            return csr
        elif self.fmt == CSR.FORMAT.CMC:
            if (
                csr.contentType.oidname != "id-signedData"
                or csr.content.encapContentInfo.eContentType.oidname != "id-cct-PKIData"
            ):
                raise ValueError("Invalid CMC wrapping !")
            req = csr.content.encapContentInfo.eContent.reqSequence[0]
            return req.request.certificationRequest
        else:
            raise ValueError("Invalid CSR format !")

    @property
    def pem(self):
        return der2pem(self.der, self.marker)

    @property
    def der(self):
        return bytes(self.csr)

    def __eq__(self, other):
        return self.der == other.der

    def __hash__(self):
        return hash(self.der)

    def isIssuer(self, other):
        return other.sid == self.sid

    def isSelfSigned(self):
        return True

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        return self.pubkey.verify(msg, sig, t=t, h=h, mgf=mgf, L=L)

    def export(self, filename, fmt=None):
        """
        Export certificate in 'fmt' format (DER or PEM) to file 'filename'
        """
        if fmt is None:
            if filename.endswith(".pem"):
                fmt = "PEM"
            else:
                fmt = "DER"
        with open(filename, "wb") as f:
            if fmt == "DER":
                return f.write(self.der)
            elif fmt == "PEM":
                return f.write(self.pem.encode())

    def show(self):
        certReqInfo = self.certReq.certificationRequestInfo

        print("Subject: " + self.subject_str)
        print("Attributes:")
        for attr in certReqInfo.attributes:
            print("  - %s" % attr.type.oidname)

    def verifySelf(self) -> bool:
        """
        Verify the signatures of the CSR
        """
        if self.fmt == self.FORMAT.CMC:
            try:
                cms_engine = CMS_Engine([self])
                cms_engine.verify(self.csr)
                return self.pubkey.verifyCsr(self)
            except ValueError:
                return False
        elif self.fmt == self.FORMAT.PKCS10:
            return self.pubkey.verifyCsr(self)
        else:
            return False

    def __repr__(self):
        return "[CSR Format: %s, Subject:%s, Verified: %s]" % (
            self.fmt.value,
            self.subject_str,
            self.verifySelf(),
        )


####################
# Certificate list #
####################


class CertList(list):
    """
    An object that can store a list of Cert objects, load them and export them
    into DER/PEM format.
    """

    def __init__(
        self,
        certList: Union[Self, List[Cert], List[CSR], Cert, str],
    ):
        """
        Construct a list of certificates/CRLs to be used as list of ROOT certificates.
        """
        # Parse the certificate list / CA
        if isinstance(certList, str):
            # It's a path. First get the _PKIObj
            obj = _PKIObjMaker.__call__(
                CertList, certList, _MAX_CERT_SIZE, "CERTIFICATE"
            )

            # Then parse the der until there's nothing left
            certList = []
            payload = obj._der
            while payload:
                cert = X509_Cert(payload)
                if conf.raw_layer in cert.payload:
                    payload = cert.payload.load
                else:
                    payload = None
                cert.remove_payload()
                certList.append(Cert(cert))

            self.frmt = obj.frmt
        elif isinstance(certList, Cert):
            certList = [certList]
            self.frmt = "PEM"
        else:
            self.frmt = "PEM"

        super(CertList, self).__init__(certList)

    def findCertBySid(self, sid):
        """
        Find a certificate in the list by SubjectIDentifier.
        """
        for cert in self:
            if isinstance(cert, Cert) and isinstance(sid, CMS_IssuerAndSerialNumber):
                if cert.issuer == sid.get_issuer():
                    return cert
            elif isinstance(cert, CSR) and isinstance(sid, CMS_SubjectKeyIdentifier):
                if cert.sid == sid.sid:
                    return cert
        raise KeyError("Certificate not found !")

    def export(self, filename, fmt=None):
        """
        Export a list of certificates 'fmt' format (DER or PEM) to file 'filename'
        """
        if fmt is None:
            if filename.endswith(".pem"):
                fmt = "PEM"
            else:
                fmt = "DER"
        with open(filename, "wb") as f:
            if fmt == "DER":
                return f.write(self.der)
            elif fmt == "PEM":
                return f.write(self.pem.encode())

    @property
    def der(self):
        return b"".join(x.der for x in self)

    @property
    def pem(self):
        return "".join(x.pem for x in self)

    def __repr__(self):
        return "<CertList %s certificates>" % (len(self),)

    def show(self):
        for i, c in enumerate(self):
            print(conf.color_theme.id(i, fmt="%04i"), end=" ")
            print(repr(c))


######################
# Certificate chains #
######################


class CertTree(CertList):
    """
    An extension to CertList that additionally has a list of ROOT CAs
    that are trusted.

    Example::

        >>> tree = CertTree("ca_chain.pem")
        >>> tree.show()
        /CN=DOMAIN-DC1-CA/dc=DOMAIN [Self Signed]
            /CN=Administrator/dc=DOMAIN [Not Self Signed]
    """

    __slots__ = ["frmt", "rootCAs"]

    def __init__(
        self,
        certList: Union[List[Cert], CertList, str],
        rootCAs: Union[List[Cert], CertList, Cert, str, None] = None,
    ):
        """
        Construct a chain of certificates that follows issuer/subject matching and
        respects signature validity.

        Note that we do not check AKID/{SKID/issuer/serial} matching,
        nor the presence of keyCertSign in keyUsage extension (if present).

        :param certList: a list of Cert/CRL objects (or path to PEM/DER file containing
            multiple certs/CRL) to try to chain.
        :param rootCAs: (optional) a list of certificates to trust. If not provided,
            trusts any self-signed certificates from the certList.
        """
        # Parse the certificate list
        certList = CertList(certList)

        # Find the ROOT CAs if store isn't specified
        if not rootCAs:
            # Build cert store.
            self.rootCAs = CertList([x for x in certList if x.isSelfSigned()])
            # And remove those certs from the list
            for cert in self.rootCAs:
                certList.remove(cert)
        else:
            # Store cert store.
            self.rootCAs = CertList(rootCAs)
            # And remove those certs from the list if present (remove dups)
            for cert in self.rootCAs:
                if cert in certList:
                    certList.remove(cert)

        # Append our root CAs to the certList
        certList.extend(self.rootCAs)

        # Super instantiate
        super(CertTree, self).__init__(certList)

    @property
    def tree(self):
        """
        Get a tree-like object of the certificate list
        """
        # We store the tree object as a dictionary that contains children.
        tree = [(x, []) for x in self.rootCAs]

        # We'll empty this list eventually
        certList = list(self)

        # We make a list of certificates we have to search children for, and iterate
        # through it until it's empty.
        todo = list(tree)

        # Iterate
        while todo:
            cert, children = todo.pop()
            for c in certList:
                # Check if this certificate matches the one we're looking at
                if c.isIssuer(cert) and c != cert:
                    item = (c, [])
                    children.append(item)
                    certList.remove(c)
                    todo.append(item)

        return tree

    def getchain(self, cert):
        """
        Return a chain of certificate that points from a ROOT CA to a certificate.
        """

        def _rec_getchain(chain, curtree):
            # See if an element of the current tree signs the cert, if so add it to
            # the chain, else recurse.
            for c, subtree in curtree:
                curchain = chain + [c]
                # If 'cert' is issued by c
                if cert.isIssuer(c):
                    # Final node of the chain !
                    # (add the final cert if not self signed)
                    if c != cert:
                        curchain += [cert]
                    return curchain
                else:
                    # Not the final node of the chain ! Recurse.
                    curchain = _rec_getchain(curchain, subtree)
                    if curchain:
                        return curchain
            return None

        chain = _rec_getchain([], self.tree)
        if chain is not None:
            return CertTree(chain)
        else:
            return None

    def verify(self, cert):
        """
        Verify that a certificate is properly signed.
        """
        # Check that we can find a chain to this certificate
        if not self.getchain(cert):
            raise ValueError("Certificate verification failed !")

    def show(self, ret: bool = False):
        """
        Return the CertTree as a string certificate tree
        """

        def _rec_show(c, children, lvl=0):
            s = ""
            # Process the current CA
            if c:
                if not c.isSelfSigned():
                    s += "%s [Not Self Signed]\n" % c.subject_str
                else:
                    s += "%s [Self Signed]\n" % c.subject_str
                s = lvl * "  " + s
                lvl += 1
            # Process all sub-CAs at a lower level
            for child, subchildren in children:
                s += _rec_show(child, subchildren, lvl=lvl)
            return s

        showed = _rec_show(None, self.tree)
        if ret:
            return showed
        else:
            print(showed)

    def __repr__(self):
        return "<CertTree %s certificates (%s ROOT CA)>" % (
            len(self),
            len(self.rootCAs),
        )


#######
# CMS #
#######

# RFC3852


class CMS_Engine:
    """
    A utility class to perform CMS/PKCS7 operations, as specified by RFC3852.

    :param store: a ROOT CA certificate list to trust.
    :param crls: a list of CRLs to include. This is currently not checked.
    """

    def __init__(
        self,
        store: CertList,
        crls: List[X509_CRL] = [],
    ):
        self.store = store
        self.crls = crls

    def sign(
        self,
        message: Union[bytes, Packet],
        eContentType: ASN1_OID,
        cert: Cert,
        key: PrivKey,
        h: Optional[str] = None,
    ):
        """
        Sign a message using CMS.

        :param message: the inner content to sign.
        :param eContentType: the OID of the inner content.
        :param cert: the certificate whose key to use use for signing.
        :param key: the private key to use for signing.
        :param h: the hash to use (default: same as the certificate's signature)

        We currently only support X.509 certificates !
        """
        # RFC3852 - 5.4. Message Digest Calculation Process
        h = h or _get_cert_sig_hashname(cert)
        hash = hashes.Hash(_get_hash(h))
        hash.update(bytes(message))
        hashed_message = hash.finalize()

        # 5.5. Signature Generation Process
        signerInfo = CMS_SignerInfo(
            version=1,
            sid=CMS_IssuerAndSerialNumber(
                issuer=cert.tbsCertificate.issuer,
                serialNumber=cert.tbsCertificate.serialNumber,
            ),
            digestAlgorithm=X509_AlgorithmIdentifier(
                algorithm=ASN1_OID(h),
                parameters=ASN1_NULL(0),
            ),
            signedAttrs=[
                X509_Attribute(
                    type=ASN1_OID("contentType"),
                    values=[
                        X509_AttributeValue(value=eContentType),
                    ],
                ),
                X509_Attribute(
                    type=ASN1_OID("messageDigest"),
                    # "A message-digest attribute MUST have a single attribute value"
                    values=[
                        X509_AttributeValue(value=ASN1_STRING(hashed_message)),
                    ],
                ),
            ],
            signatureAlgorithm=cert.tbsCertificate.signature,
        )
        signerInfo.signature = ASN1_STRING(
            key.sign(
                bytes(
                    CMS_SignedAttrsForSignature(
                        signedAttrs=signerInfo.signedAttrs,
                    )
                ),
                h=h,
            )
        )

        # Build a chain of X509_Cert to ship (but skip the ROOT certificate)
        certTree = CertTree(cert, self.store)
        certificates = [x.x509Cert for x in certTree if not x.isSelfSigned()]

        # Build final structure
        return CMS_ContentInfo(
            contentType=ASN1_OID("id-signedData"),
            content=CMS_SignedData(
                version=3 if certificates else 1,
                digestAlgorithms=X509_AlgorithmIdentifier(
                    algorithm=ASN1_OID(h),
                    parameters=ASN1_NULL(0),
                ),
                encapContentInfo=CMS_EncapsulatedContentInfo(
                    eContentType=eContentType,
                    eContent=message,
                ),
                certificates=(
                    [CMS_CertificateChoices(certificate=cert) for cert in certificates]
                    if certificates
                    else None
                ),
                crls=(
                    [CMS_RevocationInfoChoice(crl=crl) for crl in self.crls]
                    if self.crls
                    else None
                ),
                signerInfos=[
                    signerInfo,
                ],
            ),
        )

    def verify(
        self,
        contentInfo: CMS_ContentInfo,
        eContentType: Optional[ASN1_OID] = None,
    ):
        """
        Verify a CMS message against the list of trusted certificates,
        and return the unpacked message if the verification succeeds.

        :param contentInfo: the ContentInfo whose signature to verify
        :param eContentType: if provided, verifies that the content type is valid
        """
        if contentInfo.contentType.oidname != "id-signedData":
            raise ValueError("ContentInfo isn't signed !")

        signeddata = contentInfo.content

        # Build the certificate chain
        certificates = []
        if signeddata.certificates:
            certificates = [Cert(x.certificate) for x in signeddata.certificates]
        certTree = CertTree(certificates, self.store)

        # Check there's at least one signature
        if not signeddata.signerInfos:
            raise ValueError("ContentInfo contained no signature !")

        # Check all signatures
        for signerInfo in signeddata.signerInfos:
            # Find certificate in the chain that did this
            cert: Cert = certTree.findCertBySid(signerInfo.sid)

            # Verify certificate signature
            certTree.verify(cert)

            # Verify the message hash
            if signerInfo.signedAttrs:
                # Verify the contentType
                try:
                    contentType = next(
                        x.values[0].value
                        for x in signerInfo.signedAttrs
                        if x.type.oidname == "contentType"
                    )

                    if contentType != signeddata.encapContentInfo.eContentType:
                        raise ValueError(
                            "Inconsistent 'contentType' was detected in packet !"
                        )

                    if eContentType is not None and eContentType != contentType:
                        raise ValueError(
                            "Expected '%s' but got '%s' contentType !"
                            % (
                                eContentType,
                                contentType,
                            )
                        )
                except StopIteration:
                    raise ValueError("Missing contentType in signedAttrs !")

                # Verify the messageDigest value
                try:
                    # "A message-digest attribute MUST have a single attribute value"
                    messageDigest = next(
                        x.values[0].value
                        for x in signerInfo.signedAttrs
                        if x.type.oidname == "messageDigest"
                    )

                    # Re-calculate hash
                    h = signerInfo.digestAlgorithm.algorithm.oidname
                    hash = hashes.Hash(_get_hash(h))
                    hash.update(bytes(signeddata.encapContentInfo.eContent))
                    hashed_message = hash.finalize()

                    if hashed_message != messageDigest:
                        raise ValueError("Invalid messageDigest value !")
                except StopIteration:
                    raise ValueError("Missing messageDigest in signedAttrs !")

                # Verify the signature
                cert.verify(
                    msg=bytes(
                        CMS_SignedAttrsForSignature(
                            signedAttrs=signerInfo.signedAttrs,
                        )
                    ),
                    sig=signerInfo.signature.val,
                )
            else:
                cert.verify(
                    msg=bytes(signeddata.encapContentInfo),
                    sig=signerInfo.signature.val,
                )

        # Return the content
        return signeddata.encapContentInfo.eContent
