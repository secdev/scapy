# This file is part of Scapy
# Copyright (C) 2008 Arnaud Ebalard <arnaud.ebalard@eads.net>
#                                   <arno@natisbad.org>
#   2015, 2016, 2017 Maxence Tury   <maxence.tury@ssi.gouv.fr>
# This program is published under a GPLv2 license

"""
High-level methods for PKI objects (X.509 certificates, CRLs, asymmetric keys).
Supports both RSA and ECDSA objects.

The classes below are wrappers for the ASN.1 objects defined in x509.py.
By collecting their attributes, we bypass the ASN.1 structure, hence
there is no direct method for exporting a new full DER-encoded version
of a Cert instance after its serial has been modified (for example).
If you need to modify an import, just use the corresponding ASN1_Packet.

For instance, here is what you could do in order to modify the serial of
'cert' and then resign it with whatever 'key':
    f = open('cert.der')
    c = X509_Cert(f.read())
    c.tbsCertificate.serialNumber = 0x4B1D
    k = PrivKey('key.pem')
    new_x509_cert = k.resignCert(c)
No need for obnoxious openssl tweaking anymore. :)
"""

from __future__ import absolute_import
from __future__ import print_function
import base64
import os
import time

from scapy.config import conf, crypto_validator
import scapy.modules.six as six
from scapy.modules.six.moves import range
from scapy.error import warning
from scapy.utils import binrepr
from scapy.asn1.asn1 import ASN1_BIT_STRING
from scapy.asn1.mib import hash_by_oid
from scapy.layers.x509 import (X509_SubjectPublicKeyInfo,
                               RSAPublicKey, RSAPrivateKey,
                               ECDSAPublicKey, ECDSAPrivateKey,
                               RSAPrivateKey_OpenSSL, ECDSAPrivateKey_OpenSSL,
                               X509_Cert, X509_CRL)
from scapy.layers.tls.crypto.pkcs1 import pkcs_os2ip, _get_hash, \
    _EncryptAndVerifyRSA, _DecryptAndSignRSA
from scapy.compat import raw, bytes_encode
if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
if conf.crypto_valid_recent:
    from cryptography.hazmat.backends.openssl.ec import InvalidSignature


# Maximum allowed size in bytes for a certificate file, to avoid
# loading huge file when importing a cert
_MAX_KEY_SIZE = 50 * 1024
_MAX_CERT_SIZE = 50 * 1024
_MAX_CRL_SIZE = 10 * 1024 * 1024   # some are that big


#####################################################################
# Some helpers
#####################################################################

@conf.commands.register
def der2pem(der_string, obj="UNKNOWN"):
    """Convert DER octet string to PEM format (with optional header)"""
    # Encode a byte string in PEM format. Header advertizes <obj> type.
    pem_string = ("-----BEGIN %s-----\n" % obj).encode()
    base64_string = base64.b64encode(der_string)
    chunks = [base64_string[i:i + 64] for i in range(0, len(base64_string), 64)]  # noqa: E501
    pem_string += b'\n'.join(chunks)
    pem_string += ("\n-----END %s-----\n" % obj).encode()
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
        end_idx = s.find(b"\n", end_idx) + 1
        pem_strings.append(s[start_idx:end_idx])
        s = s[end_idx:]
    return pem_strings


class _PKIObj(object):
    def __init__(self, frmt, der, pem):
        # Note that changing attributes of the _PKIObj does not update these
        # values (e.g. modifying k.modulus does not change k.der).
        # XXX use __setattr__ for this
        self.frmt = frmt
        self.der = der
        self.pem = pem

    def __str__(self):
        return self.der


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

        if (b'\x00' not in obj_path) and os.path.isfile(obj_path):
            _size = os.path.getsize(obj_path)
            if _size > obj_max_size:
                raise Exception(error_msg)
            try:
                f = open(obj_path, "rb")
                _raw = f.read()
                f.close()
            except Exception:
                raise Exception(error_msg)
        else:
            _raw = obj_path

        try:
            if b"-----BEGIN" in _raw:
                frmt = "PEM"
                pem = _raw
                der_list = split_pem(_raw)
                der = b''.join(map(pem2der, der_list))
            else:
                frmt = "DER"
                der = _raw
                pem = ""
                if pem_marker is not None:
                    pem = der2pem(_raw, pem_marker)
                # type identification may be needed for pem_marker
                # in such case, the pem attribute has to be updated
        except Exception:
            raise Exception(error_msg)

        p = _PKIObj(frmt, der, pem)
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
    def __call__(cls, key_path=None):

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
        # _an ECDSAPublicKey.
        obj = _PKIObjMaker.__call__(cls, key_path, _MAX_KEY_SIZE)
        try:
            spki = X509_SubjectPublicKeyInfo(obj.der)
            pubkey = spki.subjectPublicKey
            if isinstance(pubkey, RSAPublicKey):
                obj.__class__ = PubKeyRSA
                obj.import_from_asn1pkt(pubkey)
            elif isinstance(pubkey, ECDSAPublicKey):
                obj.__class__ = PubKeyECDSA
                try:
                    obj.import_from_der(obj.der)
                except ImportError:
                    pass
            else:
                raise
            marker = b"PUBLIC KEY"
        except Exception:
            try:
                pubkey = RSAPublicKey(obj.der)
                obj.__class__ = PubKeyRSA
                obj.import_from_asn1pkt(pubkey)
                marker = b"RSA PUBLIC KEY"
            except Exception:
                # We cannot import an ECDSA public key without curve knowledge
                raise Exception("Unable to import public key")

        if obj.frmt == "DER":
            obj.pem = der2pem(obj.der, marker)
        return obj


class PubKey(six.with_metaclass(_PubKeyFactory, object)):
    """
    Parent class for both PubKeyRSA and PubKeyECDSA.
    Provides a common verifyCert() method.
    """

    def verifyCert(self, cert):
        """ Verifies either a Cert or an X509_Cert. """
        tbsCert = cert.tbsCertificate
        sigAlg = tbsCert.signature
        h = hash_by_oid[sigAlg.algorithm.val]
        sigVal = raw(cert.signatureValue)
        return self.verify(raw(tbsCert), sigVal, h=h, t='pkcs')


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
            private_key = rsa.generate_private_key(public_exponent=pubExp,
                                                   key_size=real_modulusLen,
                                                   backend=default_backend())
            self.pubkey = private_key.public_key()
        else:
            real_modulusLen = len(binrepr(modulus))
            if modulusLen and real_modulusLen != modulusLen:
                warning("modulus and modulusLen do not match!")
            pubNum = rsa.RSAPublicNumbers(n=modulus, e=pubExp)
            self.pubkey = pubNum.public_key(default_backend())
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
        self.pem = self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.der = pem2der(self.pem)

    def import_from_asn1pkt(self, pubkey):
        modulus = pubkey.modulus.val
        pubExp = pubkey.publicExponent.val
        self.fill_and_store(modulus=modulus, pubExp=pubExp)

    def encrypt(self, msg, t="pkcs", h="sha256", mgf=None, L=None):
        # no ECDSA encryption support, hence no ECDSA specific keywords here
        return _EncryptAndVerifyRSA.encrypt(self, msg, t=t, h=h, mgf=mgf, L=L)

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        return _EncryptAndVerifyRSA.verify(
            self, msg, sig, t=t, h=h, mgf=mgf, L=L)


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
        self.pubkey = serialization.load_der_public_key(pubkey,
                                                        backend=default_backend())  # noqa: E501

    def encrypt(self, msg, h="sha256", **kwargs):
        # cryptography lib does not support ECDSA encryption
        raise Exception("No ECDSA encryption support")

    @crypto_validator
    def verify(self, msg, sig, h="sha256", **kwargs):
        # 'sig' should be a DER-encoded signature, as per RFC 3279
        if conf.crypto_valid_recent:
            try:
                self.pubkey.verify(sig, msg, ec.ECDSA(_get_hash(h)))
                return True
            except InvalidSignature:
                return False
        else:
            verifier = self.pubkey.verifier(sig, ec.ECDSA(_get_hash(h)))
            verifier.update(msg)
            return verifier.verify()


################
# Private Keys #
################

class _PrivKeyFactory(_PKIObjMaker):
    """
    Metaclass for PrivKey creation.
    It casts the appropriate class on the fly, then fills in
    the appropriate attributes with import_from_asn1pkt() submethod.
    """
    def __call__(cls, key_path=None):
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

        obj = _PKIObjMaker.__call__(cls, key_path, _MAX_KEY_SIZE)
        multiPEM = False
        try:
            privkey = RSAPrivateKey_OpenSSL(obj.der)
            privkey = privkey.privateKey
            obj.__class__ = PrivKeyRSA
            marker = b"PRIVATE KEY"
        except Exception:
            try:
                privkey = ECDSAPrivateKey_OpenSSL(obj.der)
                privkey = privkey.privateKey
                obj.__class__ = PrivKeyECDSA
                marker = b"EC PRIVATE KEY"
                multiPEM = True
            except Exception:
                try:
                    privkey = RSAPrivateKey(obj.der)
                    obj.__class__ = PrivKeyRSA
                    marker = b"RSA PRIVATE KEY"
                except Exception:
                    try:
                        privkey = ECDSAPrivateKey(obj.der)
                        obj.__class__ = PrivKeyECDSA
                        marker = b"EC PRIVATE KEY"
                    except Exception:
                        raise Exception("Unable to import private key")
        try:
            obj.import_from_asn1pkt(privkey)
        except ImportError:
            pass

        if obj.frmt == "DER":
            if multiPEM:
                # this does not restore the EC PARAMETERS header
                obj.pem = der2pem(raw(privkey), marker)
            else:
                obj.pem = der2pem(obj.der, marker)
        return obj


class _Raw_ASN1_BIT_STRING(ASN1_BIT_STRING):
    """A ASN1_BIT_STRING that ignores BER encoding"""
    def __bytes__(self):
        return self.val_readable
    __str__ = __bytes__


class PrivKey(six.with_metaclass(_PrivKeyFactory, object)):
    """
    Parent class for both PrivKeyRSA and PrivKeyECDSA.
    Provides common signTBSCert() and resignCert() methods.
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
        sigVal = self.sign(raw(tbsCert), h=h, t='pkcs')
        c = X509_Cert()
        c.tbsCertificate = tbsCert
        c.signatureAlgorithm = sigAlg
        c.signatureValue = _Raw_ASN1_BIT_STRING(sigVal, readable=True)
        return c

    def resignCert(self, cert):
        """ Rewrite the signature of either a Cert or an X509_Cert. """
        return self.signTBSCert(cert.tbsCertificate)

    def verifyCert(self, cert):
        """ Verifies either a Cert or an X509_Cert. """
        tbsCert = cert.tbsCertificate
        sigAlg = tbsCert.signature
        h = hash_by_oid[sigAlg.algorithm.val]
        sigVal = raw(cert.signatureValue)
        return self.verify(raw(tbsCert), sigVal, h=h, t='pkcs')


class PrivKeyRSA(PrivKey, _EncryptAndVerifyRSA, _DecryptAndSignRSA):
    """
    Wrapper for RSA keys based on _DecryptAndSignRSA from crypto/pkcs1.py
    Use the 'key' attribute to access original object.
    """
    @crypto_validator
    def fill_and_store(self, modulus=None, modulusLen=None, pubExp=None,
                       prime1=None, prime2=None, coefficient=None,
                       exponent1=None, exponent2=None, privExp=None):
        pubExp = pubExp or 65537
        if None in [modulus, prime1, prime2, coefficient, privExp,
                    exponent1, exponent2]:
            # note that the library requires every parameter
            # in order to call RSAPrivateNumbers(...)
            # if one of these is missing, we generate a whole new key
            real_modulusLen = modulusLen or 2048
            self.key = rsa.generate_private_key(public_exponent=pubExp,
                                                key_size=real_modulusLen,
                                                backend=default_backend())
            self.pubkey = self.key.public_key()
        else:
            real_modulusLen = len(binrepr(modulus))
            if modulusLen and real_modulusLen != modulusLen:
                warning("modulus and modulusLen do not match!")
            pubNum = rsa.RSAPublicNumbers(n=modulus, e=pubExp)
            privNum = rsa.RSAPrivateNumbers(p=prime1, q=prime2,
                                            dmp1=exponent1, dmq1=exponent2,
                                            iqmp=coefficient, d=privExp,
                                            public_numbers=pubNum)
            self.key = privNum.private_key(default_backend())
            self.pubkey = self.key.public_key()

        # Lines below are only useful for the legacy part of pkcs1.py
        pubNum = self.pubkey.public_numbers()
        self._modulusLen = real_modulusLen
        self._modulus = pubNum.n
        self._pubExp = pubNum.e

    def import_from_asn1pkt(self, privkey):
        modulus = privkey.modulus.val
        pubExp = privkey.publicExponent.val
        privExp = privkey.privateExponent.val
        prime1 = privkey.prime1.val
        prime2 = privkey.prime2.val
        exponent1 = privkey.exponent1.val
        exponent2 = privkey.exponent2.val
        coefficient = privkey.coefficient.val
        self.fill_and_store(modulus=modulus, pubExp=pubExp,
                            privExp=privExp, prime1=prime1, prime2=prime2,
                            exponent1=exponent1, exponent2=exponent2,
                            coefficient=coefficient)

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        # Let's copy this from PubKeyRSA instead of adding another baseclass :)
        return _EncryptAndVerifyRSA.verify(
            self, msg, sig, t=t, h=h, mgf=mgf, L=L)

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
        self.pubkey = self.key.public_key()

    @crypto_validator
    def import_from_asn1pkt(self, privkey):
        self.key = serialization.load_der_private_key(raw(privkey), None,
                                                      backend=default_backend())  # noqa: E501
        self.pubkey = self.key.public_key()

    @crypto_validator
    def verify(self, msg, sig, h="sha256", **kwargs):
        # 'sig' should be a DER-encoded signature, as per RFC 3279
        if conf.crypto_valid_recent:
            try:
                self.pubkey.verify(sig, msg, ec.ECDSA(_get_hash(h)))
                return True
            except InvalidSignature:
                return False
        else:
            verifier = self.pubkey.verifier(sig, ec.ECDSA(_get_hash(h)))
            verifier.update(msg)
            return verifier.verify()

    @crypto_validator
    def sign(self, data, h="sha256", **kwargs):
        if conf.crypto_valid_recent:
            return self.key.sign(data, ec.ECDSA(_get_hash(h)))
        else:
            signer = self.key.signer(ec.ECDSA(_get_hash(h)))
            signer.update(data)
            return signer.finalize()


################
# Certificates #
################

class _CertMaker(_PKIObjMaker):
    """
    Metaclass for Cert creation. It is not necessary as it was for the keys,
    but we reuse the model instead of creating redundant constructors.
    """
    def __call__(cls, cert_path):
        obj = _PKIObjMaker.__call__(cls, cert_path,
                                    _MAX_CERT_SIZE, "CERTIFICATE")
        obj.__class__ = Cert
        try:
            cert = X509_Cert(obj.der)
        except Exception:
            raise Exception("Unable to import certificate")
        obj.import_from_asn1pkt(cert)
        return obj


class Cert(six.with_metaclass(_CertMaker, object)):
    """
    Wrapper for the X509_Cert from layers/x509.py.
    Use the 'x509Cert' attribute to access original object.
    """

    def import_from_asn1pkt(self, cert):
        error_msg = "Unable to import certificate"

        self.x509Cert = cert

        tbsCert = cert.tbsCertificate
        self.tbsCertificate = tbsCert

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
        notBefore = tbsCert.validity.not_before.val
        if notBefore[-1] == "Z":
            notBefore = notBefore[:-1]
        try:
            _format = tbsCert.validity.not_before._format
            self.notBefore = time.strptime(notBefore, _format)
        except Exception:
            raise Exception(error_msg)
        self.notBefore_str_simple = time.strftime("%x", self.notBefore)

        self.notAfter_str = tbsCert.validity.not_after.pretty_time
        notAfter = tbsCert.validity.not_after.val
        if notAfter[-1] == "Z":
            notAfter = notAfter[:-1]
        try:
            _format = tbsCert.validity.not_after._format
            self.notAfter = time.strptime(notAfter, _format)
        except Exception:
            raise Exception(error_msg)
        self.notAfter_str_simple = time.strftime("%x", self.notAfter)

        self.pubKey = PubKey(raw(tbsCert.subjectPublicKeyInfo))

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

        self.signatureValue = raw(cert.signatureValue)
        self.signatureLen = len(self.signatureValue)

    def isIssuerCert(self, other):
        """
        True if 'other' issued 'self', i.e.:
          - self.issuer == other.subject
          - self is signed by other
        """
        if self.issuer_hash != other.subject_hash:
            return False
        return other.pubKey.verifyCert(self)

    def isSelfSigned(self):
        """
        Return True if the certificate is self-signed:
          - issuer and subject are the same
          - the signature of the certificate is valid.
        """
        if self.issuer_hash == self.subject_hash:
            return self.isIssuerCert(self)
        return False

    def encrypt(self, msg, t="pkcs", h="sha256", mgf=None, L=None):
        # no ECDSA *encryption* support, hence only RSA specific keywords here
        return self.pubKey.encrypt(msg, t=t, h=h, mgf=mgf, L=L)

    def verify(self, msg, sig, t="pkcs", h="sha256", mgf=None, L=None):
        return self.pubKey.verify(msg, sig, t=t, h=h, mgf=mgf, L=L)

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
                if '/' in now:
                    now = time.strptime(now, '%m/%d/%y')
                else:
                    now = time.strptime(now, '%b %d %H:%M:%S %Y %Z')
            except Exception:
                warning("Bad time string provided, will use localtime() instead.")  # noqa: E501
                now = time.localtime()

        now = time.mktime(now)
        nft = time.mktime(self.notAfter)
        diff = (nft - now) / (24. * 3600)
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
            if (self.authorityKeyID is not None and
                c.authorityKeyID is not None and
                    self.authorityKeyID == c.authorityKeyID):
                return self.serial in (x[0] for x in c.revoked_cert_serials)
            elif self.issuer == c.issuer:
                return self.serial in (x[0] for x in c.revoked_cert_serials)
        return False

    def export(self, filename, fmt="DER"):
        """
        Export certificate in 'fmt' format (DER or PEM) to file 'filename'
        """
        f = open(filename, "wb")
        if fmt == "DER":
            f.write(self.der)
        elif fmt == "PEM":
            f.write(self.pem)
        f.close()

    def show(self):
        print("Serial: %s" % self.serial)
        print("Issuer: " + self.issuer_str)
        print("Subject: " + self.subject_str)
        print("Validity: %s to %s" % (self.notBefore_str, self.notAfter_str))

    def __repr__(self):
        return "[X.509 Cert. Subject:%s, Issuer:%s]" % (self.subject_str, self.issuer_str)  # noqa: E501


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
            crl = X509_CRL(obj.der)
        except Exception:
            raise Exception("Unable to import CRL")
        obj.import_from_asn1pkt(crl)
        return obj


class CRL(six.with_metaclass(_CRLMaker, object)):
    """
    Wrapper for the X509_CRL from layers/x509.py.
    Use the 'x509CRL' attribute to access original object.
    """

    def import_from_asn1pkt(self, crl):
        error_msg = "Unable to import CRL"

        self.x509CRL = crl

        tbsCertList = crl.tbsCertList
        self.tbsCertList = raw(tbsCertList)

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

        self.signatureValue = raw(crl.signatureValue)
        self.signatureLen = len(self.signatureValue)

    def isIssuerCert(self, other):
        # This is exactly the same thing as in Cert method.
        if self.issuer_hash != other.subject_hash:
            return False
        return other.pubKey.verifyCert(self)

    def verify(self, anchors):
        # Return True iff the CRL is signed by one of the provided anchors.
        return any(self.isIssuerCert(a) for a in anchors)

    def show(self):
        print("Version: %d" % self.version)
        print("sigAlg: " + self.sigAlg)
        print("Issuer: " + self.issuer_str)
        print("lastUpdate: %s" % self.lastUpdate_str)
        print("nextUpdate: %s" % self.nextUpdate_str)


######################
# Certificate chains #
######################

class Chain(list):
    """
    Basically, an enhanced array of Cert.
    """

    def __init__(self, certList, cert0=None):
        """
        Construct a chain of certificates starting with a self-signed
        certificate (or any certificate submitted by the user)
        and following issuer/subject matching and signature validity.
        If there is exactly one chain to be constructed, it will be,
        but if there are multiple potential chains, there is no guarantee
        that the retained one will be the longest one.
        As Cert and CRL classes both share an isIssuerCert() method,
        the trailing element of a Chain may alternatively be a CRL.

        Note that we do not check AKID/{SKID/issuer/serial} matching,
        nor the presence of keyCertSign in keyUsage extension (if present).
        """
        list.__init__(self, ())
        if cert0:
            self.append(cert0)
        else:
            for root_candidate in certList:
                if root_candidate.isSelfSigned():
                    self.append(root_candidate)
                    certList.remove(root_candidate)
                    break

        if len(self) > 0:
            while certList:
                tmp_len = len(self)
                for c in certList:
                    if c.isIssuerCert(self[-1]):
                        self.append(c)
                        certList.remove(c)
                        break
                if len(self) == tmp_len:
                    # no new certificate appended to self
                    break

    def verifyChain(self, anchors, untrusted=None):
        """
        Perform verification of certificate chains for that certificate.
        A list of anchors is required. The certificates in the optional
        untrusted list may be used as additional elements to the final chain.
        On par with chain instantiation, only one chain constructed with the
        untrusted candidates will be retained. Eventually, dates are checked.
        """
        untrusted = untrusted or []
        for a in anchors:
            chain = Chain(self + untrusted, a)
            if len(chain) == 1:             # anchor only
                continue
            # check that the chain does not exclusively rely on untrusted
            if any(c in chain[1:] for c in self):
                for c in chain:
                    if c.remainingDays() < 0:
                        break
                if c is chain[-1]:      # we got to the end of the chain
                    return chain
        return None

    def verifyChainFromCAFile(self, cafile, untrusted_file=None):
        """
        Does the same job as .verifyChain() but using the list of anchors
        from the cafile. As for .verifyChain(), a list of untrusted
        certificates can be passed (as a file, this time).
        """
        try:
            f = open(cafile, "rb")
            ca_certs = f.read()
            f.close()
        except Exception:
            raise Exception("Could not read from cafile")

        anchors = [Cert(c) for c in split_pem(ca_certs)]

        untrusted = None
        if untrusted_file:
            try:
                f = open(untrusted_file, "rb")
                untrusted_certs = f.read()
                f.close()
            except Exception:
                raise Exception("Could not read from untrusted_file")
            untrusted = [Cert(c) for c in split_pem(untrusted_certs)]

        return self.verifyChain(anchors, untrusted)

    def verifyChainFromCAPath(self, capath, untrusted_file=None):
        """
        Does the same job as .verifyChainFromCAFile() but using the list
        of anchors in capath directory. The directory should (only) contain
        certificates files in PEM format. As for .verifyChainFromCAFile(),
        a list of untrusted certificates can be passed as a file
        (concatenation of the certificates in PEM format).
        """
        try:
            anchors = []
            for cafile in os.listdir(capath):
                anchors.append(Cert(open(os.path.join(capath, cafile), "rb").read()))  # noqa: E501
        except Exception:
            raise Exception("capath provided is not a valid cert path")

        untrusted = None
        if untrusted_file:
            try:
                f = open(untrusted_file, "rb")
                untrusted_certs = f.read()
                f.close()
            except Exception:
                raise Exception("Could not read from untrusted_file")
            untrusted = [Cert(c) for c in split_pem(untrusted_certs)]

        return self.verifyChain(anchors, untrusted)

    def __repr__(self):
        llen = len(self) - 1
        if llen < 0:
            return ""
        c = self[0]
        s = "__ "
        if not c.isSelfSigned():
            s += "%s [Not Self Signed]\n" % c.subject_str
        else:
            s += "%s [Self Signed]\n" % c.subject_str
        idx = 1
        while idx <= llen:
            c = self[idx]
            s += "%s_ %s" % (" " * idx * 2, c.subject_str)
            if idx != llen:
                s += "\n"
            idx += 1
        return s
