## This file is part of Scapy
## Copyright (C) 2008 Arnaud Ebalard <arnaud.ebalard@eads.net>
##                                   <arno@natisbad.org>
##         2015, 2016 Maxence Tury   <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
High-level methods for PKI objects (X.509 certificates, CRLs, asymmetric keys).
Supports both RSA and ECDSA objects.
"""

## This module relies on python-crypto and python-ecdsa.
##
## The classes below are wrappers for the ASN.1 objects defined in x509.py.
## By collecting their attributes, we bypass the ASN.1 structure, hence
## there is no direct method for exporting a new full DER-encoded version
## of a Cert instance after its serial has been modified (for example).
## If you need to modify an import, just use the corresponding ASN1_Packet.
##
## For instance, here is what you could do in order to modify the serial of
## 'cert' and then resign it with whatever 'key':
##     f = open('cert.der')
##     c = X509_Cert(f.read())
##     c.tbsCertificate.serialNumber = 0x4B1D
##     k = PrivKey('key.pem')
##     new_x509_cert = k.resignCert(c)
## No need for obnoxious openssl tweaking anymore. :)

import base64, os, time

import ecdsa
from Crypto.PublicKey import RSA

from scapy.layers.tls.crypto.curves import import_curve
from scapy.layers.tls.crypto.pkcs1 import pkcs_os2ip, pkcs_i2osp, mapHashFunc
from scapy.layers.tls.crypto.pkcs1 import _EncryptAndVerifyRSA
from scapy.layers.tls.crypto.pkcs1 import _DecryptAndSignRSA

from scapy.asn1.asn1 import ASN1_BIT_STRING
from scapy.asn1.mib import hash_by_oid
from scapy.layers.x509 import X509_SubjectPublicKeyInfo
from scapy.layers.x509 import RSAPublicKey, RSAPrivateKey
from scapy.layers.x509 import ECDSAPublicKey, ECDSAPrivateKey
from scapy.layers.x509 import RSAPrivateKey_OpenSSL, ECDSAPrivateKey_OpenSSL
from scapy.layers.x509 import X509_Cert, X509_CRL
from scapy.utils import binrepr

# Maximum allowed size in bytes for a certificate file, to avoid
# loading huge file when importing a cert
MAX_KEY_SIZE = 50*1024
MAX_CERT_SIZE = 50*1024
MAX_CRL_SIZE = 10*1024*1024   # some are that big


#####################################################################
# Some helpers
#####################################################################

def der2pem(der_string, obj="UNKNOWN"):
    """
    Encode a byte string in PEM format. Header advertizes <obj> type.
    """
    pem_string = "-----BEGIN %s-----\n" % obj
    base64_string = base64.b64encode(der_string)
    chunks = [base64_string[i:i+64] for i in range(0, len(base64_string), 64)]
    pem_string += '\n'.join(chunks)
    pem_string += "\n-----END %s-----\n" % obj
    return pem_string

def pem2der(pem_string):
    """
    Encode every line between the first '-----\n' and the 2nd-to-last '-----'.
    """
    pem_string = pem_string.replace("\r", "")
    first_idx = pem_string.find("-----\n") + 6
    if pem_string.find("-----BEGIN", first_idx) != -1:
        raise Exception("pem2der() expects only one PEM-encoded object")
    last_idx = pem_string.rfind("-----", 0, pem_string.rfind("-----"))
    base64_string = pem_string[first_idx:last_idx]
    base64_string.replace("\n", "")
    der_string = base64.b64decode(base64_string)
    return der_string

def split_pem(s):
    """
    Split PEM objects. Useful to process concatenated certificates.
    """
    pem_strings = []
    while s != "":
        start_idx = s.find("-----BEGIN")
        if start_idx == -1:
            break
        end_idx = s.find("-----END")
        end_idx = s.find("\n", end_idx) + 1
        pem_strings.append(s[start_idx:end_idx])
        s = s[end_idx:]
    return pem_strings


class _PKIObj(object):
    def __init__(self, frmt, der, pem):
        # Note that changing attributes of the _PKIObj does not update these
        # values (e.g. modifying k.modulus does not change k.der).
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

        if (not '\x00' in obj_path) and os.path.isfile(obj_path):
            _size = os.path.getsize(obj_path)
            if _size > obj_max_size:
                raise Exception(error_msg)
            try:
                f = open(obj_path)
                raw = f.read()
                f.close()
            except:
                raise Exception(error_msg)
        else:
            raw = obj_path

        try:
            if "-----BEGIN" in raw:
                frmt = "PEM"
                pem = raw
                der_list = split_pem(raw)
                der = ''.join(map(pem2der, der_list))
            else:
                frmt = "DER"
                der = raw
                pem = ""
                if pem_marker is not None:
                    pem = der2pem(raw, pem_marker)
                # type identification may be needed for pem_marker
                # in such case, the pem attribute has to be updated
        except:
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
    the appropriate attributes with updateWith() submethod.
    """
    def __call__(cls, key_path):

        # First, we deal with the exceptional RSA KEA call.
        if type(key_path) is tuple:
            e, m, mLen = key_path
            obj = type.__call__(cls)
            obj.frmt = "tuple"
            obj.modulus = m
            obj.modulusLen = mLen
            obj.pubExp = e
            return obj

        # Now for the usual calls, key_path may be the path to either:
        # _an X509_SubjectPublicKeyInfo, as processed by openssl;
        # _an RSAPublicKey;
        # _an ECDSAPublicKey.
        obj = _PKIObjMaker.__call__(cls, key_path, MAX_KEY_SIZE)
        try:
            spki = X509_SubjectPublicKeyInfo(obj.der)
            pubkey = spki.subjectPublicKey
            if isinstance(pubkey, RSAPublicKey):
                obj.__class__ = PubKeyRSA
                obj.updateWith(pubkey)
            elif isinstance(pubkey, ECDSAPublicKey):
                obj.__class__ = PubKeyECDSA
                obj.updateWith(spki)
            else:
                raise Exception("Unsupported publicKey type")
            marker = "PUBLIC KEY"
        except:
            try:
                pubkey = RSAPublicKey(obj.der)
                obj.__class__ = PubKeyRSA
                obj.updateWith(pubkey)
                marker = "RSA PUBLIC KEY"
            except:
                # We cannot import an ECDSA public key without curve knowledge
                raise Exception("Unable to import public key")

        if obj.frmt == "DER":
            obj.pem = der2pem(obj.der, marker)
        return obj


class PubKey(object):
    """
    Parent class for both PubKeyRSA and PubKeyECDSA.
    Provides a common verifyCert() method.
    """
    __metaclass__ = _PubKeyFactory

    def verifyCert(self, cert):
        """
        Verifies either a Cert or an X509_Cert.
        """
        tbsCert = cert.tbsCertificate
        sigAlg = tbsCert.signature
        h = hash_by_oid[sigAlg.algorithm.val]
        sigVal = str(cert.signatureValue)
        return self.verify(str(tbsCert), sigVal, h=h,
                           t='pkcs',
                           sigdecode=ecdsa.util.sigdecode_der)


class PubKeyRSA(_PKIObj, PubKey, _EncryptAndVerifyRSA):
    """
    Wrapper for RSA keys based on _EncryptAndVerifyRSA from crypto/pkcs1.py
    Use the 'key' attribute to access original object.
    """
    def updateWith(self, pubkey):
        self.modulus    = pubkey.modulus.val
        self.modulusLen = len(binrepr(pubkey.modulus.val))
        self.pubExp     = pubkey.publicExponent.val
        self.key = RSA.construct((self.modulus, self.pubExp, ))
    def encrypt(self, msg, t=None, h=None, mgf=None, L=None):
        # no ECDSA encryption support, hence no ECDSA specific keywords here
        return _EncryptAndVerifyRSA.encrypt(self, msg, t=t, h=h, mgf=mgf, L=L)
    def verify(self, msg, sig, h=None,
               t=None, mgf=None, sLen=None,
               sigdecode=None):
        return _EncryptAndVerifyRSA.verify(self, msg, sig, h=h,
                                           t=t, mgf=mgf, sLen=sLen)


class PubKeyECDSA(_PKIObj, PubKey):
    """
    Wrapper for ECDSA keys based on VerifyingKey from ecdsa library.
    Use the 'key' attribute to access original object.
    """
    def updateWith(self, spki):
        # For now we use from_der() or from_string() methods,
        # which do not offer support for compressed points.
        #XXX Try using the from_public_point() method.
        try:
            self.key = ecdsa.VerifyingKey.from_der(str(spki))
            # from_der() raises an exception on explicit curves
        except:
            s = spki.subjectPublicKey.val_readable[1:]
            p = spki.signatureAlgorithm.parameters
            c = import_curve(p.fieldID.prime.val,
                             p.curve.a.val,
                             p.curve.b.val,
                             p.base.val,
                             p.order.val)
            self.key = ecdsa.VerifyingKey.from_string(s, c)
    def encrypt(self, msg, t=None, h=None, mgf=None, L=None):
        # python-ecdsa does not support encryption
        raise Exception("No ECDSA encryption support")
    def verify(self, msg, sig, h=None,
               t=None, mgf=None, sLen=None,
               sigdecode=ecdsa.util.sigdecode_string):
        try:
            return self.key.verify(sig, msg, hashfunc=mapHashFunc(h),
                                   sigdecode=sigdecode)
        except ecdsa.keys.BadSignatureError:
            return False


################
# Private Keys #
################

class _PrivKeyFactory(_PKIObjMaker):
    """
    Metaclass for PrivKey creation.
    It casts the appropriate class on the fly, then fills in
    the appropriate attributes with updateWith() submethod.
    """
    def __call__(cls, key_path):
        """
        key_path may be the path to either:
            _an RSAPrivateKey_OpenSSL (as generated by openssl);
            _an ECDSAPrivateKey_OpenSSL (as generated by openssl);
            _an RSAPrivateKey;
            _an ECDSAPrivateKey.
        """
        obj = _PKIObjMaker.__call__(cls, key_path, MAX_KEY_SIZE)
        multiPEM = False
        try:
            privkey = RSAPrivateKey_OpenSSL(obj.der)
            privkey = privkey.privateKey
            obj.__class__ = PrivKeyRSA
            marker = "PRIVATE KEY"
        except:
            try:
                privkey = ECDSAPrivateKey_OpenSSL(obj.der)
                privkey = privkey.privateKey
                obj.__class__ = PrivKeyECDSA
                marker = "EC PRIVATE KEY"
                multiPEM = True
            except:
                try:
                    privkey = RSAPrivateKey(obj.der)
                    obj.__class__ = PrivKeyRSA
                    marker = "RSA PRIVATE KEY"
                except:
                    try:
                        privkey = ECDSAPrivateKey(obj.der)
                        obj.__class__ = PrivKeyECDSA
                        marker = "EC PRIVATE KEY"
                    except:
                        raise Exception("Unable to import private key")
        obj.updateWith(privkey)

        if obj.frmt == "DER":
            if multiPEM:
                # this does not restore the EC PARAMETERS header
                obj.pem = der2pem(str(privkey), marker)
            else:
                obj.pem = der2pem(obj.der, marker)
        return obj


class PrivKey(object):
    """
    Parent class for both PrivKeyRSA and PrivKeyECDSA.
    Provides common signTBSCert() and resignCert() methods.
    """
    __metaclass__ = _PrivKeyFactory

    def signTBSCert(self, tbsCert, h=None):
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
        Here, t will be passed eventually to pkcs1._DecryptAndSignRSA.sign(),
        while sigencode will be passed to ecdsa.keys.SigningKey.sign().
        """
        sigAlg = tbsCert.signature
        h = h or hash_by_oid[sigAlg.algorithm.val]
        sigVal = self.sign(str(tbsCert), h=h,
                           t='pkcs',
                           sigencode=ecdsa.util.sigencode_der)
        c = X509_Cert()
        c.tbsCertificate = tbsCert
        c.signatureAlgorithm = sigAlg
        c.signatureValue = ASN1_BIT_STRING(sigVal, readable=True)
        return c

    def resignCert(self, cert):
        # works with both Cert and X509_Cert types
        return self.signTBSCert(cert.tbsCertificate)


class PrivKeyRSA(_PKIObj, PrivKey, _EncryptAndVerifyRSA, _DecryptAndSignRSA):
    """
    Wrapper for RSA keys based on _DecryptAndSignRSA from crypto/pkcs1.py
    Use the 'key' attribute to access original object.
    """
    def updateWith(self, privkey):
        self.modulus     = privkey.modulus.val
        self.modulusLen  = len(binrepr(privkey.modulus.val))
        self.pubExp      = privkey.publicExponent.val
        self.privExp     = privkey.privateExponent.val
        self.prime1      = privkey.prime1.val
        self.prime2      = privkey.prime2.val
        self.exponent1   = privkey.exponent1.val
        self.exponent2   = privkey.exponent2.val
        self.coefficient = privkey.coefficient.val
        self.key = RSA.construct((self.modulus, self.pubExp, self.privExp))
    def verify(self, msg, sig, h=None,
               t=None, mgf=None, sLen=None,
               sigdecode=None):
        # Let's copy this from PubKeyRSA instead of adding another baseclass :)
        return _EncryptAndVerifyRSA.verify(self, msg, sig, h=h,
                                           t=t, mgf=mgf, sLen=sLen)
    def sign(self, data, h=None,
             t=None, mgf=None, sLen=None,
             k=None, entropy=None, sigencode=None):
        return _DecryptAndSignRSA.sign(self, data, h=h,
                                       t=t, mgf=mgf, sLen=sLen)


class PrivKeyECDSA(_PKIObj, PrivKey):
    """
    Wrapper for ECDSA keys based on SigningKey from ecdsa library.
    Use the 'key' attribute to access original object.
    """
    def updateWith(self, privkey):
        self.privKey = pkcs_os2ip(privkey.privateKey.val)
        self.key = ecdsa.SigningKey.from_der(str(privkey))
        self.vkey = self.key.get_verifying_key()
    def verify(self, msg, sig, h=None,
               t=None, mgf=None, sLen=None,
               sigdecode=None):
        return self.vkey.verify(sig, msg, hashfunc=mapHashFunc(h),
                                sigdecode=sigdecode)
    def sign(self, data, h=None,
             t=None, mgf=None, sLen=None,
             k=None, entropy=None, sigencode=ecdsa.util.sigencode_string):
        return self.key.sign(data, hashfunc=mapHashFunc(h),
                             k=k, entropy=entropy, sigencode=sigencode)


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
                                    MAX_CERT_SIZE, "CERTIFICATE")
        obj.__class__ = Cert
        try:
            cert = X509_Cert(obj.der)
        except:
            raise Exception("Unable to import certificate")
        obj.updateWith(cert)
        return obj


class Cert(_PKIObj):
    """
    Wrapper for the X509_Cert from layers/x509.py.
    Use the 'x509Cert' attribute to access original object.
    """
    __metaclass__ = _CertMaker

    def updateWith(self, cert):
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

        self.notBefore_str = tbsCert.validity.not_before.pretty_time
        notBefore = tbsCert.validity.not_before.val
        if notBefore[-1] == "Z":
            notBefore = notBefore[:-1]
        try:
            self.notBefore = time.strptime(notBefore, "%y%m%d%H%M%S")
        except:
            raise Exception(error_msg)
        self.notBefore_str_simple = time.strftime("%x", self.notBefore)

        self.notAfter_str = tbsCert.validity.not_after.pretty_time
        notAfter = tbsCert.validity.not_after.val
        if notAfter[-1] == "Z":
            notAfter = notAfter[:-1]
        try:
            self.notAfter = time.strptime(notAfter, "%y%m%d%H%M%S")
        except:
            raise Exception(error_msg)
        self.notAfter_str_simple = time.strftime("%x", self.notAfter)

        self.pubKey = PubKey(str(tbsCert.subjectPublicKeyInfo))

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

        self.signatureValue = str(cert.signatureValue)
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

    def encrypt(self, msg, t=None, h=None, mgf=None, L=None):
        # no ECDSA *encryption* support, hence only RSA specific keywords here
        return self.pubKey.encrypt(msg, t=t, h=h, mgf=mgf, L=L)

    def verify(self, msg, sig, h=None,
               t=None, mgf=None, sLen=None,
               sigdecode=None):
        return self.pubKey.verify(msg, sig, h=h,
                                  t=t, mgf=mgf, sLen=sLen,
                                  sigdecode=sigdecode)

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
        elif type(now) is str:
            try:
                if '/' in now:
                    now = time.strptime(now, '%m/%d/%y')
                else:
                    now = time.strptime(now, '%b %d %H:%M:%S %Y %Z')
            except:
                print "Bad time string provided, will use localtime() instead."
                now = time.localtime()

        now = time.mktime(now)
        nft = time.mktime(self.notAfter)
        diff = (nft - now)/(24.*3600)
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
                return self.serial in map(lambda x: x[0],
                                                    c.revoked_cert_serials)
            elif self.issuer == c.issuer:
                return self.serial in map(lambda x: x[0],
                                                    c.revoked_cert_serials)
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
        print "Serial: %s" % self.serial
        print "Issuer: " + self.issuer_str
        print "Subject: " + self.subject_str
        print "Validity: %s to %s" % (self.notBefore_str, self.notAfter_str)

    def __repr__(self):
        return "[X.509 Cert. Subject:%s, Issuer:%s]" % (self.subject_str, self.issuer_str)


################################
# Certificate Revocation Lists #
################################

class _CRLMaker(_PKIObjMaker):
    """
    Metaclass for CRL creation. It is not necessary as it was for the keys,
    but we reuse the model instead of creating redundant constructors.
    """
    def __call__(cls, cert_path):
        obj = _PKIObjMaker.__call__(cls, cert_path, MAX_CRL_SIZE, "X509 CRL")
        obj.__class__ = CRL
        try:
            crl = X509_CRL(obj.der)
        except:
            raise Exception("Unable to import CRL")
        obj.updateWith(crl)
        return obj


class CRL(_PKIObj):
    """
    Wrapper for the X509_CRL from layers/x509.py.
    Use the 'x509CRL' attribute to access original object.
    """
    __metaclass__ = _CRLMaker

    def updateWith(self, crl):
        error_msg = "Unable to import CRL"

        self.x509CRL = crl

        tbsCertList = crl.tbsCertList
        self.tbsCertList = str(tbsCertList)

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
        except:
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
            except:
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
                    revocationDate = time.strptime(date, "%y%m%d%H%M%S")
                except:
                    raise Exception(error_msg)
                revoked.append((serial, date))
        self.revoked_cert_serials = revoked

        self.signatureValue = str(crl.signatureValue)
        self.signatureLen = len(self.signatureValue)

    def isIssuerCert(self, other):
        # This is exactly the same thing as in Cert method.
        if self.issuer_hash != other.subject_hash:
            return False
        return other.pubKey.verifyCert(self)

    def verify(self, anchors):
        # Return True iff the CRL is signed by one of the provided anchors.
        for a in anchors:
            if self.isIssuerCert(a):
                return True
        return False

    def show(self):
        print "Version: %d" % self.version
        print "sigAlg: " + self.sigAlg
        print "Issuer: " + self.issuer_str
        print "lastUpdate: %s" % self.lastUpdate_str
        print "nextUpdate: %s" % self.nextUpdate_str


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
                l = len(self)
                for c in certList:
                    if c.isIssuerCert(self[-1]):
                        self.append(c)
                        certList.remove(c)
                        break
                if len(self) == l:
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
            found = False
            for c in self:
                if c in chain[1:]:
                    found = True
            if found:
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
            f = open(cafile)
            ca_certs = f.read()
            f.close()
        except:
            raise Exception("Could not read from cafile")

        anchors = [Cert(c) for c in split_pem(ca_certs)]

        untrusted = None
        if untrusted_file:
            try:
                f = open(untrusted_file)
                untrusted_certs = f.read()
                f.close()
            except:
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
                anchors.append(Cert(open(cafile).read()))
        except:
            raise Exception("capath provided is not a valid cert path")

        untrusted = None
        if untrusted_file:
            try:
                f = open(untrusted_file)
                untrusted_certs = f.read()
                f.close()
            except:
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
            s += "%s\_ %s" % (" "*idx*2, c.subject_str)
            if idx != llen:
                s += "\n"
            idx += 1
        return s

