## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS key exchange logic.
"""

import math

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa

from scapy.config import conf
from scapy.error import warning
from scapy.fields import *
from scapy.packet import Packet, Raw, Padding
from scapy.layers.tls.cert import PubKeyRSA, PrivKeyRSA
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.basefields import _tls_version, _TLSClientVersionField
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip
from scapy.layers.tls.crypto.ffdh import FFDH_GROUPS


###############################################################################
### Common Fields                                                           ###
###############################################################################

_tls_hash_sig = { 0x0000: "none+anon",    0x0001: "none+rsa",
                  0x0002: "none+dsa",     0x0003: "none+ecdsa",
                  0x0100: "md5+anon",     0x0101: "md5+rsa",
                  0x0102: "md5+dsa",      0x0103: "md5+ecdsa",
                  0x0200: "sha1+anon",    0x0201: "sha1+rsa",
                  0x0202: "sha1+dsa",     0x0203: "sha1+ecdsa",
                  0x0300: "sha224+anon",  0x0301: "sha224+rsa",
                  0x0302: "sha224+dsa",   0x0303: "sha224+ecdsa",
                  0x0400: "sha256+anon",  0x0401: "sha256+rsa",
                  0x0402: "sha256+dsa",   0x0403: "sha256+ecdsa",
                  0x0500: "sha384+anon",  0x0501: "sha384+rsa",
                  0x0502: "sha384+dsa",   0x0503: "sha384+ecdsa",
                  0x0600: "sha512+anon",  0x0601: "sha512+rsa",
                  0x0602: "sha512+dsa",   0x0603: "sha512+ecdsa" }


def phantom_mode(pkt):
    """
    We expect this. If tls_version is not set, this means we did not process
    any complete ClientHello, so we're most probably reading/building a
    signature_algorithms extension, hence we cannot be in phantom_mode.
    However, if the tls_version has been set, we test for TLS 1.2.
    XXX Make this more generic. Also, factorize the classes below (metaclass?).
    """
    if not pkt.tls_session:
        return False
    if not pkt.tls_session.tls_version:
        return False
    return pkt.tls_session.tls_version < 0x0303

def phantom_decorate(f, get_or_add):
    """
    Decorator for version-dependent fields.
    If get_or_add is True (means get), we return s, self.phantom_value.
    If it is False (means add), we return s.
    """
    def wrapper(*args):
        self, pkt, s = args[:3]
        if phantom_mode(pkt):
            if get_or_add:
                return s, self.phantom_value
            return s
        return f(*args)
    return wrapper

class SigAndHashAlgField(EnumField):
    """
    Used in _TLSSignature.
    """
    phantom_value = None
    getfield = phantom_decorate(EnumField.getfield, True)
    addfield = phantom_decorate(EnumField.addfield, False)

class SigAndHashAlgsLenField(FieldLenField):
    """
    Used in TLS_Ext_SignatureAlgorithms and TLSCertificateResquest.
    """
    phantom_value = 0
    getfield = phantom_decorate(FieldLenField.getfield, True)
    addfield = phantom_decorate(FieldLenField.addfield, False)

class SigAndHashAlgsField(FieldListField):
    """
    Used in TLS_Ext_SignatureAlgorithms and TLSCertificateResquest.
    """
    phantom_value = []
    getfield = phantom_decorate(FieldListField.getfield, True)
    addfield = phantom_decorate(FieldListField.addfield, False)


class _TLSSignature(_GenericTLSSessionInheritance):
    """
    Prior to TLS 1.2, digitally-signed structure implictly used the
    concatenation of a SHA-1 hash and a MD5 hash (this is the 'tls' mode
    of key signing). TLS 1.2 introduced explicit SignatureAndHashAlgorithms,
    i.e. couples of (hash_alg, sig_alg). See RFC 5246, section 7.4.1.4.1.

    By default, the _TLSSignature implements the TLS 1.2 scheme,
    but if it is provided a TLS context with a tls_version < 0x0303
    at initialization, it will fall back to the implicit signature.

    #XXX 'sig_alg' should be set in __init__ depending on the context.
    """
    name = "TLS Digital Signature"
    fields_desc = [ SigAndHashAlgField("sig_alg", 0x0401, _tls_hash_sig),
                    FieldLenField("sig_len", None, fmt="!H",
                                  length_of="sig_val"),
                    StrLenField("sig_val", None,
                                length_from = lambda pkt: pkt.sig_len) ]

    def __init__(self, *args, **kargs):
        _GenericTLSSessionInheritance.__init__(self, *args, **kargs)
        if ("tls_session" in kargs and
            kargs["tls_session"].tls_version and
            kargs["tls_session"].tls_version < 0x0303):
            self.sig_alg = None

    def _update_sig(self, m, key):
        """
        Sign 'm' with the PrivKey 'key' and update our own 'sig_val'.
        Note that, even when 'sig_alg' is not None, we use the signature scheme
        of the PrivKey (neither do we care to compare the both of them).
        """
        if self.sig_alg is None:
            self.sig_val = key.sign(m, t='pkcs', h='tls')
        else:
            h = _tls_hash_sig[self.sig_alg].split('+')[0]
            self.sig_val = key.sign(m, t='pkcs', h=h)

    def _verify_sig(self, m, cert):
        """
        Verify that our own 'sig_val' carries the signature of 'm' by the
        key associated to the Cert 'cert'.
        """
        if self.sig_val:
            if self.sig_alg:
                h = _tls_hash_sig[self.sig_alg].split('+')[0]
                return cert.verify(m, self.sig_val, t='pkcs', h=h)
            else:
                return cert.verify(m, self.sig_val, t='pkcs', h='tls')
        return False

    def guess_payload_class(self, p):
        return Padding

class _TLSSignatureField(PacketField):
    """
    Used for 'digitally-signed struct' in several ServerKeyExchange,
    and also in CertificateVerify. We can handle the anonymous case.
    """
    __slots__ = ["length_from"]
    def __init__(self, name, default, length_from=None, remain=0):
        self.length_from = length_from
        PacketField.__init__(self, name, default, _TLSSignature, remain=remain)

    def m2i(self, pkt, m):
        l = self.length_from(pkt)
        if l == 0:
           return None
        return _TLSSignature(m, tls_session=pkt.tls_session)


class _TLSServerParamsField(PacketField):
    """
    This is a dispatcher for the Server*DHParams below, used in
    TLSServerKeyExchange and based on the key_exchange.server_kx_msg_cls.
    When this cls is None, it means that we should not see a ServerKeyExchange,
    so we grab everything within length_from and make it available using Raw.

    When the context has not been set (e.g. when no ServerHello was parsed or
    dissected beforehand), we (kinda) clumsily set the cls by trial and error.
    XXX We could use Serv*DHParams.check_params() once it has been implemented.
    """
    __slots__ = ["length_from"]
    def __init__(self, name, default, length_from=None, remain=0):
        self.length_from = length_from
        PacketField.__init__(self, name, default, None, remain=remain)

    def m2i(self, pkt, m):
        s = pkt.tls_session
        l = self.length_from(pkt)
        if s.prcs:
            cls = s.prcs.key_exchange.server_kx_msg_cls(m)
            if cls is None:
                return None, Raw(m[:l])/Padding(m[l:])
            return cls(m, tls_session=s)
        else:
            try:
                p = ServerDHParams(m, tls_session=s)
                if pkcs_os2ip(p.load[:2]) not in _tls_hash_sig:
                    raise Exception
                return p
            except:
                cls = _tls_server_ecdh_cls_guess(m)
                p = cls(m, tls_session=s)
                if pkcs_os2ip(p.load[:2]) not in _tls_hash_sig:
                    return None, Raw(m[:l])/Padding(m[l:])
                return p


###############################################################################
### Server Key Exchange parameters & value                                  ###
###############################################################################

### Finite Field Diffie-Hellman

class ServerDHParams(_GenericTLSSessionInheritance):
    """
    ServerDHParams for FFDH-based key exchanges,
    as it is defined in RFC 5246, section 7.4.3.

    Either with .fill_missing() or .post_dissection(), the server_kx_params and
    client_kx_params of the TLS context are updated according to the
    parsed/assembled values. It is the user's responsibility to store and
    restore the original values if he wants to keep them. For instance, this
    could be done between the writing of a ServerKeyExchange and the receiving
    of a ClientKeyExchange (which includes secret generation).
    """
    name = "Server FFDH parameters"
    fields_desc = [ FieldLenField("dh_plen", None, length_of="dh_p"),
                    StrLenField("dh_p", "",
                                length_from=lambda pkt: pkt.dh_plen),
                    FieldLenField("dh_glen", None, length_of="dh_g"),
                    StrLenField("dh_g", "",
                                length_from=lambda pkt: pkt.dh_glen),
                    FieldLenField("dh_Yslen", None, length_of="dh_Ys"),
                    StrLenField("dh_Ys", "",
                                length_from=lambda pkt: pkt.dh_Yslen) ]

    def fill_missing(self):
        """
        We do not want TLSServerKeyExchange.build() to overload and recompute
        things everytime it is called. This method can be called specifically
        to have things filled in a smart fashion.

        Note that we do not expect dh_params_def.g to be more than 0xff.
        """
        s = self.tls_session

        default_params = FFDH_GROUPS['modp2048'][0].parameter_numbers()
        default_mLen = FFDH_GROUPS['modp2048'][1]

        if self.dh_p is "":
            self.dh_p = pkcs_i2osp(default_params.p, default_mLen/8)
        if self.dh_plen is None:
            self.dh_plen = len(self.dh_p)

        if self.dh_g is "":
            self.dh_g = pkcs_i2osp(default_params.g, 1)
        if self.dh_glen is None:
            self.dh_glen = 1

        p = pkcs_os2ip(self.dh_p)
        g = pkcs_os2ip(self.dh_g)
        real_params = dh.DHParameterNumbers(p, g).parameters(default_backend())

        if self.dh_Ys is "":
            s.server_kx_privkey = real_params.generate_private_key()
            pubkey = s.server_kx_privkey.public_key()
            y = pubkey.public_numbers().y
            self.dh_Ys = pkcs_i2osp(y, pubkey.key_size/8)
        # else, we assume that the user wrote the server_kx_privkey by himself
        if self.dh_Yslen is None:
            self.dh_Yslen = len(self.dh_Ys)

        if not s.client_kx_ffdh_params:
            s.client_kx_ffdh_params = real_params

    def post_dissection(self, r):
        """
        XXX Check that the pubkey received is in the group.
        """
        #if self.dh_g and self.dh_p and self.dh_Ys: #XXX remove this, probably
        p = pkcs_os2ip(self.dh_p)
        g = pkcs_os2ip(self.dh_g)
        pn = dh.DHParameterNumbers(p, g)

        y = pkcs_os2ip(self.dh_Ys)
        public_numbers = dh.DHPublicNumbers(y, pn)

        s = self.tls_session
        s.server_kx_pubkey = public_numbers.public_key(default_backend())

        if not s.client_kx_ffdh_params:
            s.client_kx_ffdh_params = pn.parameters(default_backend())

    def guess_payload_class(self, p):
        """
        The signature after the params gets saved as Padding.
        This way, the .getfield() which _TLSServerParamsField inherits
        from PacketField will return the signature remain as expected.
        """
        return Padding


### Elliptic Curve Diffie-Hellman

_tls_ec_curve_types = { 1: "explicit_prime",
                        2: "explicit_char2",
                        3: "named_curve" }

_tls_named_curves = {  1: "sect163k1",  2: "sect163r1",  3: "sect163r2",
                       4: "sect193r1",  5: "sect193r2",  6: "sect233k1",
                       7: "sect233r1",  8: "sect239k1",  9: "sect283k1",
                      10: "sect283r1", 11: "sect409k1", 12: "sect409r1",
                      13: "sect571k1", 14: "sect571r1", 15: "secp160k1",
                      16: "secp160r1", 17: "secp160r2", 18: "secp192k1",
                      19: "secp192r1", 20: "secp224k1", 21: "secp224r1",
                      22: "secp256k1", 23: "secp256r1", 24: "secp384r1",
                      25: "secp521r1", 26: "brainpoolP256r1",
                      27: "brainpoolP384r1", 28: "brainpoolP512r1",
                      0xff01: "arbitrary_explicit_prime_curves",
                      0xff02: "arbitrary_explicit_char2_curves"}

_tls_ec_basis_types = { 0: "ec_basis_trinomial", 1: "ec_basis_pentanomial"}

class ECCurvePkt(Packet):
    name = "Elliptic Curve"
    fields_desc = [ FieldLenField("alen", None, length_of="a", fmt="B"),
                    StrLenField("a", "", length_from = lambda pkt: pkt.alen),
                    FieldLenField("blen", None, length_of="b", fmt="B"),
                    StrLenField("b", "", length_from = lambda pkt: pkt.blen) ]


## Char2 Curves

class ECTrinomialBasis(Packet):
    name = "EC Trinomial Basis"
    val = 0
    fields_desc = [ FieldLenField("klen", None, length_of="k", fmt="B"),
                    StrLenField("k", "", length_from = lambda pkt: pkt.klen) ]
    def guess_payload_class(self, p):
        return Padding

class ECPentanomialBasis(Packet):
    name = "EC Pentanomial Basis"
    val = 1
    fields_desc = [ FieldLenField("k1len", None, length_of="k1", fmt="B"),
                    StrLenField("k1", "", length_from=lambda pkt: pkt.k1len),
                    FieldLenField("k2len", None, length_of="k2", fmt="B"),
                    StrLenField("k2", "", length_from=lambda pkt: pkt.k2len),
                    FieldLenField("k3len", None, length_of="k3", fmt="B"),
                    StrLenField("k3", "", length_from=lambda pkt: pkt.k3len) ]
    def guess_payload_class(self, p):
        return Padding

_tls_ec_basis_cls = { 0: ECTrinomialBasis, 1: ECPentanomialBasis}

class _ECBasisTypeField(ByteEnumField):
    __slots__ = ["basis_type_of"]
    def __init__(self, name, default, enum, basis_type_of, remain=0):
        self.basis_type_of = basis_type_of
        EnumField.__init__(self, name, default, enum, "B")

    def i2m(self, pkt, x):
        if x is None:
            val = 0
            fld,fval = pkt.getfield_and_val(self.basis_type_of)
            x = fld.i2basis_type(pkt, fval)
        return x

class _ECBasisField(PacketField):
    __slots__ = ["clsdict", "basis_type_from"]
    def __init__(self, name, default, basis_type_from, clsdict, remain=0):
        self.clsdict = clsdict
        self.basis_type_from = basis_type_from
        PacketField.__init__(self, name, default, None, remain=remain)

    def m2i(self, pkt, m):
        basis = self.basis_type_from(pkt)
        cls = self.clsdict[basis]
        return cls(m)

    def i2basis_type(self, pkt, x):
        val = 0
        try:
            val = x.val
        except:
            pass
        return val


## Distinct ECParameters
##
## To support the different ECParameters structures defined in Sect. 5.4 of
## RFC 4492, we define 3 separates classes for implementing the 3 associated
## ServerECDHParams: ServerECDHNamedCurveParams, ServerECDHExplicitPrimeParams
## and ServerECDHExplicitChar2Params (support for this one is only partial).
## The most frequent encounter of the 3 is (by far) ServerECDHNamedCurveParams.

class ServerECDHExplicitPrimeParams(_GenericTLSSessionInheritance):
    """
    XXX We provide parsing abilities for ExplicitPrimeParams, but there is no
    'cryptography' support, hence no context operations.
    """
    name = "Server ECDH parameters - Explicit Prime"
    fields_desc = [ ByteEnumField("curve_type", 1, _tls_ec_curve_types),
		    FieldLenField("plen", None, length_of="p", fmt="B"),
		    StrLenField("p", "", length_from=lambda pkt: pkt.plen),
                    PacketField("curve", None, ECCurvePkt),
                    FieldLenField("baselen", None, length_of="base", fmt="B"),
                    StrLenField("base", "",
                                length_from=lambda pkt: pkt.baselen),
		    FieldLenField("orderlen", None,
                                  length_of="order", fmt="B"),
		    StrLenField("order", "",
                                length_from=lambda pkt: pkt.orderlen),
		    FieldLenField("cofactorlen", None,
                                  length_of="cofactor", fmt="B"),
		    StrLenField("cofactor", "",
                                length_from=lambda pkt: pkt.cofactorlen),
                    FieldLenField("pointlen", None,
                                  length_of="point", fmt="B"),
                    StrLenField("point", "",
                                length_from=lambda pkt: pkt.pointlen) ]

    def fill_missing(self):
        """
        We do not want TLSServerKeyExchange.build() to overload and recompute
        things everytime it is called. This method can be called specifically
        to have things filled in a smart fashion.

        XXX Note that if it is not set by the user, the cofactor will always
        be 1. It is true for most, but not all, TLS elliptic curves.

        XXX Try and create a curve with the 'cryptography' lib somehow,
        extract the missing fields for filling, then set s.server_kx_privkey.
        """
        if self.curve_type is None:
            self.curve_type = _tls_ec_curve_types["explicit_prime"]

    def post_dissection(self, pkt):
        """
        XXX Store the server_kx_pubkey.
        XXX Check that the pubkey received is on the curve.
        """

    def guess_payload_class(self, p):
        return Padding


class ServerECDHExplicitChar2Params(_GenericTLSSessionInheritance):
    """
    XXX We provide parsing abilities for Char2Params, but there is no
    'cryptography' support, hence no context operations.
    """
    name = "Server ECDH parameters - Explicit Char2"
    fields_desc = [ ByteEnumField("curve_type", 2, _tls_ec_curve_types),
                    ShortField("m", None),
                    _ECBasisTypeField("basis_type", None,
                                      _tls_ec_basis_types, "basis"),
                    _ECBasisField("basis", ECTrinomialBasis(),
                                  lambda pkt: pkt.basis_type,
                                  _tls_ec_basis_cls),
                    PacketField("curve", ECCurvePkt(), ECCurvePkt),
                    FieldLenField("baselen", None, length_of="base", fmt="B"),
                    StrLenField("base", "",
                                length_from = lambda pkt: pkt.baselen),
                    ByteField("order", None),
                    ByteField("cofactor", None),
                    FieldLenField("pointlen", None,
                                  length_of="point", fmt="B"),
                    StrLenField("point", "",
                                length_from = lambda pkt: pkt.pointlen) ]

    def fill_missing(self):
        """
        We do not want TLSServerKeyExchange.build() to overload and recompute
        things everytime it is called. This method can be called specifically
        to have things filled in a smart fashion.
        """
        if self.curve_type is None:
            self.curve_type = _tls_ec_curve_types["explicit_char2"]

    def post_dissection(self, pkt):
        """
        XXX Store the server_kx_pubkey.
        XXX Check that the pubkey received is in the group.
        """
        pass

    def guess_payload_class(self, p):
        return Padding


class ServerECDHNamedCurveParams(_GenericTLSSessionInheritance):
    name = "Server ECDH parameters - Named Curve"
    fields_desc = [ ByteEnumField("curve_type", 3, _tls_ec_curve_types),
                    ShortEnumField("named_curve", None, _tls_named_curves),
                    FieldLenField("pointlen", None,
                                  length_of="point", fmt="B"),
                    StrLenField("point", None,
                                length_from = lambda pkt: pkt.pointlen) ]

    def fill_missing(self):
        """
        We do not want TLSServerKeyExchange.build() to overload and recompute
        things everytime it is called. This method can be called specifically
        to have things filled in a smart fashion.
        XXX We should account for the point_format (before 'point' filling).
        """
        s = self.tls_session

        if self.curve_type is None:
            self.curve_type = _tls_ec_curve_types["named_curve"]

        if self.named_curve is None:
            curve = ec.SECP256R1()
            s.server_kx_privkey = ec.generate_private_key(curve,
                                                          default_backend())
            curve_id = 0
            for cid, name in _tls_named_curves.iteritems():
                if name == curve.name:
                    curve_id = cid
                    break
            self.named_curve = curve_id
        else:
            curve_name = _tls_named_curves.get(self.named_curve)
            if curve_name is None:
                # this fallback is arguable
                curve = ec.SECP256R1()
            else:
                curve_cls = ec._CURVE_TYPES.get(curve_name)
                if curve_cls is None:
                    # this fallback is arguable
                    curve = ec.SECP256R1()
                else:
                    curve = curve_cls()
            s.server_kx_privkey = ec.generate_private_key(curve,
                                                          default_backend())

        if self.point is None:
            pubkey = s.server_kx_privkey.public_key()
            self.point = pubkey.public_numbers().encode_point()
        # else, we assume that the user wrote the server_kx_privkey by himself
        if self.pointlen is None:
            self.pointlen = len(self.point)

        if not s.client_kx_ecdh_params:
            s.client_kx_ecdh_params = curve

    def post_dissection(self, r):
        """
        XXX Support compressed point format.
        XXX Check that the pubkey received is on the curve.
        """
        #point_format = 0
        #if self.point[0] in ['\x02', '\x03']:
        #    point_format = 1

        #if self.named_curve and self.point: #XXX remove this, probably
        curve_name = _tls_named_curves[self.named_curve]
        curve = ec._CURVE_TYPES[curve_name]()
        import_point = ec.EllipticCurvePublicNumbers.from_encoded_point
        pubnum = import_point(curve, self.point)
        s = self.tls_session
        s.server_kx_pubkey = pubnum.public_key(default_backend())

        if not s.client_kx_ecdh_params:
            s.client_kx_ecdh_params = curve

    def guess_payload_class(self, p):
        return Padding


_tls_server_ecdh_cls = { 1: ServerECDHExplicitPrimeParams,
                         2: ServerECDHExplicitChar2Params,
                         3: ServerECDHNamedCurveParams }

def _tls_server_ecdh_cls_guess(m):
    if not m:
        return None
    curve_type = ord(m[0])
    return _tls_server_ecdh_cls.get(curve_type, None)


### RSA Encryption (export)

class ServerRSAParams(_GenericTLSSessionInheritance):
    """
    Defined for RSA_EXPORT kx : it enables servers to share RSA keys shorter
    than their principal {>512}-bit key, when it is not allowed for kx.

    This should not appear in standard RSA kx negotiation, as the key
    has already been advertised in the Certificate message.
    """
    name = "Server RSA_EXPORT parameters"
    fields_desc = [ FieldLenField("rsamodlen", None, length_of="rsamod"),
                    StrLenField("rsamod", "",
                                length_from = lambda pkt: pkt.rsamodlen),
                    FieldLenField("rsaexplen", None, length_of="rsaexp"),
                    StrLenField("rsaexp", "",
                                length_from = lambda pkt: pkt.rsaexplen) ]

    def fill_missing(self):
        ext_k = rsa.generate_private_key(public_exponent=0x10001,
                                         key_size=512,
                                         backend=default_backend())
        pem_k = ext_k.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption())
        k = PrivKeyRSA(pem_k)
        self.tls_session.server_tmp_rsa_key = k
        pubNum = k.pubkey.public_numbers()

        if self.rsamod is "":
            self.rsamod = pkcs_i2osp(pubNum.n, k.pubkey.key_size/8)
        if self.rsamodlen is None:
            self.rsamodlen = len(self.rsamod)

        rsaexplen = math.ceil(math.log(pubNum.e)/math.log(2)/8.)
        if self.rsaexp is "":
            self.rsaexp = pkcs_i2osp(pubNum.e, rsaexplen)
        if self.rsaexplen is None:
            self.rsaexplen = len(self.rsaexp)

    def post_dissection(self, pkt):
        mLen = self.rsamodlen
        m    = self.rsamod
        e    = self.rsaexp
        self.tls_session.server_tmp_rsa_key = PubKeyRSA((e, m, mLen))

    def guess_payload_class(self, p):
        return Padding


### Pre-Shared Key

class ServerPSKParams(Packet):
    """
    XXX We provide some parsing abilities for ServerPSKParams, but the
    context operations have not been implemented yet. See RFC 4279.
    Note that we do not cover the (EC)DHE_PSK key exchange,
    which should contain a Server*DHParams after 'psk_identity_hint'.
    """
    name = "Server PSK parameters"
    fields_desc = [ FieldLenField("psk_identity_hint_len", None,
                                  length_of="psk_identity_hint", fmt="!H"),
                    StrLenField("psk_identity_hint", "",
                        length_from=lambda pkt: pkt.psk_identity_hint_len) ]

    def fill_missing(self):
        """
        We do not want TLSServerKeyExchange.build() to overload and recompute
        things everytime it is called. This method can be called specifically
        to have things filled in a smart fashion.
        """
        pass

    def post_dissection(self, pkt):
        pass

    def guess_payload_class(self, p):
        return Padding


###############################################################################
### Client Key Exchange value                                               ###
###############################################################################

### FFDH/ECDH

class ClientDiffieHellmanPublic(_GenericTLSSessionInheritance):
    """
    If the user provides a value for dh_Yc attribute,
    the pms and ms are set accordingly when .post_build() is called.

    XXX As specified in 7.4.7.2. of RFC 4346, we should distinguish the needs
    for implicit or explicit value depending on availability of DH parameters
    in *client* certificate. For now we can only do ephemeral/explicit DH.
    """
    name = "Client DH Public Value"
    fields_desc = [ FieldLenField("dh_Yclen", None, length_of="dh_Yc"),
                    StrLenField("dh_Yc", "",
                                length_from=lambda pkt: pkt.dh_Yclen) ]

    def post_build(self, pkt, pay):
        s = self.tls_session

        if self.dh_Yc == "":
            params = s.client_kx_ffdh_params
            s.client_kx_privkey = params.generate_private_key()
            pubkey = s.client_kx_privkey.public_key()
            y = pubkey.public_numbers().y
            self.dh_Yc = pkcs_i2osp(y, pubkey.key_size/8)
        # else, we assume that the user wrote the client_kx_privkey by himself
        if self.dh_Yclen is None:
            self.dh_Yclen = len(self.dh_Yc)

        if s.client_kx_privkey and s.server_kx_pubkey:
            pms = s.client_kx_privkey.exchange(s.server_kx_pubkey)
            s.pre_master_secret = pms
            s.compute_ms_and_derive_keys()

        return pkcs_i2osp(self.dh_Yclen, 2) + self.dh_Yc + pay

    def post_dissection(self, m):
        """
        First we update the client DHParams. Then, we try to update the server
        DHParams generated during Server*DHParams building, with the shared
        secret. Finally, we derive the session keys and update the context.
        """
        s = self.tls_session

        if s.client_kx_ffdh_params:
            y = pkcs_os2ip(self.dh_Yc)
            param_numbers = s.client_kx_ffdh_params.parameter_numbers()
            public_numbers = dh.DHPublicNumbers(y, param_numbers)
            s.client_kx_pubkey = public_numbers.public_key(default_backend())

        if s.server_kx_privkey and s.client_kx_pubkey:
            ZZ = s.server_kx_privkey.exchange(s.client_kx_pubkey)
            s.pre_master_secret = ZZ
            s.compute_ms_and_derive_keys()

    def guess_payload_class(self, p):
        return Padding

class ClientECDiffieHellmanPublic(_GenericTLSSessionInheritance):
    """
    Note that the 'len' field is 1 byte longer than with the previous class.
    """
    name = "Client ECDH Public Value"
    fields_desc = [ FieldLenField("ecdh_Yclen", None,
                                  length_of="ecdh_Yc", fmt="B"),
                    StrLenField("ecdh_Yc", "",
                                length_from=lambda pkt: pkt.ecdh_Yclen)]

    def post_build(self, pkt, pay):
        s = self.tls_session

        if self.ecdh_Yc == "":
            params = s.client_kx_ecdh_params
            s.client_kx_privkey = ec.generate_private_key(params,
                                                          default_backend())
            pubkey = s.client_kx_privkey.public_key()
            x = pubkey.public_numbers().x
            y = pubkey.public_numbers().y
            self.ecdh_Yc = ("\x04" +
                            pkcs_i2osp(x, params.key_size/8) +
                            pkcs_i2osp(y, params.key_size/8))
        # else, we assume that the user wrote the client_kx_privkey by himself
        if self.ecdh_Yclen is None:
            self.ecdh_Yclen = len(self.ecdh_Yc)

        if s.client_kx_privkey and s.server_kx_pubkey:
            pms = s.client_kx_privkey.exchange(ec.ECDH(), s.server_kx_pubkey)
            s.pre_master_secret = pms
            s.compute_ms_and_derive_keys()

        return pkcs_i2osp(self.ecdh_Yclen, 1) + self.ecdh_Yc + pay

    def post_dissection(self, m):
        s = self.tls_session

        if s.client_kx_ecdh_params:
            import_point = ec.EllipticCurvePublicNumbers.from_encoded_point
            pub_num = import_point(s.client_kx_ecdh_params, self.ecdh_Yc)
            s.client_kx_pubkey = pub_num.public_key(default_backend())

        if s.server_kx_privkey and s.client_kx_pubkey:
            ZZ = s.server_kx_privkey.exchange(ec.ECDH(), s.client_kx_pubkey)
            s.pre_master_secret = ZZ
            s.compute_ms_and_derive_keys()


### RSA Encryption (standard & export)

class EncryptedPreMasterSecret(_GenericTLSSessionInheritance):
    """
    Pay attention to implementation notes in section 7.4.7.1 of RFC 5246.
    """
    name = "RSA Encrypted PreMaster Secret"
    fields_desc = [ _TLSClientVersionField("client_version", None,
                                           _tls_version),
                    StrFixedLenField("random", None, 46) ]

    def pre_dissect(self, m):
        s = self.tls_session
        tbd = m
        if s.tls_version >= 0x0301:
            if len(m) < 2:      # Should not happen
                return m
            l = struct.unpack("!H", m[:2])[0]
            if len(m) != l+2:
                err = "TLS 1.0+, but RSA Encrypted PMS with no explicit length"
                warning(err)
            else:
                tbd = m[2:]
        if s.server_tmp_rsa_key is not None:
            # priority is given to the tmp_key, if there is one
            decrypted = s.server_tmp_rsa_key.decrypt(tbd)
            pms = decrypted[-48:]
        elif s.server_rsa_key is not None:
            decrypted = s.server_rsa_key.decrypt(tbd)
            pms = decrypted[-48:]
        else:
            pms = "\x00"*48     # Hack but we should not be there anyway
            err = "No server RSA key to decrypt Pre Master Secret. Skipping."
            warning(err)

        s.pre_master_secret = pms
        s.compute_ms_and_derive_keys()

        return pms

    def post_build(self, pkt, pay):
        """
        We encrypt the premaster secret (the 48 bytes) with either the server
        certificate or the temporary RSA key provided in a server key exchange
        message. After that step, we add the 2 bytes to provide the length, as
        described in implementation notes at the end of section 7.4.7.1.
        """
        enc = pkt

        s = self.tls_session
        s.pre_master_secret = enc
        s.compute_ms_and_derive_keys()

        if s.server_tmp_rsa_key is not None:
            enc = s.server_tmp_rsa_key.encrypt(pkt, "pkcs")
        elif s.server_certs is not None and len(s.server_certs) > 0:
            enc = s.server_certs[0].encrypt(pkt, "pkcs")
        else:
            warning("No material to encrypt Pre Master Secret")

        l = ""
        if s.tls_version >= 0x0301:
            l = struct.pack("!H", len(enc))
        return "%s%s%s" % (l, enc, pay)

    def guess_payload_class(self, p):
        return Padding


# Pre-Shared Key

class ClientPSKIdentity(Packet):
    """
    XXX We provide parsing abilities for ServerPSKParams, but the context
    operations have not been implemented yet. See RFC 4279.
    Note that we do not cover the (EC)DHE_PSK nor the RSA_PSK key exchange,
    which should contain either an EncryptedPMS or a ClientDiffieHellmanPublic.
    """
    name = "Server PSK parameters"
    fields_desc = [ FieldLenField("psk_identity_len", None,
                                  length_of="psk_identity", fmt="!H"),
                    StrLenField("psk_identity", "",
                        length_from=lambda pkt: pkt.psk_identity_len) ]

