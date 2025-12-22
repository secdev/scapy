# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Acknowledgment: Arnaud Ebalard & Maxence Tury

# Cool history about this file: http://natisbad.org/scapy/index.html

"""
X.509 certificates, OCSP, CRL, CMS and other crypto-related ASN.1 structures
"""

from scapy.asn1.ber import BER_Decoding_Error
from scapy.asn1.mib import conf  # loads conf.mib
from scapy.asn1.asn1 import (
    ASN1_Codecs,
    ASN1_IA5_STRING,
    ASN1_OID,
    ASN1_PRINTABLE_STRING,
    ASN1_UTC_TIME,
    ASN1_UTF8_STRING,
)
from scapy.asn1packet import ASN1_Packet
from scapy.asn1fields import (
    ASN1F_BIT_STRING_ENCAPS,
    ASN1F_BIT_STRING,
    ASN1F_BMP_STRING,
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_enum_INTEGER,
    ASN1F_ENUMERATED,
    ASN1F_field,
    ASN1F_FLAGS,
    ASN1F_GENERALIZED_TIME,
    ASN1F_IA5_STRING,
    ASN1F_INTEGER,
    ASN1F_ISO646_STRING,
    ASN1F_NULL,
    ASN1F_OID,
    ASN1F_omit,
    ASN1F_optional,
    ASN1F_PACKET,
    ASN1F_PRINTABLE_STRING,
    ASN1F_SEQUENCE_OF,
    ASN1F_SEQUENCE,
    ASN1F_SET_OF,
    ASN1F_STRING_ENCAPS,
    ASN1F_STRING_PacketField,
    ASN1F_STRING,
    ASN1F_T61_STRING,
    ASN1F_UNIVERSAL_STRING,
    ASN1F_UTC_TIME,
    ASN1F_UTF8_STRING,
)
from scapy.packet import Packet
from scapy.fields import (
    MultipleTypeField,
    PacketField,
)
from scapy.volatile import ZuluTime, GeneralizedTime
from scapy.compat import plain_str

from scapy.layers.tpm import KeyAttestationStatement


class ASN1P_OID(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_OID("oid", "0")


class ASN1P_INTEGER(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("number", 0)


class ASN1P_PRIVSEQ(ASN1_Packet):
    # This class gets used in x509.uts
    # It showcases the private high-tag decoding capacities of scapy.
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_IA5_STRING("str", ""),
        ASN1F_STRING("int", 0),
        explicit_tag=0,
        flexible_tag=True)


#######################
#     RSA packets     #
#######################
# based on RFC 3447

# It could be interesting to use os.urandom and try to generate
# a new modulus each time RSAPublicKey is called with default values.
# (We might have to dig into scapy field initialization mechanisms...)
# NEVER rely on the key below, which is provided only for debugging purposes.
class RSAPublicKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("modulus", 10),
        ASN1F_INTEGER("publicExponent", 3))


class RSAOtherPrimeInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("prime", 0),
        ASN1F_INTEGER("exponent", 0),
        ASN1F_INTEGER("coefficient", 0))


class RSAPrivateKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 0, ["two-prime", "multi"]),
        ASN1F_INTEGER("modulus", 10),
        ASN1F_INTEGER("publicExponent", 3),
        ASN1F_INTEGER("privateExponent", 3),
        ASN1F_INTEGER("prime1", 2),
        ASN1F_INTEGER("prime2", 5),
        ASN1F_INTEGER("exponent1", 0),
        ASN1F_INTEGER("exponent2", 3),
        ASN1F_INTEGER("coefficient", 1),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("otherPrimeInfos", None,
                              RSAOtherPrimeInfo)))

####################################
#      Diffie Hellman Packets      #
####################################
# From X9.42 (or RFC3279)


class ValidationParms(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_BIT_STRING("seed", ""),
        ASN1F_INTEGER("pgenCounter", 0),
    )


class DomainParameters(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("p", 0),
        ASN1F_INTEGER("g", 0),
        ASN1F_INTEGER("q", 0),
        ASN1F_optional(ASN1F_INTEGER("j", 0)),
        ASN1F_optional(
            ASN1F_PACKET("validationParms", None, ValidationParms),
        ),
    )


class DHPublicKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("y", 0)


####################################
#          ECDSA packets           #
####################################
# based on RFC 3279 & 5480 & 5915


class ECFieldID(ASN1_Packet):
    # No characteristic-two-field support for now.
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("fieldType", "prime-field"),
        ASN1F_INTEGER("prime", 0))


class ECCurve(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING("a", ""),
        ASN1F_STRING("b", ""),
        ASN1F_optional(
            ASN1F_BIT_STRING("seed", None)))


class ECSpecifiedDomain(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 1, {1: "ecpVer1"}),
        ASN1F_PACKET("fieldID", ECFieldID(), ECFieldID),
        ASN1F_PACKET("curve", ECCurve(), ECCurve),
        ASN1F_STRING("base", ""),
        ASN1F_INTEGER("order", 0),
        ASN1F_optional(
            ASN1F_INTEGER("cofactor", None)))


class ECParameters(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("curve", ASN1_OID("ansip384r1"),
                             ASN1F_OID,      # for named curves
                             ASN1F_NULL,     # for implicit curves
                             ECSpecifiedDomain)


class ECDSAPublicKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_BIT_STRING("ecPoint", "")


class ECDSAPrivateKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 1, {1: "ecPrivkeyVer1"}),
        ASN1F_STRING("privateKey", ""),
        ASN1F_optional(
            ASN1F_PACKET("parameters", None, ECParameters,
                         explicit_tag=0xa0)),
        ASN1F_optional(
            ASN1F_PACKET("publicKey", None,
                         ECDSAPublicKey,
                         explicit_tag=0xa1)))


class ECDSASignature(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("r", 0),
        ASN1F_INTEGER("s", 0))


####################################
#  Diffie Hellman Exchange Packets #
####################################
# based on PKCS#3

# PKCS#3 sect 9

class DHParameter(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("p", 0),
        ASN1F_INTEGER("g", 0),
        ASN1F_optional(
            ASN1F_INTEGER("l", 0)  # aka. 'privateValueLength'
        ),
    )


####################################
#      x25519/x448 packets         #
####################################
# based on RFC 8410

class EdDSAPublicKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_BIT_STRING("ecPoint", "")


class AlgorithmIdentifier(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("algorithm", None),
    )


class EdDSAPrivateKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 1, {1: "ecPrivkeyVer1"}),
        ASN1F_PACKET("privateKeyAlgorithm", AlgorithmIdentifier(), AlgorithmIdentifier),
        ASN1F_STRING("privateKey", ""),
        ASN1F_optional(
            ASN1F_PACKET("publicKey", None,
                         ECDSAPublicKey,
                         explicit_tag=0xa1)))


######################
#    X509 packets    #
######################
# based on RFC 5280


#       Names       #

class ASN1F_X509_DirectoryString(ASN1F_CHOICE):
    # we include ASN1 bit strings and bmp strings for rare instances of x500 addresses
    def __init__(self, name, default, **kwargs):
        ASN1F_CHOICE.__init__(self, name, default,
                              ASN1F_PRINTABLE_STRING, ASN1F_UTF8_STRING,
                              ASN1F_IA5_STRING, ASN1F_T61_STRING,
                              ASN1F_UNIVERSAL_STRING, ASN1F_BIT_STRING,
                              ASN1F_BMP_STRING,
                              **kwargs)


# More details on attributes in PKCS#9
_X509_ATTRIBUTE_TYPE = {}


class _AttributeValue_Field(ASN1F_field):
    def m2i(self, pkt, s):
        # Some types have special structures
        if pkt.underlayer:
            attrType = pkt.underlayer.type.val
            if attrType in _X509_ATTRIBUTE_TYPE:
                return self.extract_packet(
                    _X509_ATTRIBUTE_TYPE[attrType],
                    s,
                    _underlayer=pkt,
                )
        try:
            return super(_AttributeValue_Field, self).m2i(pkt, s)
        except BER_Decoding_Error:
            # Do not fail on special attributes
            return s, b""

    def i2m(self, pkt, x):
        # The special structures should be just bytes()
        if pkt.underlayer and pkt.underlayer.type.val in _X509_ATTRIBUTE_TYPE:
            return bytes(x)
        return super(_AttributeValue_Field, self).i2m(pkt, x)


class X509_AttributeValue(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = _AttributeValue_Field("value", ASN1_PRINTABLE_STRING("FR"))


class X509_Attribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("type", "2.5.4.6"),
        ASN1F_SET_OF("values",
                     [X509_AttributeValue()],
                     X509_AttributeValue))


class X509_AttributeTypeAndValue(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("type", "2.5.4.6"),
        ASN1F_X509_DirectoryString("value",
                                   ASN1_PRINTABLE_STRING("FR")))


class X509_RDN(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF("rdn", [X509_AttributeTypeAndValue()],
                             X509_AttributeTypeAndValue)


class X509_OtherName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("type_id", "0"),
        ASN1F_CHOICE("value", None,
                     ASN1F_IA5_STRING, ASN1F_ISO646_STRING,
                     ASN1F_BMP_STRING, ASN1F_UTF8_STRING,
                     ASN1F_STRING,
                     explicit_tag=0xa0))


class ASN1F_X509_otherName(ASN1F_SEQUENCE):
    # field version of X509_OtherName, for usage in [MS-WCCE]
    def __init__(self, **kargs):
        seq = [ASN1F_SEQUENCE(*X509_OtherName.ASN1_root.seq,
                              implicit_tag=0xA0)]
        ASN1F_SEQUENCE.__init__(self, *seq, **kargs)


class X509_RFC822Name(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_IA5_STRING("rfc822Name", "")


class X509_DNSName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_IA5_STRING("dNSName", "")

# XXX write me


class X509_X400Address(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_field("x400Address", "")


_default_directoryName = [
    X509_RDN(),
    X509_RDN(
        rdn=[X509_AttributeTypeAndValue(
            type=ASN1_OID("2.5.4.10"),
            value=ASN1_PRINTABLE_STRING("Scapy, Inc."))]),
    X509_RDN(
        rdn=[X509_AttributeTypeAndValue(
            type=ASN1_OID("2.5.4.3"),
            value=ASN1_PRINTABLE_STRING("Scapy Default Name"))])
]


class X509_DirectoryName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("directoryName", _default_directoryName,
                                  X509_RDN)


class X509_EDIPartyName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_X509_DirectoryString("nameAssigner", None,
                                       explicit_tag=0xa0)),
        ASN1F_X509_DirectoryString("partyName", None,
                                   explicit_tag=0xa1))


class X509_URI(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_IA5_STRING("uniformResourceIdentifier", "")


class X509_IPAddress(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING("iPAddress", "")


class X509_RegisteredID(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_OID("registeredID", "")


class X509_GeneralName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("generalName", X509_DirectoryName(),
                             ASN1F_PACKET("otherName", None, X509_OtherName,
                                          implicit_tag=0xa0),
                             ASN1F_PACKET("rfc822Name", None, X509_RFC822Name,
                                          implicit_tag=0x81),
                             ASN1F_PACKET("dNSName", None, X509_DNSName,
                                          implicit_tag=0x82),
                             ASN1F_PACKET("x400Address", None, X509_X400Address,  # noqa: E501
                                          explicit_tag=0xa3),
                             ASN1F_PACKET("directoryName", None, X509_DirectoryName,  # noqa: E501
                                          explicit_tag=0xa4),
                             ASN1F_PACKET("ediPartyName", None, X509_EDIPartyName,  # noqa: E501
                                          explicit_tag=0xa5),
                             ASN1F_PACKET("uniformResourceIdentifier", None, X509_URI,  # noqa: E501
                                          implicit_tag=0x86),
                             ASN1F_PACKET("ipAddress", None, X509_IPAddress,
                                          implicit_tag=0x87),
                             ASN1F_PACKET("registeredID", None, X509_RegisteredID,  # noqa: E501
                                          implicit_tag=0x88))


#       Extensions       #

class X509_ExtAuthorityKeyIdentifier(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_STRING("keyIdentifier", b"\xff" * 20,
                         implicit_tag=0x80)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("authorityCertIssuer", None,
                              X509_GeneralName,
                              implicit_tag=0xa1)),
        ASN1F_optional(
            ASN1F_INTEGER("authorityCertSerialNumber", None,
                          implicit_tag=0x82)))


class X509_ExtSubjectDirectoryAttributes(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("subjectDirectoryAttributes",
                                  [X509_Attribute()],
                                  X509_Attribute)


class X509_ExtSubjectKeyIdentifier(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING("keyIdentifier", "xff" * 20)


class X509_ExtFullName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("fullName", [X509_GeneralName()],
                                  X509_GeneralName, implicit_tag=0xa0)


class X509_ExtNameRelativeToCRLIssuer(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_PACKET("nameRelativeToCRLIssuer", X509_RDN(), X509_RDN,
                             implicit_tag=0xa1)


class X509_ExtDistributionPointName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("distributionPointName", None,
                             X509_ExtFullName, X509_ExtNameRelativeToCRLIssuer)


_reasons_mapping = ["unused",
                    "keyCompromise",
                    "cACompromise",
                    "affiliationChanged",
                    "superseded",
                    "cessationOfOperation",
                    "certificateHold",
                    "privilegeWithdrawn",
                    "aACompromise"]


class X509_ExtDistributionPoint(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_PACKET("distributionPoint",
                         X509_ExtDistributionPointName(),
                         X509_ExtDistributionPointName,
                         explicit_tag=0xa0)),
        ASN1F_optional(
            ASN1F_FLAGS("reasons", None, _reasons_mapping,
                        implicit_tag=0x81)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("cRLIssuer", None,
                              X509_GeneralName,
                              implicit_tag=0xa2)))


_ku_mapping = ["digitalSignature",
               "nonRepudiation",
               "keyEncipherment",
               "dataEncipherment",
               "keyAgreement",
               "keyCertSign",
               "cRLSign",
               "encipherOnly",
               "decipherOnly"]


class X509_ExtKeyUsage(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_FLAGS("keyUsage", "101", _ku_mapping)

    def get_keyUsage(self):
        return self.ASN1_root.get_flags(self)


class X509_ExtPrivateKeyUsagePeriod(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_GENERALIZED_TIME("notBefore",
                                   str(GeneralizedTime(-600)),
                                   implicit_tag=0x80)),
        ASN1F_optional(
            ASN1F_GENERALIZED_TIME("notAfter",
                                   str(GeneralizedTime(+86400)),
                                   implicit_tag=0x81)))


class X509_PolicyMapping(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("issuerDomainPolicy", None),
        ASN1F_OID("subjectDomainPolicy", None))


class X509_ExtPolicyMappings(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("policyMappings", [], X509_PolicyMapping)


class X509_ExtBasicConstraints(ASN1_Packet):
    # The cA field should not be optional, but some certs omit it for False.
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_BOOLEAN("cA", False)),
        ASN1F_optional(
            ASN1F_INTEGER("pathLenConstraint", None)))


class X509_ExtCRLNumber(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("cRLNumber", 0)


_cRL_reasons = ["unspecified",
                "keyCompromise",
                "cACompromise",
                "affiliationChanged",
                "superseded",
                "cessationOfOperation",
                "certificateHold",
                "unused_reasonCode",
                "removeFromCRL",
                "privilegeWithdrawn",
                "aACompromise"]


class X509_ExtReasonCode(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_ENUMERATED("cRLReason", 0, _cRL_reasons)


class X509_ExtDeltaCRLIndicator(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("deltaCRLIndicator", 0)


class X509_ExtIssuingDistributionPoint(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_PACKET("distributionPoint",
                         X509_ExtDistributionPointName(),
                         X509_ExtDistributionPointName,
                         explicit_tag=0xa0)),
        ASN1F_BOOLEAN("onlyContainsUserCerts", False,
                      implicit_tag=0x81),
        ASN1F_BOOLEAN("onlyContainsCACerts", False,
                      implicit_tag=0x82),
        ASN1F_optional(
            ASN1F_FLAGS("onlySomeReasons", None,
                        _reasons_mapping,
                        implicit_tag=0x83)),
        ASN1F_BOOLEAN("indirectCRL", False,
                      implicit_tag=0x84),
        ASN1F_BOOLEAN("onlyContainsAttributeCerts", False,
                      implicit_tag=0x85))


class X509_ExtCertificateIssuer(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("certificateIssuer", [], X509_GeneralName)


class X509_ExtInvalidityDate(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_GENERALIZED_TIME("invalidityDate", str(ZuluTime(+86400)))


class X509_ExtSubjectAltName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("subjectAltName", [], X509_GeneralName)


class X509_ExtIssuerAltName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("issuerAltName", [], X509_GeneralName)


class X509_ExtGeneralSubtree(ASN1_Packet):
    # 'minimum' is not optional in RFC 5280, yet it is in some implementations.
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("base", X509_GeneralName(), X509_GeneralName),
        ASN1F_optional(
            ASN1F_INTEGER("minimum", None, implicit_tag=0x80)),
        ASN1F_optional(
            ASN1F_INTEGER("maximum", None, implicit_tag=0x81)))


class X509_ExtNameConstraints(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("permittedSubtrees", None,
                              X509_ExtGeneralSubtree,
                              implicit_tag=0xa0)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("excludedSubtrees", None,
                              X509_ExtGeneralSubtree,
                              implicit_tag=0xa1)))


class X509_ExtPolicyConstraints(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_INTEGER("requireExplicitPolicy", None,
                          implicit_tag=0x80)),
        ASN1F_optional(
            ASN1F_INTEGER("inhibitPolicyMapping", None,
                          implicit_tag=0x81)))


class X509_ExtExtendedKeyUsage(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("extendedKeyUsage", [], ASN1P_OID)

    def get_extendedKeyUsage(self):
        eku_array = self.extendedKeyUsage
        return [eku.oid.oidname for eku in eku_array]


class X509_ExtNoticeReference(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_CHOICE("organization",
                     ASN1_UTF8_STRING("Dummy Organization"),
                     ASN1F_IA5_STRING, ASN1F_ISO646_STRING,
                     ASN1F_BMP_STRING, ASN1F_UTF8_STRING),
        ASN1F_SEQUENCE_OF("noticeNumbers", [], ASN1P_INTEGER))


class X509_ExtUserNotice(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_PACKET("noticeRef", None,
                         X509_ExtNoticeReference)),
        ASN1F_optional(
            ASN1F_CHOICE("explicitText",
                         ASN1_UTF8_STRING("Dummy ExplicitText"),
                         ASN1F_IA5_STRING, ASN1F_ISO646_STRING,
                         ASN1F_BMP_STRING, ASN1F_UTF8_STRING)))


class X509_ExtPolicyQualifierInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("policyQualifierId", "1.3.6.1.5.5.7.2.1"),
        ASN1F_CHOICE("qualifier", ASN1_IA5_STRING("cps_str"),
                     ASN1F_IA5_STRING, X509_ExtUserNotice))


class X509_ExtPolicyInformation(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("policyIdentifier", "2.5.29.32.0"),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("policyQualifiers", None,
                              X509_ExtPolicyQualifierInfo)))


class X509_ExtCertificatePolicies(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("certificatePolicies",
                                  [X509_ExtPolicyInformation()],
                                  X509_ExtPolicyInformation)


class X509_ExtCRLDistributionPoints(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("cRLDistributionPoints",
                                  [X509_ExtDistributionPoint()],
                                  X509_ExtDistributionPoint)


class X509_ExtInhibitAnyPolicy(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("skipCerts", 0)


class X509_ExtFreshestCRL(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("cRLDistributionPoints",
                                  [X509_ExtDistributionPoint()],
                                  X509_ExtDistributionPoint)


class X509_AccessDescription(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("accessMethod", "0"),
        ASN1F_PACKET("accessLocation", X509_GeneralName(),
                     X509_GeneralName))


class X509_ExtAuthInfoAccess(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("authorityInfoAccess",
                                  [X509_AccessDescription()],
                                  X509_AccessDescription)


class X509_ExtQcStatement(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("statementId", "0.4.0.1862.1.1"),
        ASN1F_optional(
            ASN1F_field("statementInfo", None)))


class X509_ExtQcStatements(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("qcStatements",
                                  [X509_ExtQcStatement()],
                                  X509_ExtQcStatement)


class X509_ExtSubjInfoAccess(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("subjectInfoAccess",
                                  [X509_AccessDescription()],
                                  X509_AccessDescription)


class X509_ExtNetscapeCertType(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_BIT_STRING("netscapeCertType", "")


class X509_ExtComment(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("comment",
                             ASN1_UTF8_STRING("Dummy comment."),
                             ASN1F_IA5_STRING, ASN1F_ISO646_STRING,
                             ASN1F_BMP_STRING, ASN1F_UTF8_STRING)


class X509_ExtCertificateTemplateName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_BMP_STRING("Name", b"")


class X509_ExtOidNTDSCaSecurity(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_X509_otherName()
    type_id = ASN1_OID("1.3.6.1.4.1.311.25.2.1")
    value = ASN1_UTF8_STRING("")


# [MS-WCCE] sect 2.2.2.7.7.2

class X509_ExtCertificateTemplateOID(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("templateID", "0"),
        ASN1F_optional(
            ASN1F_INTEGER("templateMajorVersion", 0),
        ),
        ASN1F_optional(
            ASN1F_INTEGER("templateMinorVersion", 0),
        ),
    )


# oid-info.com shows that some extensions share multiple OIDs.
# Here we only reproduce those written in RFC5280.
_ext_mapping = {
    "2.5.29.9": X509_ExtSubjectDirectoryAttributes,
    "2.5.29.14": X509_ExtSubjectKeyIdentifier,
    "2.5.29.15": X509_ExtKeyUsage,
    "2.5.29.16": X509_ExtPrivateKeyUsagePeriod,
    "2.5.29.17": X509_ExtSubjectAltName,
    "2.5.29.18": X509_ExtIssuerAltName,
    "2.5.29.19": X509_ExtBasicConstraints,
    "2.5.29.20": X509_ExtCRLNumber,
    "2.5.29.21": X509_ExtReasonCode,
    "2.5.29.24": X509_ExtInvalidityDate,
    "2.5.29.27": X509_ExtDeltaCRLIndicator,
    "2.5.29.28": X509_ExtIssuingDistributionPoint,
    "2.5.29.29": X509_ExtCertificateIssuer,
    "2.5.29.30": X509_ExtNameConstraints,
    "2.5.29.31": X509_ExtCRLDistributionPoints,
    "2.5.29.32": X509_ExtCertificatePolicies,
    "2.5.29.33": X509_ExtPolicyMappings,
    "2.5.29.35": X509_ExtAuthorityKeyIdentifier,
    "2.5.29.36": X509_ExtPolicyConstraints,
    "2.5.29.37": X509_ExtExtendedKeyUsage,
    "2.5.29.46": X509_ExtFreshestCRL,
    "2.5.29.54": X509_ExtInhibitAnyPolicy,
    "2.16.840.1.113730.1.1": X509_ExtNetscapeCertType,
    "2.16.840.1.113730.1.13": X509_ExtComment,
    "1.3.6.1.4.1.311.20.2": X509_ExtCertificateTemplateName,
    "1.3.6.1.4.1.311.21.7": X509_ExtCertificateTemplateOID,
    "1.3.6.1.4.1.311.21.10": X509_ExtCertificatePolicies,
    "1.3.6.1.4.1.311.25.2": X509_ExtOidNTDSCaSecurity,
    "1.3.6.1.5.5.7.1.1": X509_ExtAuthInfoAccess,
    "1.3.6.1.5.5.7.1.3": X509_ExtQcStatements,
    "1.3.6.1.5.5.7.1.11": X509_ExtSubjInfoAccess
}


class _X509_ExtField(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_X509_ExtField, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.extnID.val in _ext_mapping:
            return (
                _ext_mapping[pkt.extnID.val](val[0].val, _underlayer=pkt),
                val[1],
            )
        return val


class ASN1F_EXT_SEQUENCE(ASN1F_SEQUENCE):
    def __init__(self, **kargs):
        seq = [ASN1F_OID("extnID", "2.5.29.19"),
               ASN1F_optional(
                   ASN1F_BOOLEAN("critical", False)),
               _X509_ExtField("extnValue", X509_ExtBasicConstraints())]
        ASN1F_SEQUENCE.__init__(self, *seq, **kargs)


class X509_Extension(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_EXT_SEQUENCE()


class X509_Extensions(ASN1_Packet):
    # we use this in OCSP status requests, in tls/handshake.py
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_optional(
        ASN1F_SEQUENCE_OF("extensions",
                          None, X509_Extension))


# Aka 'ExtensionReq' in CMS
_X509_ATTRIBUTE_TYPE["1.2.840.113549.1.9.14"] = X509_Extensions


#       Public key wrapper       #

class X509_AlgorithmIdentifier(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("algorithm", "1.2.840.113549.1.1.11"),
        MultipleTypeField(
            [
                (
                    # RFC4055:
                    # "The correct encoding is to omit the parameters field"
                    # "All implementations MUST accept both NULL and absent
                    # parameters as legal and equivalent encodings."

                    # RFC8017:
                    # "should generally be omitted, but if present, it shall have a
                    # value of type NULL."
                    ASN1F_optional(ASN1F_NULL("parameters", None)),
                    lambda pkt: (
                        pkt.algorithm.val[:19] == "1.2.840.113549.1.1." or
                        pkt.algorithm.val[:21] == "2.16.840.1.101.3.4.2." or
                        pkt.algorithm.val[:11] == "1.3.14.3.2."
                    )
                ),
                (
                    # RFC5758:
                    # "the encoding MUST omit the parameters field"

                    # RFC8410:
                    # "For all of the OIDs, the parameters MUST be absent."
                    ASN1F_omit("parameters", None),
                    lambda pkt: (
                        pkt.algorithm.val[:16] == "1.2.840.10045.4." or
                        pkt.algorithm.val in ["1.3.101.112", "1.3.101.113"]
                    )
                ),
                # RFC5480
                (
                    ASN1F_PACKET(
                        "parameters",
                        ECParameters(),
                        ECParameters,
                    ),
                    lambda pkt: pkt.algorithm.val == "1.2.840.10045.2.1",
                ),
                # RFC3279
                (
                    ASN1F_PACKET(
                        "parameters",
                        DomainParameters(),
                        DomainParameters,
                    ),
                    lambda pkt: pkt.algorithm.val == "1.2.840.10046.2.1",
                ),
                # PKCS#3
                (
                    ASN1F_PACKET(
                        "parameters",
                        DHParameter(),
                        DHParameter,
                    ),
                    lambda pkt: pkt.algorithm.val == "1.2.840.113549.1.3.1",
                ),
                # TripleDES
                (
                    ASN1F_STRING(
                        "parameters",
                        "",
                    ),
                    lambda pkt: pkt.algorithm.val == "1.2.840.113549.3.7",
                ),
            ],
            # Default: fail, probably. This is most likely unimplemented.
            ASN1F_NULL("parameters", 0),
        )
    )


class ASN1F_X509_SubjectPublicKeyInfo(ASN1F_SEQUENCE):
    def __init__(self, **kargs):
        seq = [ASN1F_PACKET("signatureAlgorithm",
                            X509_AlgorithmIdentifier(),
                            X509_AlgorithmIdentifier),
               MultipleTypeField(
                   [
                       (ASN1F_BIT_STRING_ENCAPS("subjectPublicKey",
                                                RSAPublicKey(),
                                                RSAPublicKey),
                        lambda pkt: "rsa" in pkt.signatureAlgorithm.algorithm.oidname.lower()),  # noqa: E501
                       (ASN1F_PACKET("subjectPublicKey",
                                     ECDSAPublicKey(),
                                     ECDSAPublicKey),
                        lambda pkt: "ecPublicKey" == pkt.signatureAlgorithm.algorithm.oidname),  # noqa: E501
                       (ASN1F_BIT_STRING_ENCAPS("subjectPublicKey",
                                                DHPublicKey(),
                                                DHPublicKey),
                        lambda pkt: "dhpublicnumber" == pkt.signatureAlgorithm.algorithm.oidname),  # noqa: E501
                       (ASN1F_PACKET("subjectPublicKey",
                                     EdDSAPublicKey(),
                                     EdDSAPublicKey),
                        lambda pkt: pkt.signatureAlgorithm.algorithm.oidname in ["Ed25519", "Ed448"]),  # noqa: E501
                   ],
                   ASN1F_BIT_STRING("subjectPublicKey", ""))]
        ASN1F_SEQUENCE.__init__(self, *seq, **kargs)


class X509_SubjectPublicKeyInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_X509_SubjectPublicKeyInfo()


#      OpenSSL compatibility wrappers      #

# XXX As ECDSAPrivateKey already uses the structure from RFC 5958,
# and as we would prefer encapsulated RSA private keys to be parsed,
# this lazy implementation actually supports RSA encoding only.
# We'd rather call it RSAPrivateKey_OpenSSL than X509_PrivateKeyInfo.
class RSAPrivateKey_OpenSSL(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 0, ["v1", "v2"]),
        ASN1F_PACKET("privateKeyAlgorithm",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_PACKET("privateKey",
                     RSAPrivateKey(),
                     RSAPrivateKey,
                     explicit_tag=0x04),
        ASN1F_optional(
            ASN1F_PACKET("parameters", None, ECParameters,
                         explicit_tag=0xa0)),
        ASN1F_optional(
            ASN1F_PACKET("publicKey", None,
                         ECDSAPublicKey,
                         explicit_tag=0xa1)))

# We need this hack because ECParameters parsing below must return
# a Padding payload, and making the ASN1_Packet class have Padding
# instead of Raw payload would break things...


class _PacketFieldRaw(PacketField):
    def getfield(self, pkt, s):
        i = self.m2i(pkt, s)
        remain = ""
        if conf.raw_layer in i:
            r = i[conf.raw_layer]
            del r.underlayer.payload
            remain = r.load
        return remain, i


class ECDSAPrivateKey_OpenSSL(Packet):
    name = "ECDSA Params + Private Key"
    fields_desc = [_PacketFieldRaw("ecparam",
                                   ECParameters(),
                                   ECParameters),
                   PacketField("privateKey",
                               ECDSAPrivateKey(),
                               ECDSAPrivateKey)]


#       TBSCertificate & Certificate       #

_default_issuer = [
    X509_RDN(),
    X509_RDN(
        rdn=[X509_AttributeTypeAndValue(
            type=ASN1_OID("2.5.4.10"),
            value=ASN1_PRINTABLE_STRING("Scapy, Inc."))]),
    X509_RDN(
        rdn=[X509_AttributeTypeAndValue(
            type=ASN1_OID("2.5.4.3"),
            value=ASN1_PRINTABLE_STRING("Scapy Default Issuer"))])
]

_default_subject = [
    X509_RDN(),
    X509_RDN(
        rdn=[X509_AttributeTypeAndValue(
            type=ASN1_OID("2.5.4.10"),
            value=ASN1_PRINTABLE_STRING("Scapy, Inc."))]),
    X509_RDN(
        rdn=[X509_AttributeTypeAndValue(
            type=ASN1_OID("2.5.4.3"),
            value=ASN1_PRINTABLE_STRING("Scapy Default Subject"))])
]


class _IssuerUtils:
    def get_issuer(self):
        attrs = self.issuer
        attrsDict = {}
        for attr in attrs:
            # we assume there is only one name in each rdn ASN1_SET
            attrsDict[attr.rdn[0].type.oidname] = plain_str(attr.rdn[0].value.val)  # noqa: E501
        return attrsDict

    def get_issuer_str(self):
        """
        Returns a one-line string containing every type/value
        in a rather specific order. sorted() built-in ensures unicity.
        """
        name_str = ""
        attrsDict = self.get_issuer()
        for attrType, attrSymbol in _attrName_mapping:
            if attrType in attrsDict:
                name_str += "/" + attrSymbol + "="
                name_str += attrsDict[attrType]
        for attrType in sorted(attrsDict):
            if attrType not in _attrName_specials:
                name_str += "/" + attrType + "="
                name_str += attrsDict[attrType]
        return name_str


class X509_Validity(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_CHOICE("not_before",
                     ASN1_UTC_TIME(str(ZuluTime(-600))),
                     ASN1F_UTC_TIME, ASN1F_GENERALIZED_TIME),
        ASN1F_CHOICE("not_after",
                     ASN1_UTC_TIME(str(ZuluTime(+86400))),
                     ASN1F_UTC_TIME, ASN1F_GENERALIZED_TIME))


_attrName_mapping = [
    ("countryName", "C"),
    ("stateOrProvinceName", "ST"),
    ("localityName", "L"),
    ("organizationName", "O"),
    ("organizationUnitName", "OU"),
    ("commonName", "CN")
]
_attrName_specials = [name for name, symbol in _attrName_mapping]


class X509_TBSCertificate(ASN1_Packet, _IssuerUtils):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_enum_INTEGER("version", 0x2, ["v1", "v2", "v3"],
                               explicit_tag=0xa0)),
        ASN1F_INTEGER("serialNumber", 1),
        ASN1F_PACKET("signature",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_SEQUENCE_OF("issuer", _default_issuer, X509_RDN),
        ASN1F_PACKET("validity",
                     X509_Validity(),
                     X509_Validity),
        ASN1F_SEQUENCE_OF("subject", _default_subject, X509_RDN),
        ASN1F_PACKET("subjectPublicKeyInfo",
                     X509_SubjectPublicKeyInfo(),
                     X509_SubjectPublicKeyInfo),
        ASN1F_optional(
            ASN1F_BIT_STRING("issuerUniqueID", None,
                             implicit_tag=0x81)),
        ASN1F_optional(
            ASN1F_BIT_STRING("subjectUniqueID", None,
                             implicit_tag=0x82)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("extensions",
                              [X509_Extension()],
                              X509_Extension,
                              explicit_tag=0xa3)))

    def get_subject(self):
        attrs = self.subject
        attrsDict = {}
        for attr in attrs:
            # we assume there is only one name in each rdn ASN1_SET
            attrsDict[attr.rdn[0].type.oidname] = plain_str(attr.rdn[0].value.val)  # noqa: E501
        return attrsDict

    def get_subject_str(self):
        name_str = ""
        attrsDict = self.get_subject()
        for attrType, attrSymbol in _attrName_mapping:
            if attrType in attrsDict:
                name_str += "/" + attrSymbol + "="
                name_str += attrsDict[attrType]
        for attrType in sorted(attrsDict):
            if attrType not in _attrName_specials:
                name_str += "/" + attrType + "="
                name_str += attrsDict[attrType]
        return name_str


class ASN1F_X509_Cert(ASN1F_SEQUENCE):
    def __init__(self, **kargs):
        seq = [ASN1F_PACKET("tbsCertificate",
                            X509_TBSCertificate(),
                            X509_TBSCertificate),
               ASN1F_PACKET("signatureAlgorithm",
                            X509_AlgorithmIdentifier(),
                            X509_AlgorithmIdentifier),
               MultipleTypeField(
                   [
                       (ASN1F_BIT_STRING_ENCAPS("signatureValue",
                                                ECDSASignature(),
                                                ECDSASignature),
                        lambda pkt: "ecdsa" in pkt.signatureAlgorithm.algorithm.oidname.lower()),  # noqa: E501
                   ],
                   ASN1F_BIT_STRING("signatureValue",
                                    "defaultsignature" * 2))]
        ASN1F_SEQUENCE.__init__(self, *seq, **kargs)


class X509_Cert(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_X509_Cert()


#       TBSCertList & CRL       #

class X509_RevokedCertificate(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(ASN1F_INTEGER("serialNumber", 1),
                               ASN1F_UTC_TIME("revocationDate",
                                              str(ZuluTime(+86400))),
                               ASN1F_optional(
                                   ASN1F_SEQUENCE_OF("crlEntryExtensions",
                                                     None, X509_Extension)))


class X509_TBSCertList(ASN1_Packet, _IssuerUtils):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_enum_INTEGER("version", 1, ["v1", "v2"])),
        ASN1F_PACKET("signature",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_SEQUENCE_OF("issuer", _default_issuer, X509_RDN),
        ASN1F_UTC_TIME("this_update", str(ZuluTime(-1))),
        ASN1F_optional(
            ASN1F_UTC_TIME("next_update", None)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("revokedCertificates", None,
                              X509_RevokedCertificate)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("crlExtensions", None,
                              X509_Extension,
                              explicit_tag=0xa0)))


class ASN1F_X509_CRL(ASN1F_SEQUENCE):
    def __init__(self, **kargs):
        seq = [ASN1F_PACKET("tbsCertList",
                            X509_TBSCertList(),
                            X509_TBSCertList),
               ASN1F_PACKET("signatureAlgorithm",
                            X509_AlgorithmIdentifier(),
                            X509_AlgorithmIdentifier),
               MultipleTypeField(
                   [
                       (ASN1F_BIT_STRING_ENCAPS("signatureValue",
                                                ECDSASignature(),
                                                ECDSASignature),
                        lambda pkt: "ecdsa" in pkt.signatureAlgorithm.algorithm.oidname.lower()),  # noqa: E501
                   ],
                   ASN1F_BIT_STRING("signatureValue",
                                    "defaultsignature" * 2))]
        ASN1F_SEQUENCE.__init__(self, *seq, **kargs)


class X509_CRL(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_X509_CRL()


#####################
#    CMS packets    #
#####################
# based on RFC 3852

CMSVersion = ASN1F_INTEGER

# RFC3852 sect 5.2

# Other layers should store the structures that can be encapsulated
# by CMS here, referred by their OIDs.
_CMS_ENCAPSULATED = {}


class _EncapsulatedContent_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_EncapsulatedContent_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val

        # Get encapsulated value from its type
        if pkt.eContentType.val in _CMS_ENCAPSULATED:
            return (
                _CMS_ENCAPSULATED[pkt.eContentType.val](val[0].val, _underlayer=pkt),
                val[1],
            )

        return val


class CMS_EncapsulatedContentInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("eContentType", "0"),
        ASN1F_optional(
            _EncapsulatedContent_Field("eContent", None,
                                       explicit_tag=0xA0),
        ),
    )


# RFC3852 sect 10.2.1

class CMS_RevocationInfoChoice(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "crl", None,
        ASN1F_PACKET("crl", X509_CRL(), X509_Cert),
        # -- TODO: 1
    )


# RFC3852 sect 10.2.2

class CMS_CertificateChoices(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "certificate", None,
        ASN1F_PACKET("certificate", X509_Cert(), X509_Cert),
        # -- TODO: 0, 1, 2
    )


# RFC3852 sect 10.2.4

class CMS_IssuerAndSerialNumber(ASN1_Packet, _IssuerUtils):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE_OF("issuer", _default_issuer, X509_RDN),
        ASN1F_INTEGER("serialNumber", 0)
    )


# RFC3852 sect 10.2.7

class CMS_OtherKeyAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("keyAttrId", "0"),
        ASN1F_field("keyAttr", 0),
    )


# RFC3852 sect 5.3


class CMS_SubjectKeyIdentifier(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING("sid", "")


class CMS_SignerInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        CMSVersion("version", 1),
        ASN1F_CHOICE(
            "sid",
            CMS_IssuerAndSerialNumber(),
            ASN1F_PACKET("sid", CMS_IssuerAndSerialNumber(),
                         CMS_IssuerAndSerialNumber),
            ASN1F_PACKET("sid", CMS_SubjectKeyIdentifier(),
                         CMS_SubjectKeyIdentifier,
                         implicit_tag=0x80),
        ),
        ASN1F_PACKET("digestAlgorithm", X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_optional(
            ASN1F_SET_OF(
                "signedAttrs",
                None,
                X509_Attribute,
                implicit_tag=0xA0,
            )
        ),
        ASN1F_PACKET("signatureAlgorithm", X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_STRING("signature", ASN1_UTF8_STRING("")),
        ASN1F_optional(
            ASN1F_SET_OF(
                "unsignedAttrs",
                None,
                X509_Attribute,
                implicit_tag=0xA1,
            )
        )
    )


# RFC3852 sect 5.4

class CMS_SignedAttrsForSignature(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF(
        "signedAttrs",
        None,
        X509_Attribute,
    )


# RFC3852 sect 5.1

class CMS_SignedData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        CMSVersion("version", 1),
        ASN1F_SET_OF("digestAlgorithms", [], X509_AlgorithmIdentifier),
        ASN1F_PACKET("encapContentInfo", CMS_EncapsulatedContentInfo(),
                     CMS_EncapsulatedContentInfo),
        ASN1F_optional(
            ASN1F_SET_OF(
                "certificates",
                None,
                CMS_CertificateChoices,
                implicit_tag=0xA0,
            )
        ),
        ASN1F_optional(
            ASN1F_SET_OF(
                "crls",
                None,
                CMS_RevocationInfoChoice,
                implicit_tag=0xA1,
            )
        ),
        ASN1F_SET_OF(
            "signerInfos",
            [],
            CMS_SignerInfo,
        ),
    )


# RFC3852 sect 6.2.1

class CMS_KeyTransRecipientInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        CMSVersion("version", 0),
        ASN1F_CHOICE(
            "rid",
            CMS_IssuerAndSerialNumber(),
            ASN1F_PACKET("rid", CMS_IssuerAndSerialNumber(),
                         CMS_IssuerAndSerialNumber),
            ASN1F_PACKET("rid", CMS_SubjectKeyIdentifier(),
                         CMS_SubjectKeyIdentifier,
                         implicit_tag=0x80),
        ),
        ASN1F_PACKET("keyEncryptionAlgorithm",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_STRING("encryptedKey", ""),
    )


# RFC3852 sect 6.2.2

class CMS_OriginatorPublicKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("algorithm",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_BIT_STRING("publicKey", ""),
    )


class CMS_OriginatorIdentifierOrKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "originator",
        CMS_IssuerAndSerialNumber(),
        ASN1F_PACKET("issuerAndSerialNumber", CMS_IssuerAndSerialNumber(),
                     CMS_IssuerAndSerialNumber),
        ASN1F_PACKET("subjectKeyIdentifier", CMS_SubjectKeyIdentifier(),
                     CMS_SubjectKeyIdentifier,
                     implicit_tag=0x80),
        ASN1F_PACKET("originatorKey", CMS_OriginatorPublicKey(),
                     CMS_OriginatorPublicKey,
                     implicit_tag=0xA1),
    )


class CMS_RecipientEncryptedKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("subjectKeyIdentifier", CMS_SubjectKeyIdentifier(),
                     CMS_SubjectKeyIdentifier),
        ASN1F_optional(
            ASN1F_GENERALIZED_TIME("date", ""),
        ),
        ASN1F_optional(
            ASN1F_PACKET("other", CMS_OtherKeyAttribute(), CMS_OtherKeyAttribute),
        ),
    )


class CMS_KeyAgreeRecipientInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        CMSVersion("version", 3),
        ASN1F_PACKET("originator", CMS_OriginatorIdentifierOrKey(),
                     CMS_OriginatorIdentifierOrKey,
                     explicit_tag=0xA0),
        ASN1F_optional(
            ASN1F_STRING("ukm", None, "",
                         explicit_tag=0x81),
        ),
        ASN1F_PACKET("keyEncryptionAlgorithm",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_SEQUENCE_OF("recipientEncryptedKeys", [], CMS_RecipientEncryptedKey),
    )


# RFC3852 sect 6.2

class CMS_RecipientInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "recipientInfo",
        CMS_KeyTransRecipientInfo(),
        ASN1F_PACKET("ktri", CMS_KeyTransRecipientInfo(), CMS_KeyTransRecipientInfo),
        ASN1F_PACKET("kari", CMS_KeyAgreeRecipientInfo(), CMS_KeyAgreeRecipientInfo,
                     implicit_tag=0xA1),
    )


# RFC3852 sect 6.1

class CMS_OriginatorInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_SET_OF(
                "certs",
                None,
                CMS_CertificateChoices,
                implicit_tag=0xA0,
            )
        ),
        ASN1F_optional(
            ASN1F_SET_OF(
                "crls",
                None,
                CMS_RevocationInfoChoice,
                implicit_tag=0xA1,
            )
        ),
    )


class CMS_EncryptedContentInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("contentType", "1.2.840.113549.1.7.2"),
        ASN1F_PACKET("contentEncryptionAlgorithm",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_optional(
            ASN1F_STRING("encryptedContent", "",
                         implicit_tag=0x80),
        )
    )


class CMS_EnvelopedData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        CMSVersion("version", 1),
        ASN1F_optional(
            ASN1F_PACKET("originatorInfo", None, CMS_OriginatorInfo,
                         implicit_tag=0xA0),
        ),
        ASN1F_SET_OF("recipientInfos", CMS_RecipientInfo(), CMS_RecipientInfo),
        ASN1F_PACKET("encryptedContentInfo", CMS_EncryptedContentInfo(),
                     CMS_EncryptedContentInfo),
        ASN1F_optional(
            ASN1F_SET_OF("unprotectedAttrs", [], X509_Attribute,
                         implicit_tag=0xA1),
        )
    )


# RFC3852 sect 3

class CMS_ContentInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("contentType", "1.2.840.113549.1.7.2"),
        MultipleTypeField(
            [
                (
                    ASN1F_PACKET("content", None, CMS_SignedData,
                                 explicit_tag=0xA0),
                    lambda pkt: pkt.contentType.oidname == "id-signedData"
                ),
                (
                    ASN1F_PACKET("content", None, CMS_EnvelopedData,
                                 explicit_tag=0xA0),
                    lambda pkt: pkt.contentType.oidname == "id-envelopedData"
                ),
            ],
            ASN1F_BIT_STRING("content", "", explicit_tag=0xA0)
        )
    )


#####################
#    CSR packets    #
#####################

#       based on PKCS#10       #


class PKCS10_CertificationRequestInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("version", 0),
        ASN1F_SEQUENCE_OF("subject", _default_subject, X509_RDN),
        ASN1F_PACKET("subjectPublicKeyInfo",
                     X509_SubjectPublicKeyInfo(),
                     X509_SubjectPublicKeyInfo),
        ASN1F_SET_OF("attributes", [], X509_Attribute,
                     implicit_tag=0xA0),
    )

    get_subject = X509_TBSCertificate.get_subject
    get_subject_str = X509_TBSCertificate.get_subject_str


class PKCS10_CertificationRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("certificationRequestInfo", PKCS10_CertificationRequestInfo(),
                     PKCS10_CertificationRequestInfo),
        ASN1F_PACKET("signatureAlgorithm", X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_BIT_STRING("signature", ASN1F_BIT_STRING("", "")),
    )


#       based on CMC       #

# RFC 5272 sect 3.2.1.1

class CMC_TaggedAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("bodyPartID", 0),
        ASN1F_OID("type", "0"),  # attrType for compat
        ASN1F_SET_OF("attrValues", [], X509_AttributeValue),
    )


# RFC 5272 sect 3.2.1.2.1

class CMC_TaggedCertificationRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("bodyPartID", 0),
        ASN1F_PACKET("certificationRequest", PKCS10_CertificationRequest(),
                     PKCS10_CertificationRequest)
    )


# RFC 5272 sect 3.2.1.2

class CMC_TaggedRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "request", CMC_TaggedCertificationRequest(),
        ASN1F_PACKET("tcr", CMC_TaggedCertificationRequest(),
                     CMC_TaggedCertificationRequest,
                     implicit_tag=0xA0),
        # XXX there are others
    )


# RFC 5272 sect 3.2.1.3

class CMC_TaggedContentInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("bodyPartID", 0),
        ASN1F_PACKET("contentInfo", CMS_ContentInfo(),
                     CMS_ContentInfo)
    )


# RFC 5272 sect 3.2.1.4

class CMC_OtherMsg(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("bodyPartID", 0),
        ASN1F_OID("otherMsgType", "0"),
        ASN1F_field("otherMsgValue", ""),
    )


# RFC 5272 sect 3.2.1

class CMC_PKIData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE_OF("controlSequence", [], CMC_TaggedAttribute),
        ASN1F_SEQUENCE_OF("reqSequence", [], CMC_TaggedRequest),
        ASN1F_SEQUENCE_OF("cmsSequence", [], CMC_TaggedContentInfo),
        ASN1F_SEQUENCE_OF("otherMsgSequence", [], CMC_OtherMsg),
    )


_CMS_ENCAPSULATED["1.3.6.1.5.5.7.12.2"] = CMC_PKIData


#       Windows extensions       #

# https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cmc-extensions

class CMC_AddExtensions(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("pkiDataReference", 0),
        ASN1F_SEQUENCE_OF("certReferences", [], ASN1F_INTEGER),
        ASN1F_PACKET("extensions", X509_Extensions(), X509_Extensions),
    )


_X509_ATTRIBUTE_TYPE["1.3.6.1.5.5.7.7.8"] = CMC_AddExtensions


# https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cmc-attributes

class CMC_AddAttributes(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("pkiDataReference", 0),
        ASN1F_SEQUENCE_OF("certReferences", [], ASN1F_INTEGER),
        ASN1F_SET_OF("attributes", X509_Attribute(), X509_Attribute),
    )


_X509_ATTRIBUTE_TYPE["1.3.6.1.4.1.311.10.10.1"] = CMC_AddAttributes


# [MS-WCCE] sect 2.2.2.7.2

class CMC_ENROLLMENT_CSP_PROVIDER(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("KeySpec", 0),
        ASN1F_BMP_STRING("ProviderName", ""),
        ASN1F_BIT_STRING("Signature", ""),
    )


_X509_ATTRIBUTE_TYPE["1.3.6.1.4.1.311.13.2.2"] = CMC_ENROLLMENT_CSP_PROVIDER


# [MS-WCCE] sect 2.2.2.7.4

class CMC_REQUEST_CLIENT_INFO(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("clientId", 0),
        ASN1F_UTF8_STRING("MachineName", ""),
        ASN1F_UTF8_STRING("UserName", ""),
        ASN1F_UTF8_STRING("ProcessName", ""),
    )


_X509_ATTRIBUTE_TYPE["1.3.6.1.4.1.311.21.20"] = CMC_REQUEST_CLIENT_INFO


# [MS-WCCE] sect 2.2.2.7.10

class CMC_EnrollmentNameValuePair(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_BMP_STRING("Name", ""),
        ASN1F_BMP_STRING("Value", ""),
    )


_X509_ATTRIBUTE_TYPE["1.3.6.1.4.1.311.13.2.1"] = CMC_EnrollmentNameValuePair


# [MS-WCCE] sect 2.2.2.7.12

class CMC_ENROLL_ATTESTATION_STATEMENT(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING_ENCAPS("kas", KeyAttestationStatement(),
                                    KeyAttestationStatement)


_X509_ATTRIBUTE_TYPE["1.3.6.1.4.1.311.21.24"] = CMC_ENROLL_ATTESTATION_STATEMENT


# [MS-WCCE] sect 2.2.2.7.13

_X509_ATTRIBUTE_TYPE["1.3.6.1.4.1.311.21.23"] = CMS_ContentInfo


#############################
#    OCSP Status packets    #
#############################
# based on RFC 6960

class OCSP_CertID(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("hashAlgorithm",
                     X509_AlgorithmIdentifier(),
                     X509_AlgorithmIdentifier),
        ASN1F_STRING("issuerNameHash", ""),
        ASN1F_STRING("issuerKeyHash", ""),
        ASN1F_INTEGER("serialNumber", 0))


class OCSP_GoodInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_NULL("info", 0)


class OCSP_RevokedInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_GENERALIZED_TIME("revocationTime", ""),
        ASN1F_optional(
            ASN1F_PACKET("revocationReason", None,
                         X509_ExtReasonCode,
                         explicit_tag=0xa0)))


class OCSP_UnknownInfo(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_NULL("info", 0)


class OCSP_CertStatus(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("certStatus", None,
                             ASN1F_PACKET("good", OCSP_GoodInfo(),
                                          OCSP_GoodInfo, implicit_tag=0x80),
                             ASN1F_PACKET("revoked", OCSP_RevokedInfo(),
                                          OCSP_RevokedInfo, implicit_tag=0xa1),
                             ASN1F_PACKET("unknown", OCSP_UnknownInfo(),
                                          OCSP_UnknownInfo, implicit_tag=0x82))


class OCSP_SingleResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("certID", OCSP_CertID(), OCSP_CertID),
        ASN1F_PACKET("certStatus", OCSP_CertStatus(certStatus=OCSP_GoodInfo()),
                     OCSP_CertStatus),
        ASN1F_GENERALIZED_TIME("thisUpdate", ""),
        ASN1F_optional(
            ASN1F_GENERALIZED_TIME("nextUpdate", "",
                                   explicit_tag=0xa0)),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("singleExtensions", None,
                              X509_Extension,
                              explicit_tag=0xa1)))


class OCSP_ByName(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("byName", [], X509_RDN)


class OCSP_ByKey(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING("byKey", "")


class OCSP_ResponderID(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("responderID", None,
                             ASN1F_PACKET("byName", OCSP_ByName(), OCSP_ByName,
                                          explicit_tag=0xa1),
                             ASN1F_PACKET("byKey", OCSP_ByKey(), OCSP_ByKey,
                                          explicit_tag=0xa2))


class OCSP_ResponseData(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            ASN1F_enum_INTEGER("version", 0, {0: "v1"},
                               explicit_tag=0x80)),
        ASN1F_PACKET("responderID", OCSP_ResponderID(responderID=OCSP_ByName()),
                     OCSP_ResponderID),
        ASN1F_GENERALIZED_TIME("producedAt",
                               str(GeneralizedTime())),
        ASN1F_SEQUENCE_OF("responses", [], OCSP_SingleResponse),
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("responseExtensions", None,
                              X509_Extension,
                              explicit_tag=0xa1)))


class ASN1F_OCSP_BasicResponse(ASN1F_SEQUENCE):
    def __init__(self, **kargs):
        seq = [ASN1F_PACKET("tbsResponseData",
                            OCSP_ResponseData(),
                            OCSP_ResponseData),
               ASN1F_PACKET("signatureAlgorithm",
                            X509_AlgorithmIdentifier(),
                            X509_AlgorithmIdentifier),
               MultipleTypeField(
                   [
                       (ASN1F_BIT_STRING_ENCAPS("signature",
                                                ECDSASignature(),
                                                ECDSASignature),
                        lambda pkt: "ecdsa" in pkt.signatureAlgorithm.algorithm.oidname.lower()),  # noqa: E501
                   ],
                   ASN1F_BIT_STRING("signature",
                                    "defaultsignature" * 2)),
               ASN1F_optional(
                   ASN1F_SEQUENCE_OF("certs", None, X509_Cert,
                                     explicit_tag=0xa0))]
        ASN1F_SEQUENCE.__init__(self, *seq, **kargs)


class OCSP_ResponseBytes(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_OID("responseType", "1.3.6.1.5.5.7.48.1.1"),
        ASN1F_OCSP_BasicResponse(explicit_tag=0x04))


_responseStatus_mapping = ["successful",
                           "malformedRequest",
                           "internalError",
                           "tryLater",
                           "notUsed",
                           "sigRequired",
                           "unauthorized"]


class OCSP_Response(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_ENUMERATED("responseStatus", 0,
                         _responseStatus_mapping),
        ASN1F_optional(
            ASN1F_PACKET("responseBytes", None,
                         OCSP_ResponseBytes,
                         explicit_tag=0xa0)))
