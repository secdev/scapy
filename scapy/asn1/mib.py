## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Modified by Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
Management Information Base (MIB) parsing
"""

import re
from glob import glob
from scapy.dadict import DADict,fixname
from scapy.config import conf
from scapy.utils import do_graph

#################
## MIB parsing ##
#################

_mib_re_integer = re.compile("^[0-9]+$")
_mib_re_both = re.compile("^([a-zA-Z_][a-zA-Z0-9_-]*)\(([0-9]+)\)$")
_mib_re_oiddecl = re.compile("$\s*([a-zA-Z0-9_-]+)\s+OBJECT([^:\{\}]|\{[^:]+\})+::=\s*\{([^\}]+)\}",re.M)
_mib_re_strings = re.compile('"[^"]*"')
_mib_re_comments = re.compile('--.*(\r|\n)')

class MIBDict(DADict):
    def _findroot(self, x):
        if x.startswith("."):
            x = x[1:]
        if not x.endswith("."):
            x += "."
        max=0
        root="."
        for k in self.iterkeys():
            if x.startswith(self[k]+"."):
                if max < len(self[k]):
                    max = len(self[k])
                    root = k
        return root, x[max:-1]
    def _oidname(self, x):
        root,remainder = self._findroot(x)
        return root+remainder
    def _oid(self, x):
        xl = x.strip(".").split(".")
        p = len(xl)-1
        while p >= 0 and _mib_re_integer.match(xl[p]):
            p -= 1
        if p != 0 or xl[p] not in self:
            return x
        xl[p] = self[xl[p]] 
        return ".".join(xl[p:])
    def _make_graph(self, other_keys=None, **kargs):
        if other_keys is None:
            other_keys = []
        nodes = [(k, self[k]) for k in self.iterkeys()]
        oids = [self[k] for k in self.iterkeys()]
        for k in other_keys:
            if k not in oids:
                nodes.append(self.oidname(k),k)
        s = 'digraph "mib" {\n\trankdir=LR;\n\n'
        for k,o in nodes:
            s += '\t"%s" [ label="%s"  ];\n' % (o,k)
        s += "\n"
        for k,o in nodes:
            parent,remainder = self._findroot(o[:-1])
            remainder = remainder[1:]+o[-1]
            if parent != ".":
                parent = self[parent]
            s += '\t"%s" -> "%s" [label="%s"];\n' % (parent, o,remainder)
        s += "}\n"
        do_graph(s, **kargs)
    def __len__(self):
        return len(self.keys())


def mib_register(ident, value, the_mib, unresolved):
    if ident in the_mib or ident in unresolved:
        return ident in the_mib
    resval = []
    not_resolved = 0
    for v in value:
        if _mib_re_integer.match(v):
            resval.append(v)
        else:
            v = fixname(v)
            if v not in the_mib:
                not_resolved = 1
            if v in the_mib:
                v = the_mib[v]
            elif v in unresolved:
                v = unresolved[v]
            if type(v) is list:
                resval += v
            else:
                resval.append(v)
    if not_resolved:
        unresolved[ident] = resval
        return False
    else:
        the_mib[ident] = resval
        keys = unresolved.keys()
        i = 0
        while i < len(keys):
            k = keys[i]
            if mib_register(k,unresolved[k], the_mib, {}):
                del(unresolved[k])
                del(keys[i])
                i = 0
            else:
                i += 1
                    
        return True


def load_mib(filenames):
    the_mib = {'iso': ['1']}
    unresolved = {}
    for k in conf.mib.iterkeys():
        mib_register(k, conf.mib[k].split("."), the_mib, unresolved)

    if type(filenames) is str:
        filenames = [filenames]
    for fnames in filenames:
        for fname in glob(fnames):
            f = open(fname)
            text = f.read()
            cleantext = " ".join(_mib_re_strings.split(" ".join(_mib_re_comments.split(text))))
            for m in _mib_re_oiddecl.finditer(cleantext):
                gr = m.groups()
                ident,oid = gr[0],gr[-1]
                ident=fixname(ident)
                oid = oid.split()
                for i, elt in enumerate(oid):
                    m = _mib_re_both.match(elt)
                    if m:
                        oid[i] = m.groups()[1]
                mib_register(ident, oid, the_mib, unresolved)

    newmib = MIBDict(_name="MIB")
    for k,o in the_mib.iteritems():
        newmib[k]=".".join(o)
    for k,o in unresolved.iteritems():
        newmib[k]=".".join(o)

    conf.mib=newmib


####################
## OID references ##
####################

####### pkcs1 #######

pkcs1_oids = {
        "rsaEncryption"                     : "1.2.840.113549.1.1.1",
        "md2WithRSAEncryption"              : "1.2.840.113549.1.1.2",
        "md4WithRSAEncryption"              : "1.2.840.113549.1.1.3",
        "md5WithRSAEncryption"              : "1.2.840.113549.1.1.4",
        "sha1-with-rsa-signature"           : "1.2.840.113549.1.1.5",
        "rsaOAEPEncryptionSET"              : "1.2.840.113549.1.1.6",
        "id-RSAES-OAEP"                     : "1.2.840.113549.1.1.7",
        "id-mgf1"                           : "1.2.840.113549.1.1.8",
        "id-pSpecified"                     : "1.2.840.113549.1.1.9",
        "rsassa-pss"                        : "1.2.840.113549.1.1.10",
        "sha256WithRSAEncryption"           : "1.2.840.113549.1.1.11",
        "sha384WithRSAEncryption"           : "1.2.840.113549.1.1.12",
        "sha512WithRSAEncryption"           : "1.2.840.113549.1.1.13",
        "sha224WithRSAEncryption"           : "1.2.840.113549.1.1.14"
        }

####### secsig oiw #######

secsig_oids = {
        "sha1"                              : "1.3.14.3.2.26"
        }

####### pkcs9 #######

pkcs9_oids = {
        "modules"                           : "1.2.840.113549.1.9.0",
        "emailAddress"                      : "1.2.840.113549.1.9.1",
        "unstructuredName"                  : "1.2.840.113549.1.9.2",
        "contentType"                       : "1.2.840.113549.1.9.3",
        "messageDigest"                     : "1.2.840.113549.1.9.4",
        "signing-time"                      : "1.2.840.113549.1.9.5",
        "countersignature"                  : "1.2.840.113549.1.9.6",
        "challengePassword"                 : "1.2.840.113549.1.9.7",
        "unstructuredAddress"               : "1.2.840.113549.1.9.8",
        "extendedCertificateAttributes"     : "1.2.840.113549.1.9.9",
        "signingDescription"                : "1.2.840.113549.1.9.13",
        "extensionRequest"                  : "1.2.840.113549.1.9.14",
        "smimeCapabilities"                 : "1.2.840.113549.1.9.15",
        "smime"                             : "1.2.840.113549.1.9.16",
        "pgpKeyID"                          : "1.2.840.113549.1.9.17",
        "friendlyName"                      : "1.2.840.113549.1.9.20",
        "localKeyID"                        : "1.2.840.113549.1.9.21",
        "certTypes"                         : "1.2.840.113549.1.9.22",
        "crlTypes"                          : "1.2.840.113549.1.9.23",
        "pkcs-9-oc"                         : "1.2.840.113549.1.9.24",
        "pkcs-9-at"                         : "1.2.840.113549.1.9.25",
        "pkcs-9-sx"                         : "1.2.840.113549.1.9.26",
        "pkcs-9-mr"                         : "1.2.840.113549.1.9.27",
        "id-aa-CMSAlgorithmProtection"      : "1.2.840.113549.1.9.52"
        }

####### x509 #######

attributeType_oids = {
        "objectClass"                       : "2.5.4.0",
        "aliasedEntryName"                  : "2.5.4.1",
        "knowledgeInformation"              : "2.5.4.2",
        "commonName"                        : "2.5.4.3",
        "surname"                           : "2.5.4.4",
        "serialNumber"                      : "2.5.4.5",
        "countryName"                       : "2.5.4.6",
        "localityName"                      : "2.5.4.7",
        "stateOrProvinceName"               : "2.5.4.8",
        "streetAddress"                     : "2.5.4.9",
        "organizationName"                  : "2.5.4.10",
        "organizationUnitName"              : "2.5.4.11",
        "title"                             : "2.5.4.12",
        "description"                       : "2.5.4.13",
        "searchGuide"                       : "2.5.4.14",
        "businessCategory"                  : "2.5.4.15",
        "postalAddress"                     : "2.5.4.16",
        "postalCode"                        : "2.5.4.17",
        "postOfficeBox"                     : "2.5.4.18",
        "physicalDeliveryOfficeName"        : "2.5.4.19",
        "telephoneNumber"                   : "2.5.4.20",
        "telexNumber"                       : "2.5.4.21",
        "teletexTerminalIdentifier"         : "2.5.4.22",
        "facsimileTelephoneNumber"          : "2.5.4.23",
        "x121Address"                       : "2.5.4.24",
        "internationalISDNNumber"           : "2.5.4.25",
        "registeredAddress"                 : "2.5.4.26",
        "destinationIndicator"              : "2.5.4.27",
        "preferredDeliveryMethod"           : "2.5.4.28",
        "presentationAddress"               : "2.5.4.29",
        "supportedApplicationContext"       : "2.5.4.30",
        "member"                            : "2.5.4.31",
        "owner"                             : "2.5.4.32",
        "roleOccupant"                      : "2.5.4.33",
        "seeAlso"                           : "2.5.4.34",
        "userPassword"                      : "2.5.4.35",
        "userCertificate"                   : "2.5.4.36",
        "cACertificate"                     : "2.5.4.37",
        "authorityRevocationList"           : "2.5.4.38",
        "certificateRevocationList"         : "2.5.4.39",
        "crossCertificatePair"              : "2.5.4.40",
        "name"                              : "2.5.4.41",
        "givenName"                         : "2.5.4.42",
        "initials"                          : "2.5.4.43",
        "generationQualifier"               : "2.5.4.44",
        "uniqueIdentifier"                  : "2.5.4.45",
        "dnQualifier"                       : "2.5.4.46",
        "enhancedSearchGuide"               : "2.5.4.47",
        "protocolInformation"               : "2.5.4.48",
        "distinguishedName"                 : "2.5.4.49",
        "uniqueMember"                      : "2.5.4.50",
        "houseIdentifier"                   : "2.5.4.51",
        "supportedAlgorithms"               : "2.5.4.52",
        "deltaRevocationList"               : "2.5.4.53",
        "dmdName"                           : "2.5.4.54",
        "clearance"                         : "2.5.4.55",
        "defaultDirQop"                     : "2.5.4.56",
        "attributeIntegrityInfo"            : "2.5.4.57",
        "attributeCertificate"              : "2.5.4.58",
        "attributeCertificateRevocationList": "2.5.4.59",
        "confKeyInfo"                       : "2.5.4.60",
        "aACertificate"                     : "2.5.4.61",
        "attributeDescriptorCertificate"    : "2.5.4.62",
        "attributeAuthorityRevocationList"  : "2.5.4.63",
        "family-information"                : "2.5.4.64",
        "pseudonym"                         : "2.5.4.65",
        "communicationsService"             : "2.5.4.66",
        "communicationsNetwork"             : "2.5.4.67",
        "certificationPracticeStmt"         : "2.5.4.68",
        "certificatePolicy"                 : "2.5.4.69",
        "pkiPath"                           : "2.5.4.70",
        "privPolicy"                        : "2.5.4.71",
        "role"                              : "2.5.4.72",
        "delegationPath"                    : "2.5.4.73",
        "protPrivPolicy"                    : "2.5.4.74",
        "xMLPrivilegeInfo"                  : "2.5.4.75",
        "xmlPrivPolicy"                     : "2.5.4.76",
        "uuidpair"                          : "2.5.4.77",
        "tagOid"                            : "2.5.4.78",
        "uiiFormat"                         : "2.5.4.79",
        "uiiInUrh"                          : "2.5.4.80",
        "contentUrl"                        : "2.5.4.81",
        "permission"                        : "2.5.4.82",
        "uri"                               : "2.5.4.83",
        "pwdAttribute"                      : "2.5.4.84",
        "userPwd"                           : "2.5.4.85",
        "urn"                               : "2.5.4.86",
        "url"                               : "2.5.4.87",
        "utmCoordinates"                    : "2.5.4.88",
        "urnC"                              : "2.5.4.89",
        "uii"                               : "2.5.4.90",
        "epc"                               : "2.5.4.91",
        "tagAfi"                            : "2.5.4.92",
        "epcFormat"                         : "2.5.4.93",
        "epcInUrn"                          : "2.5.4.94",
        "ldapUrl"                           : "2.5.4.95",
        "ldapUrl"                           : "2.5.4.96",
        "organizationIdentifier"            : "2.5.4.97"
        }

certificateExtension_oids = {
        "authorityKeyIdentifier"            : "2.5.29.1",
        "keyAttributes"                     : "2.5.29.2",
        "certificatePolicies"               : "2.5.29.3",
        "keyUsageRestriction"               : "2.5.29.4",
        "policyMapping"                     : "2.5.29.5",
        "subtreesConstraint"                : "2.5.29.6",
        "subjectAltName"                    : "2.5.29.7",
        "issuerAltName"                     : "2.5.29.8",
        "subjectDirectoryAttributes"        : "2.5.29.9",
        "basicConstraints"                  : "2.5.29.10",
        "subjectKeyIdentifier"              : "2.5.29.14",
        "keyUsage"                          : "2.5.29.15",
        "privateKeyUsagePeriod"             : "2.5.29.16",
        "subjectAltName"                    : "2.5.29.17",
        "issuerAltName"                     : "2.5.29.18",
        "basicConstraints"                  : "2.5.29.19",
        "cRLNumber"                         : "2.5.29.20",
        "reasonCode"                        : "2.5.29.21",
        "expirationDate"                    : "2.5.29.22",
        "instructionCode"                   : "2.5.29.23",
        "invalidityDate"                    : "2.5.29.24",
        "cRLDistributionPoints"             : "2.5.29.25",
        "issuingDistributionPoint"          : "2.5.29.26",
        "deltaCRLIndicator"                 : "2.5.29.27",
        "issuingDistributionPoint"          : "2.5.29.28",
        "certificateIssuer"                 : "2.5.29.29",
        "nameConstraints"                   : "2.5.29.30",
        "cRLDistributionPoints"             : "2.5.29.31",
        "certificatePolicies"               : "2.5.29.32",
        "policyMappings"                    : "2.5.29.33",
        "policyConstraints"                 : "2.5.29.34",
        "authorityKeyIdentifier"            : "2.5.29.35",
        "policyConstraints"                 : "2.5.29.36",
        "extKeyUsage"                       : "2.5.29.37",
        "authorityAttributeIdentifier"      : "2.5.29.38",
        "roleSpecCertIdentifier"            : "2.5.29.39",
        "cRLStreamIdentifier"               : "2.5.29.40",
        "basicAttConstraints"               : "2.5.29.41",
        "delegatedNameConstraints"          : "2.5.29.42",
        "timeSpecification"                 : "2.5.29.43",
        "cRLScope"                          : "2.5.29.44",
        "statusReferrals"                   : "2.5.29.45",
        "freshestCRL"                       : "2.5.29.46",
        "orderedList"                       : "2.5.29.47",
        "attributeDescriptor"               : "2.5.29.48",
        "userNotice"                        : "2.5.29.49",
        "sOAIdentifier"                     : "2.5.29.50",
        "baseUpdateTime"                    : "2.5.29.51",
        "acceptableCertPolicies"            : "2.5.29.52",
        "deltaInfo"                         : "2.5.29.53",
        "inhibitAnyPolicy"                  : "2.5.29.54",
        "targetInformation"                 : "2.5.29.55",
        "noRevAvail"                        : "2.5.29.56",
        "acceptablePrivilegePolicies"       : "2.5.29.57",
        "id-ce-toBeRevoked"                 : "2.5.29.58",
        "id-ce-RevokedGroups"               : "2.5.29.59",
        "id-ce-expiredCertsOnCRL"           : "2.5.29.60",
        "indirectIssuer"                    : "2.5.29.61",
        "id-ce-noAssertion"                 : "2.5.29.62",
        "id-ce-aAissuingDistributionPoint"  : "2.5.29.63",
        "id-ce-issuedOnBehaIFOF"            : "2.5.29.64",
        "id-ce-singleUse"                   : "2.5.29.65",
        "id-ce-groupAC"                     : "2.5.29.66",
        "id-ce-allowedAttAss"               : "2.5.29.67",
        "id-ce-attributeMappings"           : "2.5.29.68",
        "id-ce-holderNameConstraints"       : "2.5.29.69"
        }

certExt_oids = {
        "cert-type"                 : "2.16.840.1.113730.1.1",
        "base-url"                  : "2.16.840.1.113730.1.2",
        "revocation-url"            : "2.16.840.1.113730.1.3",
        "ca-revocation-url"         : "2.16.840.1.113730.1.4",
        "ca-crl-url"                : "2.16.840.1.113730.1.5",
        "ca-cert-url"               : "2.16.840.1.113730.1.6",
        "renewal-url"               : "2.16.840.1.113730.1.7",
        "ca-policy-url"             : "2.16.840.1.113730.1.8",
        "homepage-url"              : "2.16.840.1.113730.1.9",
        "entity-logo"               : "2.16.840.1.113730.1.10",
        "user-picture"              : "2.16.840.1.113730.1.11",
        "ssl-server-name"           : "2.16.840.1.113730.1.12",
        "comment"                   : "2.16.840.1.113730.1.13",
        "lost-password-url"         : "2.16.840.1.113730.1.14",
        "cert-renewal-time"         : "2.16.840.1.113730.1.15",
        "aia"                       : "2.16.840.1.113730.1.16",
        "cert-scope-of-use"         : "2.16.840.1.113730.1.17",
        }

certPkixPe_oids = {
        "authorityInfoAccess"       : "1.3.6.1.5.5.7.1.1",
        "biometricInfo"             : "1.3.6.1.5.5.7.1.2",
        "qcStatements"              : "1.3.6.1.5.5.7.1.3",
        "auditIdentity"             : "1.3.6.1.5.5.7.1.4",
        "aaControls"                : "1.3.6.1.5.5.7.1.6",
        "proxying"                  : "1.3.6.1.5.5.7.1.10",
        "subjectInfoAccess"         : "1.3.6.1.5.5.7.1.11"
        }

certPkixQt_oids = {
        "cps"                       : "1.3.6.1.5.5.7.2.1",
        "unotice"                   : "1.3.6.1.5.5.7.2.2"
        }

certPkixKp_oids = {
        "serverAuth"                : "1.3.6.1.5.5.7.3.1",
        "clientAuth"                : "1.3.6.1.5.5.7.3.2",
        "codeSigning"               : "1.3.6.1.5.5.7.3.3",
        "emailProtection"           : "1.3.6.1.5.5.7.3.4",
        "ipsecEndSystem"            : "1.3.6.1.5.5.7.3.5",
        "ipsecTunnel"               : "1.3.6.1.5.5.7.3.6",
        "ipsecUser"                 : "1.3.6.1.5.5.7.3.7",
        "timeStamping"              : "1.3.6.1.5.5.7.3.8",
        "ocspSigning"               : "1.3.6.1.5.5.7.3.9",
        "dvcs"                      : "1.3.6.1.5.5.7.3.10",
        "secureShellClient"         : "1.3.6.1.5.5.7.3.21",
        "secureShellServer"         : "1.3.6.1.5.5.7.3.22"
        }

certPkixAd_oids = {
        "ocsp"                          : "1.3.6.1.5.5.7.48.1",
        "caIssuers"                     : "1.3.6.1.5.5.7.48.2",
        "timestamping"                  : "1.3.6.1.5.5.7.48.3",
        "id-ad-dvcs"                    : "1.3.6.1.5.5.7.48.4",
        "id-ad-caRepository"            : "1.3.6.1.5.5.7.48.5",
        "id-pkix-ocsp-archive-cutoff"   : "1.3.6.1.5.5.7.48.6",
        "id-pkix-ocsp-service-locator"  : "1.3.6.1.5.5.7.48.7",
        "id-ad-cmc"                     : "1.3.6.1.5.5.7.48.12",
        "basic-response"                : "1.3.6.1.5.5.7.48.1.1"
        }

####### ansi-x962 #######

x962KeyType_oids = {
        "prime-field"               : "1.2.840.10045.1.1",
        "characteristic-two-field"  : "1.2.840.10045.1.2",
        "ecPublicKey"               : "1.2.840.10045.2.1",
        }

x962Signature_oids = {
        "ecdsa-with-SHA1"           : "1.2.840.10045.4.1",
        "ecdsa-with-Recommended"    : "1.2.840.10045.4.2",
        "ecdsa-with-SHA224"         : "1.2.840.10045.4.3.1",
        "ecdsa-with-SHA256"         : "1.2.840.10045.4.3.2",
        "ecdsa-with-SHA384"         : "1.2.840.10045.4.3.3",
        "ecdsa-with-SHA512"         : "1.2.840.10045.4.3.4"
        }

####### elliptic curves #######

ansiX962Curve_oids = {
        "prime192v1"                : "1.2.840.10045.3.1.1",
        "prime192v2"                : "1.2.840.10045.3.1.2",
        "prime192v3"                : "1.2.840.10045.3.1.3",
        "prime239v1"                : "1.2.840.10045.3.1.4",
        "prime239v2"                : "1.2.840.10045.3.1.5",
        "prime239v3"                : "1.2.840.10045.3.1.6",
        "prime256v1"                : "1.2.840.10045.3.1.7"
        }

certicomCurve_oids = {
        "ansit163k1"                : "1.3.132.0.1",
        "ansit163r1"                : "1.3.132.0.2",
        "ansit239k1"                : "1.3.132.0.3",
        "sect113r1"                 : "1.3.132.0.4",
        "sect113r2"                 : "1.3.132.0.5",
        "secp112r1"                 : "1.3.132.0.6",
        "secp112r2"                 : "1.3.132.0.7",
        "ansip160r1"                : "1.3.132.0.8",
        "ansip160k1"                : "1.3.132.0.9",
        "ansip256k1"                : "1.3.132.0.10",
        "ansit163r2"                : "1.3.132.0.15",
        "ansit283k1"                : "1.3.132.0.16",
        "ansit283r1"                : "1.3.132.0.17",
        "sect131r1"                 : "1.3.132.0.22",
        "ansit193r1"                : "1.3.132.0.24",
        "ansit193r2"                : "1.3.132.0.25",
        "ansit233k1"                : "1.3.132.0.26",
        "ansit233r1"                : "1.3.132.0.27",
        "secp128r1"                 : "1.3.132.0.28",
        "secp128r2"                 : "1.3.132.0.29",
        "ansip160r2"                : "1.3.132.0.30",
        "ansip192k1"                : "1.3.132.0.31",
        "ansip224k1"                : "1.3.132.0.32",
        "ansip224r1"                : "1.3.132.0.33",
        "ansip384r1"                : "1.3.132.0.34",
        "ansip521r1"                : "1.3.132.0.35",
        "ansit409k1"                : "1.3.132.0.36",
        "ansit409r1"                : "1.3.132.0.37",
        "ansit571k1"                : "1.3.132.0.38",
        "ansit571r1"                : "1.3.132.0.39"
        }

####### policies #######

certPolicy_oids = {
        "anyPolicy"                 : "2.5.29.32.0"
        }

# from Chromium source code (ev_root_ca_metadata.cc)
evPolicy_oids = {
        "EV AC Camerfirma S.A. Chambers of Commerce Root - 2008"            : "1.3.6.1.4.1.17326.10.14.2.1.2",
        "EV AC Camerfirma S.A. Chambers of Commerce Root - 2008"            : "1.3.6.1.4.1.17326.10.14.2.2.2",
        "EV AC Camerfirma S.A. Global Chambersign Root - 2008"              : "1.3.6.1.4.1.17326.10.8.12.1.2",
        "EV AC Camerfirma S.A. Global Chambersign Root - 2008"              : "1.3.6.1.4.1.17326.10.8.12.2.2",
        "EV AddTrust/Comodo/USERTrust"                                      : "1.3.6.1.4.1.6449.1.2.1.5.1",
        "EV AddTrust External CA Root"                                      : "1.3.6.1.4.1.782.1.2.1.8.1",
        "EV Actualis Authentication Root CA"                                : "1.3.159.1.17.1",
        "EV AffirmTrust Commercial"                                         : "1.3.6.1.4.1.34697.2.1",
        "EV AffirmTrust Networking"                                         : "1.3.6.1.4.1.34697.2.2",
        "EV AffirmTrust Premium"                                            : "1.3.6.1.4.1.34697.2.3",
        "EV AffirmTrust Premium ECC"                                        : "1.3.6.1.4.1.34697.2.4",
        "EV Autoridad de Certificacion Firmaprofesional CIF A62634068"      : "1.3.6.1.4.1.13177.10.1.3.10",
        "EV Baltimore CyberTrust Root"                                      : "1.3.6.1.4.1.6334.1.100.1",
        "EV Buypass Class 3"                                                : "2.16.578.1.26.1.3.3",
        "EV Certificate Authority of WoSign"                                : "1.3.6.1.4.1.36305.2",
        "EV CertPlus Class 2 Primary CA (KEYNECTIS)"                        : "1.3.6.1.4.1.22234.2.5.2.3.1",
        "EV Certum Trusted Network CA"                                      : "1.2.616.1.113527.2.5.1.1",
        "EV China Internet Network Information Center EV Certificates Root" : "1.3.6.1.4.1.29836.1.10",
        "EV Cybertrust Global Root"                                         : "1.3.6.1.4.1.6334.1.100.1",
        "EV DigiCert High Assurance EV Root CA"                             : "2.16.840.1.114412.2.1",
        "EV D-TRUST Root Class 3 CA 2 EV 2009"                              : "1.3.6.1.4.1.4788.2.202.1",
        "EV Entrust Certification Authority"                                : "2.16.840.1.114028.10.1.2",
        "EV Equifax Secure Certificate Authority (GeoTrust)"                : "1.3.6.1.4.1.14370.1.6",
        "EV E-Tugra Certification Authority"                                : "2.16.792.3.0.4.1.1.4",
        "EV GeoTrust Primary Certification Authority"                       : "1.3.6.1.4.1.14370.1.6",
        "EV GlobalSign Root CAs"                                            : "1.3.6.1.4.1.4146.1.1",
        "EV Go Daddy Certification Authority"                               : "2.16.840.1.114413.1.7.23.3",
        "EV Izenpe.com roots Business"                                      : "1.3.6.1.4.1.14777.6.1.1",
        "EV Izenpe.com roots Government"                                    : "1.3.6.1.4.1.14777.6.1.2",
        "EV Network Solutions Certificate Authority"                        : "1.3.6.1.4.1.781.1.2.1.8.1",
        "EV QuoVadis Roots"                                                 : "1.3.6.1.4.1.8024.0.2.100.1.2",
        "EV SecureTrust Corporation Roots"                                  : "2.16.840.1.114404.1.1.2.4.1",
        "EV Security Communication RootCA1"                                 : "1.2.392.200091.100.721.1",
        "EV Staat der Nederlanden EV Root CA"                               : "2.16.528.1.1003.1.2.7",
        "EV StartCom Certification Authority"                               : "1.3.6.1.4.1.23223.1.1.1",
        "EV Starfield Certificate Authority"                                : "2.16.840.1.114414.1.7.23.3",
        "EV Starfield Service Certificate Authority"                        : "2.16.840.1.114414.1.7.24.3",
        "EV SwissSign Gold CA - G2"                                         : "2.16.756.1.89.1.2.1.1",
        "EV Swisscom Root EV CA 2"                                          : "2.16.756.1.83.21.0",
        "EV thawte CAs"                                                     : "2.16.840.1.113733.1.7.48.1",
        "EV TWCA Roots"                                                     : "1.3.6.1.4.1.40869.1.1.22.3",
        "EV T-Telessec GlobalRoot Class 3"                                  : "1.3.6.1.4.1.7879.13.24.1",
        "EV USERTrust Certification Authorities"                            : "1.3.6.1.4.1.6449.1.2.1.5.1",
        "EV ValiCert Class 2 Policy Validation Authority"                   : "2.16.840.1.114413.1.7.23.3",
        "EV VeriSign Certification Authorities"                             : "2.16.840.1.113733.1.7.23.6",
        "EV Wells Fargo WellsSecure Public Root Certification Authority"    : "2.16.840.1.114171.500.9",
        "EV XRamp Global Certification Authority"                           : "2.16.840.1.114404.1.1.2.4.1",
        "jurisdictionOfIncorporationLocalityName"                           : "1.3.6.1.4.1.311.60.2.1.1",
        "jurisdictionOfIncorporationStateOrProvinceName"                    : "1.3.6.1.4.1.311.60.2.1.2",
        "jurisdictionOfIncorporationCountryName"                            : "1.3.6.1.4.1.311.60.2.1.3"
        }


x509_oids_sets = [
                 pkcs1_oids,
                 secsig_oids,
                 pkcs9_oids,
                 attributeType_oids,
                 certificateExtension_oids,
                 certExt_oids,
                 certPkixPe_oids,
                 certPkixQt_oids,
                 certPkixKp_oids,
                 certPkixAd_oids,
                 certPolicy_oids,
                 evPolicy_oids,
                 x962KeyType_oids,
                 x962Signature_oids,
                 ansiX962Curve_oids,
                 certicomCurve_oids
                 ]

x509_oids = {}

for oids_set in x509_oids_sets:
    x509_oids.update(oids_set)

conf.mib = MIBDict(_name="MIB", **x509_oids)


#########################
## Hash mapping helper ##
#########################

# This dict enables static access to string references to the hash functions
# of some algorithms from pkcs1_oids and x962Signature_oids.

hash_by_oid = {
        "1.2.840.113549.1.1.2"  : "md2",
        "1.2.840.113549.1.1.3"  : "md4",
        "1.2.840.113549.1.1.4"  : "md5",
        "1.2.840.113549.1.1.5"  : "sha1",
        "1.2.840.113549.1.1.11" : "sha256",
        "1.2.840.113549.1.1.12" : "sha384",
        "1.2.840.113549.1.1.13" : "sha512",
        "1.2.840.113549.1.1.14" : "sha224",
        "1.2.840.10045.4.1"     : "sha1",
        "1.2.840.10045.4.3.1"   : "sha224",
        "1.2.840.10045.4.3.2"   : "sha256",
        "1.2.840.10045.4.3.3"   : "sha384",
        "1.2.840.10045.4.3.4"   : "sha512"
        }

