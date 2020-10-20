# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Modified by Maxence Tury <maxence.tury@ssi.gouv.fr>
# This program is published under a GPLv2 license

"""
Management Information Base (MIB) parsing
"""

from __future__ import absolute_import
import re
from glob import glob
from scapy.dadict import DADict, fixname
from scapy.config import conf
from scapy.utils import do_graph
import scapy.modules.six as six
from scapy.compat import plain_str

from scapy.compat import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)

#################
#  MIB parsing  #
#################

_mib_re_integer = re.compile(r"^[0-9]+$")
_mib_re_both = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_-]*)\(([0-9]+)\)$")
_mib_re_oiddecl = re.compile(r"$\s*([a-zA-Z0-9_-]+)\s+OBJECT([^:\{\}]|\{[^:]+\})+::=\s*\{([^\}]+)\}", re.M)  # noqa: E501
_mib_re_strings = re.compile(r'"[^"]*"')
_mib_re_comments = re.compile(r'--.*(\r|\n)')


class MIBDict(DADict[str, str]):
    def _findroot(self, x):
        # type: (str) -> Tuple[str, str, str]
        """Internal MIBDict function used to find a partial OID"""
        if x.startswith("."):
            x = x[1:]
        if not x.endswith("."):
            x += "."
        max = 0
        root = "."
        root_key = ""
        for k in six.iterkeys(self):
            if x.startswith(k + "."):
                if max < len(k):
                    max = len(k)
                    root = self[k]
                    root_key = k
        return root, root_key, x[max:-1]

    def _oidname(self, x):
        # type: (str) -> str
        """Deduce the OID name from its OID ID"""
        root, _, remainder = self._findroot(x)
        return root + remainder

    def _oid(self, x):
        # type: (str) -> str
        """Parse the OID id/OID generator, and return real OID"""
        xl = x.strip(".").split(".")
        p = len(xl) - 1
        while p >= 0 and _mib_re_integer.match(xl[p]):
            p -= 1
        if p != 0 or xl[p] not in six.itervalues(self.d):
            return x
        xl[p] = next(k for k, v in six.iteritems(self.d) if v == xl[p])
        return ".".join(xl[p:])

    def _make_graph(self, other_keys=None, **kargs):
        # type: (Optional[Any], **Any) -> None
        if other_keys is None:
            other_keys = []
        nodes = [(self[key], key) for key in self.iterkeys()]
        oids = set(self.iterkeys())
        for k in other_keys:
            if k not in oids:
                nodes.append((self._oidname(k), k))
        s = 'digraph "mib" {\n\trankdir=LR;\n\n'
        for k, o in nodes:
            s += '\t"%s" [ label="%s"  ];\n' % (o, k)
        s += "\n"
        for k, o in nodes:
            parent, parent_key, remainder = self._findroot(o[:-1])
            remainder = remainder[1:] + o[-1]
            if parent != ".":
                parent = parent_key
            s += '\t"%s" -> "%s" [label="%s"];\n' % (parent, o, remainder)
        s += "}\n"
        do_graph(s, **kargs)


def _mib_register(ident,  # type: str
                  value,  # type: List[str]
                  the_mib,  # type: Dict[str, List[str]]
                  unresolved,  # type: Dict[str, List[str]]
                  alias,  # type: Dict[str, str]
                  ):
    # type: (...) -> bool
    """
    Internal function used to register an OID and its name in a MIBDict
    """
    if ident in the_mib:
        # We have already resolved this one. Store the alias
        alias[".".join(value)] = ident
        return True
    if ident in unresolved:
        # We know we can't resolve this one
        return False
    resval = []
    not_resolved = 0
    # Resolve the OID
    # (e.g. 2.basicConstraints.3 -> 2.2.5.29.19.3)
    for v in value:
        if _mib_re_integer.match(v):
            resval.append(v)
        else:
            v = fixname(plain_str(v))
            if v not in the_mib:
                not_resolved = 1
            if v in the_mib:
                resval += the_mib[v]
            elif v in unresolved:
                resval += unresolved[v]
            else:
                resval.append(v)
    if not_resolved:
        # Unresolved
        unresolved[ident] = resval
        return False
    else:
        # Fully resolved
        the_mib[ident] = resval
        keys = list(unresolved)
        i = 0
        # Go through the unresolved to update the ones that
        # depended on the one we just did
        while i < len(keys):
            k = keys[i]
            if _mib_register(k, unresolved[k], the_mib, {}, alias):
                # Now resolved: we can remove it from unresolved
                del(unresolved[k])
                del(keys[i])
                i = 0
            else:
                i += 1

        return True


def load_mib(filenames):
    # type: (str) -> None
    """
    Load the conf.mib dict from a list of filenames
    """
    the_mib = {'iso': ['1']}
    unresolved = {}  # type: Dict[str, List[str]]
    alias = {}  # type: Dict[str, str]
    # Export the current MIB to a working dictionary
    for k in six.iterkeys(conf.mib):
        _mib_register(conf.mib[k], k.split("."), the_mib, unresolved, alias)

    # Read the files
    if isinstance(filenames, (str, bytes)):
        files_list = [filenames]
    else:
        files_list = filenames
    for fnames in files_list:
        for fname in glob(fnames):
            with open(fname) as f:
                text = f.read()
            cleantext = " ".join(
                _mib_re_strings.split(" ".join(_mib_re_comments.split(text)))
            )
            for m in _mib_re_oiddecl.finditer(cleantext):
                gr = m.groups()
                ident, oid_s = gr[0], gr[-1]
                ident = fixname(ident)
                oid_l = oid_s.split()
                for i, elt in enumerate(oid_l):
                    m2 = _mib_re_both.match(elt)
                    if m2:
                        oid_l[i] = m2.groups()[1]
                _mib_register(ident, oid_l, the_mib, unresolved, alias)

    # Create the new MIB
    newmib = MIBDict(_name="MIB")
    # Add resolved values
    for oid, key in six.iteritems(the_mib):
        newmib[".".join(key)] = oid
    # Add unresolved values
    for oid, key in six.iteritems(unresolved):
        newmib[".".join(key)] = oid
    # Add aliases
    for key, oid in six.iteritems(alias):
        newmib[key] = oid

    conf.mib = newmib


####################
#  OID references  #
####################

#      pkcs1       #

pkcs1_oids = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1-with-rsa-signature",
    "1.2.840.113549.1.1.6": "rsaOAEPEncryptionSET",
    "1.2.840.113549.1.1.7": "id-RSAES-OAEP",
    "1.2.840.113549.1.1.8": "id-mgf1",
    "1.2.840.113549.1.1.9": "id-pSpecified",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption"
}

#       secsig oiw       #

secsig_oids = {
    "1.3.14.3.2.26": "sha1"
}

#       pkcs9       #

pkcs9_oids = {
    "1.2.840.113549.1.9.0": "modules",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.1.9.2": "unstructuredName",
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signing-time",
    "1.2.840.113549.1.9.6": "countersignature",
    "1.2.840.113549.1.9.7": "challengePassword",
    "1.2.840.113549.1.9.8": "unstructuredAddress",
    "1.2.840.113549.1.9.9": "extendedCertificateAttributes",
    "1.2.840.113549.1.9.13": "signingDescription",
    "1.2.840.113549.1.9.14": "extensionRequest",
    "1.2.840.113549.1.9.15": "smimeCapabilities",
    "1.2.840.113549.1.9.16": "smime",
    "1.2.840.113549.1.9.17": "pgpKeyID",
    "1.2.840.113549.1.9.20": "friendlyName",
    "1.2.840.113549.1.9.21": "localKeyID",
    "1.2.840.113549.1.9.22": "certTypes",
    "1.2.840.113549.1.9.23": "crlTypes",
    "1.2.840.113549.1.9.24": "pkcs-9-oc",
    "1.2.840.113549.1.9.25": "pkcs-9-at",
    "1.2.840.113549.1.9.26": "pkcs-9-sx",
    "1.2.840.113549.1.9.27": "pkcs-9-mr",
    "1.2.840.113549.1.9.52": "id-aa-CMSAlgorithmProtection"
}

#       x509       #

attributeType_oids = {
    "2.5.4.0": "objectClass",
    "2.5.4.1": "aliasedEntryName",
    "2.5.4.2": "knowledgeInformation",
    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationUnitName",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.14": "searchGuide",
    "2.5.4.15": "businessCategory",
    "2.5.4.16": "postalAddress",
    "2.5.4.17": "postalCode",
    "2.5.4.18": "postOfficeBox",
    "2.5.4.19": "physicalDeliveryOfficeName",
    "2.5.4.20": "telephoneNumber",
    "2.5.4.21": "telexNumber",
    "2.5.4.22": "teletexTerminalIdentifier",
    "2.5.4.23": "facsimileTelephoneNumber",
    "2.5.4.24": "x121Address",
    "2.5.4.25": "internationalISDNNumber",
    "2.5.4.26": "registeredAddress",
    "2.5.4.27": "destinationIndicator",
    "2.5.4.28": "preferredDeliveryMethod",
    "2.5.4.29": "presentationAddress",
    "2.5.4.30": "supportedApplicationContext",
    "2.5.4.31": "member",
    "2.5.4.32": "owner",
    "2.5.4.33": "roleOccupant",
    "2.5.4.34": "seeAlso",
    "2.5.4.35": "userPassword",
    "2.5.4.36": "userCertificate",
    "2.5.4.37": "cACertificate",
    "2.5.4.38": "authorityRevocationList",
    "2.5.4.39": "certificateRevocationList",
    "2.5.4.40": "crossCertificatePair",
    "2.5.4.41": "name",
    "2.5.4.42": "givenName",
    "2.5.4.43": "initials",
    "2.5.4.44": "generationQualifier",
    "2.5.4.45": "uniqueIdentifier",
    "2.5.4.46": "dnQualifier",
    "2.5.4.47": "enhancedSearchGuide",
    "2.5.4.48": "protocolInformation",
    "2.5.4.49": "distinguishedName",
    "2.5.4.50": "uniqueMember",
    "2.5.4.51": "houseIdentifier",
    "2.5.4.52": "supportedAlgorithms",
    "2.5.4.53": "deltaRevocationList",
    "2.5.4.54": "dmdName",
    "2.5.4.55": "clearance",
    "2.5.4.56": "defaultDirQop",
    "2.5.4.57": "attributeIntegrityInfo",
    "2.5.4.58": "attributeCertificate",
    "2.5.4.59": "attributeCertificateRevocationList",
    "2.5.4.60": "confKeyInfo",
    "2.5.4.61": "aACertificate",
    "2.5.4.62": "attributeDescriptorCertificate",
    "2.5.4.63": "attributeAuthorityRevocationList",
    "2.5.4.64": "family-information",
    "2.5.4.65": "pseudonym",
    "2.5.4.66": "communicationsService",
    "2.5.4.67": "communicationsNetwork",
    "2.5.4.68": "certificationPracticeStmt",
    "2.5.4.69": "certificatePolicy",
    "2.5.4.70": "pkiPath",
    "2.5.4.71": "privPolicy",
    "2.5.4.72": "role",
    "2.5.4.73": "delegationPath",
    "2.5.4.74": "protPrivPolicy",
    "2.5.4.75": "xMLPrivilegeInfo",
    "2.5.4.76": "xmlPrivPolicy",
    "2.5.4.77": "uuidpair",
    "2.5.4.78": "tagOid",
    "2.5.4.79": "uiiFormat",
    "2.5.4.80": "uiiInUrh",
    "2.5.4.81": "contentUrl",
    "2.5.4.82": "permission",
    "2.5.4.83": "uri",
    "2.5.4.84": "pwdAttribute",
    "2.5.4.85": "userPwd",
    "2.5.4.86": "urn",
    "2.5.4.87": "url",
    "2.5.4.88": "utmCoordinates",
    "2.5.4.89": "urnC",
    "2.5.4.90": "uii",
    "2.5.4.91": "epc",
    "2.5.4.92": "tagAfi",
    "2.5.4.93": "epcFormat",
    "2.5.4.94": "epcInUrn",
    "2.5.4.95": "ldapUrl",
    "2.5.4.96": "ldapUrl",
    "2.5.4.97": "organizationIdentifier"
}

certificateExtension_oids = {
    "2.5.29.1": "authorityKeyIdentifier",
    "2.5.29.2": "keyAttributes",
    "2.5.29.3": "certificatePolicies",
    "2.5.29.4": "keyUsageRestriction",
    "2.5.29.5": "policyMapping",
    "2.5.29.6": "subtreesConstraint",
    "2.5.29.7": "subjectAltName",
    "2.5.29.8": "issuerAltName",
    "2.5.29.9": "subjectDirectoryAttributes",
    "2.5.29.10": "basicConstraints",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.16": "privateKeyUsagePeriod",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.20": "cRLNumber",
    "2.5.29.21": "reasonCode",
    "2.5.29.22": "expirationDate",
    "2.5.29.23": "instructionCode",
    "2.5.29.24": "invalidityDate",
    "2.5.29.25": "cRLDistributionPoints",
    "2.5.29.26": "issuingDistributionPoint",
    "2.5.29.27": "deltaCRLIndicator",
    "2.5.29.28": "issuingDistributionPoint",
    "2.5.29.29": "certificateIssuer",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.33": "policyMappings",
    "2.5.29.34": "policyConstraints",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.36": "policyConstraints",
    "2.5.29.37": "extKeyUsage",
    "2.5.29.38": "authorityAttributeIdentifier",
    "2.5.29.39": "roleSpecCertIdentifier",
    "2.5.29.40": "cRLStreamIdentifier",
    "2.5.29.41": "basicAttConstraints",
    "2.5.29.42": "delegatedNameConstraints",
    "2.5.29.43": "timeSpecification",
    "2.5.29.44": "cRLScope",
    "2.5.29.45": "statusReferrals",
    "2.5.29.46": "freshestCRL",
    "2.5.29.47": "orderedList",
    "2.5.29.48": "attributeDescriptor",
    "2.5.29.49": "userNotice",
    "2.5.29.50": "sOAIdentifier",
    "2.5.29.51": "baseUpdateTime",
    "2.5.29.52": "acceptableCertPolicies",
    "2.5.29.53": "deltaInfo",
    "2.5.29.54": "inhibitAnyPolicy",
    "2.5.29.55": "targetInformation",
    "2.5.29.56": "noRevAvail",
    "2.5.29.57": "acceptablePrivilegePolicies",
    "2.5.29.58": "id-ce-toBeRevoked",
    "2.5.29.59": "id-ce-RevokedGroups",
    "2.5.29.60": "id-ce-expiredCertsOnCRL",
    "2.5.29.61": "indirectIssuer",
    "2.5.29.62": "id-ce-noAssertion",
    "2.5.29.63": "id-ce-aAissuingDistributionPoint",
    "2.5.29.64": "id-ce-issuedOnBehaIFOF",
    "2.5.29.65": "id-ce-singleUse",
    "2.5.29.66": "id-ce-groupAC",
    "2.5.29.67": "id-ce-allowedAttAss",
    "2.5.29.68": "id-ce-attributeMappings",
    "2.5.29.69": "id-ce-holderNameConstraints"
}

certExt_oids = {
    "2.16.840.1.113730.1.1": "cert-type",
    "2.16.840.1.113730.1.2": "base-url",
    "2.16.840.1.113730.1.3": "revocation-url",
    "2.16.840.1.113730.1.4": "ca-revocation-url",
    "2.16.840.1.113730.1.5": "ca-crl-url",
    "2.16.840.1.113730.1.6": "ca-cert-url",
    "2.16.840.1.113730.1.7": "renewal-url",
    "2.16.840.1.113730.1.8": "ca-policy-url",
    "2.16.840.1.113730.1.9": "homepage-url",
    "2.16.840.1.113730.1.10": "entity-logo",
    "2.16.840.1.113730.1.11": "user-picture",
    "2.16.840.1.113730.1.12": "ssl-server-name",
    "2.16.840.1.113730.1.13": "comment",
    "2.16.840.1.113730.1.14": "lost-password-url",
    "2.16.840.1.113730.1.15": "cert-renewal-time",
    "2.16.840.1.113730.1.16": "aia",
    "2.16.840.1.113730.1.17": "cert-scope-of-use",
}

certPkixPe_oids = {
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.5.5.7.1.2": "biometricInfo",
    "1.3.6.1.5.5.7.1.3": "qcStatements",
    "1.3.6.1.5.5.7.1.4": "auditIdentity",
    "1.3.6.1.5.5.7.1.6": "aaControls",
    "1.3.6.1.5.5.7.1.10": "proxying",
    "1.3.6.1.5.5.7.1.11": "subjectInfoAccess"
}

certPkixQt_oids = {
    "1.3.6.1.5.5.7.2.1": "cps",
    "1.3.6.1.5.5.7.2.2": "unotice"
}

certPkixKp_oids = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.5": "ipsecEndSystem",
    "1.3.6.1.5.5.7.3.6": "ipsecTunnel",
    "1.3.6.1.5.5.7.3.7": "ipsecUser",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "ocspSigning",
    "1.3.6.1.5.5.7.3.10": "dvcs",
    "1.3.6.1.5.5.7.3.21": "secureShellClient",
    "1.3.6.1.5.5.7.3.22": "secureShellServer"
}

certPkixAd_oids = {
    "1.3.6.1.5.5.7.48.1": "ocsp",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
    "1.3.6.1.5.5.7.48.3": "timestamping",
    "1.3.6.1.5.5.7.48.4": "id-ad-dvcs",
    "1.3.6.1.5.5.7.48.5": "id-ad-caRepository",
    "1.3.6.1.5.5.7.48.6": "id-pkix-ocsp-archive-cutoff",
    "1.3.6.1.5.5.7.48.7": "id-pkix-ocsp-service-locator",
    "1.3.6.1.5.5.7.48.12": "id-ad-cmc",
    "1.3.6.1.5.5.7.48.1.1": "basic-response"
}

#       ansi-x962       #

x962KeyType_oids = {
    "1.2.840.10045.1.1": "prime-field",
    "1.2.840.10045.1.2": "characteristic-two-field",
    "1.2.840.10045.2.1": "ecPublicKey",
}

x962Signature_oids = {
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.2": "ecdsa-with-Recommended",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512"
}

#       elliptic curves       #

ansiX962Curve_oids = {
    "1.2.840.10045.3.1.1": "prime192v1",
    "1.2.840.10045.3.1.2": "prime192v2",
    "1.2.840.10045.3.1.3": "prime192v3",
    "1.2.840.10045.3.1.4": "prime239v1",
    "1.2.840.10045.3.1.5": "prime239v2",
    "1.2.840.10045.3.1.6": "prime239v3",
    "1.2.840.10045.3.1.7": "prime256v1"
}

certicomCurve_oids = {
    "1.3.132.0.1": "ansit163k1",
    "1.3.132.0.2": "ansit163r1",
    "1.3.132.0.3": "ansit239k1",
    "1.3.132.0.4": "sect113r1",
    "1.3.132.0.5": "sect113r2",
    "1.3.132.0.6": "secp112r1",
    "1.3.132.0.7": "secp112r2",
    "1.3.132.0.8": "ansip160r1",
    "1.3.132.0.9": "ansip160k1",
    "1.3.132.0.10": "ansip256k1",
    "1.3.132.0.15": "ansit163r2",
    "1.3.132.0.16": "ansit283k1",
    "1.3.132.0.17": "ansit283r1",
    "1.3.132.0.22": "sect131r1",
    "1.3.132.0.24": "ansit193r1",
    "1.3.132.0.25": "ansit193r2",
    "1.3.132.0.26": "ansit233k1",
    "1.3.132.0.27": "ansit233r1",
    "1.3.132.0.28": "secp128r1",
    "1.3.132.0.29": "secp128r2",
    "1.3.132.0.30": "ansip160r2",
    "1.3.132.0.31": "ansip192k1",
    "1.3.132.0.32": "ansip224k1",
    "1.3.132.0.33": "ansip224r1",
    "1.3.132.0.34": "ansip384r1",
    "1.3.132.0.35": "ansip521r1",
    "1.3.132.0.36": "ansit409k1",
    "1.3.132.0.37": "ansit409r1",
    "1.3.132.0.38": "ansit571k1",
    "1.3.132.0.39": "ansit571r1"
}

#       policies       #

certPolicy_oids = {
    "2.5.29.32.0": "anyPolicy"
}

# from Chromium source code (ev_root_ca_metadata.cc)
evPolicy_oids = {
    '1.2.392.200091.100.721.1': 'EV Security Communication RootCA1',
    '1.2.616.1.113527.2.5.1.1': 'EV Certum Trusted Network CA',
    '1.3.159.1.17.1': 'EV Actualis Authentication Root CA',
    '1.3.6.1.4.1.13177.10.1.3.10': 'EV Autoridad de Certificacion Firmaprofesional CIF A62634068',  # noqa: E501
    '1.3.6.1.4.1.14370.1.6': 'EV GeoTrust Primary Certification Authority',
    '1.3.6.1.4.1.14777.6.1.1': 'EV Izenpe.com roots Business',
    '1.3.6.1.4.1.14777.6.1.2': 'EV Izenpe.com roots Government',
    '1.3.6.1.4.1.17326.10.14.2.1.2': 'EV AC Camerfirma S.A. Chambers of Commerce Root - 2008',  # noqa: E501
    '1.3.6.1.4.1.17326.10.14.2.2.2': 'EV AC Camerfirma S.A. Chambers of Commerce Root - 2008',  # noqa: E501
    '1.3.6.1.4.1.17326.10.8.12.1.2': 'EV AC Camerfirma S.A. Global Chambersign Root - 2008',  # noqa: E501
    '1.3.6.1.4.1.17326.10.8.12.2.2': 'EV AC Camerfirma S.A. Global Chambersign Root - 2008',  # noqa: E501
    '1.3.6.1.4.1.22234.2.5.2.3.1': 'EV CertPlus Class 2 Primary CA (KEYNECTIS)',  # noqa: E501
    '1.3.6.1.4.1.23223.1.1.1': 'EV StartCom Certification Authority',
    '1.3.6.1.4.1.29836.1.10': 'EV China Internet Network Information Center EV Certificates Root',  # noqa: E501
    '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionOfIncorporationLocalityName',
    '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionOfIncorporationStateOrProvinceName',  # noqa: E501
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionOfIncorporationCountryName',
    '1.3.6.1.4.1.34697.2.1': 'EV AffirmTrust Commercial',
    '1.3.6.1.4.1.34697.2.2': 'EV AffirmTrust Networking',
    '1.3.6.1.4.1.34697.2.3': 'EV AffirmTrust Premium',
    '1.3.6.1.4.1.34697.2.4': 'EV AffirmTrust Premium ECC',
    '1.3.6.1.4.1.36305.2': 'EV Certificate Authority of WoSign',
    '1.3.6.1.4.1.40869.1.1.22.3': 'EV TWCA Roots',
    '1.3.6.1.4.1.4146.1.1': 'EV GlobalSign Root CAs',
    '1.3.6.1.4.1.4788.2.202.1': 'EV D-TRUST Root Class 3 CA 2 EV 2009',
    '1.3.6.1.4.1.6334.1.100.1': 'EV Cybertrust Global Root',
    '1.3.6.1.4.1.6449.1.2.1.5.1': 'EV USERTrust Certification Authorities',
    '1.3.6.1.4.1.781.1.2.1.8.1': 'EV Network Solutions Certificate Authority',
    '1.3.6.1.4.1.782.1.2.1.8.1': 'EV AddTrust External CA Root',
    '1.3.6.1.4.1.7879.13.24.1': 'EV T-Telessec GlobalRoot Class 3',
    '1.3.6.1.4.1.8024.0.2.100.1.2': 'EV QuoVadis Roots',
    '2.16.528.1.1003.1.2.7': 'EV Staat der Nederlanden EV Root CA',
    '2.16.578.1.26.1.3.3': 'EV Buypass Class 3',
    '2.16.756.1.83.21.0': 'EV Swisscom Root EV CA 2',
    '2.16.756.1.89.1.2.1.1': 'EV SwissSign Gold CA - G2',
    '2.16.792.3.0.4.1.1.4': 'EV E-Tugra Certification Authority',
    '2.16.840.1.113733.1.7.23.6': 'EV VeriSign Certification Authorities',
    '2.16.840.1.113733.1.7.48.1': 'EV thawte CAs',
    '2.16.840.1.114028.10.1.2': 'EV Entrust Certification Authority',
    '2.16.840.1.114171.500.9': 'EV Wells Fargo WellsSecure Public Root Certification Authority',  # noqa: E501
    '2.16.840.1.114404.1.1.2.4.1': 'EV XRamp Global Certification Authority',
    '2.16.840.1.114412.2.1': 'EV DigiCert High Assurance EV Root CA',
    '2.16.840.1.114413.1.7.23.3': 'EV ValiCert Class 2 Policy Validation Authority',  # noqa: E501
    '2.16.840.1.114414.1.7.23.3': 'EV Starfield Certificate Authority',
    '2.16.840.1.114414.1.7.24.3': 'EV Starfield Service Certificate Authority'  # noqa: E501
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
#  Hash mapping helper  #
#########################

# This dict enables static access to string references to the hash functions
# of some algorithms from pkcs1_oids and x962Signature_oids.

hash_by_oid = {
    "1.2.840.113549.1.1.2": "md2",
    "1.2.840.113549.1.1.3": "md4",
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512"
}
