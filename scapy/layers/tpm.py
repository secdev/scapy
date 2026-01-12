# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Implementation of structures related to TPM 2.0 and Windows PCP

(Windows Plateform Crypto Provider)
"""

from scapy.config import conf
from scapy.packet import Packet
from scapy.fields import (
    BitField,
    ByteField,
    ConditionalField,
    FlagsField,
    IntField,
    LEIntEnumField,
    LEIntField,
    LongField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
)


##########################
#    TPM 2 structures    #
##########################

IMPLEMENTATION_PCR = 24
PCR_SELECT_MAX = (IMPLEMENTATION_PCR + 7) // 8
MAX_RSA_KEY_BITS = 2048
MAX_RSA_KEY_BYTES = (MAX_RSA_KEY_BITS + 7) // 8

# TPM20.h source

TPM_ALG = {
    0x0000: "TPM_ALG_ERROR",
    0x0001: "TPM_ALG_RSA",
    0x0004: "TPM_ALG_SHA1",
    0x0005: "TPM_ALG_HMAC",
    0x0006: "TPM_ALG_AES",
    0x0007: "TPM_ALG_MGF1",
    0x0008: "TPM_ALG_KEYEDHASH",
    0x000A: "TPM_ALG_XOR",
    0x000B: "TPM_ALG_SHA256",
    0x000C: "TPM_ALG_SHA384",
    0x000D: "TPM_ALG_SHA512",
    0x0010: "TPM_ALG_NULL",
    0x0012: "TPM_ALG_SM3_256",
    0x0013: "TPM_ALG_SM4",
    0x0014: "TPM_ALG_RSASSA",
    0x0015: "TPM_ALG_RSAES",
    0x0016: "TPM_ALG_RSAPSS",
    0x0017: "TPM_ALG_OAEP",
    0x0018: "TPM_ALG_ECDSA",
    0x0019: "TPM_ALG_ECDH",
    0x001A: "TPM_ALG_ECDAA",
    0x001B: "TPM_ALG_SM2",
    0x001C: "TPM_ALG_ECSCHNORR",
    0x001D: "TPM_ALG_ECMQV",
    0x0020: "TPM_ALG_KDF1_SP800_56a",
    0x0021: "TPM_ALG_KDF2",
    0x0022: "TPM_ALG_KDF1_SP800_108",
    0x0023: "TPM_ALG_ECC",
    0x0025: "TPM_ALG_SYMCIPHER",
    0x0040: "TPM_ALG_CTR",
    0x0041: "TPM_ALG_OFB",
    0x0042: "TPM_ALG_CBC",
    0x0043: "TPM_ALG_CFB",
    0x0044: "TPM_ALG_ECB",
}

TPM_ST = {
    0x00C4: "TPM_ST_RSP_COMMAND",
    0x8000: "TPM_ST_NULL",
    0x8001: "TPM_ST_NO_SESSIONS",
    0x8002: "TPM_ST_SESSIONS",
    0x8014: "TPM_ST_ATTEST_NV",
    0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
    0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
    0x8017: "TPM_ST_ATTEST_CERTIFY",
    0x8018: "TPM_ST_ATTEST_QUOTE",
    0x8019: "TPM_ST_ATTEST_TIME",
    0x801A: "TPM_ST_ATTEST_CREATION",
    0x8021: "TPM_ST_CREATION",
    0x8022: "TPM_ST_VERIFIED",
    0x8023: "TPM_ST_AUTH_SECRET",
    0x8024: "TPM_ST_HASHCHECK",
    0x8025: "TPM_ST_AUTH_SIGNED",
    0x8029: "TPM_ST_FU_MANIFEST",
}


class _Packet(Packet):
    def default_payload_class(self, payload):
        return conf.padding_layer


class TPMS_SCHEME_SIGHASH(_Packet):
    fields_desc = [
        ShortEnumField("hashAlg", 0, TPM_ALG),
    ]


class TPMT_RSA_SCHEME(_Packet):
    fields_desc = [
        ShortEnumField("scheme", 0, TPM_ALG),
        # TPMU_ASYM_SCHEME
        MultipleTypeField(
            [
                (
                    PacketField(
                        "parameters", TPMS_SCHEME_SIGHASH(), TPMS_SCHEME_SIGHASH
                    ),
                    lambda pkt: pkt.scheme
                    in [
                        0x0014,  # RSASSA
                        0x0016,  # RSAPSS
                        0x001A,  # RSAPSS
                        0x001B,  # SM2
                        0x001C,  # ECSCHNORR
                    ],
                )
            ],
            StrFixedLenField("parameters", b"", length=0),
        ),
    ]


class TPMT_SYM_DEF_OBJECT(_Packet):
    fields_desc = [
        ShortEnumField("algorithm", 0, TPM_ALG),
        ConditionalField(
            ShortField("keyBits", 0),
            lambda pkt: pkt.algorithm != 0x0010,
        ),
        ConditionalField(
            ShortField("mode", 0),
            lambda pkt: pkt.algorithm != 0x0010,
        ),
    ]


class TPMS_RSA_PARMS(_Packet):
    fields_desc = [
        PacketField("symmetric", TPMT_SYM_DEF_OBJECT(), TPMT_SYM_DEF_OBJECT),
        PacketField("scheme", TPMT_RSA_SCHEME(), TPMT_RSA_SCHEME),
        ShortField("keyBits", 0),
        IntField("exponent", 0),
    ]


class TPM2B_DIGEST(_Packet):
    fields_desc = [
        ShortField("size", 0),
        StrLenField("buffer", b"", length_from=lambda pkt: pkt.size),
    ]


class TPML_DIGEST(_Packet):
    fields_desc = [
        IntField("count", 0),
        PacketListField("digests", [], TPM2B_DIGEST, count_from=lambda pkt: pkt.count),
    ]


class TPMS_NULL_PARMS(_Packet):
    fields_desc = [
        ShortEnumField("algorithm", 0x0010, TPM_ALG),
    ]


class TPMT_PUBLIC(_Packet):
    fields_desc = [
        ShortEnumField("type", 0x0001, TPM_ALG),
        ShortEnumField("nameAlg", 0, TPM_ALG),
        FlagsField(
            "objectAttributes",
            0,
            32,
            [
                "reserved1",
                "fixedTPM",
                "stClear",
                "reserved4",
                "fixedParent",
                "sensitiveDataOrigin",
                "userWithAuth",
                "adminWithPolicy",
                "reserved8",
                "reserved9",
                "noDA",
                "encryptedDuplication",
                "reserved12",
                "reserved13",
                "reserved14",
                "reserved15",
                "restricted",
                "decrypt",
                "sign",
            ],
        ),
        PacketField("authPolicy", TPM2B_DIGEST(), TPM2B_DIGEST),
        MultipleTypeField(
            [
                # TPMU_PUBLIC_PARMS
                (
                    PacketField("parameters", TPMS_RSA_PARMS(), TPMS_RSA_PARMS),
                    lambda pkt: pkt.type == 0x0001,
                )
            ],
            StrFixedLenField("parameters", b"", length=0),
        ),
        # TPMU_PUBLIC_ID
        PacketField("unique", TPM2B_DIGEST(), TPM2B_DIGEST),
    ]


class TPM2B_PUBLIC(_Packet):
    fields_desc = [
        ShortField("size", 0),
        PacketLenField(
            "publicArea",
            TPMT_PUBLIC(),
            TPMT_PUBLIC,
            length_from=lambda pkt: pkt.size,
        ),
    ]


class TPM2B_PRIVATE_KEY_RSA(_Packet):
    fields_desc = [
        ShortField("size", 0),
        StrLenField(
            "buffer",
            b"",
            length_from=lambda pkt: pkt.size,
        ),
    ]


TPM2B_AUTH = TPM2B_DIGEST


class TPMT_SENSITIVE(_Packet):
    fields_desc = [
        ShortEnumField("sensitiveType", 0, TPM_ALG),
        PacketField("authValue", TPM2B_AUTH(), TPM2B_AUTH),
        PacketField("seedValue", TPM2B_DIGEST(), TPM2B_DIGEST),
        MultipleTypeField(
            [
                # TPMU_SENSITIVE_COMPOSITE
                (
                    PacketField(
                        "sensitive", TPM2B_PRIVATE_KEY_RSA(), TPM2B_PRIVATE_KEY_RSA
                    ),
                    lambda pkt: pkt.sensitiveType == 0x0001,  # TPM_ALG_RSA
                ),
            ],
            StrField("sensitive", b""),
        ),
    ]


class TPM2B_SENSITIVE(_Packet):
    fields_desc = [
        ShortField("size", 0),
        PacketLenField(
            "sensitiveArea",
            TPMT_SENSITIVE(),
            TPMT_SENSITIVE,
            length_from=lambda pkt: pkt.size,
        ),
    ]


class _PRIVATE(_Packet):
    fields_desc = [
        PacketField("integrityOuter", TPM2B_DIGEST(), TPM2B_DIGEST),
        PacketField("integrityInner", TPM2B_DIGEST(), TPM2B_DIGEST),
        StrField("sensitive", b""),  # Encrypted
    ]


class TPM2B_PRIVATE(_Packet):
    fields_desc = [
        ShortField("size", 0),
        PacketLenField(
            "buffer",
            _PRIVATE(),
            _PRIVATE,
            length_from=lambda pkt: pkt.size,
        ),
    ]


class TPM2B_NAME(_Packet):
    fields_desc = [
        ShortField("size", 0),
        StrLenField("Name", b"", length_from=lambda pkt: pkt.size),
    ]


class TPM2B_DATA(_Packet):
    fields_desc = [
        ShortField("size", 0),
        StrLenField("buffer", b"", length_from=lambda pkt: pkt.size),
    ]


class TPMA_LOCALITY(_Packet):
    fields_desc = [
        BitField("locZero", 0, 1),
        BitField("locOne", 0, 1),
        BitField("locTwo", 0, 1),
        BitField("locThree", 0, 1),
        BitField("locFour", 0, 1),
        BitField("Extended", 0, 3),
    ]


class TPMS_PCR_SELECTION(_Packet):
    fields_desc = [
        ShortEnumField("hash", 0, TPM_ALG),
        ByteField("sizeOfSelect", 0),
        StrFixedLenField("pcrSelect", b"", length=PCR_SELECT_MAX),
    ]


class TPML_PCR_SELECTION(_Packet):
    fields_desc = [
        IntField("count", 0),
        PacketListField(
            "pcrSelections", [], TPMS_PCR_SELECTION, count_from=lambda pkt: pkt.count
        ),
    ]


class TPMS_CREATION_DATA(_Packet):
    fields_desc = [
        PacketField("pcrSelect", TPML_PCR_SELECTION(), TPML_PCR_SELECTION),
        PacketField("pcrDigest", TPM2B_DIGEST(), TPM2B_DIGEST),
        PacketField("locality", TPMA_LOCALITY(), TPMA_LOCALITY),
        ShortEnumField("parentNameAlg", 0, TPM_ALG),
        PacketField("parentName", TPM2B_NAME(), TPM2B_NAME),
        PacketField("parentQualifiedName", TPM2B_NAME(), TPM2B_NAME),
        PacketField("outsideInfo", TPM2B_DATA(), TPM2B_DATA),
    ]


class TPM2B_CREATION_DATA(_Packet):
    fields_desc = [
        ShortField("size", 0),
        PacketLenField(
            "creationData",
            TPMS_CREATION_DATA(),
            TPMS_CREATION_DATA,
            length_from=lambda pkt: pkt.size,
        ),
    ]


class TPMS_CLOCK_INFO(_Packet):
    fields_desc = [
        LongField("clock", 0),  # obfuscated
        IntField("resetCount", 0),  # obfuscated
        IntField("restartCount", 0),  # obfuscated
        ByteField("safe", 0),
    ]


class TPMS_CREATION_INFO(_Packet):
    fields_desc = [
        PacketField("objectName", TPM2B_NAME(), TPM2B_NAME),
        PacketField("creationHash", TPM2B_DIGEST(), TPM2B_DIGEST),
    ]


class TPMS_CERTIFY_INFO(_Packet):
    fields_desc = [
        PacketField("Name", TPM2B_NAME(), TPM2B_NAME),
        PacketField("qualifiedName", TPM2B_DIGEST(), TPM2B_DIGEST),
    ]


class TPMS_ATTEST(_Packet):
    fields_desc = [
        StrFixedLenField("magic", b"\xffTCG", length=4),
        ShortEnumField("type", 0, TPM_ST),
        PacketField("qualifiedSigned", TPM2B_NAME(), TPM2B_NAME),
        PacketField("extraData", TPM2B_DATA(), TPM2B_DATA),
        PacketField("clockInfo", TPMS_CLOCK_INFO(), TPMS_CLOCK_INFO),
        LongField("firmwareVersion", 0),
        MultipleTypeField(
            [
                # TPMU_ATTEST
                (
                    PacketField("attested", TPMS_CERTIFY_INFO(), TPMS_CERTIFY_INFO),
                    lambda pkt: pkt.type == 0x8017,  # TPM_ST_ATTEST_CERTIFY
                ),
                (
                    PacketField("attested", TPMS_CREATION_INFO(), TPMS_CREATION_INFO),
                    lambda pkt: pkt.type == 0x801A,  # TPM_ST_ATTEST_CREATION
                ),
            ],
            StrField("attested", b""),
        ),
    ]


class TPM2B_ATTEST(_Packet):
    fields_desc = [
        ShortField("size", 0),
        PacketLenField(
            "attestationData",
            TPMS_ATTEST(),
            TPMS_ATTEST,
            length_from=lambda pkt: pkt.size,
        ),
    ]


class TPM2B_PUBLIC_KEY_RSA(_Packet):
    fields_desc = [
        ShortField("size", 0),
        StrFixedLenField("buffer", b"", length=MAX_RSA_KEY_BYTES),
    ]


class TPMS_SIGNATURE_RSASSA(_Packet):
    fields_desc = [
        ShortEnumField("hash", 0, TPM_ALG),
        PacketField("sig", TPM2B_PUBLIC_KEY_RSA(), TPM2B_PUBLIC_KEY_RSA),
    ]


class TPMS_SIGNATURE_RSAPSS(_Packet):
    fields_desc = [
        ShortEnumField("hash", 0, TPM_ALG),
        PacketField("sig", TPM2B_PUBLIC_KEY_RSA(), TPM2B_PUBLIC_KEY_RSA),
    ]


class TPMT_SIGNATURE(_Packet):
    fields_desc = [
        ShortEnumField("sigAlg", 0, TPM_ALG),
        MultipleTypeField(
            [
                # TPMU_SIGNATURE
                (
                    PacketField(
                        "signature", TPMS_SIGNATURE_RSASSA(), TPMS_SIGNATURE_RSASSA
                    ),
                    lambda pkt: pkt.sigAlg == 0x0014,  # RSASSA
                ),
                (
                    PacketField(
                        "signature", TPMS_SIGNATURE_RSAPSS(), TPMS_SIGNATURE_RSAPSS
                    ),
                    lambda pkt: pkt.sigAlg == 0x0016,  # RSASSA
                ),
            ],
            StrField("signature", b""),
        ),
    ]


# From "Using the Windows 8 Platform PCP" documentation
# https://github.com/Microsoft/TSS.MSR/blob/main/PCPTool.v11/inc/TpmAtt.h


# NCRYPT_PCP_TPM12_IDBINDING
class PCP_IDBinding20(Packet):
    fields_desc = [
        PacketField("PublicKey", TPM2B_PUBLIC(), TPM2B_PUBLIC),
        PacketField("CreationData", TPM2B_CREATION_DATA(), TPM2B_CREATION_DATA),
        PacketField("Attest", TPM2B_ATTEST(), TPM2B_ATTEST),
        PacketField("Signature", TPMT_SIGNATURE(), TPMT_SIGNATURE),
    ]


_PCP_TYPE = {
    1: "TPM 1.2",
    2: "TPM 2.0",
}


class PCP_KEY_BLOB(Packet):
    fields_desc = [
        StrFixedLenField("Magic", b"PCPM", length=4),
        LEIntField("cbHeader", 0),
        LEIntEnumField("pcpType", 1, _PCP_TYPE),
        FlagsField(
            "flags",
            0,
            -32,
            {
                0x00000001: "authRequired",
                0x00000002: "undocumented2",
            },
        ),
        LEIntField("cbTpmKey", 0),
        StrLenField(
            "tpmKey",
            b"",
            length_from=lambda pkt: pkt.cbTpmKey,
        ),
    ]


class PCP_20_KEY_BLOB(Packet):
    fields_desc = [
        StrFixedLenField("Magic", b"PCPM", length=4),
        LEIntField("cbHeader", 0),
        LEIntEnumField("pcpType", 2, _PCP_TYPE),
        FlagsField(
            "flags",
            0,
            -32,
            {
                0x00000001: "authRequired",
                0x00000002: "undocumented2",
            },
        ),
        LEIntField("cbPublic", 0),
        LEIntField("cbPrivate", 0),
        LEIntField("cbMigrationPublic", 0),
        LEIntField("cbMigrationPrivate", 0),
        LEIntField("cbPolicyDigestList", 0),
        LEIntField("cbPCRBinding", 0),
        LEIntField("cbPCRDigest", 0),
        LEIntField("cbEncryptedSecret", 0),
        LEIntField("cbTpm12HostageBlob", 0),
        LEIntField("pcrAlgId", 0),
        PacketLenField(
            "public",
            TPM2B_PUBLIC(),
            TPM2B_PUBLIC,
            length_from=lambda pkt: pkt.cbPublic,
        ),
        PacketLenField(
            "private",
            TPM2B_PRIVATE(),
            TPM2B_PRIVATE,
            length_from=lambda pkt: pkt.cbPrivate,
        ),
        PacketLenField(
            "migrationPublic",
            None,
            TPM2B_PUBLIC,
            length_from=lambda pkt: pkt.cbMigrationPublic,
        ),
        PacketLenField(
            "migrationPrivate",
            TPM2B_PRIVATE(),
            TPM2B_PRIVATE,
            length_from=lambda pkt: pkt.cbMigrationPrivate,
        ),
        PacketLenField(
            "policyDigestList",
            TPML_DIGEST(),
            TPML_DIGEST,
            length_from=lambda pkt: pkt.cbPolicyDigestList,
        ),
        StrLenField(
            "pcrBinding",
            b"",
            length_from=lambda pkt: pkt.cbPCRBinding,
        ),
        StrLenField(
            "pcrDigest",
            b"",
            length_from=lambda pkt: pkt.cbPCRDigest,
        ),
        StrLenField(
            "encryptedSecret",
            b"",
            length_from=lambda pkt: pkt.cbEncryptedSecret,
        ),
        StrLenField(
            "tpm12HostageBlob",
            b"",
            length_from=lambda pkt: pkt.cbTpm12HostageBlob,
        ),
    ]


###########################
#    Microsoft Windows    #
###########################

# [MS-WCCE] sect 2.2.2.5


class KeyAttestation(Packet):
    fields_desc = [
        StrFixedLenField("Magic", b"KADS", length=4),
        LEIntEnumField("Platform", 2, _PCP_TYPE),
        LEIntField("HeaderSize", 0),
        LEIntField("cbKeyAttest", 0),
        LEIntField("cbSignature", 0),
        LEIntField("cbKeyBlob", 0),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "keyAttest",
                        TPMS_ATTEST(),
                        TPMS_ATTEST,
                        length_from=lambda pkt: pkt.cbKeyAttest,
                    ),
                    lambda pkt: pkt.Platform == 2,
                )
            ],
            StrLenField(
                "keyAttest",
                b"",
                length_from=lambda pkt: pkt.cbKeyAttest,
            ),
        ),
        StrLenField(
            "signature",
            b"",
            length_from=lambda pkt: pkt.cbSignature,
        ),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "keyBlob",
                        PCP_20_KEY_BLOB(),
                        PCP_20_KEY_BLOB,
                        length_from=lambda pkt: pkt.cbKeyBlob,
                    ),
                    lambda pkt: pkt.Platform == 2,
                ),
                (
                    PacketLenField(
                        "keyBlob",
                        PCP_KEY_BLOB(),
                        PCP_KEY_BLOB,
                        length_from=lambda pkt: pkt.cbKeyBlob,
                    ),
                    lambda pkt: pkt.Platform == 1,
                ),
            ],
            StrLenField(
                "keyBlob",
                b"",
                length_from=lambda pkt: pkt.cbKeyBlob,
            ),
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class KeyAttestationStatement(Packet):
    fields_desc = [
        StrFixedLenField("Magic", b"KAST", length=4),
        LEIntField("Version", 1),
        LEIntEnumField("Platform", 2, _PCP_TYPE),
        LEIntField("HeaderSize", 0),
        LEIntField("cbIdBinding", 0),
        LEIntField("cbKeyAttestation", 0),
        LEIntField("cbAIKOpaque", 0),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "idBinding",
                        PCP_IDBinding20(),
                        PCP_IDBinding20,
                        length_from=lambda pkt: pkt.cbIdBinding,
                    ),
                    lambda pkt: pkt.Platform == 2,
                )
            ],
            StrLenField(
                "idBinding",
                b"",
                length_from=lambda pkt: pkt.cbIdBinding,
            ),
        ),
        PacketLenField(
            "keyAttestation",
            KeyAttestation(),
            KeyAttestation,
            length_from=lambda pkt: pkt.cbKeyAttestation,
        ),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "aikOpaque",
                        PCP_20_KEY_BLOB(),
                        PCP_20_KEY_BLOB,
                        length_from=lambda pkt: pkt.cbAIKOpaque,
                    ),
                    lambda pkt: pkt.Platform == 2,
                ),
                (
                    PacketLenField(
                        "aikOpaque",
                        PCP_KEY_BLOB(),
                        PCP_KEY_BLOB,
                        length_from=lambda pkt: pkt.cbAIKOpaque,
                    ),
                    lambda pkt: pkt.Platform == 1,
                ),
            ],
            StrLenField(
                "aikOpaque",
                b"",
                length_from=lambda pkt: pkt.cbAIKOpaque,
            ),
        ),
    ]
