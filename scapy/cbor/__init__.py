# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Package holding CBOR (Concise Binary Object Representation) related modules.
Follows the same paradigm as ASN.1 implementation.
"""

from scapy.cbor.cbor import (
    CBOR_Error,
    CBOR_Encoding_Error,
    CBOR_Decoding_Error,
    CBOR_BadTag_Decoding_Error,
    CBOR_Codecs,
    CBOR_MajorTypes,
    CBOR_Object,
    CBOR_UNSIGNED_INTEGER,
    CBOR_NEGATIVE_INTEGER,
    CBOR_BYTE_STRING,
    CBOR_TEXT_STRING,
    CBOR_ARRAY,
    CBOR_MAP,
    CBOR_SEMANTIC_TAG,
    CBOR_SIMPLE_VALUE,
    CBOR_FALSE,
    CBOR_TRUE,
    CBOR_NULL,
    CBOR_UNDEFINED,
    CBOR_FLOAT,
    CBOR_DECODING_ERROR,
    RandCBORObject,
)

from scapy.cbor.cborcodec import (
    CBORcodec_Object,
    CBORcodec_UNSIGNED_INTEGER,
    CBORcodec_NEGATIVE_INTEGER,
    CBORcodec_BYTE_STRING,
    CBORcodec_TEXT_STRING,
    CBORcodec_ARRAY,
    CBORcodec_MAP,
    CBORcodec_SEMANTIC_TAG,
    CBORcodec_SIMPLE_AND_FLOAT,
)

__all__ = [
    # Exceptions
    "CBOR_Error",
    "CBOR_Encoding_Error",
    "CBOR_Decoding_Error",
    "CBOR_BadTag_Decoding_Error",
    # Codecs
    "CBOR_Codecs",
    "CBOR_MajorTypes",
    # Objects
    "CBOR_Object",
    "CBOR_UNSIGNED_INTEGER",
    "CBOR_NEGATIVE_INTEGER",
    "CBOR_BYTE_STRING",
    "CBOR_TEXT_STRING",
    "CBOR_ARRAY",
    "CBOR_MAP",
    "CBOR_SEMANTIC_TAG",
    "CBOR_SIMPLE_VALUE",
    "CBOR_FALSE",
    "CBOR_TRUE",
    "CBOR_NULL",
    "CBOR_UNDEFINED",
    "CBOR_FLOAT",
    "CBOR_DECODING_ERROR",
    # Random/Fuzzing
    "RandCBORObject",
    # Codec classes
    "CBORcodec_Object",
    "CBORcodec_UNSIGNED_INTEGER",
    "CBORcodec_NEGATIVE_INTEGER",
    "CBORcodec_BYTE_STRING",
    "CBORcodec_TEXT_STRING",
    "CBORcodec_ARRAY",
    "CBORcodec_MAP",
    "CBORcodec_SEMANTIC_TAG",
    "CBORcodec_SIMPLE_AND_FLOAT",
]
