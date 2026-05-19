# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tyler M

# scapy.contrib.description = DICOM (Digital Imaging and Communications in Medicine)
# scapy.contrib.status = loads

"""
DICOM (Digital Imaging and Communications in Medicine) Protocol

Upper Layer PDUs (PS3.8), DIMSE-C/N commands (PS3.7), association
negotiation sub-items (PS3.7 D.3.3), and Transfer Syntax constants (PS3.5).

The DICOM protocol stack::

    +---------------------------+
    |  DIMSE Messages (PS3.7)   |  C-ECHO, C-STORE, N-GET, ...
    +---------------------------+
    |  P-DATA-TF PDV payload    |
    +---------------------------+
    |  Upper Layer PDUs (PS3.8) |  A-ASSOCIATE, P-DATA-TF, A-RELEASE
    +---------------------------+
    |          TCP              |
    +---------------------------+

DIMSE Command Sets are always Implicit VR Little Endian (PS3.7 §9.3);
the negotiated Transfer Syntax applies only to Data Sets in P-DATA-TF PDVs.

References:
    https://dicom.nema.org/medical/dicom/current/output/html/part05.html
    https://dicom.nema.org/medical/dicom/current/output/html/part07.html
    https://dicom.nema.org/medical/dicom/current/output/html/part08.html
"""

import logging
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from scapy.compat import Self
from scapy.packet import Packet, bind_layers
from scapy.error import Scapy_Exception
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    IntField,
    LenField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    StrLenField,
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.volatile import RandShort, RandInt, RandString

__all__ = [
    # Constants
    "DICOM_PORT", "DICOM_PORT_ALT", "APP_CONTEXT_UID",
    # Transfer Syntax UIDs (PS3.5 Annex A)
    "DEFAULT_TRANSFER_SYNTAX_UID", "IMPLICIT_VR_LITTLE_ENDIAN_UID",
    "EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "ENCAPSULATED_UNCOMPRESSED_EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "EXPLICIT_VR_BIG_ENDIAN_UID",
    "JPEG_BASELINE_UID", "JPEG_EXTENDED_UID", "JPEG_LOSSLESS_UID",
    "JPEG_LS_LOSSLESS_UID", "JPEG_LS_LOSSY_UID",
    "JPEG_2000_LOSSLESS_UID", "JPEG_2000_UID",
    "JPEG_2000_PART2_MC_LOSSLESS_UID", "JPEG_2000_PART2_MC_UID",
    "MPEG2_MPML_UID", "MPEG2_MPHL_UID",
    "MPEG4_AVC_H264_HP_LEVEL_4_1_UID",
    "MPEG4_AVC_H264_BD_COMPATIBLE_HP_LEVEL_4_1_UID",
    "MPEG4_AVC_H264_HP_LEVEL_4_2_2D_UID",
    "MPEG4_AVC_H264_HP_LEVEL_4_2_3D_UID",
    "MPEG4_AVC_H264_STEREO_HP_LEVEL_2_UID",
    "HEVC_H265_MP_LEVEL_5_1_UID", "HEVC_H265_10P_LEVEL_5_1_UID",
    "JPEGXL_LOSSLESS_UID", "JPEGXL_RECOMPRESSION_UID", "JPEGXL_UID",
    "RLE_LOSSLESS_UID",
    "HTJP2K_LOSSLESS_UID", "HTJP2K_LOSSLESS_RPCL_UID", "HTJP2K_UID",
    "JPIP_REFERENCED_UID", "JPIP_REFERENCED_DEFLATE_UID",
    "JPIP_HTJ2K_REFERENCED_UID", "JPIP_HTJ2K_REFERENCED_DEFLATE_UID",
    "MPEG2_MPML_FRAG_UID", "MPEG2_MPHL_FRAG_UID",
    "MPEG4_AVC_H264_HP_LEVEL_4_1_FRAG_UID",
    "MPEG4_AVC_H264_BD_COMPATIBLE_HP_LEVEL_4_1_FRAG_UID",
    "MPEG4_AVC_H264_HP_LEVEL_4_2_2D_FRAG_UID",
    "MPEG4_AVC_H264_HP_LEVEL_4_2_3D_FRAG_UID",
    "MPEG4_AVC_H264_STEREO_HP_LEVEL_2_FRAG_UID",
    "SMPTE_ST_2110_20_UNCOMPRESSED_PROGRESSIVE_UID",
    "SMPTE_ST_2110_20_UNCOMPRESSED_INTERLACED_UID",
    "SMPTE_ST_2110_30_PCM_AUDIO_UID",
    # SOP Class UIDs (PS3.4)
    "SOP_CLASS_NAMES",
    "VERIFICATION_SOP_CLASS_UID", "CT_IMAGE_STORAGE_SOP_CLASS_UID",
    "MR_IMAGE_STORAGE_SOP_CLASS_UID", "SECONDARY_CAPTURE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_FIND_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_GET_SOP_CLASS_UID",
    "STUDY_ROOT_QR_FIND_SOP_CLASS_UID",
    "STUDY_ROOT_QR_MOVE_SOP_CLASS_UID",
    "STUDY_ROOT_QR_GET_SOP_CLASS_UID",
    # PDU Classes (PS3.8 Section 9.3)
    "DICOM", "A_ASSOCIATE_RQ", "A_ASSOCIATE_AC", "A_ASSOCIATE_RJ",
    "P_DATA_TF", "A_RELEASE_RQ", "A_RELEASE_RP", "A_ABORT",
    "PresentationDataValueItem",
    # Variable Items (PS3.8 Section 9.3.2)
    "DICOMVariableItem", "DICOMApplicationContext",
    "DICOMPresentationContextRQ", "DICOMPresentationContextAC",
    "DICOMAbstractSyntax", "DICOMTransferSyntax",
    "DICOMUserInformation", "DICOMMaximumLength", "DICOMGenericItem",
    # Extended User Info Sub-Items (PS3.7 D.3.3)
    "DICOMImplementationClassUID", "DICOMAsyncOperationsWindow",
    "DICOMSCPSCURoleSelection", "DICOMImplementationVersionName",
    "DICOMSOPClassExtendedNegotiation",
    "DICOMSOPClassCommonExtendedNegotiation",
    "DICOMUserIdentity", "DICOMUserIdentityResponse",
    # DIMSE Field Classes
    "DICOMAETitleField", "DICOMElementField",
    "DICOMUIDField", "DICOMUIDFieldRaw",
    "DICOMUSField", "DICOMULField", "DICOMStatusField",
    "DICOMAEDIMSEField", "DICOMATField",
    # DIMSE Base Class
    "DIMSEPacket",
    # DIMSE-C Commands (PS3.7 Section 9.3)
    "C_ECHO_RQ", "C_ECHO_RSP", "C_STORE_RQ", "C_STORE_RSP",
    "C_FIND_RQ", "C_FIND_RSP", "C_MOVE_RQ", "C_MOVE_RSP",
    "C_GET_RQ", "C_GET_RSP", "C_CANCEL_RQ",
    # DIMSE-N Commands (PS3.7 Section 10.3)
    "N_EVENT_REPORT_RQ", "N_EVENT_REPORT_RSP",
    "N_GET_RQ", "N_GET_RSP", "N_SET_RQ", "N_SET_RSP",
    "N_ACTION_RQ", "N_ACTION_RSP", "N_CREATE_RQ", "N_CREATE_RSP",
    "N_DELETE_RQ", "N_DELETE_RSP",
    # Utilities
    "DICOMSocket", "parse_dimse_status", "dimse_status_repr",
    "_uid_to_bytes", "_uid_to_bytes_raw",
    "build_presentation_context_rq", "build_user_information",
    # DIMSE Status Codes (PS3.7 Annex C)
    "DIMSE_STATUS_CODES",
    "STATUS_SUCCESS", "STATUS_CANCEL",
    "STATUS_PENDING", "STATUS_PENDING_WARNINGS",
    "STATUS_WARNING_ATTRIBUTE_LIST", "STATUS_WARNING_ATTR_OUT_OF_RANGE",
    "STATUS_ERR_SOP_CLASS_NOT_SUPPORTED",
    "STATUS_ERR_CLASS_INSTANCE_CONFLICT",
    "STATUS_ERR_DUPLICATE_SOP_INSTANCE",
    "STATUS_ERR_DUPLICATE_INVOCATION",
    "STATUS_ERR_INVALID_ARGUMENT", "STATUS_ERR_INVALID_ATTRIBUTE_VALUE",
    "STATUS_ERR_INVALID_SOP_INSTANCE", "STATUS_ERR_MISSING_ATTRIBUTE",
    "STATUS_ERR_MISSING_ATTRIBUTE_VALUE", "STATUS_ERR_MISTYPED_ARGUMENT",
    "STATUS_ERR_NO_SUCH_ARGUMENT", "STATUS_ERR_NO_SUCH_ATTRIBUTE",
    "STATUS_ERR_NO_SUCH_EVENT_TYPE", "STATUS_ERR_NO_SUCH_SOP_INSTANCE",
    "STATUS_ERR_NO_SUCH_SOP_CLASS", "STATUS_ERR_PROCESSING_FAILURE",
    "STATUS_ERR_RESOURCE_LIMITATION", "STATUS_ERR_UNRECOGNIZED_OPERATION",
    "STATUS_ERR_NO_SUCH_ACTION_TYPE", "STATUS_ERR_NOT_AUTHORIZED",
    "STATUS_ERR_REFUSED_OUT_OF_RESOURCES",
    "STATUS_ERR_REFUSED_OUT_OF_RESOURCES_MOVE",
    "STATUS_ERR_REFUSED_MOVE_DESTINATION_UNKNOWN",
    "STATUS_ERR_REFUSED_SOP_CLASS_NOT_SUPPORTED",
]

log = logging.getLogger("scapy.contrib.dicom")

DICOM_PORT = 104
DICOM_PORT_ALT = 11112
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"

# Transfer Syntax UIDs (PS3.5 Annex A)
# -- Core --
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
IMPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2"
EXPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2.1"
ENCAPSULATED_UNCOMPRESSED_EXPLICIT_VR_LITTLE_ENDIAN_UID = \
    "1.2.840.10008.1.2.1.98"
DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2.1.99"
EXPLICIT_VR_BIG_ENDIAN_UID = "1.2.840.10008.1.2.2"  # retired
# -- JPEG --
JPEG_BASELINE_UID = "1.2.840.10008.1.2.4.50"
JPEG_EXTENDED_UID = "1.2.840.10008.1.2.4.51"
JPEG_LOSSLESS_UID = "1.2.840.10008.1.2.4.70"
# -- JPEG-LS --
JPEG_LS_LOSSLESS_UID = "1.2.840.10008.1.2.4.80"
JPEG_LS_LOSSY_UID = "1.2.840.10008.1.2.4.81"
# -- JPEG 2000 --
JPEG_2000_LOSSLESS_UID = "1.2.840.10008.1.2.4.90"
JPEG_2000_UID = "1.2.840.10008.1.2.4.91"
JPEG_2000_PART2_MC_LOSSLESS_UID = "1.2.840.10008.1.2.4.92"
JPEG_2000_PART2_MC_UID = "1.2.840.10008.1.2.4.93"
# -- MPEG-2 (PS3.5 A.4.4) --
MPEG2_MPML_UID = "1.2.840.10008.1.2.4.100"
MPEG2_MPHL_UID = "1.2.840.10008.1.2.4.101"
# -- MPEG-4 / H.264 (PS3.5 A.4.5–A.4.9) --
MPEG4_AVC_H264_HP_LEVEL_4_1_UID = "1.2.840.10008.1.2.4.102"
MPEG4_AVC_H264_BD_COMPATIBLE_HP_LEVEL_4_1_UID = "1.2.840.10008.1.2.4.103"
MPEG4_AVC_H264_HP_LEVEL_4_2_2D_UID = "1.2.840.10008.1.2.4.104"
MPEG4_AVC_H264_HP_LEVEL_4_2_3D_UID = "1.2.840.10008.1.2.4.105"
MPEG4_AVC_H264_STEREO_HP_LEVEL_2_UID = "1.2.840.10008.1.2.4.106"
# -- HEVC / H.265 (PS3.5 A.4.10–A.4.11) --
HEVC_H265_MP_LEVEL_5_1_UID = "1.2.840.10008.1.2.4.107"
HEVC_H265_10P_LEVEL_5_1_UID = "1.2.840.10008.1.2.4.108"
# -- JPEG XL (PS3.5 A.4.12–A.4.14) --
JPEGXL_LOSSLESS_UID = "1.2.840.10008.1.2.4.110"
JPEGXL_RECOMPRESSION_UID = "1.2.840.10008.1.2.4.111"
JPEGXL_UID = "1.2.840.10008.1.2.4.112"
# -- RLE --
RLE_LOSSLESS_UID = "1.2.840.10008.1.2.5"
# -- HTJ2K (PS3.5 A.4.15–A.4.17) --
HTJP2K_LOSSLESS_UID = "1.2.840.10008.1.2.4.201"
HTJP2K_LOSSLESS_RPCL_UID = "1.2.840.10008.1.2.4.202"
HTJP2K_UID = "1.2.840.10008.1.2.4.203"
# -- JPIP Referenced (PS3.5 A.6) --
JPIP_REFERENCED_UID = "1.2.840.10008.1.2.4.94"
JPIP_REFERENCED_DEFLATE_UID = "1.2.840.10008.1.2.4.95"
JPIP_HTJ2K_REFERENCED_UID = "1.2.840.10008.1.2.4.204"
JPIP_HTJ2K_REFERENCED_DEFLATE_UID = "1.2.840.10008.1.2.4.205"
# -- Fragmentable video variants --
MPEG2_MPML_FRAG_UID = "1.2.840.10008.1.2.4.100.1"
MPEG2_MPHL_FRAG_UID = "1.2.840.10008.1.2.4.101.1"
MPEG4_AVC_H264_HP_LEVEL_4_1_FRAG_UID = "1.2.840.10008.1.2.4.102.1"
MPEG4_AVC_H264_BD_COMPATIBLE_HP_LEVEL_4_1_FRAG_UID = \
    "1.2.840.10008.1.2.4.103.1"
MPEG4_AVC_H264_HP_LEVEL_4_2_2D_FRAG_UID = "1.2.840.10008.1.2.4.104.1"
MPEG4_AVC_H264_HP_LEVEL_4_2_3D_FRAG_UID = "1.2.840.10008.1.2.4.105.1"
MPEG4_AVC_H264_STEREO_HP_LEVEL_2_FRAG_UID = "1.2.840.10008.1.2.4.106.1"
# -- SMPTE ST 2110 (PS3.5 A.7) --
SMPTE_ST_2110_20_UNCOMPRESSED_PROGRESSIVE_UID = "1.2.840.10008.1.2.7.1"
SMPTE_ST_2110_20_UNCOMPRESSED_INTERLACED_UID = "1.2.840.10008.1.2.7.2"
SMPTE_ST_2110_30_PCM_AUDIO_UID = "1.2.840.10008.1.2.7.3"

# SOP Class UIDs (PS3.4)
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"
MR_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.4"
SECONDARY_CAPTURE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"
PATIENT_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.1"
PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.2"
PATIENT_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.3"
STUDY_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.1"
STUDY_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.2"
STUDY_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.3"

# Display-only lookup for commonly negotiated SOP Classes (PS3.4).
SOP_CLASS_NAMES = {
    "1.2.840.10008.1.1": "Verification",
    # Storage — imaging
    "1.2.840.10008.5.1.4.1.1.1": "CR Image Storage",
    "1.2.840.10008.5.1.4.1.1.1.1": "Digital X-Ray Image Storage (Presentation)",
    "1.2.840.10008.5.1.4.1.1.1.1.1": "Digital X-Ray Image Storage (Processing)",
    "1.2.840.10008.5.1.4.1.1.2": "CT Image Storage",
    "1.2.840.10008.5.1.4.1.1.2.1": "Enhanced CT Image Storage",
    "1.2.840.10008.5.1.4.1.1.2.2": "Legacy Converted Enhanced CT Image Storage",
    "1.2.840.10008.5.1.4.1.1.3.1": "Ultrasound Multi-frame Image Storage",
    "1.2.840.10008.5.1.4.1.1.4": "MR Image Storage",
    "1.2.840.10008.5.1.4.1.1.4.1": "Enhanced MR Image Storage",
    "1.2.840.10008.5.1.4.1.1.4.4": "Legacy Converted Enhanced MR Image Storage",
    "1.2.840.10008.5.1.4.1.1.6.1": "Ultrasound Image Storage",
    "1.2.840.10008.5.1.4.1.1.6.2": "Enhanced US Volume Storage",
    "1.2.840.10008.5.1.4.1.1.7": "Secondary Capture Image Storage",
    "1.2.840.10008.5.1.4.1.1.7.1": "Multi-frame Single Bit SC Image Storage",
    "1.2.840.10008.5.1.4.1.1.7.2": "Multi-frame Grayscale Byte SC Image Storage",
    "1.2.840.10008.5.1.4.1.1.7.3": "Multi-frame Grayscale Word SC Image Storage",
    "1.2.840.10008.5.1.4.1.1.7.4": "Multi-frame True Color SC Image Storage",
    "1.2.840.10008.5.1.4.1.1.12.1": "X-Ray Angiographic Image Storage",
    "1.2.840.10008.5.1.4.1.1.12.2": "X-Ray Radiofluoroscopic Image Storage",
    "1.2.840.10008.5.1.4.1.1.20": "Nuclear Medicine Image Storage",
    "1.2.840.10008.5.1.4.1.1.77.1.1": "VL Endoscopic Image Storage",
    "1.2.840.10008.5.1.4.1.1.77.1.4": "VL Photographic Image Storage",
    "1.2.840.10008.5.1.4.1.1.77.1.5.1": "Ophthalmic Photography 8 Bit Image Storage",
    "1.2.840.10008.5.1.4.1.1.104.1": "Encapsulated PDF Storage",
    "1.2.840.10008.5.1.4.1.1.128": "PET Image Storage",
    "1.2.840.10008.5.1.4.1.1.128.1": "Enhanced PET Image Storage",
    "1.2.840.10008.5.1.4.1.1.481.1": "RT Image Storage",
    "1.2.840.10008.5.1.4.1.1.481.2": "RT Dose Storage",
    "1.2.840.10008.5.1.4.1.1.481.3": "RT Structure Set Storage",
    "1.2.840.10008.5.1.4.1.1.481.5": "RT Plan Storage",
    "1.2.840.10008.5.1.4.1.1.66.4": "Segmentation Storage",
    # Query/Retrieve
    "1.2.840.10008.5.1.4.1.2.1.1": "Patient Root QR Find",
    "1.2.840.10008.5.1.4.1.2.1.2": "Patient Root QR Move",
    "1.2.840.10008.5.1.4.1.2.1.3": "Patient Root QR Get",
    "1.2.840.10008.5.1.4.1.2.2.1": "Study Root QR Find",
    "1.2.840.10008.5.1.4.1.2.2.2": "Study Root QR Move",
    "1.2.840.10008.5.1.4.1.2.2.3": "Study Root QR Get",
    # Worklist
    "1.2.840.10008.5.1.4.31": "Modality Worklist Find",
    # MPPS
    "1.2.840.10008.3.1.2.3.3": "Modality Performed Procedure Step",
    # Storage Commitment
    "1.2.840.10008.1.20.1": "Storage Commitment Push Model",
    # Presentation State
    "1.2.840.10008.5.1.4.1.1.11.1": "Grayscale Softcopy Presentation State Storage",
    "1.2.840.10008.5.1.4.1.1.11.2": "Color Softcopy Presentation State Storage",
    # Structured Report
    "1.2.840.10008.5.1.4.1.1.88.11": "Basic Text SR Storage",
    "1.2.840.10008.5.1.4.1.1.88.22": "Enhanced SR Storage",
    "1.2.840.10008.5.1.4.1.1.88.33": "Comprehensive SR Storage",
}

PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ", 0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ", 0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ", 0x06: "A-RELEASE-RP", 0x07: "A-ABORT",
}

ITEM_TYPES = {
    0x10: "Application Context", 0x20: "Presentation Context RQ",
    0x21: "Presentation Context AC", 0x30: "Abstract Syntax",
    0x40: "Transfer Syntax", 0x50: "User Information",
    0x51: "Maximum Length", 0x52: "Implementation Class UID",
    0x53: "Asynchronous Operations Window",
    0x54: "SCP/SCU Role Selection", 0x55: "Implementation Version Name",
    0x56: "SOP Class Extended Negotiation",
    0x57: "SOP Class Common Extended Negotiation",
    0x58: "User Identity", 0x59: "User Identity Server Response",
}

DIMSE_COMMAND_FIELDS = {
    0x0001: "C-STORE-RQ", 0x8001: "C-STORE-RSP",
    0x0010: "C-GET-RQ", 0x8010: "C-GET-RSP",
    0x0020: "C-FIND-RQ", 0x8020: "C-FIND-RSP",
    0x0021: "C-MOVE-RQ", 0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ", 0x8030: "C-ECHO-RSP", 0x0FFF: "C-CANCEL-RQ",
    0x0100: "N-EVENT-REPORT-RQ", 0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ", 0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ", 0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ", 0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ", 0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ", 0x8150: "N-DELETE-RSP",
}

DATA_SET_TYPES = {
    0x0000: "Data Set Present", 0x0001: "Data Set Present",
    0x0101: "No Data Set",
}

PRIORITY_VALUES = {0x0000: "MEDIUM", 0x0001: "HIGH", 0x0002: "LOW"}

USER_IDENTITY_TYPES = {
    1: "Username", 2: "Username and Passcode",
    3: "Kerberos Service Ticket", 4: "SAML Assertion",
    5: "JSON Web Token (JWT)",
}

# DIMSE Status Codes (PS3.7 Annex C)
STATUS_SUCCESS = 0x0000
STATUS_CANCEL = 0xFE00
STATUS_PENDING = 0xFF00
STATUS_PENDING_WARNINGS = 0xFF01
STATUS_WARNING_ATTRIBUTE_LIST = 0x0107
STATUS_WARNING_ATTR_OUT_OF_RANGE = 0x0116
STATUS_ERR_SOP_CLASS_NOT_SUPPORTED = 0x0122
STATUS_ERR_CLASS_INSTANCE_CONFLICT = 0x0119
STATUS_ERR_DUPLICATE_SOP_INSTANCE = 0x0111
STATUS_ERR_DUPLICATE_INVOCATION = 0x0210
STATUS_ERR_INVALID_ARGUMENT = 0x0115
STATUS_ERR_INVALID_ATTRIBUTE_VALUE = 0x0106
STATUS_ERR_INVALID_SOP_INSTANCE = 0x0117
STATUS_ERR_MISSING_ATTRIBUTE = 0x0120
STATUS_ERR_MISSING_ATTRIBUTE_VALUE = 0x0121
STATUS_ERR_MISTYPED_ARGUMENT = 0x0212
STATUS_ERR_NO_SUCH_ARGUMENT = 0x0114
STATUS_ERR_NO_SUCH_ATTRIBUTE = 0x0105
STATUS_ERR_NO_SUCH_EVENT_TYPE = 0x0113
STATUS_ERR_NO_SUCH_SOP_INSTANCE = 0x0112
STATUS_ERR_NO_SUCH_SOP_CLASS = 0x0118
STATUS_ERR_PROCESSING_FAILURE = 0x0110
STATUS_ERR_RESOURCE_LIMITATION = 0x0213
STATUS_ERR_UNRECOGNIZED_OPERATION = 0x0211
STATUS_ERR_NO_SUCH_ACTION_TYPE = 0x0123
STATUS_ERR_NOT_AUTHORIZED = 0x0124
STATUS_ERR_REFUSED_OUT_OF_RESOURCES = 0xA700
STATUS_ERR_REFUSED_OUT_OF_RESOURCES_MOVE = 0xA701
STATUS_ERR_REFUSED_MOVE_DESTINATION_UNKNOWN = 0xA801
STATUS_ERR_REFUSED_SOP_CLASS_NOT_SUPPORTED = 0xA900

# Combined lookup dict for display purposes.
DIMSE_STATUS_CODES = {
    0x0000: "Success",
    0x0001: "Warning: Requested optional attributes not supported",
    0x0107: "Warning: Attribute list error",
    0x0116: "Warning: Attribute value out of range",
    0x0110: "Processing failure",
    0x0111: "Duplicate SOP instance",
    0x0112: "No such SOP instance",
    0x0113: "No such event type",
    0x0114: "No such argument",
    0x0115: "Invalid argument value",
    0x0117: "Invalid SOP instance",
    0x0118: "No such SOP class",
    0x0119: "Class-instance conflict",
    0x0120: "Missing attribute",
    0x0121: "Missing attribute value",
    0x0122: "SOP class not supported",
    0x0123: "No such action type",
    0x0124: "Not authorized",
    0x0210: "Duplicate invocation",
    0x0211: "Unrecognized operation",
    0x0212: "Mistyped argument",
    0x0213: "Resource limitation",
    0xA700: "Refused: Out of resources",
    0xA701: "Refused: Out of resources — unable to calculate number of matches",
    0xA801: "Refused: Move destination unknown",
    0xA900: "Refused: SOP class not supported",
    0xFE00: "Cancel",
    0xFF00: "Pending",
    0xFF01: "Pending: Warning — optional keys not supported",
}


def dimse_status_repr(code: int) -> str:
    """Return a human-readable string for a DIMSE status code (PS3.7 Annex C)."""
    if code in DIMSE_STATUS_CODES:
        return "%s (0x%04X)" % (DIMSE_STATUS_CODES[code], code)
    if 0xA000 <= code <= 0xAFFF:
        return "Refused (service-class-specific 0x%04X)" % code
    if 0xB000 <= code <= 0xBFFF:
        return "Warning (service-class-specific 0x%04X)" % code
    if 0xC000 <= code <= 0xCFFF:
        return "Unable to process (service-class-specific 0x%04X)" % code
    return "0x%04X" % code


def _uid_to_bytes(uid: Union[str, bytes]) -> bytes:
    """Convert UID to bytes with even-length padding per PS3.8 Annex F."""
    if isinstance(uid, bytes):
        b_uid = uid
    elif isinstance(uid, str):
        b_uid = uid.encode("ascii")
    else:
        return b""
    if len(b_uid) % 2 != 0:
        b_uid += b"\x00"
    return b_uid


def _uid_to_bytes_raw(uid: Union[str, bytes]) -> bytes:
    """Convert UID to bytes without padding."""
    if isinstance(uid, bytes):
        return uid
    elif isinstance(uid, str):
        return uid.encode("ascii")
    else:
        return b""


class DICOMAETitleField(StrFixedLenField):
    """DICOM AE Title field - 16 bytes, space-padded (PS3.8 Table 9-11)."""

    def __init__(self, name: str, default: bytes = b"") -> None:
        super(DICOMAETitleField, self).__init__(name, default, length=16)

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        return val.ljust(16, b" ")[:16]

    def m2i(self, pkt: Optional[Packet], val: bytes) -> bytes:
        return val

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip()
        return str(val).rstrip()


class DICOMElementField(Field[bytes, bytes]):
    """DICOM Data Element field with Implicit VR Little Endian tag+length encoding."""

    __slots__ = ["tag_group", "tag_elem"]

    def __init__(self, name: str, default: Any, tag_group: int,
                 tag_elem: int) -> None:
        self.tag_group = tag_group
        self.tag_elem = tag_elem
        Field.__init__(self, name, default)

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        hdr = struct.pack("<HHI", self.tag_group, self.tag_elem, len(val))
        return s + hdr + val

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, bytes]:
        if len(s) < 8:
            return s, b""
        # Skip unexpected elements that sort before ours (e.g. retired (0000,0001)).
        while len(s) >= 8:
            tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
            if tag_g == self.tag_group and tag_e == self.tag_elem:
                break
            if (tag_g, tag_e) > (self.tag_group, self.tag_elem):
                return s, b""
            if len(s) < 8 + length:
                return s, b""
            log.info("Skipping unexpected DICOM element (%04X,%04X)",
                     tag_g, tag_e)
            s = s[8 + length:]
        if len(s) < 8:
            return s, b""
        tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
        if len(s) < 8 + length:
            raise Scapy_Exception(
                "Not enough bytes to decode DICOM element value: "
                "expected %d bytes, only %d available" % (length, len(s) - 8)
            )
        value = s[8:8 + length]
        return s[8 + length:], value

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            try:
                return val.decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                return val.hex()
        return repr(val)

    def randval(self) -> RandString:
        return RandString(8)


class DICOMUIDField(DICOMElementField):
    """DICOM UID element field with automatic even-length padding."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        val = _uid_to_bytes(val) if val else b""
        return DICOMElementField.addfield(self, pkt, s, val)

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip("\x00")
        return str(val)

    def randval(self) -> str:
        from scapy.volatile import RandNum
        return "1.2.3.%d.%d.%d" % (
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix()
        )


class DICOMUIDFieldRaw(DICOMElementField):
    """DICOM UID element field without automatic padding."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        val = _uid_to_bytes_raw(val) if val else b""
        return DICOMElementField.addfield(self, pkt, s, val)


class DICOMUSField(DICOMElementField):
    """DICOM Unsigned Short (US) element field."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: int) -> bytes:
        val_bytes = struct.pack("<H", val)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, int]:
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        if len(val_bytes) >= 2:
            return remain, struct.unpack("<H", val_bytes[:2])[0]
        return remain, 0

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return "0x%04X" % val

    def randval(self) -> RandShort:
        return RandShort()


class DICOMULField(DICOMElementField):
    """DICOM Unsigned Long (UL) element field."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: int) -> bytes:
        val_bytes = struct.pack("<I", val)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, int]:
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        if len(val_bytes) >= 4:
            return remain, struct.unpack("<I", val_bytes[:4])[0]
        return remain, 0

    def randval(self) -> RandInt:
        return RandInt()


class DICOMStatusField(DICOMUSField):
    """DIMSE Status field (0000,0900) with range-aware display."""

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return dimse_status_repr(val)


class DICOMAEDIMSEField(DICOMElementField):
    """DICOM AE element field for DIMSE - 16 bytes, space-padded."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        val = val.ljust(16, b" ")[:16]
        return DICOMElementField.addfield(self, pkt, s, val)

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").strip()
        return str(val).strip()


class DICOMATField(DICOMElementField):
    """DICOM Attribute Tag (AT) element field for N-GET Attribute Identifier List."""

    # islist=True prevents Scapy's SetGen from yielding nothing on empty lists,
    # which would break do_build iteration.
    islist = True

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        if val is None:
            val = []
        if not isinstance(val, (list, tuple)):
            val = [val]
        val_bytes = b""
        for tag in val:
            if isinstance(tag, tuple) and len(tag) == 2:
                val_bytes += struct.pack("<HH", tag[0], tag[1])
            elif isinstance(tag, int):
                val_bytes += struct.pack(
                    "<HH", (tag >> 16) & 0xFFFF, tag & 0xFFFF
                )
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, list]:
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        tags = []
        offset = 0
        while offset + 4 <= len(val_bytes):
            group, elem = struct.unpack("<HH", val_bytes[offset:offset + 4])
            tags.append((group, elem))
            offset += 4
        return remain, tags

    def randval(self) -> list:
        return []


class DICOMGenericItem(Packet):
    """Generic fallback — unknown sub-item types are skipped per PS3.8 D.2."""
    name = "DICOM Generic Item"
    fields_desc = [
        StrLenField(
            "data", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.data)
            )
        ),
    ]

    def post_dissect(self, s: bytes) -> bytes:
        if self.underlayer and hasattr(self.underlayer, "item_type"):
            log.info("Skipping unknown sub-item type 0x%02X (%d bytes)",
                     self.underlayer.item_type, len(self.data))
        return s

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s


class DICOMVariableItem(Packet):
    """DICOM Variable Item header (PS3.8 Section 9.3.2)."""
    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, ITEM_TYPES),
        ByteField("reserved", 0),
        LenField("length", None, fmt="!H"),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        if self.length is not None:
            if len(s) < self.length:
                raise Scapy_Exception("PDU payload incomplete")
            return s[:self.length], s[self.length:]
        return s, b""

    def guess_payload_class(self, payload: bytes) -> type:
        type_to_class = {
            0x10: DICOMApplicationContext,
            0x20: DICOMPresentationContextRQ,
            0x21: DICOMPresentationContextAC,
            0x30: DICOMAbstractSyntax,
            0x40: DICOMTransferSyntax,
            0x50: DICOMUserInformation,
            0x51: DICOMMaximumLength,
            0x52: DICOMImplementationClassUID,
            0x53: DICOMAsyncOperationsWindow,
            0x54: DICOMSCPSCURoleSelection,
            0x55: DICOMImplementationVersionName,
            0x56: DICOMSOPClassExtendedNegotiation,
            0x57: DICOMSOPClassCommonExtendedNegotiation,
            0x58: DICOMUserIdentity,
            0x59: DICOMUserIdentityResponse,
        }
        return type_to_class.get(self.item_type, DICOMGenericItem)

    def mysummary(self) -> str:
        return self.sprintf("Item %item_type%")


class DICOMApplicationContext(Packet):
    name = "DICOM Application Context"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes(APP_CONTEXT_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "AppContext %s" % self.uid.decode("ascii").rstrip("\x00")


class DICOMAbstractSyntax(Packet):
    name = "DICOM Abstract Syntax"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        uid_str = self.uid.decode("ascii").rstrip("\x00")
        name = SOP_CLASS_NAMES.get(uid_str)
        if name:
            return "AbstractSyntax %s (%s)" % (uid_str, name)
        return "AbstractSyntax %s" % uid_str


class DICOMTransferSyntax(Packet):
    name = "DICOM Transfer Syntax"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes(DEFAULT_TRANSFER_SYNTAX_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "TransferSyntax %s" % self.uid.decode("ascii").rstrip("\x00")


class DICOMPresentationContextRQ(Packet):
    name = "DICOM Presentation Context RQ"
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=64,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "PresentationContext-RQ ctx_id=%d" % self.context_id


class DICOMPresentationContextAC(Packet):
    name = "DICOM Presentation Context AC"
    RESULT_CODES = {
        0: "acceptance", 1: "user-rejection",
        2: "no-reason (provider rejection)",
        3: "abstract-syntax-not-supported (provider rejection)",
        4: "transfer-syntaxes-not-supported (provider rejection)",
    }
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteEnumField("result", 0, RESULT_CODES),
        ByteField("reserved2", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=8,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return self.sprintf(
            "PresentationContext-AC ctx_id=%context_id% result=%result%"
        )


class DICOMMaximumLength(Packet):
    """Value of 0 indicates no maximum length specified."""
    name = "DICOM Maximum Length"
    fields_desc = [IntField("max_pdu_length", 16384)]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        if self.max_pdu_length == 0:
            return "MaxLength (unlimited)"
        return "MaxLength %d" % self.max_pdu_length


class DICOMImplementationClassUID(Packet):
    name = "DICOM Implementation Class UID"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "ImplClassUID %s" % self.uid.decode("ascii").rstrip("\x00")


class DICOMImplementationVersionName(Packet):
    name = "DICOM Implementation Version Name"
    fields_desc = [
        StrLenField(
            "name", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.name)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "ImplVersion %s" % self.name.decode("ascii").rstrip("\x00")


class DICOMAsyncOperationsWindow(Packet):
    name = "DICOM Async Operations Window"
    fields_desc = [
        ShortField("max_ops_invoked", 1),
        ShortField("max_ops_performed", 1),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "AsyncOps inv=%d perf=%d" % (
            self.max_ops_invoked, self.max_ops_performed
        )


class DICOMSCPSCURoleSelection(Packet):
    name = "DICOM SCP/SCU Role Selection"
    fields_desc = [
        FieldLenField("uid_length", None, length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.uid_length),
        ByteField("scu_role", 0),
        ByteField("scp_role", 0),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "RoleSelection SCU=%d SCP=%d" % (self.scu_role, self.scp_role)


class DICOMSOPClassExtendedNegotiation(Packet):
    name = "DICOM SOP Class Extended Negotiation"
    fields_desc = [
        FieldLenField("sop_class_uid_length", None,
                      length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.sop_class_uid_length),
        StrLenField("service_class_application_information", b"",
                    length_from=lambda pkt: (
                        pkt.underlayer.length - 2 - pkt.sop_class_uid_length
                        if pkt.underlayer and pkt.underlayer.length
                        else 0
                    )),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        uid = self.sop_class_uid.decode("ascii").rstrip("\x00")
        return "SOPClassExtNeg %s" % uid


class DICOMSOPClassCommonExtendedNegotiation(Packet):
    """Item 0x57 — header byte 2 is Sub-Item-Version (PS3.7 D.3.3.6), not reserved."""
    name = "DICOM SOP Class Common Extended Negotiation"
    fields_desc = [
        FieldLenField("sop_class_uid_length", None,
                      length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.sop_class_uid_length),
        FieldLenField("service_class_uid_length", None,
                      length_of="service_class_uid", fmt="!H"),
        StrLenField("service_class_uid", b"",
                    length_from=lambda pkt: pkt.service_class_uid_length),
        FieldLenField("related_sop_class_uid_length", None,
                      length_of="related_sop_class_uids", fmt="!H"),
        StrLenField("related_sop_class_uids", b"",
                    length_from=lambda pkt: pkt.related_sop_class_uid_length),
    ]

    @property
    def sub_item_version(self) -> int:
        """Return the Sub-Item-Version from the DICOMVariableItem header."""
        if self.underlayer and hasattr(self.underlayer, "reserved"):
            return self.underlayer.reserved
        return 0

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        uid = self.sop_class_uid.decode("ascii").rstrip("\x00")
        return "SOPClassCommonExtNeg v%d %s" % (self.sub_item_version, uid)


class DICOMUserIdentity(Packet):
    name = "DICOM User Identity"
    fields_desc = [
        ByteEnumField("user_identity_type", 1, USER_IDENTITY_TYPES),
        ByteField("positive_response_requested", 0),
        FieldLenField("primary_field_length", None,
                      length_of="primary_field", fmt="!H"),
        StrLenField("primary_field", b"",
                    length_from=lambda pkt: pkt.primary_field_length),
        ConditionalField(
            FieldLenField("secondary_field_length", None,
                          length_of="secondary_field", fmt="!H"),
            lambda pkt: pkt.user_identity_type == 2
        ),
        ConditionalField(
            StrLenField("secondary_field", b"",
                        length_from=lambda pkt: pkt.secondary_field_length),
            lambda pkt: pkt.user_identity_type == 2
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return self.sprintf("UserIdentity %user_identity_type%")


class DICOMUserIdentityResponse(Packet):
    name = "DICOM User Identity Response"
    fields_desc = [
        FieldLenField("response_length", None,
                      length_of="server_response", fmt="!H"),
        StrLenField("server_response", b"",
                    length_from=lambda pkt: pkt.response_length),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "UserIdentityResponse"


class DICOMUserInformation(Packet):
    name = "DICOM User Information"
    fields_desc = [
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=32,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "UserInfo (%d items)" % len(self.sub_items)


# Layer Bindings for Variable Items
bind_layers(DICOMVariableItem, DICOMApplicationContext, item_type=0x10)
bind_layers(DICOMVariableItem, DICOMPresentationContextRQ, item_type=0x20)
bind_layers(DICOMVariableItem, DICOMPresentationContextAC, item_type=0x21)
bind_layers(DICOMVariableItem, DICOMAbstractSyntax, item_type=0x30)
bind_layers(DICOMVariableItem, DICOMTransferSyntax, item_type=0x40)
bind_layers(DICOMVariableItem, DICOMUserInformation, item_type=0x50)
bind_layers(DICOMVariableItem, DICOMMaximumLength, item_type=0x51)
bind_layers(DICOMVariableItem, DICOMImplementationClassUID, item_type=0x52)
bind_layers(DICOMVariableItem, DICOMAsyncOperationsWindow, item_type=0x53)
bind_layers(DICOMVariableItem, DICOMSCPSCURoleSelection, item_type=0x54)
bind_layers(DICOMVariableItem, DICOMImplementationVersionName, item_type=0x55)
bind_layers(DICOMVariableItem, DICOMSOPClassExtendedNegotiation, item_type=0x56)
bind_layers(DICOMVariableItem, DICOMSOPClassCommonExtendedNegotiation,
            item_type=0x57)
bind_layers(DICOMVariableItem, DICOMUserIdentity, item_type=0x58)
bind_layers(DICOMVariableItem, DICOMUserIdentityResponse, item_type=0x59)
bind_layers(DICOMVariableItem, DICOMGenericItem)


class DICOM(Packet):
    """DICOM Upper Layer PDU Header (PS3.8 Section 9.3.1)."""
    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        LenField("length", None, fmt="!I"),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        if self.length is not None:
            return s[:self.length], s[self.length:]
        return s, b""

    def mysummary(self) -> str:
        return self.sprintf("DICOM %pdu_type%")


class PresentationDataValueItem(Packet):
    # PDV header is BE (PS3.8); DIMSE payload inside data is LE (PS3.7 §9.3).

    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="!I",
                      adjust=lambda pkt, x: x + 2),
        ByteField("context_id", 1),
        BitField("reserved_bits", 0, 6),
        BitField("is_last", 0, 1),
        BitField("is_command", 0, 1),
        StrLenField("data", b"",
                    length_from=lambda pkt: max(0, (pkt.length or 2) - 2)),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        cmd_or_data = "CMD" if self.is_command else "DATA"
        last = " LAST" if self.is_last else ""
        return "PDV ctx=%d %s%s len=%d" % (
            self.context_id, cmd_or_data, last, len(self.data)
        )


class A_ASSOCIATE_RQ(Packet):
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        called = self.called_ae_title
        if isinstance(called, bytes):
            called = called.decode("ascii", errors="replace").strip()
        calling = self.calling_ae_title
        if isinstance(calling, bytes):
            calling = calling.decode("ascii", errors="replace").strip()
        return "A-ASSOCIATE-RQ %s -> %s" % (calling, called)

    def hashret(self) -> bytes:
        return self.called_ae_title + self.calling_ae_title


class A_ASSOCIATE_AC(Packet):
    # Bytes 11-42 / 43-74 are reserved but echo the AE titles from A-ASSOCIATE-RQ.
    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        called = self.called_ae_title
        if isinstance(called, bytes):
            called = called.decode("ascii", errors="replace").strip()
        calling = self.calling_ae_title
        if isinstance(calling, bytes):
            calling = calling.decode("ascii", errors="replace").strip()
        return "A-ASSOCIATE-AC %s <- %s" % (calling, called)

    def hashret(self) -> bytes:
        return self.called_ae_title + self.calling_ae_title

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_ASSOCIATE_RQ)


class A_ASSOCIATE_RJ(Packet):
    name = "A-ASSOCIATE-RJ"
    RESULT_CODES = {1: "rejected-permanent", 2: "rejected-transient"}
    SOURCE_CODES = {
        1: "DICOM UL service-user",
        2: "DICOM UL service-provider (ACSE related function)",
        3: "DICOM UL service-provider (Presentation related function)",
    }
    REASON_USER = {
        1: "no-reason-given", 2: "application-context-name-not-supported",
        3: "calling-AE-title-not-recognized",
        7: "called-AE-title-not-recognized",
    }
    REASON_ACSE = {1: "no-reason-given", 2: "protocol-version-not-supported"}
    REASON_PRESENTATION = {
        0: "reserved", 1: "temporary-congestion", 2: "local-limit-exceeded",
    }
    fields_desc = [
        ByteField("reserved1", 0),
        ByteEnumField("result", 1, RESULT_CODES),
        ByteEnumField("source", 1, SOURCE_CODES),
        ByteField("reason_diag", 1),
    ]

    def mysummary(self) -> str:
        return self.sprintf("A-ASSOCIATE-RJ %result% %source%")

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_ASSOCIATE_RQ)


class P_DATA_TF(Packet):
    name = "P-DATA-TF"
    fields_desc = [
        PacketListField(
            "pdv_items", [],
            PresentationDataValueItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        return "P-DATA-TF (%d PDVs)" % len(self.pdv_items)


class A_RELEASE_RQ(Packet):
    name = "A-RELEASE-RQ"
    fields_desc = [IntField("reserved1", 0)]

    def mysummary(self) -> str:
        return "A-RELEASE-RQ"


class A_RELEASE_RP(Packet):
    name = "A-RELEASE-RP"
    fields_desc = [IntField("reserved1", 0)]

    def mysummary(self) -> str:
        return "A-RELEASE-RP"

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_RELEASE_RQ)


class A_ABORT(Packet):
    name = "A-ABORT"
    SOURCE_CODES = {
        0: "DICOM UL service-user (initiated abort)",
        1: "reserved",
        2: "DICOM UL service-provider (initiated abort)",
    }
    REASON_PROVIDER = {
        0: "reason-not-specified", 1: "unrecognized-PDU",
        2: "unexpected-PDU", 3: "reserved",
        4: "unrecognized-PDU-parameter", 5: "unexpected-PDU-parameter",
        6: "invalid-PDU-parameter-value",
    }
    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteEnumField("source", 0, SOURCE_CODES),
        ByteField("reason_diag", 0),
    ]

    def mysummary(self) -> str:
        return self.sprintf("A-ABORT %source%")


# TCP Port and PDU Type Bindings
bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(TCP, DICOM, dport=DICOM_PORT_ALT)
bind_layers(TCP, DICOM, sport=DICOM_PORT_ALT)
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


class DIMSEPacket(Packet):
    """Base class for DIMSE commands; auto-prepends Command Group Length (0000,0000)."""
    GROUP_LENGTH_ELEMENT_SIZE = 12

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        group_len = len(pkt)
        header = struct.pack("<HHI", 0x0000, 0x0000, 4)
        header += struct.pack("<I", group_len)
        return header + pkt + pay


class C_ECHO_RQ(DIMSEPacket):
    name = "C-ECHO-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0030, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-ECHO-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_ECHO_RSP(DIMSEPacket):
    name = "C-ECHO-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8030, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-ECHO-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_ECHO_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_STORE_RQ(DIMSEPacket):
    name = "C-STORE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0001, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
        ConditionalField(
            DICOMAEDIMSEField("move_originator_ae_title", b"", 0x0000, 0x1030),
            lambda pkt: pkt.fields.get("move_originator_ae_title")
            not in (None, b"", b" " * 16)
        ),
        ConditionalField(
            DICOMUSField("move_originator_message_id", 0, 0x0000, 0x1031),
            lambda pkt: pkt.fields.get("move_originator_message_id")
            not in (None, 0)
        ),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-STORE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_STORE_RSP(DIMSEPacket):
    name = "C-STORE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8001, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-STORE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_STORE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_FIND_RQ(DIMSEPacket):
    name = "C-FIND-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0020, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-FIND-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_FIND_RSP(DIMSEPacket):
    name = "C-FIND-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8020, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-FIND-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_FIND_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_GET_RQ(DIMSEPacket):
    name = "C-GET-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0010, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-GET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_GET_RSP(DIMSEPacket):
    name = "C-GET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8010, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-GET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_MOVE_RQ(DIMSEPacket):
    """Move Destination (0000,0600) precedes Priority (0000,0700) per §6.3.1."""
    name = "C-MOVE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0021, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMAEDIMSEField("move_destination", b"", 0x0000, 0x0600),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-MOVE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_MOVE_RSP(DIMSEPacket):
    name = "C-MOVE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8021, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-MOVE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_MOVE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_CANCEL_RQ(DIMSEPacket):
    name = "C-CANCEL-RQ"
    fields_desc = [
        DICOMUSField("command_field", 0x0FFF, 0x0000, 0x0100),
        DICOMUSField("message_id_being_responded_to", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf(
            "C-CANCEL-RQ canceling=%message_id_being_responded_to%"
        )


class N_EVENT_REPORT_RQ(DIMSEPacket):
    name = "N-EVENT-REPORT-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0100, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("event_type_id", 0, 0x0000, 0x1002),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-EVENT-REPORT-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_EVENT_REPORT_RSP(DIMSEPacket):
    name = "N-EVENT-REPORT-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8100, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("event_type_id", 0, 0x0000, 0x1002),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-EVENT-REPORT-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_EVENT_REPORT_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_GET_RQ(DIMSEPacket):
    name = "N-GET-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0110, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
        DICOMATField("attribute_identifier_list", [], 0x0000, 0x1005),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-GET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_GET_RSP(DIMSEPacket):
    name = "N-GET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8110, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-GET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_SET_RQ(DIMSEPacket):
    name = "N-SET-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0120, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-SET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_SET_RSP(DIMSEPacket):
    name = "N-SET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8120, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-SET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_SET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_ACTION_RQ(DIMSEPacket):
    name = "N-ACTION-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0130, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
        DICOMUSField("action_type_id", 0, 0x0000, 0x1008),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-ACTION-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_ACTION_RSP(DIMSEPacket):
    name = "N-ACTION-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8130, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("action_type_id", 0, 0x0000, 0x1008),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-ACTION-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_ACTION_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_CREATE_RQ(DIMSEPacket):
    name = "N-CREATE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0140, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-CREATE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_CREATE_RSP(DIMSEPacket):
    name = "N-CREATE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8140, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-CREATE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_CREATE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_DELETE_RQ(DIMSEPacket):
    name = "N-DELETE-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0150, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-DELETE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_DELETE_RSP(DIMSEPacket):
    name = "N-DELETE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8150, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMStatusField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-DELETE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_DELETE_RQ):
            return self.message_id_responded == other.message_id
        return 0


def parse_dimse_status(dimse_bytes: bytes) -> Optional[int]:
    """Extract status code (0000,0900) from DIMSE response bytes."""
    try:
        if len(dimse_bytes) < 12:
            return None
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        offset = 12
        group_end_offset = offset + cmd_group_len
        while offset < group_end_offset and offset + 8 <= len(dimse_bytes):
            tag_group, tag_elem = struct.unpack(
                "<HH", dimse_bytes[offset:offset + 4]
            )
            value_len = struct.unpack(
                "<I", dimse_bytes[offset + 4:offset + 8]
            )[0]
            if (
                tag_group == 0x0000
                and tag_elem == 0x0900
                and value_len == 2
            ):
                if offset + 10 > len(dimse_bytes):
                    break
                if offset + 10 > group_end_offset:
                    break
                return struct.unpack(
                    "<H", dimse_bytes[offset + 8:offset + 10]
                )[0]
            offset += 8 + value_len
    except struct.error:
        return None
    return None


def build_presentation_context_rq(context_id: int,
                                  abstract_syntax_uid: str,
                                  transfer_syntax_uids: List[str]) -> Packet:
    """Build a Presentation Context RQ item."""
    abs_uid = _uid_to_bytes(abstract_syntax_uid)
    abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=abs_uid)
    sub_items = [abs_syn]
    for ts_uid in transfer_syntax_uids:
        ts = DICOMVariableItem() / DICOMTransferSyntax(
            uid=_uid_to_bytes(ts_uid)
        )
        sub_items.append(ts)
    return DICOMVariableItem() / DICOMPresentationContextRQ(
        context_id=context_id,
        sub_items=sub_items,
    )


def build_user_information(
    max_pdu_length: int = 16384,
    implementation_class_uid: Optional[str] = None,
    implementation_version: Optional[Union[str, bytes]] = None
) -> Packet:
    """Build a User Information item."""
    sub_items = [
        DICOMVariableItem() / DICOMMaximumLength(
            max_pdu_length=max_pdu_length
        )
    ]
    if implementation_class_uid:
        uid = _uid_to_bytes(implementation_class_uid)
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationClassUID(uid=uid)
        )
    if implementation_version:
        if isinstance(implementation_version, bytes):
            ver_bytes = implementation_version
        else:
            ver_bytes = implementation_version.encode('ascii')
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationVersionName(
                name=ver_bytes
            )
        )
    return DICOMVariableItem() / DICOMUserInformation(sub_items=sub_items)


class DICOMSocket:
    """DICOM application-layer socket for associations and DIMSE operations."""

    def __init__(self, dst_ip: str, dst_port: int, dst_ae: str,
                 src_ae: str = "SCAPY_SCU",
                 read_timeout: int = 10) -> None:
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = dst_ae
        self.src_ae = src_ae
        self.sock: Optional[socket.socket] = None
        self.stream: Optional[StreamSocket] = None
        self.assoc_established = False
        self.accepted_contexts: Dict[int, Tuple[str, str]] = {}
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
        self._proposed_max_pdu = 16384
        self.max_pdu_length = 16384
        self._proposed_context_map: Dict[int, str] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if self.assoc_established:
            try:
                self.release()
            except (socket.error, socket.timeout, OSError):
                pass
        self.close()
        return False

    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.read_timeout,
            )
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except (socket.error, socket.timeout, OSError) as e:
            log.error("Connection failed: %s", e)
            return False

    def send(self, pkt: Packet) -> None:
        self.stream.send(pkt)

    def recv(self) -> Optional[Packet]:
        try:
            return self.stream.recv()
        except socket.timeout:
            return None
        except (socket.error, OSError) as e:
            log.error("Error receiving PDU: %s", e)
            return None

    def sr1(self, *args: Any, **kargs: Any) -> Optional[Packet]:
        timeout = kargs.pop("timeout", self.read_timeout)
        try:
            return self.stream.sr1(*args, timeout=timeout, **kargs)
        except (socket.error, OSError) as e:
            log.error("Error in sr1: %s", e)
            return None

    def send_raw_bytes(self, raw_bytes: bytes) -> None:
        self.sock.sendall(raw_bytes)

    def associate(self, requested_contexts: Optional[
                  Dict[str, List[str]]] = None) -> bool:
        """
        Perform DICOM association negotiation.

        :param requested_contexts: Dict mapping SOP Class UIDs to lists
            of Transfer Syntax UIDs. Defaults to Verification SOP Class
            with Implicit VR Little Endian.
        :returns: True if association accepted, False otherwise.
        """
        if not self.stream and not self.connect():
            return False

        if requested_contexts is None:
            requested_contexts = {
                VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            }

        self._proposed_context_map = {}
        variable_items: List[Packet] = [
            DICOMVariableItem() / DICOMApplicationContext()
        ]

        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            self._proposed_context_map[ctx_id] = abs_syntax
            pctx = build_presentation_context_rq(
                ctx_id, abs_syntax, trn_syntaxes
            )
            variable_items.append(pctx)
            ctx_id += 2

        user_info = build_user_information(
            max_pdu_length=self._proposed_max_pdu
        )
        variable_items.append(user_info)

        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )

        response = self.sr1(assoc_rq)

        if response:
            if response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                self._parse_accepted_contexts(response)
                self._parse_max_pdu_length(response)
                return True
            elif response.haslayer(A_ASSOCIATE_RJ):
                log.error(
                    "Association rejected: result=%d, source=%d, reason=%d",
                    response[A_ASSOCIATE_RJ].result,
                    response[A_ASSOCIATE_RJ].source,
                    response[A_ASSOCIATE_RJ].reason_diag,
                )
                return False

        log.error("Association failed: no valid response received")
        return False

    def _parse_max_pdu_length(self, response: Packet) -> None:
        try:
            for item in response[A_ASSOCIATE_AC].variable_items:
                if item.item_type != 0x50:
                    continue
                if not item.haslayer(DICOMUserInformation):
                    continue
                user_info = item[DICOMUserInformation]
                for sub_item in user_info.sub_items:
                    if sub_item.item_type != 0x51:
                        continue
                    if not sub_item.haslayer(DICOMMaximumLength):
                        continue
                    max_len = sub_item[DICOMMaximumLength]
                    server_max = max_len.max_pdu_length
                    self.max_pdu_length = min(
                        self._proposed_max_pdu, server_max
                    )
                    return
        except (KeyError, IndexError, AttributeError):
            pass
        self.max_pdu_length = self._proposed_max_pdu

    def _parse_accepted_contexts(self, response: Packet) -> None:
        for item in response[A_ASSOCIATE_AC].variable_items:
            if item.item_type != 0x21:
                continue
            if not item.haslayer(DICOMPresentationContextAC):
                continue
            pctx = item[DICOMPresentationContextAC]
            ctx_id = pctx.context_id
            result = pctx.result
            if result != 0:
                continue
            abs_syntax = self._proposed_context_map.get(ctx_id)
            if abs_syntax is None:
                continue
            for sub_item in pctx.sub_items:
                if sub_item.item_type != 0x40:
                    continue
                if not sub_item.haslayer(DICOMTransferSyntax):
                    continue
                ts_uid = sub_item[DICOMTransferSyntax].uid
                ts_uid = ts_uid.rstrip(b"\x00").decode("ascii")
                self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                break

    def _get_next_message_id(self) -> int:
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF

    def _find_accepted_context_id(
        self, sop_class_uid: str,
        transfer_syntax_uid: Optional[str] = None
    ) -> Optional[int]:
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if (transfer_syntax_uid is None
                        or transfer_syntax_uid == ts_syntax):
                    return ctx_id
        return None

    def c_echo(self) -> Optional[int]:
        """
        Send C-ECHO-RQ and return the status code from the response.

        :returns: DIMSE status code (0x0000 = success), or None on failure.
        """
        if not self.assoc_established:
            log.error("Association not established")
            return None

        echo_ctx_id = self._find_accepted_context_id(
            VERIFICATION_SOP_CLASS_UID
        )
        if echo_ctx_id is None:
            log.error("No accepted context for Verification SOP Class")
            return None

        msg_id = self._get_next_message_id()
        dimse_rq = bytes(C_ECHO_RQ(message_id=msg_id))

        pdv_rq = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])

        response = self.sr1(pdata_rq)

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                return parse_dimse_status(pdv_rsp.data)
        return None

    def c_store(self, dataset_bytes: bytes, sop_class_uid: str,
                sop_instance_uid: str, transfer_syntax_uid: str
                ) -> Optional[int]:
        """
        Send C-STORE-RQ with dataset and return the status code.

        Large datasets are automatically fragmented into multiple
        P-DATA-TF PDUs respecting the negotiated maximum PDU length.

        :returns: DIMSE status code (0x0000 = success), or None on failure.
        """
        if not self.assoc_established:
            log.error("Association not established")
            return None

        store_ctx_id = self._find_accepted_context_id(
            sop_class_uid,
            transfer_syntax_uid,
        )
        if store_ctx_id is None:
            log.error(
                "No accepted context for SOP %s with TS %s",
                sop_class_uid,
                transfer_syntax_uid,
            )
            return None

        msg_id = self._get_next_message_id()

        dimse_rq = bytes(C_STORE_RQ(
            affected_sop_class_uid=sop_class_uid,
            affected_sop_instance_uid=sop_instance_uid,
            message_id=msg_id,
        ))

        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self.send(pdata_cmd)

        # PDV overhead: 4 (item-length) + 1 (ctx_id) + 1 (control header)
        # + 6 (DICOM PDU header) = 12
        max_pdv_data = self.max_pdu_length - 12

        if len(dataset_bytes) <= max_pdv_data:
            data_pdv = PresentationDataValueItem(
                context_id=store_ctx_id,
                data=dataset_bytes,
                is_command=0,
                is_last=1,
            )
            pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
            self.send(pdata_data)
        else:
            offset = 0
            while offset < len(dataset_bytes):
                chunk = dataset_bytes[offset:offset + max_pdv_data]
                is_last = (
                    1 if (offset + len(chunk) >= len(dataset_bytes)) else 0
                )
                data_pdv = PresentationDataValueItem(
                    context_id=store_ctx_id,
                    data=chunk,
                    is_command=0,
                    is_last=is_last,
                )
                pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
                self.send(pdata_data)
                offset += len(chunk)

        response = self.recv()

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                return parse_dimse_status(pdv_rsp.data)
        return None

    def release(self) -> bool:
        if not self.assoc_established:
            return True
        release_rq = DICOM() / A_RELEASE_RQ()
        response = self.sr1(release_rq)
        self.close()
        if response:
            return response.haslayer(A_RELEASE_RP)
        return False

    def close(self) -> None:
        if self.stream:
            try:
                self.stream.close()
            except (socket.error, OSError):
                pass
        self.sock = None
        self.stream = None
        self.assoc_established = False
