# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
ETSI ITS V2X ASN.1 packet tests.
"""

from pathlib import Path

from scapy.contrib.automotive.v2x import CAM, DENM, IVIM, MAPEM, SPATEM
from scapy.contrib.automotive.v2x.packets import ItsPduHeader
from scapy.packet import raw

try:
    import asn1tools
    HAS_ASN1TOOLS = True
except ImportError:
    asn1tools = None  # type: ignore
    HAS_ASN1TOOLS = False


def _its_asn_files():
    # type: () -> list
    asn = (
        Path(__file__).resolve().parents[3]
        / "scapy" / "contrib" / "automotive" / "v2x" / "asn"
    )
    return [
        asn / "ITS-Container.asn",
        asn / "CAM-PDU-Descriptions.asn",
        asn / "DENM-PDU-Descriptions.asn",
        asn / "SPATEM-PDU-Descriptions.asn",
        asn / "MAPEM-PDU-Descriptions.asn",
        asn / "IVIM-PDU-Descriptions.asn",
        asn / "iso-patched" / (
            "ISO24534-3_ElectronicRegistrationIdentification"
            "VehicleDataModule-patched.asn"
        ),
        asn / "iso-patched" / "ISO14823-missing.asn",
        asn / "iso-patched" / "ISO14906(2018)EfcDsrcGenericv7-patched.asn",
        asn / "iso-patched" / "ISO14906(2018)EfcDsrcApplicationv6-patched.asn",
        asn / "ISO-TS-19091-addgrp-C-2018-patched.asn",
        asn / "ISO14816_AVIAEINumberingAndDataStructures.asn",
        asn / "ISO19321IVIv2.asn",
        asn / "ISO_17419_1-1.asn",
    ]


def check_its_import():
    # type: () -> None
    assert CAM.__name__ == "CAM"
    assert DENM.__name__ == "DENM"
    assert IVIM.__name__ == "IVIM"
    assert SPATEM.__name__ == "SPATEM"
    assert MAPEM.__name__ == "MAPEM"


def check_its_messages_build():
    # type: () -> None
    for cls, message_id in [
        (CAM, 2),
        (DENM, 1),
        (IVIM, 6),
        (SPATEM, 4),
        (MAPEM, 5),
    ]:
        pkt = cls()
        pkt.header = ItsPduHeader(
            protocolVersion=1,
            messageID=message_id,
            stationID=42,
        )
        assert len(raw(pkt)) > 0


def check_its_messages_asn1tools_decode():
    # type: () -> None
    if not HAS_ASN1TOOLS:
        return
    compiled = asn1tools.compile_files(
        [str(f) for f in _its_asn_files()],
        codec="uper",
    )
    for name, cls, message_id in [
        ("CAM", CAM, 2),
        ("DENM", DENM, 1),
        ("IVIM", IVIM, 6),
        ("SPATEM", SPATEM, 4),
        ("MAPEM", MAPEM, 5),
    ]:
        pkt = cls()
        pkt.header = ItsPduHeader(
            protocolVersion=1,
            messageID=message_id,
            stationID=42,
        )
        data = raw(pkt)
        decoded = compiled.decode(name, data)
        assert decoded["header"]["stationID"] == 42
