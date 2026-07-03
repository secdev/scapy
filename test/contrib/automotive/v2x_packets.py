# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
ETSI ITS V2X ASN.1 packet tests.
"""

from pathlib import Path

from scapy.contrib.automotive.v2x import CAM, DENM, IVIM, MAPEM, SPATEM
from scapy.contrib.automotive.v2x.packets import (
    ActionID,
    Altitude,
    CauseCode,
    DecentralizedEnvironmentalNotificationMessage,
    DeltaReferencePosition,
    EventPoint,
    Heading,
    ItsPduHeader,
    LocationContainer,
    ManagementContainer,
    PathHistory,
    PosConfidenceEllipse,
    ReferencePosition,
    SituationContainer,
    Speed,
)
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


def _its_asn_files_available():
    # type: () -> bool
    return all(f.is_file() for f in _its_asn_files())


# LF Edge InstantX UPER example (DENM inside G5/BTP payload):
# https://github.com/lf-edge/instantx/blob/main/docs/Encoding.md#examples
INSTANTX_DENM_PAYLOAD_HEX = (
    "11004c01204000800050010003db00009400000000000000adbed407f974b8e6f952f45d"
    "000d000e7974b8e67952f45d000a00000000000007d200000201012fd537c78097ea9b81"
    "ed9f2d8fa1a3c7cb63e868f2f19a1e6649cc65d17917900018b5010546001f3056c1c00"
    "61000dff8480e018d841196eac3e4a01c780c518d3261453f0077e000"
)
# ITS DENM UPER (ItsPduHeader + DENM) after the BTP destination port header.
INSTANTX_DENM_ITS_HEX = (
    "0201012fd537c78097ea9b81ed9f2d8fa1a3c7cb63e868f2f19a1e6649cc65d179179"
    "00018b5010546001f3056c1c0061000dff8480e018d841196eac3e4a01c780c518d326"
    "1453f0077e000"
)


def _instantx_denm_its_bytes():
    # type: () -> bytes
    payload = bytes.fromhex(INSTANTX_DENM_PAYLOAD_HEX)
    # BTP-B header: destinationPort (2 bytes) + destinationPortInfo (2 bytes).
    return payload[60:]


def _build_instantx_denm():
    # type: () -> DENM
    return DENM(
        header=ItsPduHeader(
            protocolVersion=2,
            messageID=1,
            stationID=19911991,
        ),
        denm=DecentralizedEnvironmentalNotificationMessage(
            management=ManagementContainer(
                actionID=ActionID(
                    originatingStationID=19911991,
                    sequenceNumber=987,
                ),
                detectionTime=1071266991390,
                referenceTime=1071266991390,
                termination=None,
                eventPosition=ReferencePosition(
                    latitude=-109791002,
                    longitude=-112004003,
                    positionConfidenceEllipse=PosConfidenceEllipse(
                        semiMajorConfidence=377,
                        semiMinorConfidence=377,
                        semiMajorOrientation=0,
                    ),
                    altitude=Altitude(
                        altitudeValue=1200,
                        altitudeConfidence=1,
                    ),
                ),
                relevanceDistance=0,
                relevanceTrafficDirection=0,
                validityDuration=86400,
                transmissionInterval=500,
                stationType=5,
            ),
            situation=SituationContainer(
                informationQuality=3,
                eventType=CauseCode(causeCode=14, subCauseCode=0),
                linkedCause=CauseCode(causeCode=97, subCauseCode=0),
                eventHistory=[
                    EventPoint(
                        eventPosition=DeltaReferencePosition(
                            deltaLatitude=-123,
                            deltaLongitude=897,
                            deltaAltitude=20,
                        ),
                        eventDeltaTime=1706733817,
                        informationQuality=1,
                    ),
                    EventPoint(
                        eventPosition=DeltaReferencePosition(
                            deltaLatitude=456,
                            deltaLongitude=789,
                            deltaAltitude=10,
                        ),
                        informationQuality=2,
                    ),
                ],
            ),
            location=LocationContainer(
                eventSpeed=Speed(speedValue=1300, speedConfidence=127),
                eventPositionHeading=Heading(
                    headingValue=14,
                    headingConfidence=127,
                ),
                traces=[PathHistory()],
            ),
        ),
    )


def _assert_instantx_denm_decoded(decoded):
    # type: (dict) -> None
    assert decoded["header"]["protocolVersion"] == 2
    assert decoded["header"]["messageID"] == 1
    assert decoded["header"]["stationID"] == 19911991
    mgmt = decoded["denm"]["management"]
    assert mgmt["actionID"]["originatingStationID"] == 19911991
    assert mgmt["actionID"]["sequenceNumber"] == 987
    assert mgmt["detectionTime"] == 1071266991390
    assert mgmt["referenceTime"] == 1071266991390
    pos = mgmt["eventPosition"]
    assert pos["latitude"] == -109791002
    assert pos["longitude"] == -112004003
    assert pos["positionConfidenceEllipse"]["semiMajorConfidence"] == 377
    assert pos["altitude"]["altitudeValue"] == 1200
    assert pos["altitude"]["altitudeConfidence"] == "alt-000-02"
    assert mgmt["relevanceDistance"] == "lessThan50m"
    assert mgmt["relevanceTrafficDirection"] == "allTrafficDirections"
    assert mgmt["validityDuration"] == 86400
    assert mgmt["transmissionInterval"] == 500
    assert mgmt["stationType"] == 5
    situation = decoded["denm"]["situation"]
    assert situation["informationQuality"] == 3
    assert situation["eventType"]["causeCode"] == 14
    assert situation["linkedCause"]["causeCode"] == 97
    history = situation["eventHistory"]
    assert len(history) == 2
    assert history[0]["eventPosition"]["deltaLatitude"] == -123
    assert history[0]["eventDeltaTime"] == 1706733817
    assert history[1]["eventPosition"]["deltaLatitude"] == 456
    location = decoded["denm"]["location"]
    assert location["eventSpeed"]["speedValue"] == 1300
    assert location["eventPositionHeading"]["headingValue"] == 14
    assert location["traces"] == [[]]


def check_instantx_denm_example_encode():
    # type: () -> None
    got = raw(_build_instantx_denm())
    assert got == bytes.fromhex(INSTANTX_DENM_ITS_HEX)


def check_instantx_denm_example_scapy_decode():
    # type: () -> None
    pkt = DENM(_instantx_denm_its_bytes())
    assert pkt.header.protocolVersion.val == 2
    assert pkt.header.messageID.val == 1
    assert pkt.header.stationID.val == 19911991
    mgmt = pkt.denm.management
    assert mgmt.actionID.originatingStationID.val == 19911991
    assert mgmt.actionID.sequenceNumber.val == 987
    assert mgmt.detectionTime.val == 1071266991390
    assert mgmt.referenceTime.val == 1071266991390
    assert mgmt.termination is None
    assert mgmt.eventPosition.latitude.val == -109791002
    assert mgmt.eventPosition.longitude.val == -112004003
    assert mgmt.validityDuration.val == 86400
    assert mgmt.transmissionInterval.val == 500
    assert mgmt.stationType.val == 5
    assert pkt.denm.situation.eventType.causeCode.val == 14
    assert pkt.denm.situation.linkedCause.causeCode.val == 97
    assert len(pkt.denm.situation.eventHistory) == 2
    assert pkt.denm.situation.eventHistory[0].eventDeltaTime.val == 1706733817
    assert pkt.denm.situation.eventHistory[0].eventPosition.deltaLatitude.val == -123
    assert pkt.denm.situation.eventHistory[1].eventPosition.deltaLatitude.val == 456
    assert pkt.denm.location.eventSpeed.speedValue.val == 1300
    assert len(pkt.denm.location.traces) == 1
    assert len(pkt.denm.location.traces[0].pathPoints) == 0


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


def check_instantx_denm_example_payload():
    # type: () -> None
    its = _instantx_denm_its_bytes()
    assert its == bytes.fromhex(INSTANTX_DENM_ITS_HEX)
    assert len(its) == 76


def check_instantx_denm_example_build():
    # type: () -> None
    pkt = _build_instantx_denm()
    assert int(pkt.header.protocolVersion) == 2
    assert int(pkt.header.messageID) == 1
    assert int(pkt.header.stationID) == 19911991
    mgmt = pkt.denm.management
    assert int(mgmt.actionID.sequenceNumber) == 987
    assert int(mgmt.detectionTime) == 1071266991390
    assert int(mgmt.eventPosition.latitude) == -109791002
    assert int(mgmt.eventPosition.altitude.altitudeValue) == 1200
    assert int(pkt.denm.situation.eventType.causeCode) == 14
    assert int(pkt.denm.situation.linkedCause.causeCode) == 97
    assert len(pkt.denm.situation.eventHistory) == 2
    assert int(pkt.denm.location.eventSpeed.speedValue) == 1300
    assert len(raw(pkt)) > 0


def check_instantx_denm_example_roundtrip():
    # type: () -> None
    built = _build_instantx_denm()
    data = raw(built)
    assert data == bytes.fromhex(INSTANTX_DENM_ITS_HEX)
    decoded = DENM(data)
    assert raw(decoded) == data


def check_its_containers_build():
    # type: () -> None
    mgmt = ManagementContainer(
        actionID=ActionID(originatingStationID=1, sequenceNumber=1),
        detectionTime=1,
        referenceTime=1,
        eventPosition=ReferencePosition(
            latitude=0,
            longitude=0,
            positionConfidenceEllipse=PosConfidenceEllipse(
                semiMajorConfidence=0,
                semiMinorConfidence=0,
                semiMajorOrientation=0,
            ),
            altitude=Altitude(altitudeValue=0, altitudeConfidence=0),
        ),
        stationType=0,
    )
    assert len(raw(mgmt)) > 0

    situation = SituationContainer(
        informationQuality=1,
        eventType=CauseCode(causeCode=1, subCauseCode=0),
        eventHistory=[
            EventPoint(
                eventPosition=DeltaReferencePosition(
                    deltaLatitude=0,
                    deltaLongitude=0,
                    deltaAltitude=0,
                ),
                eventDeltaTime=1706733817,
                informationQuality=1,
            ),
        ],
    )
    assert len(raw(situation)) > 0
    assert SituationContainer(raw(situation)).eventHistory[0].eventDeltaTime.val == 1706733817

    location = LocationContainer(
        traces=[PathHistory()],
    )
    assert len(raw(location)) > 0
    assert len(LocationContainer(raw(location)).traces) == 1


def check_its_containers_dissect():
    # type: () -> None
    situation = SituationContainer(
        informationQuality=1,
        eventType=CauseCode(causeCode=1, subCauseCode=0),
        eventHistory=[
            EventPoint(
                eventPosition=DeltaReferencePosition(
                    deltaLatitude=0,
                    deltaLongitude=0,
                    deltaAltitude=0,
                ),
                eventDeltaTime=1706733817,
                informationQuality=1,
            ),
        ],
    )
    data = raw(situation)
    decoded = SituationContainer(data)
    assert decoded.informationQuality.val == 1
    assert decoded.eventType.causeCode.val == 1
    assert len(decoded.eventHistory) == 1
    assert decoded.eventHistory[0].eventDeltaTime.val == 1706733817

    location = LocationContainer(traces=[PathHistory()])
    data = raw(location)
    decoded = LocationContainer(data)
    assert len(decoded.traces) == 1
    assert len(decoded.traces[0].pathPoints) == 0


def check_instantx_denm_example_asn1tools():
    # type: () -> None
    if not HAS_ASN1TOOLS or not _its_asn_files_available():
        return
    compiled = asn1tools.compile_files(
        [str(f) for f in _its_asn_files()],
        codec="uper",
    )
    decoded = compiled.decode("DENM", _instantx_denm_its_bytes())
    _assert_instantx_denm_decoded(decoded)
