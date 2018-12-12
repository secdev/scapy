# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import FieldListField, StrFixedLenField, ByteField, \
    ShortField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs#Service_09 for further information
# IID = Information IDentification

class OBD_IID00(Packet):
    name = "IID_00_Service9SupportedInformationTypes"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class _OBD_IID_MessageCount(Packet):
    fields_desc = [
        ByteField('messageCount', 0)
    ]


class OBD_IID01(_OBD_IID_MessageCount):
    name = "IID_01_VinMessageCount"


class OBD_IID03(_OBD_IID_MessageCount):
    name = "IID_03_CalibrationIdMessageCount"


class OBD_IID05(_OBD_IID_MessageCount):
    name = "IID_05_CalibrationVerificationNumbersMessageCount"


class OBD_IID07(_OBD_IID_MessageCount):
    name = "IID_07_InUsePerformanceTrackingMessageCount"


class OBD_IID09(_OBD_IID_MessageCount):
    name = "IID_09_EcuNameMessageCount"


class OBD_IID02(Packet):
    name = "IID_02_VehicleIdentificationNumber"
    fields_desc = [
        ByteField('messageCount', 1),
        StrFixedLenField('vehicleIdentificationNumber', b'', 17)
    ]


class OBD_IID04(Packet):
    name = "IID_04_CalibrationId"
    fields_desc = [
        ByteField('messageCount', 1),
        FieldListField('calibrationIdentifications', None,
                       StrFixedLenField(b'', 0, 16),
                       count_from=lambda pkt: len(pkt.original) / 16)
    ]


class OBD_IID06(Packet):
    name = "IID_06_CalibrationVerificationNumbers"
    fields_desc = [
        ByteField('messageCount', 1),
        FieldListField('calibrationVerificationNumbers', None,
                       StrFixedLenField(b'', 0, 4),
                       count_from=lambda pkt: len(pkt.original) / 4)
    ]


class OBD_IID08(Packet):
    name = "IID_08_InUsePerformanceTracking"
    fields_desc = [
        ByteField('messageCount', 1),
        FieldListField('data', None,
                       ShortField(b'', 0),
                       count_from=lambda pkt: len(pkt.original) / 2)
    ]


class OBD_IID0A(Packet):
    name = "IID_0A_EcuName"
    fields_desc = [
        ByteField('messageCount', 1),
        StrFixedLenField('ecuName', b'', 20)
    ]


class OBD_IID0B(Packet):
    name = "IID_0B_InUsePerformanceTrackingForCompressionIgnitionVehicles"
    fields_desc = [
        ByteField('messageCount', 1),
        FieldListField('data', None,
                       ShortField(b'', 0),
                       count_from=lambda pkt: len(pkt.original) / 2)
    ]
