import binascii

from scapy.all import ls
from scapy.packet import Packet
from scapy.fields import BitField
from scapy.fields import BitEnumField
from scapy.fields import X3BytesField
from scapy.fields import ShortField
from scapy.fields import XShortField
from scapy.fields import ShortEnumField
from scapy.fields import FieldLenField
from scapy.fields import PacketLenField
from scapy.fields import XByteField
from scapy.fields import XByteEnumField
from scapy.fields import ByteEnumField
from scapy.fields import StrFixedLenField
from scapy.fields import ConditionalField
from scapy.fields import FlagsField
from scapy.fields import ByteField
from scapy.fields import IntField

PROTOCOL_NUMBERS = {
    0x01: 'LOGIN MESSAGE',
    0x13: 'HEARTBEAT',
    0x12: 'LOCATION',
    0x16: 'ALARM',
}

VOLTAGE_LEVELS = {
    0x00: "No Power (Shutdown)",
    0x01: "Extremely Low Battery",
    0x02: "Very Low Battery",
    0x03: "Low Battery",
    0x04: "Medium",
    0x05: "High",
    0x06: "Very High",
}

GSM_SIGNAL_STRENGTH = {
    0x00: "No Signal",
    0x01: "Extremely Weak Signal",
    0x02: "Very Weak Signal",
    0x03: "Good Signal",
    0x04: "Strong Signal",
}

LANGUAGE = {
    0x01: "Chinese",
    0x02: "English",
}


class BCDStrFixedLenField(StrFixedLenField):
    def i2h(self, pkt, v):
        if isinstance(v, bytes):
            return binascii.b2a_hex(v)
        return binascii.a2b_hex(v)


class CoordinateField(IntField):
    def i2h(self, pkt, v):
        value = super(IntField, self).i2h(pkt, v)
        return round(value / 1800000, 6)


class CRX1NewPacketContent(Packet):
    name = "CRX1 New Packet Content"
    fields_desc = [
        XByteEnumField('protocol_number', 0x12, PROTOCOL_NUMBERS),
        # Login
        ConditionalField(
            BCDStrFixedLenField('terminal_id', '00000000', length=8), lambda
            pkt: len(pkt.original) > 5 and pkt.protocol_number == 0x01),
        # GPS Location
        ConditionalField(
            ByteField('year', 0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('month', 0x01), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('day', 0x01), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('hour', 0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('minute', 0x00), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('second', 0x00), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitField('gps_information_length', 0x00, 4), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitField('positioning_satellite_number', 0x00, 4), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            CoordinateField('latitude', 0x00), lambda pkt: len(pkt.original) >
            5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            CoordinateField('longitude', 0x00), lambda pkt: len(pkt.original) >
            5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('speed', 0x00), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitField('course', 0x00, 10), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitEnumField('latitude_hemisphere', 0x00, 1, {
                0: "South",
                1: "North"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitEnumField('longitude_hemisphere', 0x00, 1, {
                0: "East",
                1: "West"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitEnumField('gps_been_positioning', 0x00, 1, {
                0: "No",
                1: "Yes"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitEnumField('gps_status', 0x00, 1, {
                0: "GPS real-time",
                1: "Differential positioning"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitField('course_status_reserved', 0x00, 2), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('lbs_length', 0x00), lambda pkt: len(pkt.original) > 5
            and pkt.protocol_number in (0x16, )),
        ConditionalField(
            XShortField('mcc', 0x00), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            XByteField('mnc', 0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            XShortField('lac', 0x00), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            X3BytesField('cell_id', 0x00), lambda pkt: len(pkt.original) > 5
            and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            IntField('mileage', 0x00), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, ) and len(pkt.original) > 31),
        # Heartbeat
        ConditionalField(
            BitEnumField('defence', 0x00, 1, {
                0: "Deactivated",
                1: "Activated"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField('acc', 0x00, 1, {
                0: "Low",
                1: "High"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField('charge', 0x00, 1, {
                0: "Not Charge",
                1: "Charging"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField(
                'alarm', 0x00, 3, {
                    0: "Normal",
                    1: "Vibration",
                    2: "Power Cut",
                    3: "Low Battery",
                    4: "SOS"
                }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number
            in (0x13, 0x16)),
        ConditionalField(
            BitEnumField('gps_tracking', 0x00, 1, {
                0: "Not Charge",
                1: "Charging"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField('oil_and_eletricity', 0x00, 1, {
                0: "Connected",
                1: "Disconnected"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            ByteEnumField("voltage_level", 0x00, VOLTAGE_LEVELS), lambda pkt:
            len(pkt.original) > 5 and pkt.protocol_number in (0x13, 0x16)),
        ConditionalField(
            ByteEnumField("gsm_signal_strength", 0x00,
                          GSM_SIGNAL_STRENGTH), lambda pkt: len(pkt.original) >
            5 and pkt.protocol_number in (0x13, 0x16)),
        ConditionalField(
            ByteEnumField(
                "alarm_extended", 0x00, {
                    0x00: "Normal",
                    0x01: "SOS",
                    0x02: "Power cut",
                    0x03: "Vibration",
                    0x04: "Enter fence",
                    0x05: "Exit fence",
                    0x06: "Over speed",
                    0x09: "Displacement",
                    0x0a: "Enter GPS dead zone",
                    0x0b: "Exit GPS dead zone",
                    0x0c: "Power on",
                    0x0d: "GPS First fix notice",
                    0x0e: "Low battery",
                    0x0f: "Low battery protection",
                    0x10: "SIM Change",
                    0x11: "Power off",
                    0x12: "Airplane mode",
                    0x13: "Disassemble",
                    0x14: "Door",
                    0xfe: "ACC On",
                    0xff: "ACC Off",
                }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number
            in (0x13, 0x16)),
        ConditionalField(
            ByteEnumField("language", 0x00, LANGUAGE), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x13, 0x16)),
        # Default
        XShortField('information_serial_number', None),
        XShortField('crc', None),
    ]


class CRX1New(Packet):
    name = "CRX1 New"
    fields_desc = [
        XShortField('start_bit', 0x7878),
        FieldLenField('packet_length',
                      None,
                      fmt="B",
                      length_of="packet_content"),
        PacketLenField('packet_content',
                       None,
                       CRX1NewPacketContent,
                       length_from=lambda pkt: pkt.packet_length),
        XShortField('end_bit', 0x0d0a),
    ]


if __name__ == "__main__":
    print("Login")
    raw = bytes.fromhex("78780D010353419033412836000D33510D0A")
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Login - Respone")
    raw = bytes.fromhex("7878050100059FF80D0A")
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Heartbeat")
    raw = bytes.fromhex("78780A134004040001000FDCEE0D0A")
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Heartbeat - Response")
    raw = bytes.fromhex("78780513000F008F0D0A")
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Location")
    raw = bytes.fromhex(
        "78781F120F0C1D0B0F34C6027AC74C0C4658100014D401CC00287D001F71002623090D0A"
    )
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Location - Mileage")
    raw = bytes.fromhex(
        "787823120F0C1D0B0F34C6027AC74C0C4658100014D401CC00287D001F7100000001002623090D0A"
    )
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Alarm")
    raw = bytes.fromhex(
        "787825160F0C1D0A2B21C8027AC8040C46581000146F0901CC00287D001F714804040301001C84CF0D0A"
    )
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())

    print("Alarm - Response")
    raw = bytes.fromhex("78780516001C1B280D0A")
    pkt = CRX1New(raw)
    print(ls(pkt))
    print(pkt.show())
