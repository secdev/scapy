# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

# scapy.contrib.description = SAE J1939 64-bit NAME Decoder (J1939-81)
# scapy.contrib.status = loads

"""
SAE J1939 NAME Protocol & Decoder (J1939-81).

This module decodes the 64-bit (8-byte) J1939 NAME used in Address Claiming
and Network Management (PGN 60928, 0xEE00). According to SAE J1939-81 §4.2.1,
the 64-bit NAME is transmitted in CAN data bytes 1 through 8, with Byte 1
being the Least Significant Byte (LSB, Identity Number LSB) and Byte 8 being
the Most Significant Byte (MSB, Arbitrary Address Capable, Industry Group, etc.).

Key Architecture Rules:

- Function values 0 to 127 are lower 128 pre-assigned functions defined by
  SAE J1939 (SPN 2841). These values are strictly INDEPENDENT of Vehicle System
  and Industry Group, and apply universally across all 8 Industry Groups (0-7).
- Function values 128 to 253 are Industry Group / Vehicle System dependent.

It maps the extracted bit fields to standard registries such as Industry Groups,
Pre-defined and Industry-Specific Functions, Vehicle Systems, and Manufacturer Codes.

It provides:

- Scapy packet class ``J1939Name``
"""

from typing import (
    Any,
    Optional,
)

from scapy.contrib.j1939 import (
    J1939,
    J1939_PGN_ADDRESS_CLAIMED,
)
from scapy.fields import (
    BitEnumField,
    BitField,
)
from scapy.packet import Packet, bind_layers


# ---------------------------------------------------------------------------


# J1939 Standard Registries
# ---------------------------------------------------------------------------

J1939_INDUSTRY_GROUPS = {
    0: "Global / Common across industries",
    1: "On-Highway Equipment (Trucks, Buses, Coaches)",
    2: "Agricultural and Forestry Equipment",
    3: "Construction Equipment",
    4: "Marine Equipment",
    5: "Industrial, Process Control, Stationary Equipment",
    6: "Fleet Management Systems",
    7: "Reserved for future SAE assignment",
}

# Standard pre-assigned functions (Lower 128 values: 0 to 127)
# These values are universal and independent of Industry Group and Vehicle System.
# ================================================================================
# OPEN-SOURCE & PUBLIC DATABASE REFERENCES FOR J1939 NAME FUNCTIONS (SPN 2841: 0-127)
# ================================================================================
# Public Standards & Specifications:
#   - ISO 11783-7: Tractors and machinery for agriculture and forestry -
#     Implement messages application layer (Public ISOBUS Data Dictionary)
#
# Permissive / Open-Source Implementations & Registries:
#   1. Linux Kernel SocketCAN Subsystem (include/uapi/linux/can/j1939.h)
#      - License: Dual GPL-2.0 / MIT
#      - Reference: Native kernel header defining name_t struct layout and
#        address claiming
#
#   2. Open-SAE-J1939 C Stack (https://github.com/DanielMartensson/Open-SAE-J1939)
#      - License: MIT License
#      - Reference: Embedded C stack for address claiming, PGN/SPN handling
#        & ISO 11783-7
#
#   3. jackm/j1939decode C Library (https://github.com/jackm/j1939decode)
#      - License: MIT License
#      - Reference: C-based decoder utilizing J1939db.json for PGN, SPN 2841,
#        and SA lookups
#
#   4. famez/J1939-Framework (https://github.com/famez/J1939-Framework)
#      - License: MIT License
#      - Reference: C++ frame parsing, Wireshark dissectors, and address claim
#        simulation
#
#   5. andrewdodd/decoda (https://github.com/andrewdodd/decoda)
#      - License: MIT License
#      - Reference: Python spec conversion and application payload decoding library
#
#   6. CSS Electronics CAN Decoder API & ISOBUS DBC
#      (https://github.com/CSS-Electronics/can_decoder)
#      - License: MIT License
#      - Reference: Python API for parsing raw CAN frames against open DBC databases
J1939_PRE_ASSIGNED_FUNCTIONS = {
    0: "Engine",
    1: "Auxiliary Power Unit (APU)",
    2: "Electric Propulsion Control",
    3: "Transmission",
    4: "Battery Pack Monitor",
    5: "Shift Control/Console",
    6: "Power TakeOff - (Main or Rear)",
    7: "Axle - Steering",
    8: "Axle - Drive",
    9: "Brakes - System Controller",
    10: "Brakes - Steer Axle",
    11: "Brakes - Drive axle",
    12: "Retarder - Engine",
    13: "Retarder - Driveline",
    14: "Cruise Control",
    15: "Fuel System",
    16: "Steering Controller",
    17: "Suspension - Steer Axle",
    18: "Suspension - Drive Axle",
    19: "Instrument Cluster",
    20: "Trip Recorder",
    21: "Cab Climate Control",
    22: "Aerodynamic Control",
    23: "Vehicle Navigation",
    24: "Vehicle Security",
    25: "Network Interconnect ECU",
    26: "Body Controller",
    27: "Power TakeOff (Secondary or Front)",
    28: "Off Vehicle Gateway",
    29: "Virtual Terminal (in cab)",
    30: "Management Computer",
    31: "Propulsion Battery Charger",
    32: "Headway Controller",
    33: "System Monitor",
    34: "Hydraulic Pump Controller",
    35: "Suspension - System Controller",
    36: "Pneumatic - System Controller",
    37: "Cab Controller",
    38: "Tire Pressure Control",
    39: "Ignition Control Module",
    40: "Seat Control",
    41: "Lighting - Operator Controls",
    42: "Water Pump Control",
    43: "Transmission Display",
    44: "Exhaust Emission Control",
    45: "Vehicle Dynamic Stability Control",
    46: "Oil Sensor Unit",
    47: "Information System Controller",
    48: "Ramp Control",
    49: "Clutch/Converter Control",
    50: "Auxiliary Heater",
    51: "Forward-Looking Collision Warning System",
    52: "Chassis Controller",
    53: "Alternator/Charging System",
    54: "Communications Unit, Cellular",
    55: "Communications Unit, Satellite",
    56: "Communications Unit, Radio",
    57: "Steering Column Unit",
    58: "Fan Drive Control",
    59: "Starter",
    60: "Cab Display",
    61: "File Server / Printer",
    62: "On-Board Diagnostic Unit",
    63: "Engine Valve Controller",
    64: "Endurance Braking",
    65: "Gas Flow Measurement",
    66: "I/O Controller",
    67: "Electrical System Controller",
    68: "Aftertreatment system gas measurement",
    69: "Engine Emission Aftertreatment System",
    70: "Auxiliary Regeneration Device",
    71: "Transfer Case Control",
    72: "Coolant Valve Controller",
    73: "Rollover Detection Control",
    74: "Lubrication System",
    75: "Supplemental Fan",
    76: "Temperature Sensor",
    77: "Fuel Properties Sensor",
    78: "Fire Suppression System",
    79: "Power Systems Manager",
    80: "Electric Powertrain",
    81: "Hydraulic Powertrain",
    254: "Error State",
    255: "Not Available State",
}

# Industry group specific function mappings (values 128 to 253)
J1939_INDUSTRY_SPECIFIC_FUNCTIONS = {
    1: {  # On-Highway Equipment
        130: "Cab Display / Operator Interface (On-Highway Specific)",
        131: "Tachograph Device",
        132: "Vehicle Gateway Interface",
    },
    2: {  # Agricultural and Forestry Equipment (ISOBUS / ISO 11783)
        130: "Task Controller / Mapping Computer (ISO 11783-10)",
        135: "Virtual Terminal (ISO 11783-6)",
        140: "Implement / Working Set Master",
        141: "Auxiliary Valve Control / Implement Bridge",
    },
    3: {  # Construction Equipment
        130: "Grade Control System",
        131: "Payload Scale System",
    },
    4: {  # Marine Equipment (NMEA 2000)
        130: "Autopilot / Heading Control",
        131: "Radar / Sonar System",
        132: "VHF Radio / Communications",
    },
}

# Industry group specific vehicle system mappings (values 0 to 127)
J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS = {
    1: {  # On-Highway Equipment
        1: "Tractor",
        2: "Trailer",
        3: "Public Transit Bus",
        4: "Specialized Construction Support Vehicle",
    },
    2: {  # Agricultural and Forestry Equipment
        1: "Agricultural Tractor",
        2: "Tillage Implement",
        3: "Planter / Seeder Implement",
        4: "Fertilizer Implement",
        5: "Sprayer Implement",
        6: "Combine Harvester",
        7: "Forage Harvester",
    },
    3: {  # Construction Equipment
        1: "Crawler Dozer",
        2: "Wheel Loader",
        3: "Hydraulic Excavator",
        4: "Off-Highway Haul Truck",
    },
    4: {  # Marine Equipment
        1: "Vessel System",
        2: "Engine Room Monitor",
        3: "Bridge Navigation Display",
    },
}

# Industry-assigned or common manufacturer codes (11 bits)
J1939_MANUFACTURERS = {
    8: "Caterpillar Inc.",
    15: "Cummins Inc.",
    35: "Detroit Diesel Corporation",
    49: "Deere & Company (John Deere)",
    88: "Eaton Corporation",
    117: "Allison Transmission",
    140: "Volvo Powertrain Corporation",
    154: "Bendix Commercial Vehicle Systems",
    161: "Volvo Lastvagnar AB",
    174: "Wabco Vehicle Control Systems",
    184: "PACCAR Inc.",
    275: "Detroit Diesel",
    345: "Robert Bosch GmbH",
}


# ---------------------------------------------------------------------------
# Scapy Packet Class for J1939 64-bit NAME
# ---------------------------------------------------------------------------

class J1939Name(Packet):
    """SAE J1939 64-bit NAME (J1939-81 Address Claiming).

    The 64-bit NAME is sent as the 8-byte payload in Address Claimed messages
    (PGN 60928, 0xEE00). According to SAE J1939-81 §4.2.1, the 64-bit NAME is
    transmitted Least Significant Byte (LSB) first over CAN:

    - Byte 1 (CAN data[0]): Identity Number bits 0-7 (LSB)
    - Byte 2 (CAN data[1]): Identity Number bits 8-15
    - Byte 3 (CAN data[2]): Identity Number bits 16-20, Manufacturer Code bits 21-23
    - Byte 4 (CAN data[3]): Manufacturer Code bits 24-31
    - Byte 5 (CAN data[4]): ECU Instance bits 32-34, Function Instance bits 35-39
    - Byte 6 (CAN data[5]): Function bits 40-47
    - Byte 7 (CAN data[6]): Reserved bit 48, Vehicle System bits 49-55
    - Byte 8 (CAN data[7]): Vehicle System Instance bits 56-59, Industry Group
      bits 60-62, Arbitrary Address Capable bit 63 (MSB)

    Fields (MSB to LSB):

    - ``arbitrary_address_capable``: 1 bit (bit 63)
    - ``industry_group``: 3 bits (bits 62-60)
    - ``vehicle_system_instance``: 4 bits (bits 59-56)
    - ``vehicle_system``: 7 bits (bits 55-49)
    - ``reserved``: 1 bit (bit 48)
    - ``function``: 8 bits (bits 47-40)
    - ``function_instance``: 5 bits (bits 39-35)
    - ``ecu_instance``: 3 bits (bits 34-32)
    - ``manufacturer_code``: 11 bits (bits 31-21)
    - ``identity_number``: 21 bits (bits 20-0)
    """

    name = "J1939Name"
    MIN_LEN = 8

    fields_desc = [
        BitField("arbitrary_address_capable", 0, 1, tot_size=-8),
        BitEnumField("industry_group", 0, 3, J1939_INDUSTRY_GROUPS),
        BitField("vehicle_system_instance", 0, 4),
        BitField("vehicle_system", 0, 7),
        BitField("reserved", 0, 1),
        BitEnumField("function", 0, 8, J1939_PRE_ASSIGNED_FUNCTIONS),
        BitField("function_instance", 0, 5),
        BitField("ecu_instance", 0, 3),
        BitEnumField("manufacturer_code", 0, 11, J1939_MANUFACTURERS),
        BitField("identity_number", 0, 21, end_tot_size=-8),
    ]

    def raw_value(self):
        # type: () -> int
        """Return the 64-bit integer representation of this NAME."""
        return int.from_bytes(bytes(self), "little")

    def mysummary(self):
        # type: () -> str
        mfg = J1939_MANUFACTURERS.get(
            self.manufacturer_code, str(self.manufacturer_code)
        )
        func = j1939_format_name_function(self)
        return (
            "J1939Name: mfg='{}' "
            "func='{}' "
            "identity={} "
            "arb_addr={}".format(
                mfg,
                func,
                self.identity_number,
                bool(self.arbitrary_address_capable),
            )
        )


def j1939_format_name_function(function_or_pkt, industry_group=None):
    # type: (Any, Optional[int]) -> str
    """Return the human-readable function description."""
    if isinstance(function_or_pkt, Packet):
        func = getattr(function_or_pkt, "function", 0)
        ig = (
            industry_group
            if industry_group is not None
            else getattr(function_or_pkt, "industry_group", 0)
        )
    else:
        func = int(function_or_pkt)
        ig = industry_group if industry_group is not None else 0

    if 128 <= func <= 253:
        func_table = J1939_INDUSTRY_SPECIFIC_FUNCTIONS.get(ig, {})
        return func_table.get(
            func,
            "Industry Group Specific Function {}".format(func),
        )
    if func in J1939_PRE_ASSIGNED_FUNCTIONS:
        return J1939_PRE_ASSIGNED_FUNCTIONS[func]
    if 82 <= func <= 127:
        return "Pre-Assigned / Reserved Function ({})".format(func)
    return str(func)


def j1939_format_name_industry_group(group_or_pkt):
    # type: (Any) -> str
    """Return the human-readable industry group description."""
    if isinstance(group_or_pkt, Packet):
        ig = getattr(group_or_pkt, "industry_group", 0)
    else:
        ig = int(group_or_pkt)
    return J1939_INDUSTRY_GROUPS.get(ig, str(ig))


def j1939_format_name_manufacturer(mfg_or_pkt):
    # type: (Any) -> str
    """Return the human-readable manufacturer name."""
    if isinstance(mfg_or_pkt, Packet):
        mfg = getattr(mfg_or_pkt, "manufacturer_code", 0)
    else:
        mfg = int(mfg_or_pkt)
    return J1939_MANUFACTURERS.get(mfg, str(mfg))


def j1939_format_name_vehicle_system(system_or_pkt, industry_group=None):
    # type: (Any, Optional[int]) -> str
    """Return the human-readable vehicle system description."""
    if isinstance(system_or_pkt, Packet):
        vs = getattr(system_or_pkt, "vehicle_system", 0)
        ig = (
            industry_group
            if industry_group is not None
            else getattr(system_or_pkt, "industry_group", 0)
        )
    else:
        vs = int(system_or_pkt)
        ig = industry_group if industry_group is not None else 0

    vs_table = J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS.get(ig, {})
    return vs_table.get(
        vs,
        "Industry Group Specific Vehicle System {}".format(vs)
        if ig != 0
        else "Common Vehicle System {}".format(vs),
    )


bind_layers(J1939, J1939Name, pgn=J1939_PGN_ADDRESS_CLAIMED)


__all__ = [
    "J1939Name",
    "J1939_INDUSTRY_GROUPS",
    "J1939_INDUSTRY_SPECIFIC_FUNCTIONS",
    "J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS",
    "J1939_MANUFACTURERS",
    "J1939_PRE_ASSIGNED_FUNCTIONS",
    "j1939_format_name_function",
    "j1939_format_name_industry_group",
    "j1939_format_name_manufacturer",
    "j1939_format_name_vehicle_system",
]
