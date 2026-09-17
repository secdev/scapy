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

- Scapy packet class ``J1939_NAME``
- Decoder helper ``j1939_decode_name``
- Address arbitration simulator ``simulate_arbitration``
- Active scanning helpers ``j1939_request_name`` and ``j1939_request_names``
"""

import struct
import time
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Optional,
    Tuple,
    Union,
)

from scapy.contrib.automotive.j1939.j1939_scanner import (
    J1939_DEFAULT_BITRATE,
    J1939_DEFAULT_BUSLOAD,
    J1939_GLOBAL_ADDRESS,
    J1939_PF_REQUEST,
    J1939_PGN_ADDRESS_CLAIMED,
    SockOrFactory,
    j1939_can_id,
    j1939_get_sock,
    j1939_inter_probe_delay,
)
from scapy.contrib.j1939 import (
    J1939,
    J1939Request,
    j1939_log,
)
from scapy.fields import BitField
from scapy.packet import Packet, bind_layers
from scapy.supersocket import SuperSocket


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
    10: "",
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
}

# Populate default descriptions for reserved lower 128 function values (85 through 127)
for _f in range(85, 128):
    J1939_PRE_ASSIGNED_FUNCTIONS.setdefault(
        _f, f"Pre-Assigned / Reserved Function ({_f})"
    )

# Add standard sentinel states
J1939_PRE_ASSIGNED_FUNCTIONS[254] = "Error State"
J1939_PRE_ASSIGNED_FUNCTIONS[255] = "Not Available State"

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

class J1939_NAME(Packet):
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

    name = "J1939_NAME"

    fields_desc = [
        BitField("arbitrary_address_capable", 0, 1, tot_size=-8),
        BitField("industry_group", 0, 3),
        BitField("vehicle_system_instance", 0, 4),
        BitField("vehicle_system", 0, 7),
        BitField("reserved", 0, 1),
        BitField("function", 0, 8),
        BitField("function_instance", 0, 5),
        BitField("ecu_instance", 0, 3),
        BitField("manufacturer_code", 0, 11),
        BitField("identity_number", 0, 21, end_tot_size=-8),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    @property
    def raw_value(self) -> int:
        """Return the 64-bit integer representation of this NAME."""
        return struct.unpack("<Q", bytes(self))[0]

    @property
    def manufacturer_name(self) -> str:
        """Return the human-readable manufacturer name."""
        return J1939_MANUFACTURERS.get(
            self.manufacturer_code,
            f"Unknown Manufacturer ({self.manufacturer_code})",
        )

    @property
    def function_description(self) -> str:
        """Return the human-readable function description."""
        if self.function <= 127:
            return J1939_PRE_ASSIGNED_FUNCTIONS.get(
                self.function, f"Pre-Assigned / Reserved Function ({self.function})"
            )
        if 128 <= self.function <= 253:
            func_table = J1939_INDUSTRY_SPECIFIC_FUNCTIONS.get(self.industry_group, {})
            return func_table.get(
                self.function,
                f"Industry Group Specific Function {self.function}",
            )
        if self.function == 254:
            return "Error State"
        if self.function == 255:
            return "Not Available State"
        return f"Reserved State ({self.function})"

    @property
    def vehicle_system_description(self) -> str:
        """Return the human-readable vehicle system description."""
        vs_table = J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS.get(self.industry_group, {})
        return vs_table.get(
            self.vehicle_system,
            f"Industry Group Specific Vehicle System {self.vehicle_system}"
            if self.industry_group != 0
            else f"Common Vehicle System {self.vehicle_system}",
        )

    @property
    def industry_group_description(self) -> str:
        """Return the human-readable industry group description."""
        return J1939_INDUSTRY_GROUPS.get(
            self.industry_group,
            f"Unknown Industry Group ({self.industry_group})",
        )

    def mysummary(self) -> str:
        return (
            f"J1939_NAME: mfg='{self.manufacturer_name}' "
            f"func='{self.function_description}' "
            f"identity={self.identity_number} "
            f"arb_addr={bool(self.arbitrary_address_capable)}"
        )


bind_layers(J1939, J1939_NAME, pgn=J1939_PGN_ADDRESS_CLAIMED)


# ---------------------------------------------------------------------------
# Decoding and Arbitration Helpers
# ---------------------------------------------------------------------------

def j1939_decode_name(
    payload: Union[bytes, bytearray, int, str, Packet]
) -> J1939_NAME:
    """Convenience function to decode a 64-bit J1939 NAME into a J1939_NAME packet.

    :param payload: 8-byte LE bytes/bytearray, 64-bit int, hex string,
                    or CAN/J1939/J1939_NAME packet.
    :returns: :class:`J1939_NAME` instance.
    """
    if isinstance(payload, J1939_NAME):
        return payload
    if isinstance(payload, str):
        clean_hex = payload.strip().lower().replace(" ", "")
        if clean_hex.startswith("0x"):
            clean_hex = clean_hex[2:]
        payload_bytes = bytes.fromhex(clean_hex)
    elif isinstance(payload, int):
        payload_bytes = struct.pack("<Q", payload)
    elif isinstance(payload, Packet):
        if hasattr(payload, "data") and len(payload.data) == 8:
            payload_bytes = bytes(payload.data)
        else:
            raw_bytes = bytes(payload)
            if len(raw_bytes) >= 8:
                payload_bytes = raw_bytes[:8]
            else:
                payload_bytes = raw_bytes
    else:
        payload_bytes = bytes(payload)

    if len(payload_bytes) != 8:
        raise ValueError(
            f"Payload must be exactly 8 bytes, got {len(payload_bytes)} bytes"
        )
    return J1939_NAME(payload_bytes)


def simulate_arbitration(name1: Any, name2: Any) -> Dict[str, Any]:
    """Simulate J1939 address claim arbitration between two ECUs.

    In J1939, when two ECUs claim the same address, the ECU with the lower
    numerical 64-bit NAME value wins arbitration and retains the address.

    :param name1: NAME of ECU A (hex str, bytes, int, or J1939_NAME)
    :param name2: NAME of ECU B (hex str, bytes, int, or J1939_NAME)
    :returns: dict with arbitration results (winner, loser, win_name,
              lose_name, collision)
    """
    pkt1 = j1939_decode_name(name1)
    pkt2 = j1939_decode_name(name2)
    val1 = pkt1.raw_value
    val2 = pkt2.raw_value
    hex_val1 = "%016X" % val1
    hex_val2 = "%016X" % val2

    print("\n" + "#" * 60)
    print("           SAE J1939 ADDRESS ARBITRATION SIMULATOR")
    print("#" * 60)
    print(
        f"ECU A: NAME = 0x{hex_val1} "
        f"(Function: {pkt1.function_description}, Identity: {pkt1.identity_number})"
    )
    print(
        f"ECU B: NAME = 0x{hex_val2} "
        f"(Function: {pkt2.function_description}, Identity: {pkt2.identity_number})"
    )
    print("-" * 60)

    if val1 == val2:
        print("CRITICAL COLLISION: Both NAMEs are mathematically identical!")
        print("This is a protocol violation. ECUs must have unique identity numbers.")
        print("#" * 60 + "\n")
        return {"winner": None, "loser": None, "collision": True}

    if val1 < val2:
        winner, loser = "ECU A", "ECU B"
        win_pkt, lose_pkt = pkt1, pkt2
        win_val, lose_val = val1, val2
    else:
        winner, loser = "ECU B", "ECU A"
        win_pkt, lose_pkt = pkt2, pkt1
        win_val, lose_val = val2, val1

    hex_win = "%016X" % win_val
    hex_lose = "%016X" % lose_val
    print(
        f"Winner: {winner} "
        f"(Lower numerical value: 0x{hex_win} < 0x{hex_lose})"
    )
    print("Outcome:")
    print(
        "  - %s retains its claimed address and can start network "
        "communications." % winner
    )

    if lose_pkt.arbitrary_address_capable:
        print("  - %s is Arbitrary Address Capable (Bit 63 = 1)." % loser)
        print(
            "    Action: %s must select a different address (normally "
            "between 128 and 247) and transmit a new Address Claim message."
            % loser
        )
    else:
        print(
            "  - %s is Single Address / Non-Arbitrary Capable (Bit 63 = 0)."
            % loser
        )
        print(
            "    Action: %s MUST send a 'Cannot Claim Address' message "
            "(Source Address = 254/0xFE) and cease transmitting regular message "
            "frames on the network." % loser
        )
    print("#" * 60 + "\n")

    return {
        "winner": winner,
        "loser": loser,
        "win_name": win_pkt,
        "lose_name": lose_pkt,
        "collision": False,
    }


# ---------------------------------------------------------------------------
# Active NAME Request Functions
# ---------------------------------------------------------------------------

def j1939_request_name(
    sock: SockOrFactory,
    target_da: int = J1939_GLOBAL_ADDRESS,
    src_addr: int = 0xF1,
    sniff_time: float = 0.3,
    bitrate: Optional[int] = None,
    busload: float = J1939_DEFAULT_BUSLOAD,
    reconnect_handler: Optional[Callable[[], SuperSocket]] = None,
) -> Union[Optional[J1939_NAME], Dict[int, J1939_NAME]]:
    """Request and decode J1939 NAME for a given destination address (or broadcast).

    Sends a Request (PGN 59904, 0xEA00) for Address Claimed (PGN 60928, 0xEE00)
    to *target_da* using source address *src_addr*.

    If *target_da* is a specific address (0x00..0xFD), waits for the Address
    Claimed response from that address and returns a :class:`J1939_NAME` object
    (or ``None`` if timed out).

    If *target_da* is the broadcast address (:data:`J1939_GLOBAL_ADDRESS` = 0xFF),
    sniffs for all responses and returns a dictionary ``{sa: J1939_NAME}``.
    """
    if bitrate is None:
        bitrate = getattr(sock, "bitrate", None)
        if bitrate is None:
            can_bus = getattr(sock, "ins", None)
            bitrate = getattr(can_bus, "bitrate", None)
        if bitrate is None:
            bitrate = J1939_DEFAULT_BITRATE

    req = J1939Request(req_pgn=J1939_PGN_ADDRESS_CLAIMED, dst=target_da)

    if target_da == J1939_GLOBAL_ADDRESS:
        # Broadcast request
        found: Dict[int, J1939_NAME] = {}
        with j1939_get_sock(
            sock, src_addr=src_addr, reconnect_handler=reconnect_handler
        ) as j_sock:
            j1939_log.debug(
                "j1939_request_name: broadcast request sent (CAN-ID=0x%08X)",
                j1939_can_id(6, J1939_PF_REQUEST, J1939_GLOBAL_ADDRESS, src_addr),
            )
            ans, _ = j_sock.sr(req, multi=True, timeout=sniff_time, verbose=False)
            for _, rcv in ans:
                if rcv.pgn == J1939_PGN_ADDRESS_CLAIMED:
                    raw_data = rcv.data if rcv.data else bytes(rcv.payload)
                    if len(raw_data) >= 8 and rcv.src not in found:
                        found[rcv.src] = J1939_NAME(raw_data[:8])
            return found
    else:
        # Unicast request to target_da
        with j1939_get_sock(
            sock,
            src_addr=src_addr,
            reconnect_handler=reconnect_handler,
            target_sa=target_da,
        ) as j_sock:
            j1939_log.debug(
                "j1939_request_name: unicast request sent to DA=0x%02X (CAN-ID=0x%08X)",
                target_da,
                j1939_can_id(6, J1939_PF_REQUEST, target_da, src_addr),
            )
            rcv = j_sock.sr1(req, timeout=sniff_time, verbose=False)
            _extra = j1939_inter_probe_delay(bitrate, busload, 3, 8, sniff_time)
            if _extra > 0.0:
                time.sleep(_extra)
            if rcv is not None:
                raw_data = rcv.data if rcv.data else bytes(rcv.payload)
                if len(raw_data) >= 8:
                    return J1939_NAME(raw_data[:8])
            return None


def j1939_request_names(
    sock: SockOrFactory,
    target_das: Optional[Iterable[int]] = None,
    src_addr: int = 0xF1,
    sniff_time: float = 0.3,
    bitrate: Optional[int] = None,
    busload: float = J1939_DEFAULT_BUSLOAD,
    reconnect_handler: Optional[Callable[[], SuperSocket]] = None,
) -> Dict[int, Optional[J1939_NAME]]:
    """Request and decode J1939 NAMEs for multiple target Destination Addresses.

    :param sock: raw CAN socket or socket factory
    :param target_das: iterable of destination addresses to probe. If None,
                       a single broadcast request is issued.
    :param src_addr: scanner source address
    :param sniff_time: timeout per probe
    :param bitrate: bus bitrate in bit/s (optional, auto-detected from socket)
    :param busload: max busload fraction
    :param reconnect_handler: optional socket factory called per probe
    :returns: mapping ``{da: J1939_NAME or None}``
    """
    if target_das is None:
        broadcast_res = j1939_request_name(
            sock,
            target_da=J1939_GLOBAL_ADDRESS,
            src_addr=src_addr,
            sniff_time=sniff_time,
            bitrate=bitrate,
            busload=busload,
            reconnect_handler=reconnect_handler,
        )
        return broadcast_res if isinstance(broadcast_res, dict) else {}

    results: Dict[int, Optional[J1939_NAME]] = {}
    for da in target_das:
        res = j1939_request_name(
            sock,
            target_da=da,
            src_addr=src_addr,
            sniff_time=sniff_time,
            bitrate=bitrate,
            busload=busload,
            reconnect_handler=reconnect_handler,
        )
        results[da] = res if isinstance(res, J1939_NAME) else None
    return results


__all__ = [
    "J1939_INDUSTRY_GROUPS",
    "J1939_INDUSTRY_SPECIFIC_FUNCTIONS",
    "J1939_INDUSTRY_SPECIFIC_VEHICLE_SYSTEMS",
    "J1939_MANUFACTURERS",
    "J1939_NAME",
    "J1939_PRE_ASSIGNED_FUNCTIONS",
    "j1939_decode_name",
    "j1939_request_name",
    "j1939_request_names",
    "simulate_arbitration",
]
