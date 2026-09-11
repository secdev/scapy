# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
#
# scapy.contrib.description = Zephyr Bluetooth HCI Vendor-Specific Commands
# scapy.contrib.status = loads
#
# Information sources:
# - Zephyr: https://github.com/zephyrproject-rtos/zephyr
#   - include/zephyr/bluetooth/hci_vs.h
#   - subsys/bluetooth/controller/hci/hci.c


from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    LEIntField,
    LEMACField,
    LEShortEnumField,
    LEShortField,
    PacketListField,
    XStrFixedLenField,
    XStrLenField,
)

from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

# Vendor OpCode Group Field for all VSCs
OGF_VENDOR_SPECIFIC = 0x3F

# --- OCF values (BT_HCI_OP_VS_*, hci_vs.h) --------------------------------
OCF_VS_READ_VERSION_INFO = 0x001         # opcode 0xFC01
OCF_VS_READ_SUPPORTED_COMMANDS = 0x002   # opcode 0xFC02
OCF_VS_READ_SUPPORTED_FEATURES = 0x003   # opcode 0xFC03
OCF_VS_WRITE_BD_ADDR = 0x006             # opcode 0xFC06
OCF_VS_READ_BUILD_INFO = 0x008           # opcode 0xFC08
OCF_VS_READ_STATIC_ADDRS = 0x009         # opcode 0xFC09
OCF_VS_READ_KEY_HIERARCHY_ROOTS = 0x00A  # opcode 0xFC0A

# BT_HCI_VS_HW_PLAT_* (hci_vs.h)
_zephyr_hw_platform = {
    0x0000: "reserved",
    0x0001: "Intel",
    0x0002: "Nordic Semiconductor",
    0x0003: "NXP Semiconductors",
    0x0004: "IMG",
}

# BT_HCI_VS_HW_VAR_NORDIC_* (hci_vs.h) -- meaning is platform-dependent; these
# are the Nordic variants (valid when hw_platform == Nordic Semiconductor).
_zephyr_hw_variant_nordic = {
    0x0001: "nRF51x",
    0x0002: "nRF52x",
    0x0003: "nRF53x",
    0x0004: "nRF54Hx",
    0x0005: "nRF54Lx",
}

# BT_HCI_VS_FW_VAR_* (hci_vs.h)
_zephyr_fw_variant = {
    0x00: "standard_controller",
}


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
class HCI_Cmd_VSC_Zephyr_Read_Version_Info(Packet):
    """Read Version Info (OCF 0x001, opcode 0xFC01). No parameters."""
    name = "Zephyr Read Version Info"


class HCI_Cmd_VSC_Zephyr_Read_Supported_Commands(Packet):
    """Read Supported Commands (OCF 0x002, opcode 0xFC02). No parameters."""
    name = "Zephyr Read Supported Commands"


class HCI_Cmd_VSC_Zephyr_Read_Supported_Features(Packet):
    """Read Supported Features (OCF 0x003, opcode 0xFC03). No parameters."""
    name = "Zephyr Read Supported Features"


class HCI_Cmd_VSC_Zephyr_Write_BD_Addr(Packet):
    """
    Write BD_ADDR (OCF 0x006, opcode 0xFC06).

    Sets the controller public device address to ``bd_addr``. The value persists
    across an HCI ``Reset`` (it is only re-initialised on a real power cycle /
    re-enumeration).
    """
    name = "Zephyr Write BD_ADDR"
    fields_desc = [LEMACField("bd_addr", None)]


class HCI_Cmd_VSC_Zephyr_Read_Build_Info(Packet):
    """Read Build Info (OCF 0x008, opcode 0xFC08). No parameters."""
    name = "Zephyr Read Build Info"


class HCI_Cmd_VSC_Zephyr_Read_Static_Addresses(Packet):
    """Read Static Addresses (OCF 0x009, opcode 0xFC09). No parameters."""
    name = "Zephyr Read Static Addresses"


class HCI_Cmd_VSC_Zephyr_Read_Key_Hierarchy_Roots(Packet):
    """Read Key Hierarchy Roots (OCF 0x00A, opcode 0xFC0A). No parameters."""
    name = "Zephyr Read Key Hierarchy Roots"


# ---------------------------------------------------------------------------
# Command Complete returns
# ---------------------------------------------------------------------------
class HCI_Cmd_Complete_VSC_Zephyr_Read_Version_Info(Packet):
    """
    Read Version Info (0xFC01) command complete.

    ``bt_hci_rp_vs_read_version_info``: hardware platform/variant and the
    controller firmware variant/version/revision/build.
    """
    name = "Zephyr Read Version Info complete"
    fields_desc = [
        LEShortEnumField("hw_platform", 0, _zephyr_hw_platform),
        LEShortEnumField("hw_variant", 0, _zephyr_hw_variant_nordic),
        ByteEnumField("fw_variant", 0, _zephyr_fw_variant),
        ByteField("fw_version", 0),
        LEShortField("fw_revision", 0),
        LEIntField("fw_build", 0),
    ]


class HCI_Cmd_Complete_VSC_Zephyr_Read_Supported_Commands(Packet):
    """Read Supported Commands (0xFC02) command complete: 64-byte support bitmap."""
    name = "Zephyr Read Supported Commands complete"
    fields_desc = [XStrFixedLenField("commands", b"\x00" * 64, 64)]


class HCI_Cmd_Complete_VSC_Zephyr_Read_Supported_Features(Packet):
    """Read Supported Features (0xFC03) command complete: 8-byte feature bitmap."""
    name = "Zephyr Read Supported Features complete"
    fields_desc = [XStrFixedLenField("features", b"\x00" * 8, 8)]


class HCI_Cmd_Complete_VSC_Zephyr_Read_Build_Info(Packet):
    """Read Build Info (0xFC08) command complete: the build-info string."""
    name = "Zephyr Read Build Info complete"
    fields_desc = [
        XStrLenField("build_info", b"",
                     length_from=lambda p: p.underlayer.underlayer.len - 4)
    ]


class ZephyrStaticAddr(Packet):
    """One ``bt_hci_vs_static_addr`` entry: a static random address + its IR."""
    name = "Zephyr Static Address"
    fields_desc = [
        LEMACField("addr", None),
        XStrFixedLenField("ir", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


class HCI_Cmd_Complete_VSC_Zephyr_Read_Static_Addresses(Packet):
    """
    Read Static Addresses (0xFC09) command complete.

    ``num`` static addresses, each a 6-byte address followed by its 16-byte
    Identity Root (IR). Read primitive: discloses the factory static random
    address and identity-root key material.
    """
    name = "Zephyr Read Static Addresses complete"
    fields_desc = [
        FieldLenField("num", None, count_of="addrs", fmt="B"),
        PacketListField("addrs", [], ZephyrStaticAddr,
                        count_from=lambda p: p.num),
    ]


class HCI_Cmd_Complete_VSC_Zephyr_Read_Key_Hierarchy_Roots(Packet):
    """
    Read Key Hierarchy Roots (0xFC0A) command complete.

    The Identity Root (``ir``) and Encryption Root (``er``), 16 bytes each.
    Read primitive: discloses the seeds of the BLE key hierarchy (IRK, and
    LTK/CSRK derivation).
    """
    name = "Zephyr Read Key Hierarchy Roots complete"
    fields_desc = [
        XStrFixedLenField("ir", b"\x00" * 16, 16),
        XStrFixedLenField("er", b"\x00" * 16, 16),
    ]


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Version_Info,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_READ_VERSION_INFO)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Supported_Commands,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_READ_SUPPORTED_COMMANDS)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Supported_Features,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_READ_SUPPORTED_FEATURES)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Write_BD_Addr,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_WRITE_BD_ADDR)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Build_Info,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_READ_BUILD_INFO)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Static_Addresses,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_READ_STATIC_ADDRS)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Key_Hierarchy_Roots,
            ogf=OGF_VENDOR_SPECIFIC, ocf=OCF_VS_READ_KEY_HIERARCHY_ROOTS)

bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Zephyr_Read_Version_Info, opcode=0xFC01)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Zephyr_Read_Supported_Commands, opcode=0xFC02)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Zephyr_Read_Supported_Features, opcode=0xFC03)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Zephyr_Read_Build_Info, opcode=0xFC08)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Zephyr_Read_Static_Addresses, opcode=0xFC09)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Zephyr_Read_Key_Hierarchy_Roots, opcode=0xFC0A)
