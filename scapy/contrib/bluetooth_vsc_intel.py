# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
#
# scapy.contrib.description = Intel Bluetooth HCI Vendor-Specific Commands
# scapy.contrib.status = loads
#
# Information sources:
# - Linux mainline ``drivers/bluetooth/btintel.c`` / ``btintel.h``

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField,
    ByteEnumField,
    FieldLenField,
    LEMACField,
    LEShortField,
    PacketListField,
    StrFixedLenField,
    XStrLenField,
)

from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

_intel_hw_variant = {
    0x07: "WP", 0x08: "StP", 0x0b: "SfP", 0x0c: "WsP", 0x11: "JfP",
    0x12: "ThP", 0x13: "HrP", 0x14: "CcP", 0x17: "TyP", 0x18: "Slr",
    0x19: "Slr-F", 0x1b: "Mgr", 0x1c: "GaP", 0x1d: "BzrU", 0x1e: "Bzr",
    0x1f: "ScP", 0x20: "ScP2", 0x21: "ScP2-F", 0x22: "BzrIW",
}

_intel_image_type = {
    0x01: "bootloader",
    0x02: "iml",
    0x03: "operational",
}

_intel_tlv_type = {
    0x10: "cnvi_top", 0x11: "cnvr_top", 0x12: "cnvi_bt", 0x13: "cnvr_bt",
    0x14: "cnvi_otp", 0x15: "cnvr_otp", 0x16: "dev_rev_id",
    0x17: "usb_vendor_id", 0x18: "usb_product_id", 0x19: "pcie_vendor_id",
    0x1a: "pcie_device_id", 0x1b: "pcie_subsystem_id", 0x1c: "image_type",
    0x1d: "time_stamp", 0x1e: "build_type", 0x1f: "build_num",
    0x20: "fw_build_product", 0x21: "fw_build_hw", 0x22: "fw_step",
    0x23: "bt_spec", 0x24: "mfg_name", 0x25: "hci_rev", 0x26: "lmp_subver",
    0x27: "otp_patch_ver", 0x28: "secure_boot", 0x29: "key_from_hdr",
    0x2a: "otp_lock", 0x2b: "api_lock", 0x2c: "debug_lock", 0x2d: "min_fw",
    0x2e: "limited_cce", 0x2f: "sbe_type", 0x30: "otp_bdaddr",
    0x31: "unlocked_state", 0x32: "git_sha1", 0x50: "fw_id",
}

_intel_exception_type = {
    0x00: "system"
}


class HCI_Cmd_VSC_Intel_Read_Version(Packet):
    """
    Intel Read Version (OCF 0x005, opcode 0xFC05).

    An empty ``param`` requests the legacy fixed reply.
    A ``param=0xFF`` requests the TLV reply used by modern CNVi controllers.
    """
    name = "Intel Read Version"
    fields_desc = [
        ByteField("param", 0xFF),
    ]


class HCI_Cmd_VSC_Intel_Read_Boot_Params(Packet):
    """Intel Read Boot Params (OCF 0x00D, opcode 0xFC0D). Empty body."""
    name = "Intel Read Boot Params"


class HCI_Cmd_VSC_Intel_Read_Debug_Features(Packet):
    """Intel Read Debug Features (OCF 0x0A6, opcode 0xFCA6)."""
    name = "Intel Read Debug Features"
    fields_desc = [
        ByteField("page_no", 1),
    ]


class HCI_Cmd_VSC_Intel_Exception_Info(Packet):
    """
    Intel Exception Info (OCF 0x022, opcode 0xFC22).

    Issued by the driver after a hardware-error event to fetch the exception
    string.
    """
    name = "Intel Exception Info"
    fields_desc = [
        ByteEnumField("type", 0, _intel_exception_type),
    ]


class HCI_Cmd_Complete_VSC_Intel_Version_TLV(Packet):
    """One ``intel_version_tlv`` record: type, length, value."""
    name = "Intel Version TLV"
    fields_desc = [
        ByteEnumField("type", 0, _intel_tlv_type),
        FieldLenField("len", None, length_of="value", fmt="B"),
        XStrLenField("value", b"", length_from=lambda pkt: pkt.len),
    ]

    def extract_padding(self, s):
        return b"", s


class HCI_Cmd_Complete_VSC_Intel_Read_Version(Packet):
    """
    Read Version (0xFC05) command complete.
    """
    name = "Intel Read Version (TLV) complete"
    fields_desc = [
        PacketListField("tlvs", [], HCI_Cmd_Complete_VSC_Intel_Version_TLV,
                        length_from=lambda pkt: pkt.underlayer.underlayer.len - 4),
    ]


class HCI_Cmd_Complete_VSC_Intel_Read_Boot_Params(Packet):
    """
    Read Boot Params (0xFC0D) command complete.

    Reports the secure-boot / OTP / API / debug lock state.
    """
    name = "Intel Read Boot Params complete"
    fields_desc = [
        ByteField("otp_format", 0),
        ByteField("otp_content", 0),
        ByteField("otp_patch", 0),
        LEShortField("dev_revid", 0),
        ByteField("secure_boot", 0),
        ByteField("key_from_hdr", 0),
        ByteField("key_type", 0),
        ByteField("otp_lock", 0),
        ByteField("api_lock", 0),
        ByteField("debug_lock", 0),
        LEMACField("otp_bdaddr", None),
        ByteField("min_fw_build_nn", 0),
        ByteField("min_fw_build_cw", 0),
        ByteField("min_fw_build_yy", 0),
        ByteField("limited_cce", 0),
        ByteField("unlocked_state", 0),
    ]


class HCI_Cmd_Complete_VSC_Intel_Read_Debug_Features(Packet):
    """
    Read Debug Features (0xFCA6) command complete.

    ``page1`` is the 128-bit feature mask.
    ``page1[0] & 0x3f`` gates coredump and telemetry.
    """
    name = "Intel Read Debug Features complete"
    fields_desc = [
        ByteField("page_no", 1),
        StrFixedLenField("page1", b"\x00" * 16, 16),
    ]


class HCI_Cmd_Complete_VSC_Intel_Exception_Info(Packet):
    """
    Exception Info (0xFC22) command complete: a fixed 12-byte exception string.
    """
    name = "Intel Exception Info complete"
    fields_desc = [
        StrFixedLenField("exception", b"\x00" * 12, 12),
    ]


bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Intel_Read_Version, ogf=0x3F, ocf=0x005)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Intel_Read_Boot_Params, ogf=0x3F, ocf=0x00D)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Intel_Read_Debug_Features, ogf=0x3F, ocf=0x0A6)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Intel_Exception_Info, ogf=0x3F, ocf=0x022)

bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Intel_Read_Version,
            opcode=0xFC05)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Intel_Read_Boot_Params,
            opcode=0xFC0D)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Intel_Read_Debug_Features,
            opcode=0xFCA6)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Intel_Exception_Info,
            opcode=0xFC22)
